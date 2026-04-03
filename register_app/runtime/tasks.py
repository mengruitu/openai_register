"""Registration workers and monitor loop orchestration."""

from __future__ import annotations

import builtins
import concurrent.futures
import os
import random
import threading
import time
from datetime import datetime
from typing import Any, Optional

from ..notifications import build_monitor_summary_message, send_dingtalk_alert
from .common import (
    DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
    MonitorCycleResult,
    RegisterRunner,
    ReloadCfmailHook,
    SHORTAGE_FAIL_RETRY_SECONDS,
    SHORTAGE_FAST_RETRY_SECONDS,
    count_json_files,
    log_error,
    log_info,
    log_warn,
    persist_registration_result,
)
from .tokens import (
    cleanup_active_tokens,
    cleanup_pool_tokens,
    move_pool_tokens_to_active,
)


def register_single_account(
    proxy: Optional[str],
    provider_key: str,
    thread_id: int,
    mailtm_base: str,
    token_dir: str,
    register_runner: RegisterRunner,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> bool:
    try:
        result, _used_provider = register_runner(
            proxy,
            provider_key,
            thread_id,
            mailtm_base,
            dingtalk_webhook=dingtalk_webhook,
            dingtalk_fallback_interval_seconds=dingtalk_fallback_interval_seconds,
        )
        if not result:
            log_warn(f"补号任务 #{thread_id} 失败")
            return False

        token_json, password = result
        persist_registration_result(token_json, password, thread_id, token_dir)
        return True
    except Exception as exc:
        log_error(f"补号任务 #{thread_id} 异常: {exc}")
        return False


def register_accounts(
    target_count: int,
    proxy: Optional[str],
    provider_key: str,
    mailtm_base: str,
    token_dir: str,
    batch_size: int,
    register_openai_concurrency: int,
    register_start_delay_seconds: float,
    auto_continue_non_us: bool,
    register_runner: RegisterRunner,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> int:
    if target_count <= 0:
        return 0

    if auto_continue_non_us and getattr(builtins, "yasal_bypass_ip_choice", None) is None:
        builtins.yasal_bypass_ip_choice = True

    success_count = 0
    attempts = 0
    batch_size = max(1, batch_size)
    register_openai_concurrency = max(1, register_openai_concurrency)
    register_start_delay_seconds = max(0.0, float(register_start_delay_seconds))
    max_attempts = max(target_count * 4, target_count + batch_size)

    while success_count < target_count and attempts < max_attempts:
        current_batch_size = min(
            batch_size,
            register_openai_concurrency,
            target_count - success_count,
            max_attempts - attempts,
        )
        batch_success_count = 0
        batch_results_lock = threading.Lock()
        threads: list[threading.Thread] = []

        for index in range(current_batch_size):
            current_thread_id = attempts + index + 1

            def _task(tid: int = current_thread_id) -> None:
                nonlocal batch_success_count
                is_success = register_single_account(
                    proxy,
                    provider_key,
                    tid,
                    mailtm_base,
                    token_dir,
                    register_runner,
                    dingtalk_webhook,
                    dingtalk_fallback_interval_seconds,
                )
                if is_success:
                    with batch_results_lock:
                        batch_success_count += 1

            thread = threading.Thread(target=_task, daemon=True)
            thread.start()
            threads.append(thread)
            if register_start_delay_seconds > 0 and index + 1 < current_batch_size:
                time.sleep(register_start_delay_seconds)

        for thread in threads:
            thread.join()

        attempts += current_batch_size
        batch_success = batch_success_count
        success_count += batch_success
        log_info(f"补号批次完成：本批成功 {batch_success} 个，累计成功 {success_count}/{target_count}")

        if batch_success == 0 and success_count < target_count:
            time.sleep(10)

    if success_count < target_count:
        log_warn(f"目标补号 {target_count} 个，实际仅补充成功 {success_count} 个")

    return success_count


def run_monitor_cycle(args: Any, register_runner: RegisterRunner) -> MonitorCycleResult:
    os.makedirs(args.active_token_dir, exist_ok=True)
    os.makedirs(args.token_dir, exist_ok=True)

    log_info("========== 开始执行账号检测 ==========")

    cleanup_args_a = (
        args.active_token_dir,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
        args.token_check_workers,
        args.proxy,
    )
    cleanup_args_b = (
        args.token_dir,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
        args.token_check_workers,
        args.proxy,
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as cleanup_executor:
        future_a = cleanup_executor.submit(cleanup_active_tokens, *cleanup_args_a)
        future_b = cleanup_executor.submit(cleanup_pool_tokens, *cleanup_args_b)
        kept_count, deleted_count, check_failed = future_a.result()
        pool_kept_count, pool_deleted_count, pool_check_failed = future_b.result()

    log_info(f"A 清理完成：保留 {kept_count}，删除 {deleted_count}，查询失败 {check_failed}")
    log_info(
        f"B 清理完成：保留 {pool_kept_count}，删除 {pool_deleted_count}，查询失败 {pool_check_failed}"
    )

    moved_before_register, deleted_from_pool_before = move_pool_tokens_to_active(
        args.active_token_dir,
        args.token_dir,
        args.active_min_count,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
        args.token_check_workers,
        args.proxy,
    )
    if moved_before_register > 0:
        log_info(f"首次从 B 补充到 A 共 {moved_before_register} 个")

    active_count = count_json_files(args.active_token_dir)
    pool_count = count_json_files(args.token_dir)
    active_shortage = max(args.active_min_count - active_count, 0)
    pool_shortage = max(args.pool_min_count - pool_count, 0)
    register_target = active_shortage + pool_shortage
    log_info(
        f"当前库存统计：A={active_count}/{args.active_min_count}（缺 {active_shortage}），"
        f"B={pool_count}/{args.pool_min_count}（缺 {pool_shortage}）"
    )
    replenished_count = 0
    replenished_to_active = 0
    replenished_to_pool = 0
    moved_after_register = 0
    deleted_from_pool_after = 0

    if register_target > 0:
        log_warn(
            f"检测到库存不足：A={active_count}/{args.active_min_count}，B={pool_count}/{args.pool_min_count}，准备补号 {register_target} 个"
        )
        if active_shortage > 0:
            log_info(f"A 目录存在缺口，优先直补 A：计划补 {active_shortage} 个到 {args.active_token_dir}")
            replenished_to_active = register_accounts(
                active_shortage,
                args.proxy,
                args.mail_provider,
                args.mailtm_api_base,
                args.active_token_dir,
                args.register_batch_size,
                args.register_openai_concurrency,
                args.register_start_delay_seconds,
                args.auto_continue_non_us,
                register_runner,
                args.dingtalk_webhook,
                args.dingtalk_fallback_interval,
            )
            replenished_count += replenished_to_active
            log_info(f"A 直补完成：计划补 {active_shortage} 个，实际成功 {replenished_to_active} 个")
            active_count = count_json_files(args.active_token_dir)
            pool_count = count_json_files(args.token_dir)

        remaining_active_shortage = max(args.active_min_count - active_count, 0)
        remaining_pool_shortage = max(args.pool_min_count - pool_count, 0)
        remaining_register_target = remaining_active_shortage + remaining_pool_shortage
        if remaining_register_target > 0:
            log_info(
                f"继续补充 B 目录：A 剩余缺口 {remaining_active_shortage}，"
                f"B 剩余缺口 {remaining_pool_shortage}，计划补 {remaining_register_target} 个到 {args.token_dir}"
            )
            replenished_to_pool = register_accounts(
                remaining_register_target,
                args.proxy,
                args.mail_provider,
                args.mailtm_api_base,
                args.token_dir,
                args.register_batch_size,
                args.register_openai_concurrency,
                args.register_start_delay_seconds,
                args.auto_continue_non_us,
                register_runner,
                args.dingtalk_webhook,
                args.dingtalk_fallback_interval,
            )
            replenished_count += replenished_to_pool

        log_info(
            f"注册补号完成：总计划补 {register_target} 个，"
            f"A 直补成功 {replenished_to_active} 个，"
            f"B 补号成功 {replenished_to_pool} 个，"
            f"总成功 {replenished_count} 个"
        )
        if replenished_count > 0:
            moved_after_register, deleted_from_pool_after = move_pool_tokens_to_active(
                args.active_token_dir,
                args.token_dir,
                args.active_min_count,
                args.usage_threshold,
                args.request_interval,
                args.curl_timeout,
                args.token_check_workers,
                args.proxy,
            )
            if moved_after_register > 0:
                log_info(f"补号后再次从 B 补充到 A 共 {moved_after_register} 个")
    else:
        log_info(
            f"A/B 均已达标：A={active_count}/{args.active_min_count}，B={pool_count}/{args.pool_min_count}，本轮不补号"
        )

    final_active_count = count_json_files(args.active_token_dir)
    final_pool_count = count_json_files(args.token_dir)
    final_active_shortage = max(args.active_min_count - final_active_count, 0)
    final_pool_shortage = max(args.pool_min_count - final_pool_count, 0)
    total_deleted_count = (
        deleted_count + pool_deleted_count + deleted_from_pool_before + deleted_from_pool_after
    )
    log_info(
        f"本轮汇总：删 A={deleted_count}，删 B={pool_deleted_count + deleted_from_pool_before + deleted_from_pool_after}，"
        f"B→A={moved_before_register + moved_after_register}，注册成功={replenished_count}"
    )
    log_info(
        f"检测结束：A={final_active_count}/{args.active_min_count}（缺 {final_active_shortage}），"
        f"B={final_pool_count}/{args.pool_min_count}（缺 {final_pool_shortage}），补号={replenished_count}"
    )
    log_info("========== 账号检测执行完成 ==========")
    return MonitorCycleResult(
        completed_at=datetime.now(),
        active_count=final_active_count,
        pool_count=final_pool_count,
        active_target=args.active_min_count,
        pool_target=args.pool_min_count,
        active_shortage=final_active_shortage,
        pool_shortage=final_pool_shortage,
        attempted_replenish=register_target > 0,
        register_target=register_target,
        replenished_count=replenished_count,
        deleted_count=total_deleted_count,
        active_deleted_count=deleted_count,
        pool_deleted_count=pool_deleted_count + deleted_from_pool_before + deleted_from_pool_after,
        moved_to_active_count=moved_before_register + moved_after_register,
        active_check_failed=check_failed,
        pool_check_failed=pool_check_failed,
    )


def worker(
    thread_id: int,
    proxy: Optional[str],
    once: bool,
    sleep_min: int,
    sleep_max: int,
    failure_sleep_seconds: int,
    provider_key: str,
    mailtm_base: str,
    token_dir: str,
    register_runner: RegisterRunner,
    reload_cfmail_accounts: Optional[ReloadCfmailHook] = None,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> None:
    count = 0
    while True:
        if provider_key == "cfmail" and reload_cfmail_accounts:
            reload_cfmail_accounts()
        count += 1
        log_info(f"[线程 {thread_id}] 开始第 {count} 次任务（邮箱服务: {provider_key}）")

        try:
            result, used_provider = register_runner(
                proxy,
                provider_key,
                thread_id,
                mailtm_base,
                dingtalk_webhook=dingtalk_webhook,
                dingtalk_fallback_interval_seconds=dingtalk_fallback_interval_seconds,
            )

            is_success = False
            if result:
                token_json, password = result
                file_name, _raw_email = persist_registration_result(
                    token_json,
                    password,
                    thread_id,
                    token_dir,
                )
                log_info(
                    f"[线程 {thread_id}] 账号信息已追加到 output/accounts.txt，"
                    f"Token 已保存到: {file_name}（邮箱服务: {used_provider}）"
                )
                is_success = True
            else:
                log_warn(f"[线程 {thread_id}] 本轮任务未成功")
        except Exception as exc:
            log_error(f"[线程 {thread_id}] 发生未捕获异常: {exc}")
            is_success = False

        if once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        if not is_success:
            log_info(f"[线程 {thread_id}] 本轮失败，额外等待 {failure_sleep_seconds} 秒后重试")
            wait_time += max(0, failure_sleep_seconds)

        time.sleep(wait_time)


def run_monitor_loop(
    args: Any,
    register_runner: RegisterRunner,
    reload_cfmail_accounts: Optional[ReloadCfmailHook] = None,
) -> None:
    pending_results: list[MonitorCycleResult] = []
    summary_started_at = time.time()
    while True:
        if args.mail_provider == "cfmail" and reload_cfmail_accounts:
            reload_cfmail_accounts()
        cycle_started_at = time.time()
        try:
            cycle_result = run_monitor_cycle(args, register_runner)
            pending_results.append(cycle_result)
        except Exception as exc:
            log_error(f"检测循环异常: {exc}")
            cycle_result = None

        should_send_summary = False
        now_ts = time.time()
        if pending_results:
            if args.monitor_once:
                should_send_summary = True
            elif now_ts - summary_started_at >= args.dingtalk_summary_interval:
                should_send_summary = True

        if should_send_summary:
            summary_message = build_monitor_summary_message(pending_results)
            if summary_message:
                send_dingtalk_alert(args.dingtalk_webhook, summary_message)
                log_info(f"已发送钉钉汇总通知，共汇总 {len(pending_results)} 轮检测结果")
            pending_results = []
            summary_started_at = now_ts

        if args.monitor_once:
            break

        elapsed_seconds = int(time.time() - cycle_started_at)
        has_shortage = cycle_result is not None and (
            cycle_result.active_shortage > 0 or cycle_result.pool_shortage > 0
        )
        if has_shortage:
            attempted_but_failed = cycle_result.attempted_replenish and cycle_result.replenished_count == 0
            if attempted_but_failed:
                target_interval = max(SHORTAGE_FAIL_RETRY_SECONDS, args.monitor_interval // 3)
            else:
                target_interval = max(SHORTAGE_FAST_RETRY_SECONDS, args.monitor_interval // 5)
            sleep_seconds = max(1, target_interval - elapsed_seconds)
            log_info(
                f"检测到库存缺口（A 缺 {cycle_result.active_shortage}，"
                f"B 缺 {cycle_result.pool_shortage}），缩短等待间隔，"
                f"{sleep_seconds} 秒后进入下一轮检测"
            )
        else:
            sleep_seconds = max(1, args.monitor_interval - elapsed_seconds)
            log_info(f"等待 {sleep_seconds} 秒后进入下一轮检测")
        time.sleep(sleep_seconds)


__all__ = [
    "register_accounts",
    "register_single_account",
    "run_monitor_cycle",
    "run_monitor_loop",
    "worker",
]
