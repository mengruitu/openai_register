import builtins
import concurrent.futures
import json
import os
import random
import re
import threading
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from curl_cffi import requests

from register_notifications import build_monitor_summary_message, send_dingtalk_alert

DEFAULT_TOKEN_CHECK_WORKERS = 6
TOKEN_USAGE_CACHE_TTL_SECONDS = 180
DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS = 900

output_lock = threading.Lock()
_token_usage_cache_lock = threading.Lock()
TOKEN_USAGE_CACHE: Dict[str, Dict[str, Any]] = {}

RegisterRunner = Callable[..., Tuple[Optional[Tuple[str, str]], str]]
ReloadCfmailHook = Callable[[], None]


@dataclass(frozen=True)
class MonitorCycleResult:
    completed_at: datetime
    active_count: int
    pool_count: int
    active_target: int
    pool_target: int
    active_shortage: int
    pool_shortage: int
    attempted_replenish: bool
    register_target: int
    replenished_count: int
    deleted_count: int
    active_deleted_count: int
    pool_deleted_count: int
    moved_to_active_count: int
    active_check_failed: int
    pool_check_failed: int


def log_info(message: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [信息] {message}")


def log_warn(message: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] {message}")


def log_error(message: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [错误] {message}")


def _safe_token_filename(email: str, thread_id: int) -> str:
    raw = (email or "").strip().lower()
    if not raw:
        return f"unknown_{thread_id}_{int(time.time())}.json"

    safe = re.sub(r"[^0-9a-zA-Z@._-]", "_", raw).strip("._")
    if not safe:
        safe = f"unknown_{thread_id}_{int(time.time())}"
    return f"{safe}.json"


def _build_unique_path(directory: str, base_name: str) -> str:
    path = os.path.join(directory, base_name)
    if not os.path.exists(path):
        return path

    stem, ext = os.path.splitext(base_name)
    return os.path.join(
        directory,
        f"{stem}_{int(time.time())}_{random.randint(1000, 9999)}{ext}",
    )


def _build_token_output_path(token_dir: str, email: str, thread_id: int) -> str:
    base_name = _safe_token_filename(email, thread_id)
    return _build_unique_path(token_dir, base_name)


def list_json_files(directory: str) -> List[str]:
    if not os.path.isdir(directory):
        return []

    files = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if name.endswith(".json") and os.path.isfile(path):
            files.append(path)
    return files


def count_json_files(directory: str) -> int:
    return len(list_json_files(directory))


def _token_usage_file_signature(file_path: str) -> Tuple[int, int]:
    stat = os.stat(file_path)
    return int(stat.st_mtime_ns), int(stat.st_size)


def _get_cached_used_percent(
    file_path: str,
) -> Tuple[bool, Optional[int], Optional[Tuple[int, int]]]:
    now = time.time()
    try:
        signature = _token_usage_file_signature(file_path)
    except OSError as exc:
        log_error(f"读取 {os.path.basename(file_path)} 失败: {exc}")
        return True, None, None

    with _token_usage_cache_lock:
        cached = TOKEN_USAGE_CACHE.get(file_path)
        if (
            cached
            and cached.get("signature") == signature
            and now - float(cached.get("checked_at") or 0) <= TOKEN_USAGE_CACHE_TTL_SECONDS
        ):
            return True, cached.get("used_percent"), signature

    return False, None, signature


def _store_cached_used_percent(
    file_path: str,
    signature: Optional[Tuple[int, int]],
    used_percent: Optional[int],
) -> None:
    if signature is None:
        return

    now = time.time()
    with _token_usage_cache_lock:
        TOKEN_USAGE_CACHE[file_path] = {
            "signature": signature,
            "used_percent": used_percent,
            "checked_at": now,
        }
        if len(TOKEN_USAGE_CACHE) > 2048:
            expire_before = now - (TOKEN_USAGE_CACHE_TTL_SECONDS * 2)
            for cached_path, cached in list(TOKEN_USAGE_CACHE.items()):
                if float(cached.get("checked_at") or 0) < expire_before:
                    TOKEN_USAGE_CACHE.pop(cached_path, None)


def get_used_percent(file_path: str, timeout: int) -> Optional[int]:
    has_cached, cached_value, signature = _get_cached_used_percent(file_path)
    if has_cached:
        return cached_value

    result: Optional[int] = None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        log_error(f"读取 {os.path.basename(file_path)} 失败: {exc}")
        _store_cached_used_percent(file_path, signature, None)
        return None

    access_token = str(data.get("access_token") or "").strip()
    account_id = str(data.get("account_id") or "").strip()
    if not access_token or not account_id:
        log_error(f"文件 {os.path.basename(file_path)} 缺少 access_token 或 account_id")
        _store_cached_used_percent(file_path, signature, None)
        return None

    try:
        resp = requests.get(
            "https://chatgpt.com/backend-api/wham/usage",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
                "Chatgpt-Account-Id": account_id,
            },
            impersonate="chrome",
            timeout=timeout,
        )
        if resp.status_code != 200:
            log_error(
                f"文件 {os.path.basename(file_path)} 额度查询失败，状态码: {resp.status_code}"
            )
        else:
            payload = resp.json()
            used_percent = (
                ((payload or {}).get("rate_limit") or {}).get("primary_window") or {}
            ).get("used_percent")
            if used_percent is None:
                log_error(f"文件 {os.path.basename(file_path)} 额度结果缺少 used_percent")
            else:
                result = int(float(used_percent))
    except Exception as exc:
        log_error(f"文件 {os.path.basename(file_path)} 额度查询异常: {exc}")
        result = None

    _store_cached_used_percent(file_path, signature, result)
    return result


def _collect_used_percent_results(
    file_paths: List[str],
    timeout: int,
    request_interval: int,
    max_workers: int,
) -> Dict[str, Optional[int]]:
    files = [path for path in file_paths if path]
    if not files:
        return {}

    worker_count = max(1, int(max_workers or 1))
    results: Dict[str, Optional[int]] = {}

    if worker_count == 1 or len(files) == 1:
        for index, file_path in enumerate(files):
            results[file_path] = get_used_percent(file_path, timeout)
            if request_interval > 0 and index + 1 < len(files):
                time.sleep(request_interval)
        return results

    batch_size = min(worker_count, len(files))
    for batch_start in range(0, len(files), batch_size):
        batch = files[batch_start : batch_start + batch_size]
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(worker_count, len(batch))
        ) as executor:
            future_map = {
                executor.submit(get_used_percent, file_path, timeout): file_path
                for file_path in batch
            }
            for future in concurrent.futures.as_completed(future_map):
                file_path = future_map[future]
                try:
                    results[file_path] = future.result()
                except Exception as exc:
                    log_error(f"文件 {os.path.basename(file_path)} 并发额度查询异常: {exc}")
                    results[file_path] = None

        if request_interval > 0 and batch_start + batch_size < len(files):
            time.sleep(request_interval)

    return results


def persist_registration_result(
    token_json: str, password: str, thread_id: int, token_dir: str
) -> Tuple[str, str]:
    try:
        token_data = json.loads(token_json)
        raw_email = str(token_data.get("email") or "unknown")
        refresh_token = str(token_data.get("refresh_token") or "")
    except Exception:
        raw_email = "unknown"
        refresh_token = ""

    os.makedirs(token_dir, exist_ok=True)
    file_name = _build_token_output_path(token_dir, raw_email, thread_id)
    with open(file_name, "w", encoding="utf-8") as f:
        f.write(token_json)

    os.makedirs("output", exist_ok=True)
    with output_lock:
        with open("output/accounts.txt", "a", encoding="utf-8") as f:
            f.write(f"{raw_email}----{password}----{refresh_token}\n")

    return file_name, raw_email


def _cleanup_tokens_in_dir(
    directory: str,
    label: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
) -> Tuple[int, int, int]:
    deleted_count = 0
    kept_count = 0
    check_failed = 0

    file_paths = list_json_files(directory)
    usage_results = _collect_used_percent_results(
        file_paths,
        curl_timeout,
        request_interval,
        token_check_workers,
    )

    for file_path in file_paths:
        used_percent = usage_results.get(file_path)
        if used_percent is None:
            log_warn(f"删除 {label} 中的 {os.path.basename(file_path)}，额度查询失败")
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
            deleted_count += 1
            check_failed += 1
        elif used_percent >= usage_threshold:
            log_info(
                f"删除 {label} 中的 {os.path.basename(file_path)}，已用比例 {used_percent}% >= {usage_threshold}%"
            )
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
            deleted_count += 1
        else:
            kept_count += 1
            log_info(
                f"保留 {label} 中的 {os.path.basename(file_path)}，已用比例 {used_percent}%"
            )

    return kept_count, deleted_count, check_failed


def cleanup_active_tokens(
    active_dir: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
) -> Tuple[int, int, int]:
    return _cleanup_tokens_in_dir(
        active_dir,
        "A",
        usage_threshold,
        request_interval,
        curl_timeout,
        token_check_workers,
    )


def cleanup_pool_tokens(
    pool_dir: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
) -> Tuple[int, int, int]:
    return _cleanup_tokens_in_dir(
        pool_dir,
        "B",
        usage_threshold,
        request_interval,
        curl_timeout,
        token_check_workers,
    )


def move_pool_tokens_to_active(
    active_dir: str,
    pool_dir: str,
    active_target: int,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
) -> Tuple[int, int]:
    current_active = count_json_files(active_dir)
    needed = max(active_target - current_active, 0)
    if needed <= 0:
        return 0, 0

    moved_count = 0
    deleted_count = 0
    pool_files = list_json_files(pool_dir)
    random.shuffle(pool_files)
    usage_results = _collect_used_percent_results(
        pool_files,
        curl_timeout,
        request_interval,
        token_check_workers,
    )

    for file_path in pool_files:
        if moved_count >= needed:
            break

        used_percent = usage_results.get(file_path)
        if used_percent is None:
            log_warn(f"删除 B 中的 {os.path.basename(file_path)}，额度查询失败")
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
            deleted_count += 1
        elif used_percent >= usage_threshold:
            log_info(
                f"删除 B 中的 {os.path.basename(file_path)}，已用比例 {used_percent}% >= {usage_threshold}%"
            )
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
            deleted_count += 1
        else:
            destination = _build_unique_path(active_dir, os.path.basename(file_path))
            os.replace(file_path, destination)
            moved_count += 1
            log_info(
                f"从 B 补充到 A: {os.path.basename(destination)}，已补 {moved_count}/{needed}"
            )

    return moved_count, deleted_count


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
        result, used_provider = register_runner(
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
        file_name, raw_email = persist_registration_result(
            token_json, password, thread_id, token_dir
        )
        log_info(f"补号成功: {raw_email} -> {file_name}（邮箱服务: {used_provider}）")
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

    if auto_continue_non_us and builtins.yasal_bypass_ip_choice is None:
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
        batch_results: List[bool] = []
        batch_results_lock = threading.Lock()
        threads = []

        for index in range(current_batch_size):
            current_thread_id = attempts + index + 1

            def _task(tid: int = current_thread_id) -> None:
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
                with batch_results_lock:
                    batch_results.append(is_success)

            thread = threading.Thread(target=_task)
            thread.daemon = True
            thread.start()
            threads.append(thread)
            if register_start_delay_seconds > 0 and index + 1 < current_batch_size:
                time.sleep(register_start_delay_seconds)

        for thread in threads:
            thread.join()

        attempts += current_batch_size
        batch_success = sum(1 for item in batch_results if item)
        success_count += batch_success
        log_info(
            f"补号批次完成：本批成功 {batch_success} 个，累计成功 {success_count}/{target_count}"
        )

        if batch_success == 0 and success_count < target_count:
            time.sleep(10)

    if success_count < target_count:
        log_warn(f"目标补号 {target_count} 个，实际仅补充成功 {success_count} 个")

    return success_count


def run_monitor_cycle(args: Any, register_runner: RegisterRunner) -> MonitorCycleResult:
    os.makedirs(args.active_token_dir, exist_ok=True)
    os.makedirs(args.token_dir, exist_ok=True)

    log_info("========== 开始执行账号检测 ==========")
    kept_count, deleted_count, check_failed = cleanup_active_tokens(
        args.active_token_dir,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
        args.token_check_workers,
    )
    log_info(f"A 清理完成：保留 {kept_count}，删除 {deleted_count}，查询失败 {check_failed}")

    pool_kept_count, pool_deleted_count, pool_check_failed = cleanup_pool_tokens(
        args.token_dir,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
        args.token_check_workers,
    )
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
    )
    if moved_before_register > 0:
        log_info(f"首次从 B 补充到 A 共 {moved_before_register} 个")
    else:
        log_info("首次从 B 补充到 A：本轮无需补充或 B 中无可补账号")

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
            log_info(
                f"A 目录存在缺口，优先直补 A：计划补 {active_shortage} 个到 {args.active_token_dir}"
            )
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
            log_info(
                f"A 直补完成：计划补 {active_shortage} 个，实际成功 {replenished_to_active} 个"
            )
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
            )
            if moved_after_register > 0:
                log_info(f"补号后再次从 B 补充到 A 共 {moved_after_register} 个")
            else:
                log_info("补号后再次从 B 补充到 A：A 已达标或新号暂未补入 A")
    else:
        log_info(
            f"A/B 均已达标：A={active_count}/{args.active_min_count}，B={pool_count}/{args.pool_min_count}，本轮不补号"
        )

    final_active_count = count_json_files(args.active_token_dir)
    final_pool_count = count_json_files(args.token_dir)
    final_active_shortage = max(args.active_min_count - final_active_count, 0)
    final_pool_shortage = max(args.pool_min_count - final_pool_count, 0)
    total_deleted_count = (
        deleted_count
        + pool_deleted_count
        + deleted_from_pool_before
        + deleted_from_pool_after
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
        print(
            f"\n[{datetime.now().strftime('%H:%M:%S')}] [线程 {thread_id}] [信息] 开始第 {count} 次任务（邮箱服务: {provider_key}）"
        )

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
                file_name, raw_email = persist_registration_result(
                    token_json,
                    password,
                    thread_id,
                    token_dir,
                )

                print(
                    f"[线程 {thread_id}] [成功] 账号信息已追加到 output/accounts.txt，"
                    f"Token 已保存到: {file_name}（邮箱服务: {used_provider}）"
                )
                is_success = True
            else:
                print(f"[线程 {thread_id}] [失败] 本轮任务未成功")

        except Exception as e:
            print(f"[线程 {thread_id}] [错误] 发生未捕获异常: {e}")
            print(f"[线程 {thread_id}] [错误] {traceback.format_exc()}")
            is_success = False

        if once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        if not is_success:
            print(
                f"[线程 {thread_id}] [提示] 本轮失败，额外等待 {failure_sleep_seconds} 秒后重试"
            )
            wait_time += max(0, failure_sleep_seconds)

        print(f"[线程 {thread_id}] [信息] 等待 {wait_time} 秒后继续")
        time.sleep(wait_time)


def run_monitor_loop(
    args: Any,
    register_runner: RegisterRunner,
    reload_cfmail_accounts: Optional[ReloadCfmailHook] = None,
) -> None:
    pending_results: List[MonitorCycleResult] = []
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
                log_info(
                    f"已发送钉钉汇总通知，共汇总 {len(pending_results)} 轮检测结果"
                )
            pending_results = []
            summary_started_at = now_ts

        if args.monitor_once:
            break

        elapsed_seconds = int(time.time() - cycle_started_at)
        sleep_seconds = max(1, args.monitor_interval - elapsed_seconds)
        log_info(f"等待 {sleep_seconds} 秒后进入下一轮检测")
        time.sleep(sleep_seconds)
