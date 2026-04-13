# -*- coding: utf-8 -*-
"""OpenAI 自动注册与账号巡检脚本。

支持多种临时邮箱服务，自动完成注册流程并维护 A 目录账号池。

本文件仅作为 CLI 入口：
- 核心注册流程 → register_app/registration/
- OAuth / Token 链路 → register_app/auth/
- Sentinel/指纹 → register_app/sentinel.py
- 邮箱 / cfmail → register_app/mail/
- 常量/配置管理 → register_app/config.py
"""
import argparse
import builtins
import json
import logging
import os
import subprocess
import sys
import threading
import time
from typing import Optional

from register_app.doctor import (
    build_status_snapshot,
    collect_doctor_report,
    print_doctor_report,
    print_status_snapshot,
)
from register_app.mail.cfmail import (
    CfmailAccount,
    DEFAULT_CFMAIL_ACCOUNTS,
    DEFAULT_CFMAIL_CONFIG_PATH,
    DEFAULT_CFMAIL_COOLDOWN_SECONDS,
    DEFAULT_CFMAIL_FAIL_THRESHOLD,
    build_cfmail_accounts as _build_cfmail_accounts,
    cfmail_account_names as _cfmail_account_names,
    configure_cfmail_runtime,
    get_cfmail_accounts,
    load_cfmail_accounts_from_file as _load_cfmail_accounts_from_file,
    normalize_host as _normalize_host,
    reload_cfmail_accounts_if_needed as _reload_cfmail_accounts_if_needed,
    run_cfmail_self_test,
    select_cfmail_account as _select_cfmail_account,
)
from register_app.config import (
    DEFAULT_ACTIVE_TOKEN_DIR,
    DEFAULT_CHECK_INTERVAL_SECONDS,
    DEFAULT_CONFIG_PATH,
    DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
    DEFAULT_DINGTALK_SUMMARY_INTERVAL_SECONDS,
    DEFAULT_DINGTALK_WEBHOOK,
    DEFAULT_MIN_ACTIVE_COUNT,
    DEFAULT_REGISTER_BATCH_SIZE,
    DEFAULT_REGISTER_FAILURE_EXTRA_SLEEP_SECONDS,
    DEFAULT_REGISTER_OPENAI_CONCURRENCY,
    DEFAULT_REGISTER_START_DELAY_SECONDS,
    DEFAULT_PROXY_POOL_CONSUMERS_PATH,
    DEFAULT_PROXY_POOL_CONSUMER_TTL_SECONDS,
    DEFAULT_PROXY_POOL_HEARTBEAT_INTERVAL_SECONDS,
    DEFAULT_PROXY_POOL_STATE_PATH,
    DEFAULT_PROXY_POOL_TARGET_MULTIPLIER,
    DEFAULT_R2_PREFIX,
    DEFAULT_R2_RETRY_COUNT,
    DEFAULT_R2_RETRY_DELAY_SECONDS,
    DEFAULT_TOKEN_OUTPUT_DIR,
    apply_config_to_args,
    apply_low_memory_tuning,
    load_config_file,
)
from register_app.proxy import resolve_registration_proxy, supports_generated_proxy_pool
from register_app.proxy_pool import (
    build_proxy_pool_config_from_args,
    initialize_proxy_pool_runtime,
    shutdown_proxy_pool_runtime,
)
from register_app.r2_upload import (
    build_r2_upload_config_from_args,
    run_register_only_r2_upload,
)
from register_app.registration import run_with_fallback_detailed
from register_app.mail.providers import MAILTM_BASE
from register_app.runtime import (
    RegisterModeStats,
    log_error,
    log_info,
    log_warn,
    run_monitor_loop,
    worker,
)

logger = logging.getLogger("openai_register")

builtins.yasal_bypass_ip_choice = True
builtins.openai_register_stop_requested = False

INTERACTIVE_MAIL_PROVIDERS = [
    "cfmail",
    "tempmaillol",
    "mailtm",
    "tempmailio",
    "dropmail",
    "imap",
    "imap_ms",
    "ms_mail",
    "ms_mail_g",
    "api_mail",
]


def _log_register_mode_summary(stats: RegisterModeStats) -> None:
    stats.mark_finished()
    for line in stats.summary_lines():
        log_info(line)


def _run_register_only_r2_upload_if_needed(args: argparse.Namespace) -> None:
    if not getattr(args, "register_only", False):
        return
    if getattr(args, "skip_r2_upload_on_exit", False):
        return
    if not getattr(args, "r2_enabled", False):
        return

    token_dir = str(getattr(args, "token_dir", "") or "").strip()
    r2_config = build_r2_upload_config_from_args(args)
    log_info(f"register-only 收尾上传开始：目录={token_dir}")
    try:
        result = run_register_only_r2_upload(r2_config, token_dir)
    except Exception as exc:
        log_error(f"register-only 收尾上传 R2 异常：{exc}")
        return

    if result.skipped_reason == "empty":
        log_info(f"register-only 收尾上传跳过：{token_dir} 中没有可上传的 JSON")
        return

    if result.config_error:
        log_error(f"register-only 收尾上传未执行：{result.config_error}")
        return

    if not result.attempted:
        log_info("register-only 收尾上传未执行")
        return

    if result.failures:
        first_failure = result.failures[0]
        log_warn(
            "register-only 收尾上传未全部成功："
            f"成功 {result.uploaded_count}/{result.file_count}，本地 JSON 已保留；"
            f"首个失败 key={first_failure.object_key} error={first_failure.error_message}"
        )
        return

    log_info(
        f"register-only 收尾上传完成：成功 {result.uploaded_count}/{result.file_count}，"
        f"本地删除 {result.deleted_count} 个 JSON"
    )


def _resolve_proxy_pool_runtime_spec(
    args: argparse.Namespace,
    *,
    run_single_monitor: bool,
) -> tuple[str, int]:
    if args.monitor or args.monitor_once or run_single_monitor:
        desired_threads = min(
            max(1, int(args.register_batch_size or 1)),
            max(1, int(args.register_openai_concurrency or 1)),
        )
        return "monitor", max(1, desired_threads)

    desired_threads = 1 if args.mail_provider == "cfmail" else max(1, int(args.register_openai_concurrency or 1))
    return "register_only", desired_threads


def _initialize_proxy_pool_runtime_if_needed(
    args: argparse.Namespace,
    *,
    mode: str,
    desired_threads: int,
) -> None:
    if not getattr(args, "proxy_pool_enabled", False):
        return
    initialize_proxy_pool_runtime(
        build_proxy_pool_config_from_args(args),
        mode=mode,
        desired_threads=desired_threads,
        proxy_api_url=str(getattr(args, "proxy_api_url", "") or "").strip(),
        proxy_api_scheme=str(getattr(args, "proxy_api_scheme", "http") or "http").strip().lower() or "http",
        static_proxy_url=str(getattr(args, "proxy", "") or "").strip(),
    )


def _count_mailbox_entries(file_path: str) -> int:
    path = str(file_path or "").strip()
    if not path or not os.path.isfile(path):
        return 0
    total = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file_obj:
            for raw_line in file_obj:
                line = raw_line.strip()
                if line and not line.startswith("#"):
                    total += 1
    except Exception:
        return 0
    return total


def _register_mode_mailbox_total(provider_key: str) -> int:
    provider = str(provider_key or "").strip().lower()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if provider == "imap":
        return _count_mailbox_entries(os.path.join(base_dir, "emails.txt"))
    if provider in {"imap_ms", "ms_mail_g", "ms_mail"}:
        return _count_mailbox_entries(os.path.join(base_dir, "ms_emails.txt"))
    if provider == "api_mail":
        return _count_mailbox_entries(os.path.join(base_dir, "api_emails.txt"))
    return 0


def _interactive_prompt_text(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if str(default or "").strip() else ""
    value = input(f"{label}{suffix}: ").strip()
    return value if value else str(default or "")


def _interactive_prompt_int(label: str, default: int, *, minimum: int = 0, maximum: Optional[int] = None) -> int:
    while True:
        raw = _interactive_prompt_text(label, str(default))
        try:
            value = int(raw)
        except Exception:
            print("请输入整数。")
            continue
        if value < minimum:
            print(f"请输入不小于 {minimum} 的整数。")
            continue
        if maximum is not None and value > maximum:
            print(f"请输入不大于 {maximum} 的整数。")
            continue
        return value


def _interactive_prompt_float(label: str, default: float, *, minimum: float = 0.0) -> float:
    while True:
        raw = _interactive_prompt_text(label, str(default))
        try:
            value = float(raw)
        except Exception:
            print("请输入数字。")
            continue
        if value < minimum:
            print(f"请输入不小于 {minimum} 的数字。")
            continue
        return value


def _interactive_prompt_bool(label: str, default: bool) -> bool:
    tip = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{label} [{tip}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes", "1", "true"}:
            return True
        if raw in {"n", "no", "0", "false"}:
            return False
        print("请输入 y 或 n。")


def _interactive_choose(title: str, options: list[tuple[str, str]], default_key: str) -> str:
    print("")
    print(title)
    default_index = 1
    for index, (key, label) in enumerate(options, start=1):
        marker = " (默认)" if key == default_key else ""
        print(f"  {index}. {label}{marker}")
        if key == default_key:
            default_index = index
    while True:
        raw = input(f"请输入序号 [{default_index}]: ").strip()
        if not raw:
            return options[default_index - 1][0]
        if raw.isdigit():
            index = int(raw)
            if 1 <= index <= len(options):
                return options[index - 1][0]
        print("请输入有效序号。")


def _run_interactive_mode(args: argparse.Namespace) -> None:
    print("")
    print("=========================================")
    print(" OpenAI Register 交互模式")
    print("=========================================")
    print("按回车可直接使用当前值。")

    current_mode = "monitor_loop" if args.monitor else "register_loop" if args.register_only else "monitor_once"
    if args.register_only and args.once:
        current_mode = "register_once"
    elif args.monitor_once:
        current_mode = "monitor_once"
    elif args.status:
        current_mode = "status"
    elif args.doctor:
        current_mode = "doctor"
    elif args.test_cfmail:
        current_mode = "test_cfmail"

    mode = _interactive_choose(
        "请选择运行模式：",
        [
            ("register_once", "注册模式（单次）"),
            ("register_loop", "注册模式（持续）"),
            ("monitor_once", "监控模式（单轮）"),
            ("monitor_loop", "监控模式（持续）"),
            ("status", "查看当前状态"),
            ("doctor", "执行环境检查"),
            ("test_cfmail", "测试 cfmail"),
        ],
        current_mode,
    )

    args.monitor = False
    args.monitor_once = False
    args.register_only = False
    args.once = False
    args.status = False
    args.doctor = False
    args.test_cfmail = False

    if mode == "register_once":
        args.register_only = True
        args.once = True
    elif mode == "register_loop":
        args.register_only = True
    elif mode == "monitor_once":
        args.monitor_once = True
    elif mode == "monitor_loop":
        args.monitor = True
    elif mode == "status":
        args.status = True
        return
    elif mode == "doctor":
        args.doctor = True
        return
    elif mode == "test_cfmail":
        args.test_cfmail = True
        args.mail_provider = "cfmail"
        args.cfmail_profile = _interactive_prompt_text("cfmail profile", args.cfmail_profile)
        return

    args.mail_provider = _interactive_choose(
        "请选择邮箱服务：",
        [(item, item) for item in INTERACTIVE_MAIL_PROVIDERS],
        args.mail_provider if args.mail_provider in INTERACTIVE_MAIL_PROVIDERS else "cfmail",
    )
    args.proxy = _interactive_prompt_text("静态代理（留空表示不用）", args.proxy or "")
    args.proxy_api_url = _interactive_prompt_text("代理 API URL（留空表示不用）", args.proxy_api_url or "")
    args.proxy_api_scheme = _interactive_choose(
        "代理 API 协议：",
        [("http", "http"), ("socks5", "socks5"), ("socks5h", "socks5h")],
        args.proxy_api_scheme if args.proxy_api_scheme in {"http", "socks5", "socks5h"} else "http",
    )
    args.auto_continue_non_us = _interactive_prompt_bool("非 US 出口自动继续", bool(args.auto_continue_non_us))
    args.register_start_delay_seconds = _interactive_prompt_float(
        "线程启动错峰秒数",
        float(args.register_start_delay_seconds),
        minimum=0.0,
    )
    args.failure_sleep_seconds = _interactive_prompt_int(
        "失败额外等待秒数",
        int(args.failure_sleep_seconds),
        minimum=0,
    )
    args.sleep_min = _interactive_prompt_int("最短等待秒数", int(args.sleep_min), minimum=1)
    args.sleep_max = _interactive_prompt_int("最长等待秒数", int(args.sleep_max), minimum=args.sleep_min)

    if args.register_only:
        args.token_dir = _interactive_prompt_text("注册模式 Token 输出目录", args.token_dir)
        args.register_openai_concurrency = _interactive_prompt_int(
            "注册线程数",
            int(args.register_openai_concurrency),
            minimum=1,
        )
        args.max_mailboxes_to_use = _interactive_prompt_int(
            "最多消耗邮箱数量（0 表示不限）",
            int(getattr(args, "max_mailboxes_to_use", 0) or 0),
            minimum=0,
        )
    else:
        args.active_token_dir = _interactive_prompt_text("A 目录路径", args.active_token_dir)
        args.active_min_count = _interactive_prompt_int("A 目录目标数量", int(args.active_min_count), minimum=1)
        args.monitor_interval = _interactive_prompt_int("巡检间隔秒数", int(args.monitor_interval), minimum=1)
        args.register_batch_size = _interactive_prompt_int(
            "每批注册数量",
            int(args.register_batch_size),
            minimum=1,
        )
        args.register_openai_concurrency = _interactive_prompt_int(
            "补号并发线程数",
            int(args.register_openai_concurrency),
            minimum=1,
        )

    if args.mail_provider == "cfmail":
        args.cfmail_profile = _interactive_prompt_text("cfmail profile", args.cfmail_profile)


def _resolve_cfmail_process_profiles(selected_profile: str) -> list[str]:
    accounts = get_cfmail_accounts()
    if not accounts:
        return []

    profile_name = str(selected_profile or "auto").strip() or "auto"
    if profile_name.lower() != "auto":
        matched = _select_cfmail_account(profile_name)
        return [matched.name] if matched else []

    return [account.name for account in accounts if str(account.name or "").strip()]


def _build_cfmail_profile_worker_command(
    args: argparse.Namespace,
    *,
    profile_name: str,
    sleep_min: int,
    sleep_max: int,
) -> list[str]:
    command = [
        sys.executable,
        os.path.abspath(__file__),
        "--config",
        str(args.config),
        "--register-only",
        "--mail-provider",
        "cfmail",
        "--cfmail-config",
        str(args.cfmail_config),
        "--cfmail-profile",
        str(profile_name),
        "--sleep-min",
        str(sleep_min),
        "--sleep-max",
        str(sleep_max),
        "--failure-sleep-seconds",
        str(args.failure_sleep_seconds),
        "--mailtm-api-base",
        str(args.mailtm_api_base),
        "--token-dir",
        str(args.token_dir),
        "--register-openai-concurrency",
        "1",
        "--register-start-delay-seconds",
        "0",
        "--dingtalk-fallback-interval",
        str(args.dingtalk_fallback_interval),
        "--cfmail-fail-threshold",
        str(args.cfmail_fail_threshold),
        "--cfmail-cooldown-seconds",
        str(args.cfmail_cooldown_seconds),
    ]

    if args.proxy:
        command.extend(["--proxy", str(args.proxy)])
    if getattr(args, "proxy_api_url", ""):
        command.extend(["--proxy-api-url", str(args.proxy_api_url)])
        command.extend(["--proxy-api-scheme", str(args.proxy_api_scheme)])
    if getattr(args, "proxy_pool_enabled", False):
        command.append("--proxy-pool-enabled")
        command.extend(
            [
                "--proxy-pool-consumer-ttl-seconds",
                str(args.proxy_pool_consumer_ttl_seconds),
                "--proxy-pool-heartbeat-interval-seconds",
                str(args.proxy_pool_heartbeat_interval_seconds),
                "--proxy-pool-state-path",
                str(args.proxy_pool_state_path),
                "--proxy-pool-consumers-path",
                str(args.proxy_pool_consumers_path),
                "--proxy-pool-target-multiplier",
                str(args.proxy_pool_target_multiplier),
            ]
        )
    if args.once:
        command.append("--once")
    if args.auto_continue_non_us:
        command.append("--auto-continue-non-us")
    if args.dingtalk_webhook:
        command.extend(["--dingtalk-webhook", str(args.dingtalk_webhook)])
    if getattr(args, "r2_enabled", False):
        command.append("--skip-r2-upload-on-exit")

    return command


def _run_cfmail_profile_processes(
    args: argparse.Namespace,
    *,
    sleep_min: int,
    sleep_max: int,
) -> tuple[bool, bool]:
    profile_names = _resolve_cfmail_process_profiles(args.cfmail_profile)
    if len(profile_names) <= 1:
        return False, False

    script_dir = os.path.dirname(os.path.abspath(__file__))
    processes: list[tuple[str, subprocess.Popen]] = []
    interrupted = False
    log_info(
        f"cfmail 多配置注册模式启动：共 {len(profile_names)} 个独立进程，配置={', '.join(profile_names)}"
    )

    try:
        for index, profile_name in enumerate(profile_names, start=1):
            command = _build_cfmail_profile_worker_command(
                args,
                profile_name=profile_name,
                sleep_min=sleep_min,
                sleep_max=sleep_max,
            )
            process = subprocess.Popen(command, cwd=script_dir)
            processes.append((profile_name, process))
            log_info(
                f"[父进程] 已启动 cfmail 子进程 #{index}：profile={profile_name} pid={process.pid}"
            )
            if args.register_start_delay_seconds > 0 and index < len(profile_names):
                time.sleep(args.register_start_delay_seconds)

        while processes:
            alive_processes: list[tuple[str, subprocess.Popen]] = []
            for profile_name, process in processes:
                return_code = process.poll()
                if return_code is None:
                    alive_processes.append((profile_name, process))
                    continue
                log_info(
                    f"[父进程] cfmail 子进程已退出：profile={profile_name} pid={process.pid} code={return_code}"
                )

            if not alive_processes:
                break

            processes = alive_processes
            time.sleep(1)
    except KeyboardInterrupt:
        interrupted = True
        logger.info("\n[信息] 收到中断信号，准备停止所有 cfmail 子进程")
        for _profile_name, process in processes:
            if process.poll() is not None:
                continue
            process.terminate()
        deadline = time.time() + 10
        for _profile_name, process in processes:
            remaining_seconds = max(0.0, deadline - time.time())
            try:
                process.wait(timeout=remaining_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
    return True, not interrupted


def main() -> None:
    """CLI 入口函数。"""
    parser = argparse.ArgumentParser(description="OpenAI 自动注册与账号巡检脚本")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"JSON 配置文件路径，默认 {DEFAULT_CONFIG_PATH}",
    )
    parser.add_argument(
        "--proxy", default=None, help="代理地址，如 http://127.0.0.1:7890"
    )
    parser.add_argument(
        "--proxy-api-url",
        default="",
        help="住宅代理提取 API；配置后每次注册前都会重新提取一条新代理",
    )
    parser.add_argument(
        "--proxy-api-scheme",
        default="http",
        choices=["http", "socks5", "socks5h"],
        help="代理 API 返回 host:port 时使用的协议前缀，默认 http",
    )
    parser.add_argument(
        "--proxy-pool-enabled",
        action="store_true",
        help="启用全局共享 IP 池；可从 proxy_api_url 补货，或对 Resin 静态代理预生成 Default.xxx 会话池",
    )
    parser.add_argument(
        "--proxy-pool-consumer-ttl-seconds",
        type=int,
        default=DEFAULT_PROXY_POOL_CONSUMER_TTL_SECONDS,
        help="共享 IP 池活跃消费者心跳过期秒数",
    )
    parser.add_argument(
        "--proxy-pool-heartbeat-interval-seconds",
        type=int,
        default=DEFAULT_PROXY_POOL_HEARTBEAT_INTERVAL_SECONDS,
        help="共享 IP 池心跳与后台补货间隔秒数",
    )
    parser.add_argument(
        "--proxy-pool-state-path",
        default=DEFAULT_PROXY_POOL_STATE_PATH,
        help="共享 IP 池文件路径",
    )
    parser.add_argument(
        "--proxy-pool-consumers-path",
        default=DEFAULT_PROXY_POOL_CONSUMERS_PATH,
        help="共享 IP 池消费者注册表路径",
    )
    parser.add_argument(
        "--proxy-pool-target-multiplier",
        type=int,
        default=DEFAULT_PROXY_POOL_TARGET_MULTIPLIER,
        help="共享 IP 池目标深度倍率，默认保持可用 IP >= 倍率 x 全局线程数",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="进入终端交互模式，按提示选择运行模式和关键参数",
    )
    parser.add_argument("--once", action="store_true", help="注册模式只运行一次")
    parser.add_argument(
        "--sleep-min", type=int, default=10, help="注册循环最短等待秒数"
    )
    parser.add_argument(
        "--sleep-max", type=int, default=30, help="注册循环最长等待秒数"
    )
    parser.add_argument(
        "--failure-sleep-seconds",
        type=int,
        default=DEFAULT_REGISTER_FAILURE_EXTRA_SLEEP_SECONDS,
        help="注册失败后额外等待秒数",
    )
    parser.add_argument(
        "--mail-provider",
        default="cfmail",
        choices=["cfmail", "tempmaillol", "mailtm", "tempmailio", "dropmail", "imap", "imap_ms", "ms_mail", "ms_mail_g", "api_mail"],
        help="邮箱服务（cfmail / tempmaillol / mailtm / tempmailio / dropmail / imap / imap_ms / ms_mail / ms_mail_g / api_mail）",
    )
    parser.add_argument(
        "--cfmail-profile",
        default="auto",
        help="自建邮箱配置名；auto 表示按 cfmail 配置文件中的顺序轮询",
    )
    parser.add_argument(
        "--cfmail-config",
        default=DEFAULT_CFMAIL_CONFIG_PATH,
        help="cfmail 邮箱配置 JSON 文件路径",
    )
    parser.add_argument(
        "--cfmail-worker-domain",
        default=None,
        help="临时覆盖自建邮箱后端域名，如 apimail.example.com",
    )
    parser.add_argument(
        "--cfmail-email-domain",
        default=None,
        help="临时覆盖自建邮箱域名，如 example.com",
    )
    parser.add_argument(
        "--cfmail-admin-password",
        default=None,
        help="临时覆盖自建邮箱后台管理员密码",
    )
    parser.add_argument(
        "--cfmail-profile-name",
        default="custom",
        help="临时覆盖自建邮箱配置时使用的配置名",
    )
    parser.add_argument(
        "--mailtm-api-base",
        default=MAILTM_BASE,
        help="Mail.tm API 地址（可替换为兼容 Mail.tm 的自建服务）",
    )
    parser.add_argument(
        "--token-dir",
        default=DEFAULT_TOKEN_OUTPUT_DIR,
        help="注册模式 Token 输出目录",
    )
    parser.add_argument(
        "--r2-enabled",
        action="store_true",
        help="仅在 register-only 结束后，将 token_dir 中的 JSON 上传到 Cloudflare R2",
    )
    parser.add_argument(
        "--r2-account-id",
        default="",
        help="Cloudflare 账户 ID，仅 register-only 收尾上传使用",
    )
    parser.add_argument(
        "--r2-bucket",
        default="",
        help="Cloudflare R2 桶名，仅 register-only 收尾上传使用",
    )
    parser.add_argument(
        "--r2-access-key-id",
        default="",
        help="Cloudflare R2 Access Key ID，仅 register-only 收尾上传使用",
    )
    parser.add_argument(
        "--r2-secret-access-key",
        default="",
        help="Cloudflare R2 Secret Access Key，仅 register-only 收尾上传使用",
    )
    parser.add_argument(
        "--r2-prefix",
        default=DEFAULT_R2_PREFIX,
        help="R2 对象前缀，仅 register-only 收尾上传使用",
    )
    parser.add_argument(
        "--r2-retry-count",
        type=int,
        default=DEFAULT_R2_RETRY_COUNT,
        help="R2 单文件上传失败后的重试次数，仅 register-only 收尾上传使用",
    )
    parser.add_argument(
        "--r2-retry-delay-seconds",
        type=float,
        default=DEFAULT_R2_RETRY_DELAY_SECONDS,
        help="R2 单文件上传重试间隔秒数，仅 register-only 收尾上传使用",
    )
    parser.add_argument(
        "--active-token-dir",
        default=DEFAULT_ACTIVE_TOKEN_DIR,
        help="A 目录，当前正在使用的账号目录",
    )
    parser.add_argument(
        "--active-min-count",
        type=int,
        default=DEFAULT_MIN_ACTIVE_COUNT,
        help="A 目录最少保留数量",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="持续巡检模式：每隔一段时间检查 A 目录数量并自动补号",
    )
    parser.add_argument(
        "--monitor-once",
        action="store_true",
        help="巡检模式只执行一轮",
    )
    parser.add_argument(
        "--register-only",
        action="store_true",
        help="仅执行注册逻辑，不做 A 目录补号检测",
    )
    parser.add_argument(
        "--monitor-interval",
        type=int,
        default=DEFAULT_CHECK_INTERVAL_SECONDS,
        help="巡检间隔秒数，默认 900 秒（15 分钟）",
    )
    parser.add_argument(
        "--register-batch-size",
        type=int,
        default=DEFAULT_REGISTER_BATCH_SIZE,
        help="巡检补号时每批并发注册数量",
    )
    parser.add_argument(
        "--register-openai-concurrency",
        type=int,
        default=DEFAULT_REGISTER_OPENAI_CONCURRENCY,
        help="注册流程最大并发数",
    )
    parser.add_argument(
        "--register-start-delay-seconds",
        type=float,
        default=DEFAULT_REGISTER_START_DELAY_SECONDS,
        help="启动下一个注册线程前的错峰等待秒数",
    )
    parser.add_argument(
        "--max-mailboxes-to-use",
        type=int,
        default=0,
        help="注册模式最多消耗的邮箱数量；0 表示不限",
    )
    parser.add_argument(
        "--dingtalk-webhook",
        default=DEFAULT_DINGTALK_WEBHOOK,
        help="钉钉机器人 Webhook，留空则不发送提醒",
    )
    parser.add_argument(
        "--dingtalk-summary-interval",
        type=int,
        default=DEFAULT_DINGTALK_SUMMARY_INTERVAL_SECONDS,
        help="钉钉汇总发送间隔秒数，默认 10800 秒（3 小时）",
    )
    parser.add_argument(
        "--dingtalk-fallback-interval",
        type=int,
        default=DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
        help="兼容参数，当前未使用",
    )
    parser.add_argument(
        "--auto-continue-non-us",
        action="store_true",
        help="非 US 出口时自动继续，适合无人值守巡检",
    )
    parser.add_argument(
        "--test-cfmail",
        action="store_true",
        help="仅测试 cfmail 配置是否可创建邮箱并可轮询，不执行注册",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="执行轻量环境检查并输出结果",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="输出当前池子与运行配置状态，不执行注册/巡检",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="doctor/status 以 JSON 输出",
    )
    parser.add_argument(
        "--cfmail-fail-threshold",
        type=int,
        default=DEFAULT_CFMAIL_FAIL_THRESHOLD,
        help="兼容参数，当前未使用",
    )
    parser.add_argument(
        "--cfmail-cooldown-seconds",
        type=int,
        default=DEFAULT_CFMAIL_COOLDOWN_SECONDS,
        help="兼容参数，当前未使用",
    )
    parser.add_argument(
        "--skip-r2-upload-on-exit",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    # 保存 argparse 的默认值，用于判断命令行是否显式传参
    for action in parser._actions:
        if hasattr(action, "dest") and action.dest != "help":
            setattr(args, f"_default_{action.dest}", action.default)

    # 加载配置文件（命令行参数优先于配置文件）
    config = load_config_file(args.config)
    if config:
        logger.info(f"[信息] 已加载配置文件: {args.config}")
        apply_config_to_args(args, config)

    if args.interactive:
        if not sys.stdin.isatty():
            parser.error("--interactive 需要在可交互终端中使用")
        _run_interactive_mode(args)

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)
    args.failure_sleep_seconds = max(0, args.failure_sleep_seconds)
    args.active_min_count = max(1, args.active_min_count)
    args.monitor_interval = max(1, args.monitor_interval)
    args.dingtalk_summary_interval = max(1, args.dingtalk_summary_interval)
    args.dingtalk_fallback_interval = max(0, args.dingtalk_fallback_interval)
    args.register_batch_size = max(1, args.register_batch_size)
    args.register_openai_concurrency = max(1, args.register_openai_concurrency)
    args.register_start_delay_seconds = max(0.0, float(args.register_start_delay_seconds))
    args.max_mailboxes_to_use = max(0, int(getattr(args, "max_mailboxes_to_use", 0) or 0))
    args.cfmail_fail_threshold = max(1, args.cfmail_fail_threshold)
    args.cfmail_cooldown_seconds = max(0, args.cfmail_cooldown_seconds)
    args.proxy_pool_consumer_ttl_seconds = max(
        1,
        int(
            getattr(
                args,
                "proxy_pool_consumer_ttl_seconds",
                DEFAULT_PROXY_POOL_CONSUMER_TTL_SECONDS,
            )
            or 0
        ),
    )
    args.proxy_pool_heartbeat_interval_seconds = max(
        1,
        int(
            getattr(
                args,
                "proxy_pool_heartbeat_interval_seconds",
                DEFAULT_PROXY_POOL_HEARTBEAT_INTERVAL_SECONDS,
            )
            or 0
        ),
    )
    args.proxy_pool_target_multiplier = max(
        1,
        int(
            getattr(
                args,
                "proxy_pool_target_multiplier",
                DEFAULT_PROXY_POOL_TARGET_MULTIPLIER,
            )
            or 0
        ),
    )
    args.r2_retry_count = max(0, int(getattr(args, "r2_retry_count", DEFAULT_R2_RETRY_COUNT) or 0))
    args.r2_retry_delay_seconds = max(
        0.0,
        float(getattr(args, "r2_retry_delay_seconds", DEFAULT_R2_RETRY_DELAY_SECONDS) or 0.0),
    )
    apply_low_memory_tuning(args)
    args.proxy_api_url = str(args.proxy_api_url or "").strip()
    args.proxy_api_scheme = str(args.proxy_api_scheme or "http").strip().lower() or "http"
    args.proxy_pool_state_path = (
        str(getattr(args, "proxy_pool_state_path", DEFAULT_PROXY_POOL_STATE_PATH) or "").strip()
        or DEFAULT_PROXY_POOL_STATE_PATH
    )
    args.proxy_pool_consumers_path = (
        str(getattr(args, "proxy_pool_consumers_path", DEFAULT_PROXY_POOL_CONSUMERS_PATH) or "").strip()
        or DEFAULT_PROXY_POOL_CONSUMERS_PATH
    )
    args.proxy = resolve_registration_proxy(
        args.proxy,
        None,
        proxy_api_scheme=args.proxy_api_scheme,
    )
    args.cfmail_profile = str(args.cfmail_profile or "auto").strip() or "auto"
    args.cfmail_profile_name = (
        str(args.cfmail_profile_name or "custom").strip() or "custom"
    )
    args.cfmail_config = (
        str(args.cfmail_config or DEFAULT_CFMAIL_CONFIG_PATH).strip()
        or DEFAULT_CFMAIL_CONFIG_PATH
    )
    args.r2_account_id = str(getattr(args, "r2_account_id", "") or "").strip()
    args.r2_bucket = str(getattr(args, "r2_bucket", "") or "").strip()
    args.r2_access_key_id = str(getattr(args, "r2_access_key_id", "") or "").strip()
    args.r2_secret_access_key = str(getattr(args, "r2_secret_access_key", "") or "").strip()
    args.r2_prefix = str(getattr(args, "r2_prefix", DEFAULT_R2_PREFIX) or "").strip()

    has_cfmail_override = any(
        [
            args.cfmail_worker_domain,
            args.cfmail_email_domain,
            args.cfmail_admin_password,
        ]
    )
    if has_cfmail_override and not all(
        [
            args.cfmail_worker_domain,
            args.cfmail_email_domain,
            args.cfmail_admin_password,
        ]
    ):
        parser.error(
            "--cfmail-worker-domain / --cfmail-email-domain / --cfmail-admin-password 需要同时提供"
        )

    if has_cfmail_override:
        configured_cfmail_accounts = [
            CfmailAccount(
                name=args.cfmail_profile_name,
                worker_domain=_normalize_host(args.cfmail_worker_domain),
                email_domain=_normalize_host(args.cfmail_email_domain),
                admin_password=str(args.cfmail_admin_password or "").strip(),
            )
        ]
    else:
        configured_cfmail_accounts = _build_cfmail_accounts(
            _load_cfmail_accounts_from_file(args.cfmail_config) or DEFAULT_CFMAIL_ACCOUNTS
        )

    configure_cfmail_runtime(
        accounts=configured_cfmail_accounts,
        profile_mode=args.cfmail_profile,
        config_path=args.cfmail_config,
        hot_reload_enabled=not has_cfmail_override,
        fail_threshold=args.cfmail_fail_threshold,
        cooldown_seconds=args.cfmail_cooldown_seconds,
    )

    inspection_mode = bool(args.doctor or args.status)

    if (
        not inspection_mode
        and args.mail_provider == "cfmail"
        and not get_cfmail_accounts()
    ):
        parser.error(
            "未配置可用的 cfmail 邮箱，请先在 cfmail 配置文件中添加，或通过 --cfmail-worker-domain 等参数临时指定"
        )

    if (
        not inspection_mode
        and
        args.mail_provider == "cfmail"
        and args.cfmail_profile.lower() != "auto"
        and not _select_cfmail_account(args.cfmail_profile)
    ):
        parser.error(
            f"--cfmail-profile 指定的配置不存在：{args.cfmail_profile}；当前可用配置: {_cfmail_account_names()}"
        )

    if (
        not inspection_mode
        and getattr(args, "proxy_pool_enabled", False)
        and not str(getattr(args, "proxy_api_url", "") or "").strip()
        and not supports_generated_proxy_pool(str(getattr(args, "proxy", "") or "").strip())
    ):
        parser.error("启用 --proxy-pool-enabled 时必须同时配置 --proxy-api-url，或提供可生成会话的 Resin 静态代理 --proxy")

    if inspection_mode:
        doctor_report = collect_doctor_report(args) if args.doctor else None
        status_snapshot = build_status_snapshot(args) if args.status else None

        if args.json and doctor_report and status_snapshot:
            payload = {
                "doctor": {
                    "checked_at": doctor_report.checked_at,
                    "error_count": doctor_report.error_count,
                    "warn_count": doctor_report.warn_count,
                    "checks": [
                        {
                            "name": item.name,
                            "status": item.status,
                            "summary": item.summary,
                            "detail": item.detail,
                        }
                        for item in doctor_report.checks
                    ],
                },
                "status": status_snapshot,
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            if doctor_report:
                print_doctor_report(doctor_report, output_json=args.json)
            if doctor_report and status_snapshot and not args.json:
                print("")
            if status_snapshot:
                print_status_snapshot(status_snapshot, output_json=args.json)

        if doctor_report:
            sys.exit(1 if doctor_report.error_count > 0 else 0)
        return

    if args.test_cfmail:
        ok = run_cfmail_self_test(
            get_cfmail_accounts(),
            proxy=args.proxy,
            profile_name=args.cfmail_profile,
        )
        sys.exit(0 if ok else 1)

    # 默认行为：
    # - 直接执行脚本：跑一轮 A 目录补号检测（monitor_once）
    # - --monitor：持续巡检 A 目录
    # - --register-only：跳过巡检，直接进入注册模式
    run_single_monitor = not args.register_only and not args.monitor
    args.runtime_stop_event = threading.Event()
    builtins.openai_register_stop_requested = False

    if args.monitor or args.monitor_once or run_single_monitor:
        if args.auto_continue_non_us or not sys.stdin.isatty():
            builtins.yasal_bypass_ip_choice = True

        if run_single_monitor and not args.monitor and not args.monitor_once:
            args.monitor_once = True

        cfmail_desc = ""
        if args.mail_provider == "cfmail":
            cfmail_desc = (
                f"，cfmail配置文件={args.cfmail_config}，cfmail配置={_cfmail_account_names()}，"
                f"选择={args.cfmail_profile}"
            )
        proxy_pool_desc = ""
        if args.proxy_pool_enabled:
            proxy_pool_desc = (
                f"，共享IP池=启用(multiplier={args.proxy_pool_target_multiplier}"
                f"，state={args.proxy_pool_state_path})"
            )
        log_info(
            f"巡检模式启动：A目录={args.active_token_dir}，A阈值={args.active_min_count}，巡检间隔={args.monitor_interval}秒，注册并发={args.register_openai_concurrency}，批次={args.register_batch_size}，错峰={args.register_start_delay_seconds:.1f}秒，钉钉汇总间隔={args.dingtalk_summary_interval}秒，代理模式={'API动态提取' if args.proxy_api_url else (args.proxy or '直连')}{cfmail_desc}{proxy_pool_desc}"
        )
        proxy_pool_mode, proxy_pool_threads = _resolve_proxy_pool_runtime_spec(
            args,
            run_single_monitor=run_single_monitor,
        )
        _initialize_proxy_pool_runtime_if_needed(
            args,
            mode=proxy_pool_mode,
            desired_threads=proxy_pool_threads,
        )
        try:
            run_monitor_loop(
                args,
                run_with_fallback_detailed,
                _reload_cfmail_accounts_if_needed,
            )
        except KeyboardInterrupt:
            builtins.openai_register_stop_requested = True
            args.runtime_stop_event.set()
            logger.info("\n[信息] 收到中断信号，当前批次结束后退出")
        finally:
            shutdown_proxy_pool_runtime()
        return

    if args.auto_continue_non_us:
        builtins.yasal_bypass_ip_choice = True

    startup_message = (
        f"[信息] 脚本启动：注册并发上限={args.register_openai_concurrency}，错峰={args.register_start_delay_seconds:.1f}秒，邮箱服务={args.mail_provider}，Token目录={args.token_dir}，代理模式={'API动态提取' if args.proxy_api_url else (args.proxy or '直连')}"
    )
    if args.mail_provider == "cfmail":
        startup_message += (
            f"，cfmail配置文件={args.cfmail_config}，cfmail配置={_cfmail_account_names()}，"
            f"选择={args.cfmail_profile}"
        )
    if args.r2_enabled and not args.skip_r2_upload_on_exit:
        startup_message += (
            f"，R2收尾上传=启用(bucket={args.r2_bucket or '未配置'}"
            f"，prefix={args.r2_prefix or '-'})"
        )
    if args.proxy_pool_enabled:
        startup_message += (
            f"，共享IP池=启用(multiplier={args.proxy_pool_target_multiplier}"
            f"，state={args.proxy_pool_state_path})"
        )
    logger.info(startup_message)

    handled_cfmail_profiles, cfmail_profiles_finished = (False, False)
    if args.mail_provider == "cfmail" and args.cfmail_profile.lower() == "auto":
        handled_cfmail_profiles, cfmail_profiles_finished = _run_cfmail_profile_processes(
            args,
            sleep_min=sleep_min,
            sleep_max=sleep_max,
        )
    if handled_cfmail_profiles:
        if cfmail_profiles_finished:
            _run_register_only_r2_upload_if_needed(args)
        return

    proxy_pool_mode, proxy_pool_threads = _resolve_proxy_pool_runtime_spec(
        args,
        run_single_monitor=False,
    )
    _initialize_proxy_pool_runtime_if_needed(
        args,
        mode=proxy_pool_mode,
        desired_threads=proxy_pool_threads,
    )

    worker_count = 1 if args.mail_provider == "cfmail" else max(1, args.register_openai_concurrency)
    providers_list = [args.mail_provider for _ in range(worker_count)]
    threads = []
    register_stats = RegisterModeStats(
        provider_key=args.mail_provider,
        configured_threads=worker_count,
        token_dir=str(args.token_dir or "").strip(),
        initial_mailbox_total=_register_mode_mailbox_total(args.mail_provider),
        max_mailboxes_to_use=args.max_mailboxes_to_use,
    )

    for i in range(1, worker_count + 1):
        provider_key = providers_list[i - 1]
        t = threading.Thread(
            target=worker,
            args=(
                i,
                args.proxy,
                args.proxy_api_url,
                args.proxy_api_scheme,
                bool(getattr(args, "proxy_pool_enabled", False)),
                args.runtime_stop_event,
                args.once,
                sleep_min,
                sleep_max,
                args.failure_sleep_seconds,
                provider_key,
                args.mailtm_api_base,
                args.token_dir,
                run_with_fallback_detailed,
                _reload_cfmail_accounts_if_needed,
                args.dingtalk_webhook,
                args.dingtalk_fallback_interval,
                register_stats,
            ),
        )
        t.daemon = True
        t.start()
        threads.append(t)
        if args.register_start_delay_seconds > 0 and i < worker_count:
            time.sleep(args.register_start_delay_seconds)

    all_threads_finished = False
    interrupted = False
    try:
        while True:
            time.sleep(1)
            if not any(t.is_alive() for t in threads):
                logger.info("\n[信息] 所有线程已执行完成，任务结束")
                all_threads_finished = True
                break
    except KeyboardInterrupt:
        interrupted = True
        builtins.openai_register_stop_requested = True
        args.runtime_stop_event.set()
        logger.info("\n[信息] 收到中断信号，停止接收新任务并等待当前线程安全退出")
        for thread in threads:
            thread.join()
        all_threads_finished = not any(t.is_alive() for t in threads)
    finally:
        register_stats.set_remaining_mailboxes(_register_mode_mailbox_total(args.mail_provider))
        _log_register_mode_summary(register_stats)
        shutdown_proxy_pool_runtime()
        builtins.openai_register_stop_requested = False

    if all_threads_finished and (not interrupted or not any(t.is_alive() for t in threads)):
        _run_register_only_r2_upload_if_needed(args)


if __name__ == "__main__":
    main()
