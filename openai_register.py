# -*- coding: utf-8 -*-
"""OpenAI 自动注册与账号巡检脚本。

支持多种临时邮箱服务，自动完成注册流程并维护双目录 Token 池。

本文件仅作为 CLI 入口：
- 核心注册流程 → register_core.py
- OAuth 授权逻辑 → register_auth.py
- Sentinel/指纹 → register_sentinel.py
- Token 提取策略 → register_token.py
- 常量/配置管理 → register_config.py
"""
import argparse
import builtins
import logging
import sys
import threading
import time

from register_cfmail import (
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
from register_config import (
    DEFAULT_ACTIVE_TOKEN_DIR,
    DEFAULT_CFMAIL_FALLBACK_PROVIDER,
    DEFAULT_CHECK_INTERVAL_SECONDS,
    DEFAULT_CONFIG_PATH,
    DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
    DEFAULT_DINGTALK_SUMMARY_INTERVAL_SECONDS,
    DEFAULT_DINGTALK_WEBHOOK,
    DEFAULT_MIN_ACTIVE_COUNT,
    DEFAULT_MIN_POOL_COUNT,
    DEFAULT_REGISTER_BATCH_SIZE,
    DEFAULT_REGISTER_FAILURE_EXTRA_SLEEP_SECONDS,
    DEFAULT_REGISTER_OPENAI_CONCURRENCY,
    DEFAULT_REGISTER_START_DELAY_SECONDS,
    DEFAULT_REQUEST_INTERVAL_SECONDS,
    DEFAULT_TOKEN_OUTPUT_DIR,
    DEFAULT_USAGE_THRESHOLD,
    apply_config_to_args,
    apply_low_memory_tuning,
    load_config_file,
)
from register_core import run_with_fallback
from register_mailboxes import MAILTM_BASE
from register_runtime import (
    DEFAULT_TOKEN_CHECK_WORKERS,
    log_info,
    run_monitor_loop,
    worker,
)

logger = logging.getLogger("openai_register")

builtins.yasal_bypass_ip_choice = True


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
        choices=["cfmail", "tempmaillol", "mailtm", "tempmailio", "dropmail"],
        help="邮箱服务（cfmail / tempmaillol / mailtm / tempmailio / dropmail）",
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
        help="B 目录 / Token 输出目录",
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
        "--pool-min-count",
        type=int,
        default=DEFAULT_MIN_POOL_COUNT,
        help="B 目录最少保留数量",
    )
    parser.add_argument(
        "--usage-threshold",
        type=int,
        default=DEFAULT_USAGE_THRESHOLD,
        help="账号已用比例达到该值后视为不可用",
    )
    parser.add_argument(
        "--request-interval",
        type=int,
        default=DEFAULT_REQUEST_INTERVAL_SECONDS,
        help="检测账号时每次请求之间的等待秒数",
    )
    parser.add_argument(
        "--token-check-workers",
        type=int,
        default=DEFAULT_TOKEN_CHECK_WORKERS,
        help="巡检额度查询并发数",
    )
    parser.add_argument(
        "--curl-timeout",
        type=int,
        default=15,
        help="额度检测接口超时时间（秒）",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="持续巡检模式：每隔一段时间检查 A/B 数量并自动补号",
    )
    parser.add_argument(
        "--monitor-once",
        action="store_true",
        help="巡检模式只执行一轮",
    )
    parser.add_argument(
        "--register-only",
        action="store_true",
        help="仅执行原来的注册逻辑，不做 A/B 检测",
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
        help="回退到保底邮箱服务时的钉钉提醒最小间隔秒数，默认 900 秒",
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
        "--cfmail-fail-threshold",
        type=int,
        default=DEFAULT_CFMAIL_FAIL_THRESHOLD,
        help="cfmail 连续失败达到该阈值后进入冷却",
    )
    parser.add_argument(
        "--cfmail-cooldown-seconds",
        type=int,
        default=DEFAULT_CFMAIL_COOLDOWN_SECONDS,
        help="cfmail 自动冷却时长（秒）",
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

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)
    args.failure_sleep_seconds = max(0, args.failure_sleep_seconds)
    args.active_min_count = max(1, args.active_min_count)
    args.pool_min_count = max(0, args.pool_min_count)
    args.usage_threshold = max(1, args.usage_threshold)
    args.request_interval = max(0, args.request_interval)
    args.token_check_workers = max(1, args.token_check_workers)
    args.curl_timeout = max(1, args.curl_timeout)
    args.monitor_interval = max(1, args.monitor_interval)
    args.dingtalk_summary_interval = max(1, args.dingtalk_summary_interval)
    args.dingtalk_fallback_interval = max(0, args.dingtalk_fallback_interval)
    args.register_batch_size = max(1, args.register_batch_size)
    args.register_openai_concurrency = max(1, args.register_openai_concurrency)
    args.register_start_delay_seconds = max(0.0, float(args.register_start_delay_seconds))
    args.cfmail_fail_threshold = max(1, args.cfmail_fail_threshold)
    args.cfmail_cooldown_seconds = max(0, args.cfmail_cooldown_seconds)
    apply_low_memory_tuning(args)
    args.cfmail_profile = str(args.cfmail_profile or "auto").strip() or "auto"
    args.cfmail_profile_name = (
        str(args.cfmail_profile_name or "custom").strip() or "custom"
    )
    args.cfmail_config = (
        str(args.cfmail_config or DEFAULT_CFMAIL_CONFIG_PATH).strip()
        or DEFAULT_CFMAIL_CONFIG_PATH
    )

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

    if args.mail_provider == "cfmail" and not get_cfmail_accounts():
        parser.error(
            "未配置可用的 cfmail 邮箱，请先在 cfmail 配置文件中添加，或通过 --cfmail-worker-domain 等参数临时指定"
        )

    if (
        args.mail_provider == "cfmail"
        and args.cfmail_profile.lower() != "auto"
        and not _select_cfmail_account(args.cfmail_profile)
    ):
        parser.error(
            f"--cfmail-profile 指定的配置不存在：{args.cfmail_profile}；当前可用配置: {_cfmail_account_names()}"
        )

    if args.test_cfmail:
        ok = run_cfmail_self_test(
            get_cfmail_accounts(),
            proxy=args.proxy,
            profile_name=args.cfmail_profile,
        )
        sys.exit(0 if ok else 1)

    # 默认行为：
    # - 直接执行脚本：跑一轮巡检（monitor_once）
    # - --monitor：持续巡检
    # - --register-only：跳过巡检，直接进入原始注册模式
    run_single_monitor = not args.register_only and not args.monitor

    if args.monitor or args.monitor_once or run_single_monitor:
        if args.auto_continue_non_us or not sys.stdin.isatty():
            builtins.yasal_bypass_ip_choice = True

        if run_single_monitor and not args.monitor and not args.monitor_once:
            args.monitor_once = True

        cfmail_desc = ""
        if args.mail_provider == "cfmail":
            cfmail_desc = (
                f"，cfmail配置文件={args.cfmail_config}，cfmail配置={_cfmail_account_names()}，"
                f"选择={args.cfmail_profile}，回退={DEFAULT_CFMAIL_FALLBACK_PROVIDER}，"
                f"回退钉钉间隔={args.dingtalk_fallback_interval}秒"
            )
        log_info(
            f"巡检模式启动：A目录={args.active_token_dir}，B目录={args.token_dir}，A阈值={args.active_min_count}，B阈值={args.pool_min_count}，巡检间隔={args.monitor_interval}秒，额度查询并发={args.token_check_workers}，注册并发={args.register_openai_concurrency}，错峰={args.register_start_delay_seconds:.1f}秒，钉钉汇总间隔={args.dingtalk_summary_interval}秒{cfmail_desc}"
        )
        run_monitor_loop(
            args,
            run_with_fallback,
            _reload_cfmail_accounts_if_needed,
        )
        return

    if args.auto_continue_non_us:
        builtins.yasal_bypass_ip_choice = True

    startup_message = (
        f"[信息] 脚本启动：注册并发上限={args.register_openai_concurrency}，错峰={args.register_start_delay_seconds:.1f}秒，邮箱服务={args.mail_provider}，Token目录={args.token_dir}"
    )
    if args.mail_provider == "cfmail":
        startup_message += (
            f"，cfmail配置文件={args.cfmail_config}，cfmail配置={_cfmail_account_names()}，"
            f"选择={args.cfmail_profile}，回退={DEFAULT_CFMAIL_FALLBACK_PROVIDER}，"
            f"回退钉钉间隔={args.dingtalk_fallback_interval}秒"
        )
    logger.info(startup_message)

    worker_count = min(3, args.register_openai_concurrency)
    providers_list = [args.mail_provider for _ in range(worker_count)]
    threads = []

    for i in range(1, worker_count + 1):
        provider_key = providers_list[i - 1]
        t = threading.Thread(
            target=worker,
            args=(
                i,
                args.proxy,
                args.once,
                sleep_min,
                sleep_max,
                args.failure_sleep_seconds,
                provider_key,
                args.mailtm_api_base,
                args.token_dir,
                run_with_fallback,
                _reload_cfmail_accounts_if_needed,
                args.dingtalk_webhook,
                args.dingtalk_fallback_interval,
            ),
        )
        t.daemon = True
        t.start()
        threads.append(t)
        if args.register_start_delay_seconds > 0 and i < worker_count:
            time.sleep(args.register_start_delay_seconds)

    try:
        while True:
            time.sleep(1)
            if not any(t.is_alive() for t in threads):
                logger.info("\n[信息] 所有线程已执行完成，任务结束")
                break
    except KeyboardInterrupt:
        logger.info("\n[信息] 收到中断信号，准备退出")


if __name__ == "__main__":
    main()
