# -*- coding: utf-8 -*-
"""OpenAI 自动注册与账号巡检脚本。

支持多种临时邮箱服务，自动完成注册流程并维护双目录 Token 池。
"""
import argparse
import builtins
import ctypes
import json
import logging
import math
import os
import random
import re
import secrets
import socket
import string
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from curl_cffi import requests
from register_auth import (
    bootstrap_web_signup_start_url,
    extract_continue_url_from_response as _extract_continue_url_from_response,
    generate_oauth_url,
    oauth_authorize_url as _oauth_authorize_url,
    post_email_otp_validate as _post_email_otp_validate,
    prime_oauth_session as _prime_oauth_session,
    request_sentinel_header as _request_sentinel_token,
    response_text_preview as _response_text_preview,
    submit_callback_url,
    try_token_via_existing_session as _try_token_via_existing_session,
    try_token_via_password_login as _try_token_via_password_login,
    try_token_via_session_api as _try_token_via_session_api,
    try_token_via_workspace_select as _try_token_via_workspace_select,
)
from register_cfmail import (
    CfmailAccount,
    DEFAULT_CFMAIL_ACCOUNTS,
    DEFAULT_CFMAIL_ADMIN_PASSWORD,
    DEFAULT_CFMAIL_CONFIG_PATH,
    DEFAULT_CFMAIL_COOLDOWN_SECONDS,
    DEFAULT_CFMAIL_EMAIL_DOMAIN,
    DEFAULT_CFMAIL_FAIL_THRESHOLD,
    DEFAULT_CFMAIL_PROFILE_NAME,
    DEFAULT_CFMAIL_WORKER_DOMAIN,
    build_cfmail_accounts as _build_cfmail_accounts,
    cfmail_account_names as _cfmail_account_names,
    cfmail_headers as _cfmail_headers,
    configure_cfmail_runtime,
    create_cfmail_mailbox as _create_cfmail_mailbox,
    get_cfmail_accounts,
    list_cfmail_message_ids as _list_cfmail_message_ids,
    load_cfmail_accounts_from_file as _load_cfmail_accounts_from_file,
    normalize_host as _normalize_host,
    poll_cfmail_oai_code as _poll_cfmail_oai_code,
    prune_cfmail_failure_state as _prune_cfmail_failure_state,
    record_cfmail_failure as _record_cfmail_failure,
    record_cfmail_success as _record_cfmail_success,
    reload_cfmail_accounts_if_needed as _reload_cfmail_accounts_if_needed,
    run_cfmail_self_test,
    select_cfmail_account as _select_cfmail_account,
)
from register_mailboxes import (
    MAILTM_BASE,
    TEMPMAILIO_API,
    TEMPMAILLOL_BASE,
    DROPMAIL_API,
    TempMailbox,
    create_dropmail_mailbox,
    create_hydra_mailbox,
    create_tempmaillol_mailbox,
    create_tempmailio_mailbox,
    list_dropmail_message_ids,
    list_hydra_message_ids,
    list_tempmailio_message_ids,
    list_tempmaillol_message_ids,
    poll_dropmail_oai_code,
    poll_hydra_oai_code,
    poll_tempmailio_oai_code,
    poll_tempmaillol_oai_code,
)
from register_notifications import (
    notify_fallback_provider_usage,
)
from register_runtime import (
    DEFAULT_TOKEN_CHECK_WORKERS,
    log_info,
    run_monitor_loop,
    worker,
)

logger = logging.getLogger("openai_register")

builtins.yasal_bypass_ip_choice = True

# ==========================================
# 临时邮箱 API
# ==========================================
# 脚本所在目录，作为默认路径的基准
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_ACTIVE_TOKEN_DIR = os.path.join(_SCRIPT_DIR, "auths")
DEFAULT_TOKEN_OUTPUT_DIR = os.path.join(_SCRIPT_DIR, "auths_pool")
DEFAULT_MIN_ACTIVE_COUNT = 20
DEFAULT_MIN_POOL_COUNT = 50
DEFAULT_USAGE_THRESHOLD = 90
DEFAULT_CHECK_INTERVAL_SECONDS = 900
DEFAULT_DINGTALK_SUMMARY_INTERVAL_SECONDS = 10800
DEFAULT_REQUEST_INTERVAL_SECONDS = 2
DEFAULT_REGISTER_BATCH_SIZE = 3
DEFAULT_REGISTER_OPENAI_CONCURRENCY = 3
DEFAULT_REGISTER_START_DELAY_SECONDS = 1.0
DEFAULT_REGISTER_FAILURE_EXTRA_SLEEP_SECONDS = 10
# 请改成你的钉钉机器人地址
DEFAULT_DINGTALK_WEBHOOK = ""
DEFAULT_CFMAIL_FALLBACK_PROVIDER = "tempmaillol"
DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS = 900
CREATE_ACCOUNT_MAX_ATTEMPTS = 2
CREATE_ACCOUNT_RETRY_DELAY_SECONDS = 2
LOW_MEMORY_SOFT_LIMIT_MB = 2560
LOW_MEMORY_HARD_LIMIT_MB = 1536


def _random_name_part(min_length: int = 4, max_length: int = 9) -> str:
    length = random.randint(min_length, max_length)
    letters = string.ascii_lowercase
    value = "".join(secrets.choice(letters) for _ in range(length))
    return value.capitalize()


def _random_profile_name() -> str:
    return f"{_random_name_part()} {_random_name_part(5, 10)}"


def _random_birthdate(start_year: int = 1990, end_year: int = 2005) -> str:
    start_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year, 12, 31)
    day_offset = random.randint(0, (end_date - start_date).days)
    return (start_date + timedelta(days=day_offset)).strftime("%Y-%m-%d")


def _build_random_signup_profile() -> Dict[str, str]:
    return {
        "name": _random_profile_name(),
        "birthdate": _random_birthdate(),
    }



def _build_request_proxies(proxy: Optional[str]) -> Any:
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def _post_create_account_with_retry(
    session: Any,
    *,
    create_account_body: str,
    did: str,
    proxies: Any,
    impersonate: str,
    thread_id: int,
    max_attempts: int = CREATE_ACCOUNT_MAX_ATTEMPTS,
    retry_delay_seconds: int = CREATE_ACCOUNT_RETRY_DELAY_SECONDS,
) -> Optional[Any]:
    attempts = max(1, int(max_attempts))
    delay_seconds = max(0, int(retry_delay_seconds))
    last_resp = None

    for attempt in range(1, attempts + 1):
        try:
            create_account_sentinel = _request_sentinel_token(
                did=did,
                proxies=proxies,
                impersonate=impersonate,
                thread_id=thread_id,
                flow="oauth_create_account",
            )
            if not create_account_sentinel:
                return None

            last_resp = session.post(
                "https://auth.openai.com/api/accounts/create_account",
                headers={
                    "referer": "https://auth.openai.com/about-you",
                    "accept": "application/json",
                    "content-type": "application/json",
                    "openai-sentinel-token": create_account_sentinel,
                },
                data=create_account_body,
            )
        except Exception as exc:
            if attempt < attempts:
                logger.warning(
                    f"[线程 {thread_id}] [警告] create_account 请求异常，"
                    f"第 {attempt}/{attempts} 次尝试失败: {exc}；"
                    f"{delay_seconds} 秒后重试"
                )
                time.sleep(delay_seconds)
                continue
            logger.error(f"[线程 {thread_id}] [错误] create_account 请求异常: {exc}")
            return None

        status_code = getattr(last_resp, "status_code", 0)
        if status_code == 200:
            return last_resp

        if status_code in (408, 425, 429, 500, 502, 503, 504) and attempt < attempts:
            preview = _response_text_preview(last_resp)
            logger.warning(
                f"[线程 {thread_id}] [警告] create_account 遇到临时错误，"
                f"状态码: {status_code}，第 {attempt}/{attempts} 次尝试；"
                f"{delay_seconds} 秒后重试。响应摘要: {preview}"
            )
            time.sleep(delay_seconds)
            continue

        return last_resp

    return last_resp


def get_temp_mailbox(
    provider_key: str,
    thread_id: int,
    proxies: Any = None,
    mailtm_base: str = MAILTM_BASE,
) -> Optional[TempMailbox]:
    mailbox = None
    if provider_key == "mailtm":
        mailbox = create_hydra_mailbox(
            api_base=mailtm_base,
            provider_name="Mail.tm",
            provider_key="mailtm",
            proxies=proxies,
            thread_id=thread_id,
        )
    elif provider_key == "tempmaillol":
        mailbox = create_tempmaillol_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "tempmailio":
        mailbox = create_tempmailio_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "dropmail":
        mailbox = create_dropmail_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "cfmail":
        mailbox = _create_cfmail_mailbox(proxies=proxies, thread_id=thread_id)
    else:
        logger.error(f"[线程 {thread_id}] [错误] 不支持的临时邮箱服务: {provider_key}")
        return None

    if mailbox:
        provider_desc = provider_key
        if mailbox.provider == "cfmail" and mailbox.config_name:
            provider_desc = f"{provider_key}:{mailbox.config_name}"
        logger.info(
            f"[线程 {thread_id}] [信息] 已绑定临时邮箱服务: {provider_desc}"
        )
        return mailbox

    logger.error(
        f"[线程 {thread_id}] [错误] 临时邮箱服务不可用或创建失败: {provider_key}"
    )
    return None
def get_mailbox_message_snapshot(
    mailbox: TempMailbox, thread_id: int, proxies: Any = None
) -> Set[str]:
    try:
        if mailbox.provider == "cfmail":
            return _list_cfmail_message_ids(
                api_base=mailbox.api_base,
                token=mailbox.token,
                email=mailbox.email,
                proxies=proxies,
            )
        if mailbox.provider == "mailtm":
            return list_hydra_message_ids(
                api_base=mailbox.api_base,
                token=mailbox.token,
                proxies=proxies,
            )
        if mailbox.provider == "tempmailio":
            return list_tempmailio_message_ids(email=mailbox.email, proxies=proxies)
        if mailbox.provider == "tempmaillol":
            return list_tempmaillol_message_ids(token=mailbox.token, proxies=proxies)
        if mailbox.provider == "dropmail":
            return list_dropmail_message_ids(
                sid_token=mailbox.sid_token,
                proxies=proxies,
            )
    except Exception as exc:
        logger.warning(f"[线程 {thread_id}] [警告] 获取邮箱快照失败: {exc}")

    return set()
def get_oai_code(
    mailbox: TempMailbox,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    if mailbox.provider == "cfmail":
        if not mailbox.token:
            logger.error(
                f"[线程 {thread_id}] [错误] {mailbox.provider} token 为空，无法读取邮件"
            )
            return ""
        return _poll_cfmail_oai_code(
            api_base=mailbox.api_base,
            token=mailbox.token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )
    if mailbox.provider == "mailtm":
        if not mailbox.token:
            logger.error(
                f"[线程 {thread_id}] [错误] {mailbox.provider} token 为空，无法读取邮件"
            )
            return ""
        return poll_hydra_oai_code(
            api_base=mailbox.api_base,
            token=mailbox.token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )
    if mailbox.provider == "tempmailio":
        return poll_tempmailio_oai_code(
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )
    if mailbox.provider == "tempmaillol":
        if not mailbox.token:
            logger.error(
                f"[线程 {thread_id}] [错误] {mailbox.provider} token 为空，无法读取邮件"
            )
            return ""
        return poll_tempmaillol_oai_code(
            token=mailbox.token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )
    if mailbox.provider == "dropmail":
        if not mailbox.sid_token:
            logger.error(f"[线程 {thread_id}] [错误] {mailbox.provider} 会话标识为空，无法读取邮件")
            return ""
        return poll_dropmail_oai_code(
            sid_token=mailbox.sid_token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )

    logger.error(
        f"[线程 {thread_id}] [错误] 暂不支持该邮箱服务: {mailbox.provider}"
    )
    return ""


# ==========================================
# OAuth 授权与辅助函数
# ==========================================



def _generate_password(length: int = 12) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


@dataclass
class RegistrationAttemptResult:
    success: bool = False
    token_json: str = ""
    password: str = ""
    email: str = ""
    stage: str = ""
    error_code: str = ""
    error_message: str = ""
    provider_key: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_legacy_result(self) -> Optional[Tuple[str, str]]:
        if not self.success or not self.token_json:
            return None
        return self.token_json, self.password


def _preview_response_text(resp: Any, limit: int = 600) -> str:
    preview = _response_text_preview(resp, limit=limit) if resp is not None else ""
    if preview:
        return preview
    status_code = getattr(resp, "status_code", "unknown")
    return f"status={status_code}"


def _detect_total_memory_mb() -> int:
    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return max(0, int(parts[1]) // 1024)
    except Exception:
        pass

    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return max(0, int(status.ullTotalPhys // (1024 * 1024)))
    except Exception:
        pass

    return 0


def _apply_low_memory_tuning(args: argparse.Namespace) -> None:
    total_memory_mb = _detect_total_memory_mb()
    if total_memory_mb <= 0:
        return

    args.detected_total_memory_mb = total_memory_mb
    if total_memory_mb <= LOW_MEMORY_HARD_LIMIT_MB:
        max_register_concurrency = 1
        max_register_batch_size = 1
        max_token_check_workers = 1
        profile_name = "hard"
    elif total_memory_mb <= LOW_MEMORY_SOFT_LIMIT_MB:
        max_register_concurrency = 2
        max_register_batch_size = 2
        max_token_check_workers = 2
        profile_name = "soft"
    else:
        return

    original_values = (
        args.register_openai_concurrency,
        args.register_batch_size,
        args.token_check_workers,
    )
    args.register_openai_concurrency = min(
        args.register_openai_concurrency,
        max_register_concurrency,
    )
    args.register_batch_size = min(
        args.register_batch_size,
        max_register_batch_size,
    )
    args.token_check_workers = min(
        args.token_check_workers,
        max_token_check_workers,
    )

    tuned_values = (
        args.register_openai_concurrency,
        args.register_batch_size,
        args.token_check_workers,
    )
    if tuned_values != original_values:
        logger.info(
            "[信息] 检测到低内存环境（总内存约 %s MB，profile=%s），"
            "已自动收敛并发：register_openai_concurrency=%s，register_batch_size=%s，token_check_workers=%s",
            total_memory_mb,
            profile_name,
            args.register_openai_concurrency,
            args.register_batch_size,
            args.token_check_workers,
        )


# ==========================================
# 核心注册逻辑
# ==========================================


def get_auto_proxy() -> Optional[str]:
    common_ports = [7890, 1080, 10809, 10808, 8888]

    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                logger.info(
                    f"[信息] 检测到本地代理端口可用: {port}"
                )
                return f"http://127.0.0.1:{port}"
    return None


def run(
    proxy: Optional[str], provider_key: str, thread_id: int, mailtm_base: str
) -> RegistrationAttemptResult:
    # 注册主流程：
    # 1. 检测出口 / 代理
    # 2. 创建临时邮箱
    # 3. OpenAI 注册 + 收验证码
    # 4. 提取 token 并持久化
    result = RegistrationAttemptResult(
        provider_key=str(provider_key or "").strip().lower(),
        metadata={"thread_id": thread_id},
    )

    def _set_stage(stage: str, **metadata: Any) -> None:
        result.stage = stage
        if metadata:
            result.metadata.update(metadata)

    def _fail(
        stage: str,
        error_code: str,
        error_message: str,
        *,
        affect_cooldown: bool = False,
        cfmail_reason: Optional[str] = None,
        **metadata: Any,
    ) -> RegistrationAttemptResult:
        _set_stage(stage, **metadata)
        result.success = False
        result.error_code = str(error_code or "").strip()
        result.error_message = str(error_message or "").strip()
        if affect_cooldown:
            _mark_cfmail_failure(
                cfmail_reason or f"{result.error_code or 'failed'}: {result.error_message}",
                affect_cooldown=True,
            )
        return result

    if provider_key == "cfmail":
        _reload_cfmail_accounts_if_needed()

    proxies: Any = _build_request_proxies(proxy)
    cfmail_config_name = ""

    def _mark_cfmail_failure(reason: str, *, affect_cooldown: bool = False) -> None:
        if provider_key == "cfmail" and cfmail_config_name and affect_cooldown:
            _record_cfmail_failure(cfmail_config_name, reason)

    def _mark_cfmail_success() -> None:
        if provider_key == "cfmail" and cfmail_config_name:
            _record_cfmail_success(cfmail_config_name)

    # 与 xiaomajiang.py 保持一致，固定使用 chrome 指纹
    current_impersonate = "chrome"
    logger.info(
        f"[线程 {thread_id}] [信息] 当前浏览器指纹: {current_impersonate}"
    )
    result.metadata["impersonate"] = current_impersonate

    s = requests.Session(proxies=proxies, impersonate=current_impersonate)

    try:
        _set_stage("network_check")
        trace = s.get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
        trace = trace.text
        loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
        loc = loc_re.group(1) if loc_re else None
        logger.info(
            f"[线程 {thread_id}] [信息] 当前出口地区: {loc}"
        )
        result.metadata["exit_loc"] = loc
        if loc != "US":
            if not builtins.yasal_bypass_ip_choice:
                logger.info(f"[线程 {thread_id}] [信息] 非 US 节点，已按配置停止当前线程")
                return _fail(
                    "network_check",
                    "non_us_exit_blocked",
                    f"当前出口地区 {loc} 不符合要求",
                    exit_loc=loc,
                )

            logger.info(
                f"[线程 {thread_id}] [信息] 当前节点地区 ({loc}) 不是 US，已默认继续执行"
            )

        if loc in ("CN", "HK"):
            if builtins.yasal_bypass_ip_choice:
                logger.warning(
                    f"[线程 {thread_id}] [警告] 当前地区 {loc} 风险较高，尝试自动检测本地代理"
                )
                if not proxy:
                    auto_p = get_auto_proxy()
                    if auto_p:
                        proxies = {"http": auto_p, "https": auto_p}
                        s.proxies = proxies
                        logger.info(
                            f"[线程 {thread_id}] [信息] 已自动启用本地代理: {auto_p}"
                        )
                    else:
                        logger.warning(
                            f"[线程 {thread_id}] [警告] 未检测到可用本地代理端口，将继续直连"
                        )
                # 用户选择绕过，继续执行
            else:
                logger.error(
                    f"[线程 {thread_id}] [错误] 当前节点地区 {loc} 风险过高，请更换代理后重试"
                )
                return _fail(
                    "network_check",
                    "high_risk_exit",
                    f"当前出口地区 {loc} 风险过高",
                    exit_loc=loc,
                )
    except Exception as e:
        logger.error(
            f"[线程 {thread_id}] [错误] 网络检查失败，请确认代理可用: {e}"
        )
        return _fail("network_check", "network_check_failed", str(e))

    _set_stage("mailbox_create")
    mailbox = get_temp_mailbox(
        provider_key,
        thread_id,
        proxies,
        mailtm_base=mailtm_base,
    )
    if not mailbox:
        return _fail(
            "mailbox_create",
            "mailbox_unavailable",
            f"临时邮箱服务不可用: {provider_key}",
        )
    cfmail_config_name = mailbox.config_name
    email = mailbox.email
    result.email = email
    result.metadata.update(
        {
            "mailbox_provider": mailbox.provider,
            "mailbox_email": email,
            "cfmail_config_name": cfmail_config_name or "",
        }
    )
    logger.info(
        f"[线程 {thread_id}] [*] 成功获取临时邮箱与授权: {email} ({mailbox.provider})"
    )

    oauth = generate_oauth_url()
    result.metadata["oauth_redirect_uri"] = oauth.redirect_uri

    try:
        _set_stage("signup_start")
        signup_start_url = bootstrap_web_signup_start_url(s, thread_id)
        if not signup_start_url:
            return _fail(
                "signup_start",
                "signup_start_url_missing",
                "未获取到 web signup 授权入口",
            )

        _set_stage("oauth_prime", signup_start_url=signup_start_url)
        resp = _prime_oauth_session(s, signup_start_url, thread_id)
        did = s.cookies.get("oai-did")
        logger.info(
            f"[线程 {thread_id}] [信息] 已获取 Device ID: {did}"
        )
        result.metadata["device_id"] = did or ""

        signup_body = (
            f'{{"username":{{"value":"{email}","kind":"email"}},'
            f'"screen_hint":"login_or_signup"}}'
        )
        _set_stage("authorize_continue")
        sentinel = _request_sentinel_token(
            did=did,
            proxies=proxies,
            impersonate=current_impersonate,
            thread_id=thread_id,
        )
        if not sentinel:
            return _fail(
                "authorize_continue",
                "sentinel_token_missing",
                "未获取到 openai-sentinel-token",
            )

        signup_resp = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/log-in-or-create-account",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
            data=signup_body,
        )
        logger.info(
            f"[线程 {thread_id}] [信息] 注册表单已提交，状态码: {signup_resp.status_code}"
        )
        if signup_resp.status_code in (403, 429):
            signup_error_preview = _preview_response_text(signup_resp)
            logger.error(
                f"[线程 {thread_id}] [错误] 注册请求被拒绝（{signup_resp.status_code}）: {signup_error_preview}"
            )
            return _fail(
                "authorize_continue",
                f"authorize_continue_{signup_resp.status_code}",
                signup_error_preview,
                status_code=signup_resp.status_code,
            )

        password = _generate_password()
        result.password = password
        register_body = json.dumps(
            {
                "password": password,
                "username": email,
            }
        )
        _set_stage("password_register")
        existing_signup_message_ids = get_mailbox_message_snapshot(
            mailbox, thread_id, proxies
        )
        register_resp = s.post(
            "https://auth.openai.com/api/accounts/user/register",
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=register_body,
        )
        logger.info(
            f"[线程 {thread_id}] [信息] 密码注册请求已提交，状态码: {register_resp.status_code}"
        )
        if register_resp.status_code != 200:
            register_error_preview = _preview_response_text(register_resp)
            logger.error(
                f"[线程 {thread_id}] [错误] 提交密码失败: {register_error_preview}"
            )
            return _fail(
                "password_register",
                f"user_register_{register_resp.status_code}",
                register_error_preview,
                status_code=register_resp.status_code,
            )

        _set_stage("email_otp_send")
        otp_resp = s.get(
            "https://auth.openai.com/api/accounts/email-otp/send",
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
            },
        )
        logger.info(
            f"[线程 {thread_id}] [信息] 注册阶段验证码发送请求已提交，状态码: {otp_resp.status_code}"
        )
        if otp_resp.status_code != 200:
            otp_error_preview = _preview_response_text(otp_resp)
            logger.error(
                f"[线程 {thread_id}] [错误] 注册阶段发送验证码失败: {otp_error_preview}"
            )
            return _fail(
                "email_otp_send",
                f"email_otp_send_{otp_resp.status_code}",
                otp_error_preview,
                status_code=otp_resp.status_code,
            )

        _set_stage("email_otp_wait")
        code = get_oai_code(
            mailbox,
            thread_id,
            proxies,
            skip_message_ids=existing_signup_message_ids,
        )
        if not code:
            return _fail(
                "email_otp_wait",
                "email_code_empty",
                "未获取到注册阶段验证码",
                affect_cooldown=True,
                cfmail_reason="email_code empty",
            )

        _set_stage("email_otp_validate")
        code_resp = _post_email_otp_validate(
            s,
            code=code,
            thread_id=thread_id,
            stage_label="注册阶段",
        )
        logger.info(
            f"[线程 {thread_id}] [信息] 验证码校验结果状态码: {getattr(code_resp, 'status_code', 'unknown')}"
        )
        if not code_resp or code_resp.status_code != 200:
            preview = _response_text_preview(code_resp) if code_resp else ""
            logger.error(
                f"[线程 {thread_id}] [错误] 注册阶段邮箱验证码校验失败: {preview}"
            )
            _mark_cfmail_failure(
                f"signup email otp validate status={getattr(code_resp, 'status_code', 'unknown')}",
                affect_cooldown=False,
            )
            return _fail(
                "email_otp_validate",
                f"email_otp_validate_{getattr(code_resp, 'status_code', 'unknown')}",
                preview or "注册阶段邮箱验证码校验失败",
                status_code=getattr(code_resp, "status_code", "unknown"),
            )

        signup_profile = _build_random_signup_profile()
        create_account_body = json.dumps(
            signup_profile, ensure_ascii=False, separators=(",", ":")
        )
        _set_stage("create_account", signup_profile=signup_profile)
        logger.info(
            f"[线程 {thread_id}] [信息] 本次注册资料: name={signup_profile['name']}, birthdate={signup_profile['birthdate']}"
        )
        create_account_resp = _post_create_account_with_retry(
            s,
            create_account_body=create_account_body,
            did=did,
            proxies=proxies,
            impersonate=current_impersonate,
            thread_id=thread_id,
        )
        create_account_status = getattr(create_account_resp, "status_code", 0)
        logger.info(
            f"[线程 {thread_id}] [信息] 创建账户接口状态码: {create_account_status}"
        )

        if not create_account_resp or create_account_status != 200:
            err_msg = (
                _response_text_preview(create_account_resp, limit=1200)
                if create_account_resp
                else ""
            )
            logger.error(
                f"[线程 {thread_id}] [错误] 创建账户失败: {err_msg}"
            )
            if "unsupported_email" in err_msg:
                logger.info(
                    f"[线程 {thread_id}] [提示] 当前邮箱域名可能被限制，建议更换临时邮箱服务或域名"
                )
            elif "registration_disallowed" in err_msg:
                logger.info(
                    f"[线程 {thread_id}] [提示] 当前邮箱提供商可能被风控，建议优先使用 tempmaillol"
                )
            elif "429" in str(create_account_status):
                logger.info(
                    f"[线程 {thread_id}] [提示] 请求频率过高（429），建议更换代理或降低并发"
                )
            _mark_cfmail_failure(
                f"create_account status={create_account_status} body={err_msg[:120]}",
                affect_cooldown=(
                    "unsupported_email" in err_msg
                    or "registration_disallowed" in err_msg
                ),
            )
            return _fail(
                "create_account",
                f"create_account_{create_account_status}",
                err_msg or "创建账户失败",
                status_code=create_account_status,
            )

        logger.info(
            f"[线程 {thread_id}] [信息] 注册流程已完成，当前会话可能跳到绑手机页，改用全新登录流程提取 token"
        )
        token_json = None
        token_source = ""
        if not token_json:
            _set_stage("token_password_login")
            token_json = _try_token_via_password_login(
                email=email,
                password=password,
                mailbox=mailbox,
                used_codes={code},
                oauth=oauth,
                proxies=proxies,
                impersonate=current_impersonate,
                thread_id=thread_id,
                get_oai_code_fn=get_oai_code,
                get_mailbox_message_snapshot_fn=get_mailbox_message_snapshot,
            )
            if token_json:
                token_source = "password_login"

        if not token_json:
            logger.warning(
                f"[线程 {thread_id}] [警告] 新登录流程未拿到 token，尝试回退到当前注册会话"
            )
            _set_stage("token_workspace_select")
            auth_cookie = s.cookies.get("oai-client-auth-session")
            if auth_cookie:
                token_json = _try_token_via_workspace_select(
                    s, oauth, auth_cookie, thread_id
                )
                if token_json:
                    token_source = "workspace_select"
            else:
                logger.warning(f"[线程 {thread_id}] [警告] 当前会话中暂未拿到授权 Cookie")

        if not token_json:
            _set_stage("token_existing_session")
            token_json = _try_token_via_existing_session(s, oauth, thread_id)
            if token_json:
                token_source = "existing_session"

        if not token_json:
            _set_stage("token_session_api")
            token_json = _try_token_via_session_api(s, thread_id)
            if token_json:
                token_source = "session_api"

        if token_json:
            _mark_cfmail_success()
            result.success = True
            result.token_json = token_json
            result.error_code = ""
            result.error_message = ""
            _set_stage("completed", token_source=token_source or "unknown")
            return result

        logger.error(f"[线程 {thread_id}] [错误] 已完成注册，但仍未能获取 OAuth token")
        return _fail(
            "token_finalize",
            "token_extraction_failed",
            "已完成注册，但仍未能获取可用 token",
        )

    except Exception as e:
        logger.exception(f"[线程 {thread_id}] [错误] 运行过程中发生异常: {e}")
        logger.info(
            f"[线程 {thread_id}] [提示] 本轮失败，下一轮将继续重试"
        )
        return _fail("exception", "unhandled_exception", str(e))


def _provider_fallback_chain(provider_key: str) -> List[str]:
    primary = str(provider_key or "").strip().lower()
    chain: List[str] = []
    if primary:
        chain.append(primary)
    if primary == "cfmail" and DEFAULT_CFMAIL_FALLBACK_PROVIDER not in chain:
        chain.append(DEFAULT_CFMAIL_FALLBACK_PROVIDER)
    return chain


def run_with_fallback(
    proxy: Optional[str],
    provider_key: str,
    thread_id: int,
    mailtm_base: str,
    *,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> Tuple[Optional[Tuple[str, str]], str]:
    provider_chain = _provider_fallback_chain(provider_key)
    last_used_provider = str(provider_key or "").strip().lower()

    for index, candidate_provider in enumerate(provider_chain):
        last_used_provider = candidate_provider
        if index > 0:
            logger.info(
                f"[线程 {thread_id}] [信息] 主邮箱服务 {provider_chain[0]} 不可用，"
                f"开始回退到 {candidate_provider}"
            )

        attempt = run(proxy, candidate_provider, thread_id, mailtm_base)
        if attempt.success:
            if index > 0:
                logger.info(
                    f"[线程 {thread_id}] [信息] 已通过回退邮箱服务 {candidate_provider} 完成注册"
                )
                alert_sent = notify_fallback_provider_usage(
                    dingtalk_webhook,
                    primary_provider=provider_chain[0],
                    fallback_provider=candidate_provider,
                    thread_id=thread_id,
                    throttle_seconds=dingtalk_fallback_interval_seconds,
                )
                if dingtalk_webhook and alert_sent:
                    logger.info(
                        f"[线程 {thread_id}] [信息] 已发送回退邮箱服务钉钉提醒：{provider_chain[0]} -> {candidate_provider}"
                    )
            return attempt.as_legacy_result(), candidate_provider

        logger.warning(
            f"[线程 {thread_id}] [警告] 使用邮箱服务 {candidate_provider} 的注册尝试失败："
            f"stage={attempt.stage or 'unknown'}"
            f", error_code={attempt.error_code or 'unknown'}"
            f", message={attempt.error_message or 'unknown'}"
        )

    return None, last_used_provider


def _load_config_file(config_path: str) -> dict:
    """加载 JSON 配置文件，返回配置字典。文件不存在则返回空字典。"""
    if not config_path or not os.path.isfile(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        # 过滤掉以 _ 开头的注释字段
        return {k: v for k, v in data.items() if not k.startswith("_")}
    except Exception as exc:
        logger.warning(f"[警告] 读取配置文件 {config_path} 失败: {exc}")
        return {}


# 配置文件中的 key 到 argparse dest 的映射
_CONFIG_KEY_MAP = {
    "proxy": "proxy",
    "mail_provider": "mail_provider",
    "cfmail_profile": "cfmail_profile",
    "cfmail_config": "cfmail_config",
    "cfmail_worker_domain": "cfmail_worker_domain",
    "cfmail_email_domain": "cfmail_email_domain",
    "cfmail_admin_password": "cfmail_admin_password",
    "cfmail_profile_name": "cfmail_profile_name",
    "mailtm_api_base": "mailtm_api_base",
    "token_dir": "token_dir",
    "active_token_dir": "active_token_dir",
    "active_min_count": "active_min_count",
    "pool_min_count": "pool_min_count",
    "usage_threshold": "usage_threshold",
    "request_interval": "request_interval",
    "token_check_workers": "token_check_workers",
    "curl_timeout": "curl_timeout",
    "monitor_interval": "monitor_interval",
    "register_batch_size": "register_batch_size",
    "register_openai_concurrency": "register_openai_concurrency",
    "register_start_delay_seconds": "register_start_delay_seconds",
    "dingtalk_webhook": "dingtalk_webhook",
    "dingtalk_summary_interval": "dingtalk_summary_interval",
    "dingtalk_fallback_interval": "dingtalk_fallback_interval",
    "sleep_min": "sleep_min",
    "sleep_max": "sleep_max",
    "failure_sleep_seconds": "failure_sleep_seconds",
    "cfmail_fail_threshold": "cfmail_fail_threshold",
    "cfmail_cooldown_seconds": "cfmail_cooldown_seconds",
}

# 布尔型参数（配置文件里 true/false）
_CONFIG_BOOL_KEYS = {
    "monitor", "monitor_once", "register_only",
    "auto_continue_non_us", "once", "test_cfmail",
}

DEFAULT_CONFIG_PATH = os.path.join(_SCRIPT_DIR, "monitor_config.json")


def _apply_config_to_args(args: argparse.Namespace, config: dict) -> None:
    """将配置文件中的值填入 args，仅当命令行未显式指定时生效。"""
    for config_key, arg_dest in _CONFIG_KEY_MAP.items():
        if config_key not in config:
            continue
        # 仅当 argparse 使用了默认值时才覆盖（命令行显式指定的优先）
        current_val = getattr(args, arg_dest, None)
        default_val = getattr(args, f"_default_{arg_dest}", current_val)
        if current_val == default_val:
            setattr(args, arg_dest, config[config_key])

    for bool_key in _CONFIG_BOOL_KEYS:
        if bool_key not in config:
            continue
        current_val = getattr(args, bool_key, False)
        if not current_val:
            setattr(args, bool_key, bool(config[bool_key]))


def main() -> None:
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
    config = _load_config_file(args.config)
    if config:
        logger.info(f"[信息] 已加载配置文件: {args.config}")
        _apply_config_to_args(args, config)

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
    _apply_low_memory_tuning(args)
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
