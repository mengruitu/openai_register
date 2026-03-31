# -*- coding: utf-8 -*-
"""核心注册流程与邮箱路由逻辑。

本模块包含：
- 临时邮箱路由（get_temp_mailbox / get_oai_code / get_mailbox_message_snapshot）
- 随机注册资料生成
- OpenAI 注册主流程（run）
- 带回退的注册封装（run_with_fallback）
"""
import builtins
import json
import logging
import random
import re
import secrets
import socket
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from curl_cffi import requests

from register_auth import (
    bootstrap_web_signup_start_url,
    extract_continue_url_from_response,
    generate_oauth_url,
    post_email_otp_validate,
    prime_oauth_session,
    response_text_preview,
)
from register_cfmail import (
    create_cfmail_mailbox as _create_cfmail_mailbox,
    list_cfmail_message_ids as _list_cfmail_message_ids,
    poll_cfmail_oai_code as _poll_cfmail_oai_code,
    record_cfmail_failure as _record_cfmail_failure,
    record_cfmail_success as _record_cfmail_success,
    reload_cfmail_accounts_if_needed as _reload_cfmail_accounts_if_needed,
)
from register_config import (
    CREATE_ACCOUNT_MAX_ATTEMPTS,
    CREATE_ACCOUNT_RETRY_DELAY_SECONDS,
    DEFAULT_CFMAIL_FALLBACK_PROVIDER,
    DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
)
from register_mailboxes import (
    MAILTM_BASE,
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
from register_notifications import notify_fallback_provider_usage
from register_sentinel import random_impersonate, request_sentinel_header
from register_token import (
    try_token_via_existing_session,
    try_token_via_password_login,
    try_token_via_passwordless_login,
    try_token_via_session_api,
    try_token_via_workspace_select,
)

logger = logging.getLogger("openai_register")


# ---------------------------------------------------------------------------
# 数据类
# ---------------------------------------------------------------------------


@dataclass
class RegistrationAttemptResult:
    """单次注册尝试的结果。"""

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
        """兼容旧版返回格式。"""
        if not self.success or not self.token_json:
            return None
        return self.token_json, self.password


# ---------------------------------------------------------------------------
# 临时邮箱路由
# ---------------------------------------------------------------------------


def get_temp_mailbox(
    provider_key: str,
    thread_id: int,
    proxies: Any = None,
    mailtm_base: str = MAILTM_BASE,
) -> Optional[TempMailbox]:
    """根据 provider_key 创建对应的临时邮箱。"""
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
    """获取当前邮箱中已有消息的 ID 快照。"""
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
    """从临时邮箱中轮询获取 OpenAI 验证码。"""
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


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def _random_name_part(min_length: int = 4, max_length: int = 9) -> str:
    """生成随机英文名片段。"""
    length = random.randint(min_length, max_length)
    letters = string.ascii_lowercase
    value = "".join(secrets.choice(letters) for _ in range(length))
    return value.capitalize()


def _random_profile_name() -> str:
    """生成随机的全名（名 + 姓）。"""
    return f"{_random_name_part()} {_random_name_part(5, 10)}"


def _random_birthdate(start_year: int = 1990, end_year: int = 2005) -> str:
    """生成随机的出生日期字符串。"""
    start_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year, 12, 31)
    day_offset = random.randint(0, (end_date - start_date).days)
    return (start_date + timedelta(days=day_offset)).strftime("%Y-%m-%d")


def _build_random_signup_profile() -> Dict[str, str]:
    """构建随机的注册资料。"""
    return {
        "name": _random_profile_name(),
        "birthdate": _random_birthdate(),
    }


def _build_request_proxies(proxy: Optional[str]) -> Any:
    """将代理字符串转为 requests 库所需的 proxies 字典。"""
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def _generate_password(length: int = 12) -> str:
    """生成指定长度的随机密码。"""
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def _preview_response_text(resp: Any, limit: int = 600) -> str:
    """获取 HTTP 响应的预览文本。"""
    preview = response_text_preview(resp, limit=limit) if resp is not None else ""
    if preview:
        return preview
    status_code = getattr(resp, "status_code", "unknown")
    return f"status={status_code}"


def get_auto_proxy() -> Optional[str]:
    """自动检测本地代理端口并返回代理地址。"""
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
    """带重试的创建账户请求。"""
    attempts = max(1, int(max_attempts))
    delay_seconds = max(0, int(retry_delay_seconds))
    last_resp = None

    for attempt in range(1, attempts + 1):
        try:
            create_account_sentinel = request_sentinel_header(
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
            preview = response_text_preview(last_resp)
            logger.warning(
                f"[线程 {thread_id}] [警告] create_account 遇到临时错误，"
                f"状态码: {status_code}，第 {attempt}/{attempts} 次尝试；"
                f"{delay_seconds} 秒后重试。响应摘要: {preview}"
            )
            time.sleep(delay_seconds)
            continue

        return last_resp

    return last_resp


# ---------------------------------------------------------------------------
# 核心注册主流程
# ---------------------------------------------------------------------------


def run(
    proxy: Optional[str], provider_key: str, thread_id: int, mailtm_base: str
) -> RegistrationAttemptResult:
    """注册主流程。

    1. 检测出口 / 代理
    2. 创建临时邮箱
    3. OpenAI 注册 + 收验证码
    4. 提取 token 并持久化
    """
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

    # 每次注册随机选取浏览器指纹，降低批量注册时的指纹关联性
    current_impersonate = random_impersonate()
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
        resp = prime_oauth_session(s, signup_start_url, thread_id)
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
        sentinel = request_sentinel_header(
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
        code_resp = post_email_otp_validate(
            s,
            code=code,
            thread_id=thread_id,
            stage_label="注册阶段",
        )
        logger.info(
            f"[线程 {thread_id}] [信息] 验证码校验结果状态码: {getattr(code_resp, 'status_code', 'unknown')}"
        )
        if not code_resp or code_resp.status_code != 200:
            preview = response_text_preview(code_resp) if code_resp else ""
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
                response_text_preview(create_account_resp, limit=1200)
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
            token_json = try_token_via_password_login(
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

        # 如果密码登录也被 add_phone 拦截，尝试 passwordless OTP 登录
        if not token_json:
            logger.info(
                f"[线程 {thread_id}] [信息] 密码登录未拿到 token，"
                "尝试 passwordless OTP 登录绕过 add_phone"
            )
            _set_stage("token_passwordless_login")
            token_json = try_token_via_passwordless_login(
                email=email,
                mailbox=mailbox,
                used_codes={code},
                proxies=proxies,
                impersonate=current_impersonate,
                thread_id=thread_id,
                get_oai_code_fn=get_oai_code,
                get_mailbox_message_snapshot_fn=get_mailbox_message_snapshot,
            )
            if token_json:
                token_source = "passwordless_login"

        if not token_json:
            logger.warning(
                f"[线程 {thread_id}] [警告] 新登录流程未拿到 token，尝试回退到当前注册会话"
            )
            _set_stage("token_workspace_select")
            auth_cookie = s.cookies.get("oai-client-auth-session")
            if auth_cookie:
                token_json = try_token_via_workspace_select(
                    s, oauth, auth_cookie, thread_id
                )
                if token_json:
                    token_source = "workspace_select"
            else:
                logger.warning(f"[线程 {thread_id}] [警告] 当前会话中暂未拿到授权 Cookie")

        if not token_json:
            _set_stage("token_existing_session")
            token_json = try_token_via_existing_session(s, oauth, thread_id)
            if token_json:
                token_source = "existing_session"

        if not token_json:
            _set_stage("token_session_api")
            token_json = try_token_via_session_api(s, thread_id)
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


# ---------------------------------------------------------------------------
# 带回退的注册封装
# ---------------------------------------------------------------------------


def _provider_fallback_chain(provider_key: str) -> List[str]:
    """构建邮箱服务提供商的回退链。"""
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
    """带邮箱服务回退的注册入口。"""
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
