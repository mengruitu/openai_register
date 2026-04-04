import hashlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from curl_cffi import requests

from .diagnostics import (
    increment_mailbox_wait_poll,
    mark_mailbox_wait_matched,
    mark_mailbox_wait_timeout,
    note_mailbox_messages_scanned,
    reset_mailbox_wait_diagnostics,
)
from .providers import TempMailbox

logger = logging.getLogger("openai_register")

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TEMPMAIL_BASE_URL = "https://web2.temp-mail.org"
TEMPMAIL_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Origin": TEMPMAIL_BASE_URL,
    "Referer": TEMPMAIL_BASE_URL,
}
OTP_CODE_PATTERN = re.compile(r"(?<!\d)(\d{6})(?!\d)")
TEMPMAIL_CREATE_MIN_INTERVAL_SECONDS = 12.0
TEMPMAIL_POLL_MIN_INTERVAL_SECONDS = 6.0
TEMPMAIL_CREATE_429_RETRY_DELAYS = (15.0, 30.0, 45.0)
TEMPMAIL_READ_429_RETRY_DELAYS = (8.0, 12.0)
TEMPMAIL_MAX_WAIT_SECONDS = 240

DEFAULT_CFMAIL_CONFIG_PATH = os.path.join(_SCRIPT_DIR, "cfmail_accounts.json")
DEFAULT_CFMAIL_ACCOUNTS: List[Dict[str, Any]] = [
    {
        "name": "temp-mail-org",
        "worker_domain": "web2.temp-mail.org",
        "email_domain": "temp-mail.org",
        "admin_password": "disabled",
        "enabled": True,
    }
]
DEFAULT_CFMAIL_PROFILE_NAME = (
    str(DEFAULT_CFMAIL_ACCOUNTS[0].get("name") or "").strip()
    if DEFAULT_CFMAIL_ACCOUNTS
    else "temp-mail-org"
)
DEFAULT_CFMAIL_WORKER_DOMAIN = "web2.temp-mail.org"
DEFAULT_CFMAIL_EMAIL_DOMAIN = "temp-mail.org"
DEFAULT_CFMAIL_ADMIN_PASSWORD = "disabled"
DEFAULT_CFMAIL_FAIL_THRESHOLD = 3
DEFAULT_CFMAIL_COOLDOWN_SECONDS = 300


@dataclass(frozen=True)
class CfmailAccount:
    name: str
    worker_domain: str = DEFAULT_CFMAIL_WORKER_DOMAIN
    email_domain: str = DEFAULT_CFMAIL_EMAIL_DOMAIN
    admin_password: str = DEFAULT_CFMAIL_ADMIN_PASSWORD


_cfmail_account_lock = threading.Lock()
_cfmail_reload_lock = threading.Lock()
_cfmail_failure_lock = threading.Lock()
_tempmail_rate_lock = threading.Lock()
_tempmail_last_request_at: Dict[str, float] = {}
_cfmail_account_index = 0

CFMAIL_CONFIG_PATH = (
    str(os.getenv("CFMAIL_CONFIG_PATH", DEFAULT_CFMAIL_CONFIG_PATH)).strip()
    or DEFAULT_CFMAIL_CONFIG_PATH
)
CFMAIL_ACCOUNTS: List[CfmailAccount] = []
CFMAIL_PROFILE_MODE = "auto"
CFMAIL_HOT_RELOAD_ENABLED = True
CFMAIL_CONFIG_MTIME = (
    os.path.getmtime(CFMAIL_CONFIG_PATH) if os.path.exists(CFMAIL_CONFIG_PATH) else None
)
CFMAIL_FAIL_THRESHOLD = DEFAULT_CFMAIL_FAIL_THRESHOLD
CFMAIL_COOLDOWN_SECONDS = DEFAULT_CFMAIL_COOLDOWN_SECONDS
CFMAIL_FAILURE_STATE: Dict[str, Dict[str, Any]] = {}
CFMAIL_WORKER_DOMAIN = DEFAULT_CFMAIL_WORKER_DOMAIN
CFMAIL_EMAIL_DOMAIN = DEFAULT_CFMAIL_EMAIL_DOMAIN
CFMAIL_ADMIN_PASSWORD = DEFAULT_CFMAIL_ADMIN_PASSWORD
CFMAIL_REMINDER_MARKERS = (
    "继续未完成的步骤",
    "完成帐户设置",
    "complete your account setup",
    "finish setting up your account",
    "your progress has been saved",
)


def _log_waiting_code_start(thread_id: int, email: str) -> None:
    logger.info(f"[线程 {thread_id}] [信息] 正在等待邮箱 {email} 的验证码")


def _log_waiting_code_success(thread_id: int, code: str) -> None:
    logger.info(f"[线程 {thread_id}] [信息] 已收到验证码: {code}")


def _log_waiting_code_timeout(thread_id: int) -> None:
    logger.warning(f"[线程 {thread_id}] [警告] 等待超时，未收到验证码")


def _contains_cfmail_keyword(*parts: Any) -> bool:
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        lowered = text.lower()
        if "openai" in lowered or "chatgpt" in lowered:
            return True
    return False


def normalize_host(value: str) -> str:
    value = str(value or "").strip()
    if value.startswith("https://"):
        value = value[len("https://") :]
    elif value.startswith("http://"):
        value = value[len("http://") :]
    return value.strip().strip("/")


def load_cfmail_accounts_from_file(
    config_path: str, *, silent: bool = False
) -> List[Dict[str, Any]]:
    path = str(config_path or "").strip()
    if not path or not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        if not silent:
            logger.warning(f"[警告] 读取 cfmail 配置文件失败: {path}，错误: {e}")
        return []

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        accounts = data.get("accounts")
        if isinstance(accounts, list):
            return accounts

    if not silent:
        logger.warning(f"[警告] cfmail 配置文件格式无效: {path}")
    return []


def _default_cfmail_account(name: str = DEFAULT_CFMAIL_PROFILE_NAME) -> CfmailAccount:
    return CfmailAccount(
        name=str(name or DEFAULT_CFMAIL_PROFILE_NAME).strip() or DEFAULT_CFMAIL_PROFILE_NAME,
        worker_domain=DEFAULT_CFMAIL_WORKER_DOMAIN,
        email_domain=DEFAULT_CFMAIL_EMAIL_DOMAIN,
        admin_password=DEFAULT_CFMAIL_ADMIN_PASSWORD,
    )


def _normalize_cfmail_account(raw: Dict[str, Any]) -> Optional[CfmailAccount]:
    if not isinstance(raw, dict):
        return None

    if not raw.get("enabled", True):
        return None

    name = str(raw.get("name") or raw.get("profile") or DEFAULT_CFMAIL_PROFILE_NAME).strip()
    if not name:
        name = DEFAULT_CFMAIL_PROFILE_NAME

    return CfmailAccount(
        name=name,
        worker_domain=DEFAULT_CFMAIL_WORKER_DOMAIN,
        email_domain=DEFAULT_CFMAIL_EMAIL_DOMAIN,
        admin_password=DEFAULT_CFMAIL_ADMIN_PASSWORD,
    )


def build_cfmail_accounts(raw_accounts: List[Dict[str, Any]]) -> List[CfmailAccount]:
    accounts: List[CfmailAccount] = []
    seen_names: Set[str] = set()

    for item in raw_accounts:
        account = _normalize_cfmail_account(item)
        if not account:
            continue

        key = account.name.lower()
        if key in seen_names:
            continue

        seen_names.add(key)
        accounts.append(account)

    env_profile_name = (
        str(os.getenv("CFMAIL_PROFILE_NAME", DEFAULT_CFMAIL_PROFILE_NAME)).strip()
        or DEFAULT_CFMAIL_PROFILE_NAME
    )
    if not accounts:
        accounts = [_default_cfmail_account(env_profile_name)]

    return accounts


def cfmail_account_names(accounts: Optional[List[CfmailAccount]] = None) -> str:
    items = accounts if accounts is not None else CFMAIL_ACCOUNTS
    return ", ".join(account.name for account in items) if items else "无"


def _refresh_cfmail_globals() -> None:
    global CFMAIL_WORKER_DOMAIN, CFMAIL_EMAIL_DOMAIN, CFMAIL_ADMIN_PASSWORD
    CFMAIL_WORKER_DOMAIN = CFMAIL_ACCOUNTS[0].worker_domain if CFMAIL_ACCOUNTS else DEFAULT_CFMAIL_WORKER_DOMAIN
    CFMAIL_EMAIL_DOMAIN = CFMAIL_ACCOUNTS[0].email_domain if CFMAIL_ACCOUNTS else DEFAULT_CFMAIL_EMAIL_DOMAIN
    CFMAIL_ADMIN_PASSWORD = CFMAIL_ACCOUNTS[0].admin_password if CFMAIL_ACCOUNTS else DEFAULT_CFMAIL_ADMIN_PASSWORD


def prune_cfmail_failure_state(accounts: Optional[List[CfmailAccount]] = None) -> None:
    items = accounts if accounts is not None else CFMAIL_ACCOUNTS
    valid_keys = {account.name.lower() for account in items}
    with _cfmail_failure_lock:
        for key in list(CFMAIL_FAILURE_STATE.keys()):
            if key not in valid_keys:
                CFMAIL_FAILURE_STATE.pop(key, None)


def _cfmail_skip_remaining_seconds(account_name: str) -> int:
    _ = account_name
    return 0


def record_cfmail_success(account_name: str) -> None:
    key = str(account_name or "").strip().lower()
    if not key:
        return

    with _cfmail_failure_lock:
        state = CFMAIL_FAILURE_STATE.setdefault(key, {"name": account_name})
        state["name"] = account_name
        state["consecutive_failures"] = 0
        state["cooldown_until"] = 0
        state["last_error"] = ""
        state["last_success_at"] = time.time()


def record_cfmail_failure(account_name: str, reason: str = "") -> None:
    key = str(account_name or "").strip().lower()
    if not key:
        return

    with _cfmail_failure_lock:
        state = CFMAIL_FAILURE_STATE.setdefault(key, {"name": account_name})
        state["name"] = account_name
        state["consecutive_failures"] = int(state.get("consecutive_failures") or 0) + 1
        state["last_error"] = str(reason or "").strip()[:300]
        state["last_failed_at"] = time.time()
        state["cooldown_until"] = 0


def set_cfmail_accounts(accounts: List[CfmailAccount]) -> None:
    global CFMAIL_ACCOUNTS, _cfmail_account_index
    normalized_accounts = [
        _default_cfmail_account(getattr(account, "name", DEFAULT_CFMAIL_PROFILE_NAME))
        for account in (accounts or [])
        if getattr(account, "name", "")
    ]
    CFMAIL_ACCOUNTS = normalized_accounts or [_default_cfmail_account()]
    _cfmail_account_index = 0
    _refresh_cfmail_globals()


def configure_cfmail_runtime(
    *,
    accounts: List[CfmailAccount],
    profile_mode: str,
    config_path: str,
    hot_reload_enabled: bool,
    fail_threshold: int,
    cooldown_seconds: int,
) -> None:
    global CFMAIL_PROFILE_MODE, CFMAIL_CONFIG_PATH, CFMAIL_HOT_RELOAD_ENABLED
    global CFMAIL_FAIL_THRESHOLD, CFMAIL_COOLDOWN_SECONDS, CFMAIL_CONFIG_MTIME

    set_cfmail_accounts(accounts or [_default_cfmail_account()])
    CFMAIL_PROFILE_MODE = str(profile_mode or "auto").strip() or "auto"
    CFMAIL_CONFIG_PATH = str(config_path or DEFAULT_CFMAIL_CONFIG_PATH).strip() or DEFAULT_CFMAIL_CONFIG_PATH
    CFMAIL_HOT_RELOAD_ENABLED = bool(hot_reload_enabled)
    CFMAIL_FAIL_THRESHOLD = max(1, int(fail_threshold))
    CFMAIL_COOLDOWN_SECONDS = max(0, int(cooldown_seconds))
    CFMAIL_CONFIG_MTIME = (
        os.path.getmtime(CFMAIL_CONFIG_PATH)
        if os.path.exists(CFMAIL_CONFIG_PATH)
        else None
    )
    prune_cfmail_failure_state()


def get_cfmail_accounts() -> List[CfmailAccount]:
    return list(CFMAIL_ACCOUNTS)


def select_cfmail_account(profile_name: str = "auto") -> Optional[CfmailAccount]:
    global _cfmail_account_index
    accounts = CFMAIL_ACCOUNTS
    if not accounts:
        return _default_cfmail_account()

    selected_name = str(profile_name or "auto").strip()
    if selected_name and selected_name.lower() != "auto":
        selected_key = selected_name.lower()
        for account in accounts:
            if account.name.lower() == selected_key:
                return account
        return None

    with _cfmail_account_lock:
        index = _cfmail_account_index % len(accounts)
        account = accounts[index]
        _cfmail_account_index = (index + 1) % len(accounts)
        return account


def reload_cfmail_accounts_if_needed(force: bool = False) -> bool:
    global CFMAIL_CONFIG_MTIME

    if not CFMAIL_HOT_RELOAD_ENABLED:
        return False

    config_path = str(CFMAIL_CONFIG_PATH or "").strip()
    if not config_path:
        return False

    try:
        mtime = os.path.getmtime(config_path)
    except OSError:
        if not CFMAIL_ACCOUNTS:
            set_cfmail_accounts([_default_cfmail_account()])
        return False

    with _cfmail_reload_lock:
        if not force and CFMAIL_CONFIG_MTIME == mtime:
            return False

        raw_accounts = load_cfmail_accounts_from_file(config_path)
        new_accounts = build_cfmail_accounts(raw_accounts)
        old_names = cfmail_account_names()
        set_cfmail_accounts(new_accounts)
        prune_cfmail_failure_state(new_accounts)
        CFMAIL_CONFIG_MTIME = mtime
        new_names = cfmail_account_names()
        if force or old_names != new_names:
            logger.info(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [信息] cfmail 已切换为 temp-mail.org 兼容模式：{new_names}"
            )
        return True


def cfmail_headers(*, jwt: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = dict(TEMPMAIL_HEADERS)
    if use_json:
        headers["Accept"] = "application/json"
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
        headers["Cache-Control"] = "no-cache"
    return headers


def _build_request_proxies(proxy: Any) -> Any:
    if not proxy:
        return None
    if isinstance(proxy, dict):
        return proxy
    return {"http": proxy, "https": proxy}


def _tempmail_min_interval(path: str) -> float:
    normalized = str(path or "").strip().lower()
    return (
        TEMPMAIL_CREATE_MIN_INTERVAL_SECONDS
        if normalized == "/mailbox"
        else TEMPMAIL_POLL_MIN_INTERVAL_SECONDS
    )


def _wait_for_tempmail_slot(path: str) -> None:
    min_interval = _tempmail_min_interval(path)
    if min_interval <= 0:
        return

    while True:
        with _tempmail_rate_lock:
            now_ts = time.monotonic()
            last_ts = float(_tempmail_last_request_at.get(path) or 0.0)
            wait_seconds = max(0.0, min_interval - (now_ts - last_ts))
            if wait_seconds <= 0:
                _tempmail_last_request_at[path] = now_ts
                return
        time.sleep(min(wait_seconds, 1.0))


def _request_tempmail(
    method: str,
    path: str,
    *,
    jwt: str = "",
    proxies: Any = None,
    timeout: int = 15,
) -> Any:
    target_url = f"{TEMPMAIL_BASE_URL}{path}"
    resolved_proxies = _build_request_proxies(proxies)
    retry_delays = (
        TEMPMAIL_CREATE_429_RETRY_DELAYS
        if str(path or "").strip().lower() == "/mailbox"
        else TEMPMAIL_READ_429_RETRY_DELAYS
    )
    last_error: Optional[Exception] = None

    for attempt_index in range(len(retry_delays) + 1):
        _wait_for_tempmail_slot(path)
        for candidate_proxies in ([resolved_proxies, None] if resolved_proxies else [None]):
            try:
                resp = requests.request(
                    method,
                    target_url,
                    headers=cfmail_headers(jwt=jwt, use_json=True),
                    proxies=candidate_proxies,
                    impersonate="chrome",
                    verify=False,
                    timeout=timeout,
                )
            except Exception as exc:
                last_error = exc
                if candidate_proxies is None:
                    break
                logger.warning(f"[temp-mail] 代理请求失败，尝试直连回退: {exc}")
                continue

            if resp.status_code != 429:
                return resp

            if attempt_index >= len(retry_delays):
                return resp

            backoff_seconds = float(retry_delays[attempt_index])
            logger.warning(
                f"[temp-mail] 命中 429，{backoff_seconds:.0f} 秒后重试 {path}"
            )
            time.sleep(backoff_seconds)
            break

    if last_error:
        raise last_error
    raise RuntimeError(f"请求 temp-mail 失败: {target_url}")


def _extract_message_list(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        messages = payload.get("messages") or payload.get("items") or []
    elif isinstance(payload, list):
        messages = payload
    else:
        messages = []
    return [item for item in messages if isinstance(item, dict)]


def _message_uid(message: Dict[str, Any]) -> str:
    for key in (
        "id",
        "_id",
        "uuid",
        "messageId",
        "message_id",
        "createdAt",
        "created_at",
        "receivedAt",
        "received_at",
        "date",
        "timestamp",
    ):
        value = str(message.get(key) or "").strip()
        if value:
            return value
    raw = json.dumps(message, ensure_ascii=False, sort_keys=True)
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()


def _message_text(message: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in (
        "subject",
        "from",
        "to",
        "body",
        "bodyText",
        "body_text",
        "text",
        "plain",
        "intro",
        "snippet",
        "html",
        "content",
        "mailbox",
    ):
        value = message.get(key)
        if isinstance(value, list):
            value = "\n".join(str(item) for item in value)
        elif isinstance(value, dict):
            value = json.dumps(value, ensure_ascii=False)
        value = str(value or "").strip()
        if value:
            parts.append(value)

    raw_json = json.dumps(message, ensure_ascii=False)
    if raw_json:
        parts.append(raw_json)

    return "\n".join(parts)


def _extract_cfmail_subject_and_content(message: Dict[str, Any]) -> tuple[str, str]:
    subject = str(message.get("subject") or "").strip()
    content = _message_text(message)
    return subject, content


def _extract_cfmail_oai_code(subject: str, content: str) -> str:
    text = "\n".join([str(subject or ""), str(content or "")])
    patterns = [
        r"(?:Your ChatGPT code is)\s*(\d{6})",
        r"(?:temporary verification code to continue[：:])\s*(\d{6})",
        r"(?:你的\s*ChatGPT\s*代码为)\s*(\d{6})",
        r"(?:输入此临时验证码以继续[：:])\s*(\d{6})",
        r"(?:验证码[：:])\s*(\d{6})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            return match.group(1)

    if subject:
        tail = subject.split(" ")[-1].strip()
        if tail.isdigit() and len(tail) == 6:
            return tail

    generic_match = OTP_CODE_PATTERN.search(text)
    return generic_match.group(1) if generic_match else ""


def _test_single_cfmail_account(
    account: CfmailAccount, proxy: Optional[str] = None
) -> bool:
    logger.info(f"\n[cfmail测试] 开始测试配置: {account.name}")
    logger.info(f"[cfmail测试] temp-mail base={TEMPMAIL_BASE_URL}")

    try:
        create_resp = _request_tempmail("POST", "/mailbox", proxies=proxy, timeout=20)
        if create_resp.status_code != 200:
            logger.info(
                f"[cfmail测试] 失败：创建邮箱返回 {create_resp.status_code}，响应={create_resp.text[:300]}"
            )
            return False

        data = create_resp.json() if create_resp.content else {}
        address = str(data.get("mailbox") or data.get("address") or data.get("email") or "").strip()
        jwt = str(data.get("token") or "").strip()
        if not address or not jwt:
            logger.info("[cfmail测试] 失败：创建邮箱成功但返回 mailbox/token 不完整")
            return False

        logger.info(f"[cfmail测试] 创建成功: {address}")

        poll_resp = _request_tempmail(
            "GET",
            "/messages",
            jwt=jwt,
            proxies=proxy,
            timeout=20,
        )
        if poll_resp.status_code != 200:
            logger.info(
                f"[cfmail测试] 失败：轮询接口返回 {poll_resp.status_code}，响应={poll_resp.text[:300]}"
            )
            return False

        poll_data = poll_resp.json() if poll_resp.content else {}
        messages = _extract_message_list(poll_data)
        logger.info(f"[cfmail测试] 轮询成功: count={len(messages)}")
        return True
    except Exception as e:
        logger.info(f"[cfmail测试] 失败：{account.name} 测试异常: {e}")
        return False


def run_cfmail_self_test(
    accounts: List[CfmailAccount],
    *,
    proxy: Optional[str] = None,
    profile_name: str = "auto",
) -> bool:
    if not accounts:
        accounts = [_default_cfmail_account()]

    selected_accounts = accounts
    selected_name = str(profile_name or "auto").strip()
    if selected_name and selected_name.lower() != "auto":
        selected_accounts = [
            account
            for account in accounts
            if account.name.lower() == selected_name.lower()
        ]
        if not selected_accounts:
            logger.info(
                f"[cfmail测试] 未找到指定配置: {selected_name}；当前可用配置: {cfmail_account_names(accounts)}"
            )
            return False

    logger.info(
        f"[cfmail测试] 共需测试 {len(selected_accounts)} 个配置: {cfmail_account_names(selected_accounts)}"
    )

    passed = sum(1 for account in selected_accounts if _test_single_cfmail_account(account, proxy))
    logger.info(
        f"\n[cfmail测试] 测试完成：成功 {passed} / {len(selected_accounts)}，失败 {len(selected_accounts) - passed}"
    )
    return passed == len(selected_accounts)


def create_cfmail_mailbox(
    proxies: Any = None, thread_id: int = 0
) -> Optional[TempMailbox]:
    reload_cfmail_accounts_if_needed()
    selected_account = select_cfmail_account(CFMAIL_PROFILE_MODE)
    if not selected_account:
        logger.error(
            f"[线程 {thread_id}] [错误] cfmail 兼容邮箱配置不可用；当前可用配置: {cfmail_account_names()}"
        )
        return None

    try:
        resp = _request_tempmail("POST", "/mailbox", proxies=proxies, timeout=15)
        if resp.status_code != 200:
            logger.warning(
                f"[线程 {thread_id}] [警告] temp-mail 邮箱创建失败，状态码: {resp.status_code}，响应: {resp.text[:300]}"
            )
            record_cfmail_failure(selected_account.name, f"mailbox status={resp.status_code}")
            return None

        data = resp.json() if resp.content else {}
        email = str(data.get("mailbox") or data.get("address") or data.get("email") or "").strip()
        token = str(data.get("token") or "").strip()
        if not email or not token:
            logger.warning(f"[线程 {thread_id}] [警告] temp-mail 返回数据不完整")
            record_cfmail_failure(selected_account.name, "mailbox incomplete data")
            return None

        logger.info(
            f"[线程 {thread_id}] [信息] cfmail 已禁用，当前改用 temp-mail.org: {email}"
        )
        return TempMailbox(
            email=email,
            provider="cfmail",
            token=token,
            api_base=TEMPMAIL_BASE_URL,
            domain=email.split("@", 1)[-1] if "@" in email else DEFAULT_CFMAIL_EMAIL_DOMAIN,
            config_name=selected_account.name,
        )
    except Exception as e:
        logger.warning(f"[线程 {thread_id}] [警告] 请求 temp-mail API 出错: {e}")
        record_cfmail_failure(selected_account.name, f"mailbox exception: {e}")
        return None


def list_cfmail_message_ids(
    *, api_base: str, token: str, email: str, proxies: Any = None
) -> Set[str]:
    _ = api_base, email
    if not token:
        return set()

    try:
        resp = _request_tempmail(
            "GET",
            "/messages",
            jwt=token,
            proxies=proxies,
            timeout=15,
        )
        if resp.status_code != 200:
            return set()
        data = resp.json() if resp.content else {}
        messages = _extract_message_list(data)
        return {_message_uid(msg) for msg in messages}
    except Exception:
        return set()


def poll_cfmail_oai_code(
    *,
    api_base: str,
    token: str,
    email: str,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    _ = api_base
    if not token:
        logger.error(f"[线程 {thread_id}] [错误] temp-mail token 为空，无法轮询邮件")
        return ""

    seen_ids: Set[str] = set(str(x).strip() for x in (skip_message_ids or set()) if str(x).strip())
    ignored_codes: Set[str] = set(str(x).strip() for x in (skip_codes or set()) if str(x).strip())

    _log_waiting_code_start(thread_id, email)
    reset_mailbox_wait_diagnostics("cfmail", email)

    poll_interval_seconds = TEMPMAIL_POLL_MIN_INTERVAL_SECONDS
    max_polls = max(1, int(TEMPMAIL_MAX_WAIT_SECONDS // max(1.0, poll_interval_seconds)))

    for _ in range(max_polls):
        increment_mailbox_wait_poll("cfmail", email)
        try:
            resp = _request_tempmail(
                "GET",
                "/messages",
                jwt=token,
                proxies=proxies,
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(poll_interval_seconds)
                continue

            data = resp.json() if resp.content else {}
            messages = _extract_message_list(data)
            note_mailbox_messages_scanned("cfmail", email, len(messages))

            for msg in messages:
                msg_id = _message_uid(msg)
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                subject, decoded_content = _extract_cfmail_subject_and_content(msg)
                lowered_subject = subject.lower()
                lowered_content = decoded_content.lower()
                if any(
                    marker in lowered_subject or marker in lowered_content
                    for marker in CFMAIL_REMINDER_MARKERS
                ):
                    continue

                code = _extract_cfmail_oai_code(subject, decoded_content)
                if not code:
                    if not _contains_cfmail_keyword(subject, decoded_content):
                        continue
                    code = _extract_cfmail_oai_code(subject, decoded_content)

                if code:
                    if code in ignored_codes:
                        continue
                    mark_mailbox_wait_matched("cfmail", email, code=code)
                    _log_waiting_code_success(thread_id, code)
                    return code
        except Exception:
            pass

        time.sleep(poll_interval_seconds)

    mark_mailbox_wait_timeout(
        "cfmail",
        email,
        reason="mailbox_timeout_no_message" if not seen_ids else "mailbox_timeout_no_match",
    )
    _log_waiting_code_timeout(thread_id)
    return ""


configure_cfmail_runtime(
    accounts=build_cfmail_accounts(
        load_cfmail_accounts_from_file(CFMAIL_CONFIG_PATH, silent=True)
        or DEFAULT_CFMAIL_ACCOUNTS
    ),
    profile_mode="auto",
    config_path=CFMAIL_CONFIG_PATH,
    hot_reload_enabled=True,
    fail_threshold=CFMAIL_FAIL_THRESHOLD,
    cooldown_seconds=CFMAIL_COOLDOWN_SECONDS,
)
