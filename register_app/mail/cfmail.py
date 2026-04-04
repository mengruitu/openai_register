import concurrent.futures
import email
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from email.header import decode_header
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

    worker_domain_raw = raw.get("worker_domain") or raw.get("WORKER_DOMAIN")
    email_domain_raw = raw.get("email_domain") or raw.get("EMAIL_DOMAIN")
    admin_password_raw = raw.get("admin_password") or raw.get("ADMIN_PASSWORD")

    if (
        worker_domain_raw is None
        and email_domain_raw is None
        and admin_password_raw is None
    ):
        worker_domain = DEFAULT_CFMAIL_WORKER_DOMAIN
        email_domain = DEFAULT_CFMAIL_EMAIL_DOMAIN
        admin_password = DEFAULT_CFMAIL_ADMIN_PASSWORD
    else:
        worker_domain = normalize_host(worker_domain_raw or "")
        email_domain = normalize_host(email_domain_raw or "")
        admin_password = str(admin_password_raw or "").strip()
        if not worker_domain or not email_domain or not admin_password:
            return None

    return CfmailAccount(
        name=name,
        worker_domain=worker_domain,
        email_domain=email_domain,
        admin_password=admin_password,
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

    env_worker_domain = normalize_host(os.getenv("CFMAIL_WORKER_DOMAIN", ""))
    env_email_domain = normalize_host(os.getenv("CFMAIL_EMAIL_DOMAIN", ""))
    env_admin_password = str(os.getenv("CFMAIL_ADMIN_PASSWORD", "")).strip()
    env_profile_name = (
        str(os.getenv("CFMAIL_PROFILE_NAME", DEFAULT_CFMAIL_PROFILE_NAME)).strip()
        or DEFAULT_CFMAIL_PROFILE_NAME
    )
    if env_worker_domain and env_email_domain and env_admin_password:
        env_account = CfmailAccount(
            name=env_profile_name,
            worker_domain=env_worker_domain,
            email_domain=env_email_domain,
            admin_password=env_admin_password,
        )
        env_key = env_account.name.lower()
        accounts = [account for account in accounts if account.name.lower() != env_key]
        accounts.insert(0, env_account)

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
        account
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
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [信息] cfmail 配置已生效：{new_names}"
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


def _normalize_api_base(api_base: str) -> str:
    value = str(api_base or "").strip().rstrip("/")
    if not value:
        return ""
    if value.startswith(("https://", "http://")):
        return value
    return f"https://{normalize_host(value)}"


def _is_tempmail_account(account: Optional[CfmailAccount]) -> bool:
    if not account:
        return True
    return (
        normalize_host(account.worker_domain) == normalize_host(DEFAULT_CFMAIL_WORKER_DOMAIN)
        and normalize_host(account.email_domain) == normalize_host(DEFAULT_CFMAIL_EMAIL_DOMAIN)
        and str(account.admin_password or "").strip() == DEFAULT_CFMAIL_ADMIN_PASSWORD
    )


def _is_tempmail_api_base(api_base: str) -> bool:
    normalized = _normalize_api_base(api_base)
    if not normalized:
        return normalize_host(CFMAIL_WORKER_DOMAIN) == normalize_host(DEFAULT_CFMAIL_WORKER_DOMAIN)
    return normalize_host(normalized) == normalize_host(TEMPMAIL_BASE_URL)


def _request_cfmail_api(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    proxies: Any = None,
    timeout: int = 15,
) -> Any:
    resolved_proxies = _build_request_proxies(proxies)
    last_error: Optional[Exception] = None

    for candidate_proxies in ([resolved_proxies, None] if resolved_proxies else [None]):
        try:
            return requests.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                proxies=candidate_proxies,
                impersonate="chrome",
                timeout=timeout,
            )
        except Exception as exc:
            last_error = exc
            if candidate_proxies is None:
                break
            logger.warning(f"[cfmail] 代理请求失败，尝试直连回退: {exc}")

    if last_error:
        raise last_error
    raise RuntimeError(f"请求 cfmail 失败: {url}")


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


def _decode_mime_header_value(value: str) -> str:
    parts = []
    for chunk, charset in decode_header(str(value or "")):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(str(chunk))
    return "".join(parts)


def _decode_cfmail_message_content(raw: str) -> str:
    try:
        message_obj = email.message_from_string(str(raw or ""))
    except Exception:
        return str(raw or "")

    parts: List[str] = []
    subject = _decode_mime_header_value(message_obj.get("Subject", ""))
    if subject:
        parts.append(subject)

    iter_parts = message_obj.walk() if message_obj.is_multipart() else [message_obj]
    for part in iter_parts:
        if getattr(part, "is_multipart", lambda: False)():
            continue

        payload = part.get_payload(decode=True)
        if payload is None:
            payload = str(part.get_payload() or "").encode("utf-8", errors="ignore")

        charset = part.get_content_charset() or "utf-8"
        try:
            decoded = payload.decode(charset, errors="replace")
        except Exception:
            decoded = payload.decode("utf-8", errors="replace")

        if decoded:
            parts.append(decoded)

    content = "\n".join(part for part in parts if part)
    return content or str(raw or "")


def _extract_cfmail_raw_subject_and_content(raw: str) -> tuple[str, str]:
    try:
        message_obj = email.message_from_string(str(raw or ""))
    except Exception:
        return "", str(raw or "")

    subject = _decode_mime_header_value(message_obj.get("Subject", "")).strip()
    content = _decode_cfmail_message_content(raw)
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
    if _is_tempmail_account(account):
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

    logger.info(
        f"[cfmail测试] worker_domain={account.worker_domain} email_domain={account.email_domain}"
    )
    try:
        local = f"codextest{secrets.token_hex(4)}"
        create_resp = _request_cfmail_api(
            "POST",
            f"https://{account.worker_domain}/admin/new_address",
            headers={
                "x-admin-auth": account.admin_password,
                **cfmail_headers(use_json=True),
            },
            json_body={
                "enablePrefix": True,
                "name": local,
                "domain": account.email_domain,
            },
            proxies=proxy,
            timeout=20,
        )
        if create_resp.status_code != 200:
            logger.info(
                f"[cfmail测试] 失败：创建邮箱返回 {create_resp.status_code}，响应={create_resp.text[:300]}"
            )
            return False

        data = create_resp.json() if create_resp.content else {}
        address = str(data.get("address") or "").strip()
        jwt = str(data.get("jwt") or "").strip()
        if not address or not jwt:
            logger.info("[cfmail测试] 失败：创建邮箱成功但返回 address/jwt 不完整")
            return False

        logger.info(f"[cfmail测试] 创建成功: {address}")

        poll_resp = _request_cfmail_api(
            "GET",
            f"https://{account.worker_domain}/api/mails",
            params={"limit": 5, "offset": 0},
            headers=cfmail_headers(jwt=jwt, use_json=True),
            proxies=proxy,
            timeout=20,
        )
        if poll_resp.status_code != 200:
            logger.info(
                f"[cfmail测试] 失败：轮询接口返回 {poll_resp.status_code}，响应={poll_resp.text[:300]}"
            )
            return False

        poll_data = poll_resp.json() if poll_resp.content else {}
        count = poll_data.get("count", 0) if isinstance(poll_data, dict) else 0
        logger.info(f"[cfmail测试] 轮询成功: count={count}")
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
    if len(selected_accounts) == 1:
        passed = 1 if _test_single_cfmail_account(selected_accounts[0], proxy) else 0
    else:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(selected_accounts), 4),
        ) as executor:
            futures = [
                executor.submit(_test_single_cfmail_account, account, proxy)
                for account in selected_accounts
            ]
            passed = sum(1 for future in concurrent.futures.as_completed(futures) if future.result())
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

    if _is_tempmail_account(selected_account):
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
                f"[线程 {thread_id}] [信息] 使用 temp-mail.org 兼容配置[{selected_account.name}]: {email}"
            )
            record_cfmail_success(selected_account.name)
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

    try:
        local = f"oc{secrets.token_hex(5)}"
        resp = _request_cfmail_api(
            "POST",
            f"https://{selected_account.worker_domain}/admin/new_address",
            headers={
                "x-admin-auth": selected_account.admin_password,
                **cfmail_headers(use_json=True),
            },
            json_body={
                "enablePrefix": True,
                "name": local,
                "domain": selected_account.email_domain,
            },
            proxies=proxies,
            timeout=15,
        )
        if resp.status_code != 200:
            logger.warning(
                f"[线程 {thread_id}] [警告] 自建邮箱[{selected_account.name}]创建失败，状态码: {resp.status_code}，响应: {resp.text[:300]}"
            )
            record_cfmail_failure(selected_account.name, f"new_address status={resp.status_code}")
            return None

        data = resp.json() if resp.content else {}
        email = str(data.get("address") or "").strip()
        jwt = str(data.get("jwt") or "").strip()
        if not email or not jwt:
            logger.warning(f"[线程 {thread_id}] [警告] 自建邮箱[{selected_account.name}]返回数据不完整")
            record_cfmail_failure(selected_account.name, "new_address incomplete data")
            return None

        record_cfmail_success(selected_account.name)
        return TempMailbox(
            email=email,
            provider="cfmail",
            token=jwt,
            api_base=f"https://{selected_account.worker_domain}",
            domain=selected_account.email_domain,
            config_name=selected_account.name,
        )
    except Exception as e:
        logger.warning(f"[线程 {thread_id}] [警告] 请求自建邮箱[{selected_account.name}] API 出错: {e}")
        record_cfmail_failure(selected_account.name, f"new_address exception: {e}")
        return None


def list_cfmail_message_ids(
    *, api_base: str, token: str, email: str, proxies: Any = None
) -> Set[str]:
    resolved_api_base = _normalize_api_base(api_base)
    if not token:
        return set()

    if not resolved_api_base:
        worker_domain = normalize_host(CFMAIL_WORKER_DOMAIN)
        resolved_api_base = f"https://{worker_domain}" if worker_domain else ""
    if not resolved_api_base:
        return set()

    if _is_tempmail_api_base(resolved_api_base):
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

    try:
        resp = _request_cfmail_api(
            "GET",
            f"{resolved_api_base}/api/mails",
            params={"limit": 20, "offset": 0},
            headers=cfmail_headers(jwt=token, use_json=True),
            proxies=proxies,
            timeout=15,
        )
        if resp.status_code != 200:
            return set()
        data = resp.json() if resp.content else {}
        messages = data.get("results", []) if isinstance(data, dict) else []
        if not isinstance(messages, list):
            return set()
        return {
            str((msg.get("id") or msg.get("createdAt") or "")).strip()
            for msg in messages
            if isinstance(msg, dict)
            and (
                not str(msg.get("address") or "").strip()
                or str(msg.get("address") or "").strip().lower() == email.strip().lower()
            )
        }
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
    resolved_api_base = _normalize_api_base(api_base)
    if not token:
        logger.error(f"[线程 {thread_id}] [错误] temp-mail token 为空，无法轮询邮件")
        return ""

    if not resolved_api_base:
        worker_domain = normalize_host(CFMAIL_WORKER_DOMAIN)
        resolved_api_base = f"https://{worker_domain}" if worker_domain else ""
    if not resolved_api_base:
        logger.error(f"[线程 {thread_id}] [错误] cfmail api_base 为空，无法轮询邮件")
        return ""

    seen_ids: Set[str] = set(str(x).strip() for x in (skip_message_ids or set()) if str(x).strip())
    ignored_codes: Set[str] = set(str(x).strip() for x in (skip_codes or set()) if str(x).strip())

    _log_waiting_code_start(thread_id, email)
    reset_mailbox_wait_diagnostics("cfmail", email)

    if _is_tempmail_api_base(resolved_api_base):
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
    else:
        for _ in range(40):
            increment_mailbox_wait_poll("cfmail", email)
            try:
                resp = _request_cfmail_api(
                    "GET",
                    f"{resolved_api_base}/api/mails",
                    params={"limit": 10, "offset": 0},
                    headers=cfmail_headers(jwt=token, use_json=True),
                    proxies=proxies,
                    timeout=15,
                )
                if resp.status_code != 200:
                    time.sleep(3)
                    continue

                data = resp.json() if resp.content else {}
                messages = data.get("results", []) if isinstance(data, dict) else []
                if not isinstance(messages, list):
                    time.sleep(3)
                    continue
                note_mailbox_messages_scanned("cfmail", email, len(messages))

                for msg in messages:
                    if not isinstance(msg, dict):
                        continue

                    msg_id = str(msg.get("id") or msg.get("createdAt") or "").strip()
                    if not msg_id or msg_id in seen_ids:
                        continue
                    seen_ids.add(msg_id)

                    recipient = str(msg.get("address") or "").strip().lower()
                    raw = str(msg.get("raw") or "")
                    metadata = msg.get("metadata") or {}
                    subject, decoded_content = _extract_cfmail_raw_subject_and_content(raw)

                    if recipient and recipient != email.strip().lower():
                        continue
                    lowered_subject = subject.lower()
                    lowered_content = decoded_content.lower()
                    if any(
                        marker in lowered_subject or marker in lowered_content
                        for marker in CFMAIL_REMINDER_MARKERS
                    ):
                        continue

                    if not _contains_cfmail_keyword(recipient, subject, decoded_content):
                        metadata_text = json.dumps(metadata, ensure_ascii=False) if metadata else ""
                        if not _contains_cfmail_keyword(metadata_text):
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

            time.sleep(3)

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
