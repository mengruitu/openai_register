import concurrent.futures
import email
import json
import logging
import math
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

from .providers import TempMailbox
from .diagnostics import (
    increment_mailbox_wait_poll,
    mark_mailbox_wait_matched,
    mark_mailbox_wait_timeout,
    note_mailbox_messages_scanned,
    reset_mailbox_wait_diagnostics,
)

logger = logging.getLogger("openai_register")

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEFAULT_CFMAIL_CONFIG_PATH = os.path.join(_SCRIPT_DIR, "cfmail_accounts.json")
DEFAULT_CFMAIL_ACCOUNTS: List[Dict[str, Any]] = []
DEFAULT_CFMAIL_PROFILE_NAME = (
    str(DEFAULT_CFMAIL_ACCOUNTS[0].get("name") or "").strip()
    if DEFAULT_CFMAIL_ACCOUNTS
    else "default"
)
DEFAULT_CFMAIL_WORKER_DOMAIN = (
    str(DEFAULT_CFMAIL_ACCOUNTS[0].get("worker_domain") or "").strip()
    if DEFAULT_CFMAIL_ACCOUNTS
    else ""
)
DEFAULT_CFMAIL_EMAIL_DOMAIN = (
    str(DEFAULT_CFMAIL_ACCOUNTS[0].get("email_domain") or "").strip()
    if DEFAULT_CFMAIL_ACCOUNTS
    else ""
)
DEFAULT_CFMAIL_ADMIN_PASSWORD = (
    str(DEFAULT_CFMAIL_ACCOUNTS[0].get("admin_password") or "").strip()
    if DEFAULT_CFMAIL_ACCOUNTS
    else ""
)
DEFAULT_CFMAIL_FAIL_THRESHOLD = 3
DEFAULT_CFMAIL_COOLDOWN_SECONDS = 300


@dataclass(frozen=True)
class CfmailAccount:
    name: str
    worker_domain: str
    email_domain: str
    admin_password: str


_cfmail_account_lock = threading.Lock()
_cfmail_reload_lock = threading.Lock()
_cfmail_failure_lock = threading.Lock()
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
CFMAIL_WORKER_DOMAIN = ""
CFMAIL_EMAIL_DOMAIN = ""
CFMAIL_ADMIN_PASSWORD = ""
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


def _normalize_cfmail_account(raw: Dict[str, Any]) -> Optional[CfmailAccount]:
    if not isinstance(raw, dict):
        return None

    if not raw.get("enabled", True):
        return None

    name = str(raw.get("name") or "").strip()
    worker_domain = normalize_host(
        raw.get("worker_domain") or raw.get("WORKER_DOMAIN") or ""
    )
    email_domain = normalize_host(
        raw.get("email_domain") or raw.get("EMAIL_DOMAIN") or ""
    )
    admin_password = str(
        raw.get("admin_password") or raw.get("ADMIN_PASSWORD") or ""
    ).strip()

    if not name or not worker_domain or not email_domain or not admin_password:
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
        accounts = [acc for acc in accounts if acc.name.lower() != env_key]
        accounts.insert(0, env_account)

    return accounts


def cfmail_account_names(accounts: Optional[List[CfmailAccount]] = None) -> str:
    items = accounts if accounts is not None else CFMAIL_ACCOUNTS
    return ", ".join(account.name for account in items) if items else "无"


def _refresh_cfmail_globals() -> None:
    global CFMAIL_WORKER_DOMAIN, CFMAIL_EMAIL_DOMAIN, CFMAIL_ADMIN_PASSWORD
    CFMAIL_WORKER_DOMAIN = CFMAIL_ACCOUNTS[0].worker_domain if CFMAIL_ACCOUNTS else ""
    CFMAIL_EMAIL_DOMAIN = CFMAIL_ACCOUNTS[0].email_domain if CFMAIL_ACCOUNTS else ""
    CFMAIL_ADMIN_PASSWORD = CFMAIL_ACCOUNTS[0].admin_password if CFMAIL_ACCOUNTS else ""


def prune_cfmail_failure_state(accounts: Optional[List[CfmailAccount]] = None) -> None:
    items = accounts if accounts is not None else CFMAIL_ACCOUNTS
    valid_keys = {account.name.lower() for account in items}
    with _cfmail_failure_lock:
        for key in list(CFMAIL_FAILURE_STATE.keys()):
            if key not in valid_keys:
                CFMAIL_FAILURE_STATE.pop(key, None)


def _cfmail_skip_remaining_seconds(account_name: str) -> int:
    key = str(account_name or "").strip().lower()
    if not key:
        return 0

    with _cfmail_failure_lock:
        state = CFMAIL_FAILURE_STATE.get(key) or {}
        cooldown_until = float(state.get("cooldown_until") or 0)

    remaining = int(math.ceil(cooldown_until - time.time()))
    return max(0, remaining)


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

    now = time.time()
    cooldown_seconds = max(0, int(CFMAIL_COOLDOWN_SECONDS))
    fail_threshold = max(1, int(CFMAIL_FAIL_THRESHOLD))

    with _cfmail_failure_lock:
        state = CFMAIL_FAILURE_STATE.setdefault(key, {"name": account_name})
        state["name"] = account_name
        state["consecutive_failures"] = int(state.get("consecutive_failures") or 0) + 1
        state["last_error"] = str(reason or "").strip()[:300]
        state["last_failed_at"] = now

        if state["consecutive_failures"] >= fail_threshold:
            state["cooldown_until"] = max(
                float(state.get("cooldown_until") or 0),
                now + cooldown_seconds,
            )
            state["consecutive_failures"] = 0
            cooldown_until = state["cooldown_until"]
        else:
            cooldown_until = float(state.get("cooldown_until") or 0)

    if cooldown_until > now:
        remaining = int(math.ceil(cooldown_until - now))
        logger.warning(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] cfmail 配置 {account_name} 连续失败达到阈值，已自动跳过 {remaining} 秒"
        )


def set_cfmail_accounts(accounts: List[CfmailAccount]) -> None:
    global CFMAIL_ACCOUNTS, _cfmail_account_index
    CFMAIL_ACCOUNTS = accounts
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

    set_cfmail_accounts(accounts)
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
        return None

    selected_name = str(profile_name or "auto").strip()
    if selected_name and selected_name.lower() != "auto":
        selected_key = selected_name.lower()
        for account in accounts:
            if account.name.lower() == selected_key:
                remaining = _cfmail_skip_remaining_seconds(account.name)
                if remaining > 0:
                    logger.warning(
                        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] cfmail 配置 {account.name} 当前仍在冷却中，剩余 {remaining} 秒；因你已手动指定，仍继续尝试"
                    )
                return account
        return None

    with _cfmail_account_lock:
        start_index = _cfmail_account_index % len(accounts)
        skipped_accounts = []

        for offset in range(len(accounts)):
            index = (start_index + offset) % len(accounts)
            account = accounts[index]
            remaining = _cfmail_skip_remaining_seconds(account.name)
            if remaining > 0:
                skipped_accounts.append((account.name, remaining))
                continue

            _cfmail_account_index = (index + 1) % len(accounts)
            return account

    if skipped_accounts:
        skip_desc = ", ".join(f"{name}({remaining}s)" for name, remaining in skipped_accounts)
        logger.warning(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] 所有 cfmail 配置当前都在冷却中，暂不分配邮箱：{skip_desc}"
        )
    return None


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
        return False

    with _cfmail_reload_lock:
        if not force and CFMAIL_CONFIG_MTIME == mtime:
            return False

        raw_accounts = load_cfmail_accounts_from_file(config_path)
        new_accounts = build_cfmail_accounts(raw_accounts)
        if not new_accounts:
            logger.warning(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] cfmail 配置文件热加载失败：{config_path} 中没有可用配置，保留当前配置"
            )
            CFMAIL_CONFIG_MTIME = mtime
            return False

        old_names = cfmail_account_names()
        set_cfmail_accounts(new_accounts)
        prune_cfmail_failure_state(new_accounts)
        CFMAIL_CONFIG_MTIME = mtime
        new_names = cfmail_account_names()
        if force or old_names != new_names:
            logger.info(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [信息] cfmail 配置已热加载：{new_names}"
            )
        return True


def cfmail_headers(*, jwt: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    return headers


def _build_request_proxies(proxy: Optional[str]) -> Any:
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def _test_single_cfmail_account(
    account: CfmailAccount, proxy: Optional[str] = None
) -> bool:
    proxies = _build_request_proxies(proxy)
    logger.info(f"\n[cfmail测试] 开始测试配置: {account.name}")
    logger.info(f"[cfmail测试] worker_domain={account.worker_domain} email_domain={account.email_domain}")

    try:
        local = f"codextest{secrets.token_hex(4)}"
        create_resp = requests.post(
            f"https://{account.worker_domain}/admin/new_address",
            headers={
                "x-admin-auth": account.admin_password,
                **cfmail_headers(use_json=True),
            },
            json={
                "enablePrefix": True,
                "name": local,
                "domain": account.email_domain,
            },
            proxies=proxies,
            impersonate="chrome",
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

        poll_resp = requests.get(
            f"https://{account.worker_domain}/api/mails",
            params={"limit": 5, "offset": 0},
            headers=cfmail_headers(jwt=jwt, use_json=True),
            proxies=proxies,
            impersonate="chrome",
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
        logger.info("[cfmail测试] 未找到可用的 cfmail 配置")
        return False

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

    # P4 优化：各配置之间互不依赖，使用线程并发测试以缩短总耗时
    if len(selected_accounts) == 1:
        passed = 1 if _test_single_cfmail_account(selected_accounts[0], proxy) else 0
    else:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(selected_accounts), 4),
        ) as executor:
            futures = {
                executor.submit(_test_single_cfmail_account, account, proxy): account
                for account in selected_accounts
            }
            passed = sum(
                1
                for future in concurrent.futures.as_completed(futures)
                if future.result()
            )

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
            f"[线程 {thread_id}] [错误] 自建邮箱配置不可用，请检查 {CFMAIL_CONFIG_PATH} 或 --cfmail-profile 参数；当前可用配置: {cfmail_account_names()}"
        )
        return None

    try:
        local = f"oc{secrets.token_hex(5)}"
        worker_domain = selected_account.worker_domain
        resp = requests.post(
            f"https://{worker_domain}/admin/new_address",
            headers={
                "x-admin-auth": selected_account.admin_password,
                **cfmail_headers(use_json=True),
            },
            json={
                "enablePrefix": True,
                "name": local,
                "domain": selected_account.email_domain,
            },
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code != 200:
            logger.warning(
                f"[线程 {thread_id}] [警告] 自建邮箱[{selected_account.name}]创建失败，状态码: {resp.status_code}，响应: {resp.text[:300]}"
            )
            record_cfmail_failure(selected_account.name, f"new_address status={resp.status_code}")
            return None

        data = resp.json()
        email = str(data.get("address") or "").strip()
        jwt = str(data.get("jwt") or "").strip()
        if not email or not jwt:
            logger.warning(f"[线程 {thread_id}] [警告] 自建邮箱[{selected_account.name}]返回数据不完整")
            record_cfmail_failure(selected_account.name, "new_address incomplete data")
            return None

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
    api_base = str(api_base or "").strip()
    if not api_base:
        worker_domain = normalize_host(CFMAIL_WORKER_DOMAIN)
        api_base = f"https://{worker_domain}" if worker_domain else ""
    if not api_base:
        return set()

    try:
        resp = requests.get(
            f"{api_base}/api/mails",
            params={"limit": 20, "offset": 0},
            headers=cfmail_headers(jwt=token, use_json=True),
            proxies=proxies,
            impersonate="chrome",
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
        message = email.message_from_string(str(raw or ""))
    except Exception:
        return str(raw or "")

    parts: List[str] = []
    subject = _decode_mime_header_value(message.get("Subject", ""))
    if subject:
        parts.append(subject)

    if message.is_multipart():
        iter_parts = message.walk()
    else:
        iter_parts = [message]

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


def _extract_cfmail_subject_and_content(raw: str) -> tuple[str, str]:
    try:
        message = email.message_from_string(str(raw or ""))
    except Exception:
        return "", str(raw or "")

    subject = _decode_mime_header_value(message.get("Subject", "")).strip()
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
        m = re.search(pattern, text, re.I | re.S)
        if m:
            return m.group(1)
    return ""


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
    api_base = str(api_base or "").strip()
    if not api_base:
        worker_domain = normalize_host(CFMAIL_WORKER_DOMAIN)
        api_base = f"https://{worker_domain}" if worker_domain else ""
    if not api_base:
        logger.error(f"[线程 {thread_id}] [错误] 自建邮箱 api_base 为空，无法轮询邮件")
        return ""

    seen_ids: Set[str] = set(str(x).strip() for x in (skip_message_ids or set()) if str(x).strip())
    ignored_codes: Set[str] = set(str(x).strip() for x in (skip_codes or set()) if str(x).strip())

    _log_waiting_code_start(thread_id, email)
    reset_mailbox_wait_diagnostics("cfmail", email)

    for _ in range(40):
        increment_mailbox_wait_poll("cfmail", email)
        try:
            resp = requests.get(
                f"{api_base}/api/mails",
                params={"limit": 10, "offset": 0},
                headers=cfmail_headers(jwt=token, use_json=True),
                proxies=proxies,
                impersonate="chrome",
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
                subject, decoded_content = _extract_cfmail_subject_and_content(raw)

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
