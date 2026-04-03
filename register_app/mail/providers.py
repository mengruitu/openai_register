import json
import logging
import random
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from curl_cffi import requests
from .diagnostics import (
    increment_mailbox_wait_poll,
    mark_mailbox_wait_matched,
    mark_mailbox_wait_timeout,
    note_mailbox_messages_scanned,
    reset_mailbox_wait_diagnostics,
)

logger = logging.getLogger("openai_register")

MAILTM_BASE = "https://api.mail.tm"
TEMPMAILLOL_BASE = "https://api.tempmail.lol/v2"
TEMPMAILIO_API = "https://api.internal.temp-mail.io/api/v3/email"
DROPMAIL_API = "https://dropmail.me/api/graphql"
OTP_CODE_PATTERN = re.compile(r"(?<!\d)(\d{6})(?!\d)")


@dataclass(frozen=True)
class TempMailbox:
    email: str
    provider: str
    token: str = ""
    api_base: str = ""
    login: str = ""
    domain: str = ""
    sid_token: str = ""
    password: str = ""
    config_name: str = ""


def _contains_mail_keyword(*parts: Any) -> bool:
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        lowered = text.lower()
        if "openai" in lowered or "chatgpt" in lowered:
            return True
    return False


def _extract_otp_from_parts(*parts: Any) -> str:
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        match = OTP_CODE_PATTERN.search(text)
        if match:
            return match.group(1)
    return ""


def _log_waiting_code_start(thread_id: int, email: str) -> None:
    logger.info(f"[线程 {thread_id}] [信息] 正在等待邮箱 {email} 的验证码")


def _log_waiting_code_success(thread_id: int, code: str) -> None:
    logger.info(f"[线程 {thread_id}] [信息] 已收到验证码: {code}")


def _log_waiting_code_timeout(thread_id: int) -> None:
    logger.warning(f"[线程 {thread_id}] [警告] 等待超时，未收到验证码")


def _mailtm_headers(*, token: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _hydra_domains(api_base: str, proxies: Any = None) -> List[str]:
    resp = requests.get(
        f"{api_base}/domains",
        headers=_mailtm_headers(),
        proxies=proxies,
        impersonate="chrome",
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"获取域名失败，状态码: {resp.status_code}")

    data = resp.json()
    domains = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("hydra:member") or data.get("items") or []
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip()
        is_active = item.get("isActive", True)
        is_private = item.get("isPrivate", False)
        if domain and is_active and not is_private:
            domains.append(domain)

    return domains


def create_hydra_mailbox(
    *,
    api_base: str,
    provider_name: str,
    provider_key: str,
    proxies: Any = None,
    thread_id: int,
) -> Optional[TempMailbox]:
    try:
        domains = _hydra_domains(api_base, proxies)
        if not domains:
            logger.warning(f"[线程 {thread_id}] [警告] {provider_name} 没有可用域名")
            return None

        for _ in range(5):
            local = f"oc{secrets.token_hex(5)}"
            domain = random.choice(domains)
            email = f"{local}@{domain}"
            password = secrets.token_urlsafe(18)

            create_resp = requests.post(
                f"{api_base}/accounts",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )

            if create_resp.status_code not in (200, 201):
                continue

            token_resp = requests.post(
                f"{api_base}/token",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )

            if token_resp.status_code == 200:
                token = str(token_resp.json().get("token") or "").strip()
                if token:
                    return TempMailbox(
                        email=email,
                        provider=provider_key,
                        token=token,
                        api_base=api_base,
                        password=password,
                    )

        logger.warning(f"[线程 {thread_id}] [警告] {provider_name} 邮箱创建成功但获取 Token 失败")
        return None
    except Exception as e:
        logger.warning(f"[线程 {thread_id}] [警告] 请求 {provider_name} API 出错: {e}")
        return None


def create_tempmailio_mailbox(
    proxies: Any = None, thread_id: int = 0
) -> Optional[TempMailbox]:
    try:
        resp = requests.post(
            f"{TEMPMAILIO_API}/new",
            json={"min_name_length": 10, "max_name_length": 10},
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            email = data.get("email")
            token = data.get("token")
            if email:
                return TempMailbox(
                    email=email,
                    provider="tempmailio",
                    token=token,
                )
        logger.warning(f"[线程 {thread_id}] [警告] temp-mail.io 邮箱初始化失败")
        return None
    except Exception as e:
        logger.warning(f"[线程 {thread_id}] [警告] 请求 temp-mail.io API 出错: {e}")
        return None


def create_tempmaillol_mailbox(
    proxies: Any = None, thread_id: int = 0
) -> Optional[TempMailbox]:
    try:
        resp = requests.post(
            f"{TEMPMAILLOL_BASE}/inbox/create",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={},
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            logger.warning(
                f"[线程 {thread_id}] [警告] Tempmail.lol 邮箱初始化失败，状态码: {resp.status_code}"
            )
            return None

        data = resp.json()
        email = str(data.get("address") or "").strip()
        token = str(data.get("token") or "").strip()
        if not email or not token:
            logger.warning(f"[线程 {thread_id}] [警告] Tempmail.lol 返回数据不完整")
            return None

        return TempMailbox(
            email=email,
            provider="tempmaillol",
            token=token,
        )
    except Exception as e:
        logger.warning(f"[线程 {thread_id}] [警告] 请求 Tempmail.lol API 出错: {e}")
        return None


def create_dropmail_mailbox(
    proxies: Any = None, thread_id: int = 0
) -> Optional[TempMailbox]:
    try:
        query = """
        mutation {
            introduceSession {
                id, addresses { address }
            }
        }
        """
        resp = requests.post(
            DROPMAIL_API,
            json={"query": query},
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("introduceSession", {})
            session_id = data.get("id")
            addrs = data.get("addresses", [])
            if session_id and addrs:
                email = addrs[0].get("address")
                return TempMailbox(
                    email=email,
                    provider="dropmail",
                    sid_token=session_id,
                )
        logger.warning(f"[线程 {thread_id}] [警告] Dropmail 邮箱初始化失败")
        return None
    except Exception as e:
        logger.warning(f"[线程 {thread_id}] [警告] 请求 Dropmail API 出错: {e}")
        return None


def _normalize_message_ids(message_ids: Optional[Set[str]] = None) -> Set[str]:
    if not message_ids:
        return set()
    normalized: Set[str] = set()
    for item in message_ids:
        value = str(item or "").strip()
        if value:
            normalized.add(value)
    return normalized


def _normalize_code_values(code_values: Optional[Set[str]] = None) -> Set[str]:
    if not code_values:
        return set()
    normalized: Set[str] = set()
    for item in code_values:
        value = str(item or "").strip()
        if value:
            normalized.add(value)
    return normalized


def list_hydra_message_ids(
    *, api_base: str, token: str, proxies: Any = None
) -> Set[str]:
    try:
        resp = requests.get(
            f"{api_base}/messages",
            headers=_mailtm_headers(token=token),
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code != 200:
            return set()
        data = resp.json()
        if isinstance(data, list):
            messages = data
        elif isinstance(data, dict):
            messages = data.get("hydra:member") or data.get("messages") or []
        else:
            messages = []
        return _normalize_message_ids(
            {
                str((msg or {}).get("id") or "").strip()
                for msg in messages
                if isinstance(msg, dict)
            }
        )
    except Exception:
        return set()


def list_tempmailio_message_ids(*, email: str, proxies: Any = None) -> Set[str]:
    try:
        resp = requests.get(
            f"{TEMPMAILIO_API}/{email}/messages",
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code != 200:
            return set()
        messages = resp.json()
        if not isinstance(messages, list):
            return set()
        return _normalize_message_ids(
            {
                str((msg or {}).get("id") or "").strip()
                for msg in messages
                if isinstance(msg, dict)
            }
        )
    except Exception:
        return set()


def list_tempmaillol_message_ids(*, token: str, proxies: Any = None) -> Set[str]:
    try:
        resp = requests.get(
            f"{TEMPMAILLOL_BASE}/inbox",
            params={"token": token},
            headers={"Accept": "application/json"},
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code != 200:
            return set()
        data = resp.json()
        email_list = data.get("emails", []) if isinstance(data, dict) else []
        if not isinstance(email_list, list):
            return set()
        return _normalize_message_ids(
            {
                str((msg or {}).get("id") or (msg or {}).get("date") or "").strip()
                for msg in email_list
                if isinstance(msg, dict)
            }
        )
    except Exception:
        return set()


def list_dropmail_message_ids(*, sid_token: str, proxies: Any = None) -> Set[str]:
    try:
        query = """
        query ($id: ID!) {
            session(id: $id) {
                mails { id }
            }
        }
        """
        resp = requests.post(
            DROPMAIL_API,
            json={"query": query, "variables": {"id": sid_token}},
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code != 200:
            return set()
        data = resp.json().get("data", {}).get("session", {}) or {}
        messages = data.get("mails", [])
        if not isinstance(messages, list):
            return set()
        return _normalize_message_ids(
            {
                str((msg or {}).get("id") or "").strip()
                for msg in messages
                if isinstance(msg, dict)
            }
        )
    except Exception:
        return set()


def poll_hydra_oai_code(
    *,
    api_base: str,
    token: str,
    email: str,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    url_list = f"{api_base}/messages"
    seen_ids: Set[str] = _normalize_message_ids(skip_message_ids)
    ignored_codes = _normalize_code_values(skip_codes)

    _log_waiting_code_start(thread_id, email)
    reset_mailbox_wait_diagnostics("mailtm", email)

    for _ in range(40):
        increment_mailbox_wait_poll("mailtm", email)
        try:
            resp = requests.get(
                url_list,
                headers=_mailtm_headers(token=token),
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue

            data = resp.json()
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                messages = data.get("hydra:member") or data.get("messages") or []
            else:
                messages = []
            note_mailbox_messages_scanned("mailtm", email, len(messages))

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                read_resp = requests.get(
                    f"{api_base}/messages/{msg_id}",
                    headers=_mailtm_headers(token=token),
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
                if read_resp.status_code != 200:
                    continue

                mail_data = read_resp.json()
                sender = str(((mail_data.get("from") or {}).get("address") or "")).lower()
                subject = str(mail_data.get("subject") or "")
                intro = str(mail_data.get("intro") or "")
                text = str(mail_data.get("text") or "")
                html = mail_data.get("html") or ""
                if isinstance(html, list):
                    html = "\n".join(str(x) for x in html)

                if not _contains_mail_keyword(sender, subject, intro, text, html):
                    continue

                code = _extract_otp_from_parts(subject, intro, text, html)
                if code:
                    if code in ignored_codes:
                        continue
                    mark_mailbox_wait_matched("mailtm", email, code=code)
                    _log_waiting_code_success(thread_id, code)
                    return code
        except Exception:
            pass

        time.sleep(3)

    mark_mailbox_wait_timeout(
        "mailtm",
        email,
        reason="mailbox_timeout_no_message" if not seen_ids else "mailbox_timeout_no_match",
    )
    _log_waiting_code_timeout(thread_id)
    return ""


def poll_tempmailio_oai_code(
    *,
    email: str,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    seen_ids: Set[str] = _normalize_message_ids(skip_message_ids)
    ignored_codes = _normalize_code_values(skip_codes)

    _log_waiting_code_start(thread_id, email)
    reset_mailbox_wait_diagnostics("tempmailio", email)

    for _ in range(40):
        increment_mailbox_wait_poll("tempmailio", email)
        try:
            resp = requests.get(
                f"{TEMPMAILIO_API}/{email}/messages",
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code == 200:
                messages = resp.json()
                note_mailbox_messages_scanned("tempmailio", email, len(messages or []))
                for msg in messages:
                    msg_id = msg.get("id")
                    if not msg_id or msg_id in seen_ids:
                        continue
                    seen_ids.add(msg_id)

                    sender = str(msg.get("from") or "").lower()
                    subject = str(msg.get("subject") or "")
                    body = str(msg.get("body_text") or "")

                    if not _contains_mail_keyword(sender, subject, body):
                        continue

                    code = _extract_otp_from_parts(subject, body)
                    if code:
                        if code in ignored_codes:
                            continue
                        mark_mailbox_wait_matched("tempmailio", email, code=code)
                        _log_waiting_code_success(thread_id, code)
                        return code
        except Exception:
            pass
        time.sleep(3)

    mark_mailbox_wait_timeout(
        "tempmailio",
        email,
        reason="mailbox_timeout_no_message" if not seen_ids else "mailbox_timeout_no_match",
    )
    _log_waiting_code_timeout(thread_id)
    return ""


def poll_tempmaillol_oai_code(
    *,
    token: str,
    email: str,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    seen_ids: Set[str] = _normalize_message_ids(skip_message_ids)
    ignored_codes = _normalize_code_values(skip_codes)

    _log_waiting_code_start(thread_id, email)
    reset_mailbox_wait_diagnostics("tempmaillol", email)

    for _ in range(40):
        increment_mailbox_wait_poll("tempmaillol", email)
        try:
            resp = requests.get(
                f"{TEMPMAILLOL_BASE}/inbox",
                params={"token": token},
                headers={"Accept": "application/json"},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue

            data = resp.json()
            if data is None or (isinstance(data, dict) and not data):
                logger.warning(f"[线程 {thread_id}] [警告] 邮箱已过期")
                mark_mailbox_wait_timeout("tempmaillol", email, reason="mailbox_expired")
                return ""

            email_list = data.get("emails", []) if isinstance(data, dict) else []
            if not isinstance(email_list, list):
                time.sleep(3)
                continue
            note_mailbox_messages_scanned("tempmaillol", email, len(email_list))

            for msg in email_list:
                if not isinstance(msg, dict):
                    continue

                msg_id = str(msg.get("id") or msg.get("date") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                sender = str(msg.get("from") or "").lower()
                subject = str(msg.get("subject") or "")
                body = str(msg.get("body") or "")
                html = str(msg.get("html") or "")

                if not _contains_mail_keyword(sender, subject, body, html):
                    continue

                code = _extract_otp_from_parts(subject, body, html)
                if code:
                    if code in ignored_codes:
                        continue
                    mark_mailbox_wait_matched("tempmaillol", email, code=code)
                    _log_waiting_code_success(thread_id, code)
                    return code
        except Exception:
            pass

        time.sleep(3)

    mark_mailbox_wait_timeout(
        "tempmaillol",
        email,
        reason="mailbox_timeout_no_message" if not seen_ids else "mailbox_timeout_no_match",
    )
    _log_waiting_code_timeout(thread_id)
    return ""


def poll_dropmail_oai_code(
    *,
    sid_token: str,
    email: str,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    seen_ids: Set[str] = _normalize_message_ids(skip_message_ids)
    ignored_codes = _normalize_code_values(skip_codes)
    query = """
    query ($id: ID!) {
        session(id: $id) {
            mails { id, rawSize, text }
        }
    }
    """

    _log_waiting_code_start(thread_id, email)
    reset_mailbox_wait_diagnostics("dropmail", email)

    for _ in range(40):
        increment_mailbox_wait_poll("dropmail", email)
        try:
            resp = requests.post(
                DROPMAIL_API,
                json={"query": query, "variables": {"id": sid_token}},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("session", {}) or {}
                messages = data.get("mails", [])
                note_mailbox_messages_scanned("dropmail", email, len(messages or []))
                for msg in messages:
                    msg_id = msg.get("id")
                    if not msg_id or msg_id in seen_ids:
                        continue
                    seen_ids.add(msg_id)

                    text = str(msg.get("text") or "")

                    if not _contains_mail_keyword(text):
                        continue

                    code = _extract_otp_from_parts(text)
                    if code:
                        if code in ignored_codes:
                            continue
                        mark_mailbox_wait_matched("dropmail", email, code=code)
                        _log_waiting_code_success(thread_id, code)
                        return code
        except Exception:
            pass
        time.sleep(3)

    mark_mailbox_wait_timeout(
        "dropmail",
        email,
        reason="mailbox_timeout_no_message" if not seen_ids else "mailbox_timeout_no_match",
    )
    _log_waiting_code_timeout(thread_id)
    return ""
