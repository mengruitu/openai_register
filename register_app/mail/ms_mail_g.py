# -*- coding: utf-8 -*-
"""Microsoft Graph 邮箱提供商。

使用与 `imap_ms` 相同的账号文件 `ms_emails.txt`：
    邮箱地址----密码----client_id----refresh_token

收信策略：
1. 使用 Microsoft Graph `.default` scope 刷新 access token
2. 优先读取 Inbox
3. 再读取 Junk Email
4. 从主题 / 发件人 / bodyPreview / body.content 中提取 OpenAI 验证码
"""
from __future__ import annotations

import builtins
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from curl_cffi import requests

from .diagnostics import (
    increment_mailbox_wait_poll,
    mark_mailbox_wait_matched,
    mark_mailbox_wait_timeout,
    note_mailbox_messages_scanned,
    reset_mailbox_wait_diagnostics,
)
from .imap_mail import MicrosoftImapAccount, take_imap_ms_account
from .providers import TempMailbox

logger = logging.getLogger("openai_register")

MICROSOFT_GRAPH_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MICROSOFT_GRAPH_SCOPE = "https://graph.microsoft.com/.default offline_access"
MICROSOFT_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_FOLDER_MAP = {
    "INBOX": "inbox",
    "JUNK": "junkemail",
}
OTP_CODE_PATTERN = re.compile(r"(?<!\d)(\d{6})(?!\d)")


def _runtime_stop_requested() -> bool:
    return bool(getattr(builtins, "openai_register_stop_requested", False))


def _contains_oai_keyword(*parts: Any) -> bool:
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


def _graph_headers(access_token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }


def _graph_has_mail_scope(scope: str) -> bool:
    lowered = str(scope or "").lower()
    return "mail.read" in lowered or "mail.readwrite" in lowered


def _graph_request_json(
    *,
    url: str,
    access_token: str,
    proxies: Any = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resp = requests.get(
        url,
        params=params,
        headers=_graph_headers(access_token),
        proxies=proxies,
        impersonate="chrome",
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"graph request failed: HTTP {resp.status_code} {resp.text[:300]}")
    payload = resp.json()
    return payload if isinstance(payload, dict) else {}


def _exchange_graph_token(
    account: MicrosoftImapAccount,
    *,
    proxies: Any = None,
) -> Tuple[str, str, str]:
    resp = requests.post(
        MICROSOFT_GRAPH_TOKEN_URL,
        data={
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
            "scope": MICROSOFT_GRAPH_SCOPE,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies=proxies,
        impersonate="chrome",
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"graph token refresh failed: HTTP {resp.status_code} {resp.text[:300]}")

    payload = resp.json() if resp.content else {}
    access_token = str(payload.get("access_token") or "").strip()
    new_refresh_token = str(payload.get("refresh_token") or account.refresh_token).strip()
    granted_scope = str(payload.get("scope") or "").strip()

    if not access_token:
        raise RuntimeError(f"graph token response missing access_token: {json.dumps(payload, ensure_ascii=False)[:300]}")
    if not _graph_has_mail_scope(granted_scope):
        raise RuntimeError(f"graph token missing mail scope: {granted_scope or '(empty)'}")

    return access_token, new_refresh_token, granted_scope


def _fetch_folder_messages(
    *,
    access_token: str,
    folder_name: str,
    top: int,
    proxies: Any = None,
) -> List[Dict[str, Any]]:
    folder_key = GRAPH_FOLDER_MAP.get(folder_name, folder_name)
    payload = _graph_request_json(
        url=f"{MICROSOFT_GRAPH_BASE_URL}/me/mailFolders/{folder_key}/messages",
        access_token=access_token,
        proxies=proxies,
        params={
            "$top": str(max(1, top)),
            "$select": "id,receivedDateTime,subject,from,isRead,bodyPreview,body",
        },
    )
    value = payload.get("value")
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _fetch_folder_snapshot_ids(
    *,
    access_token: str,
    folder_name: str,
    top: int,
    proxies: Any = None,
) -> Set[str]:
    ids: Set[str] = set()
    for item in _fetch_folder_messages(
        access_token=access_token,
        folder_name=folder_name,
        top=top,
        proxies=proxies,
    ):
        message_id = str(item.get("id") or "").strip()
        if message_id:
            ids.add(f"{folder_name}:{message_id}")
    return ids


def _scan_folder_for_otp(
    *,
    access_token: str,
    folder_name: str,
    seen_ids: Set[str],
    ignored_codes: Set[str],
    top: int,
    proxies: Any = None,
) -> Optional[str]:
    messages = _fetch_folder_messages(
        access_token=access_token,
        folder_name=folder_name,
        top=top,
        proxies=proxies,
    )
    for item in messages:
        message_id = str(item.get("id") or "").strip()
        if not message_id:
            continue
        message_key = f"{folder_name}:{message_id}"
        if message_key in seen_ids:
            continue
        seen_ids.add(message_key)

        sender_info = item.get("from") if isinstance(item.get("from"), dict) else {}
        email_address = sender_info.get("emailAddress") if isinstance(sender_info.get("emailAddress"), dict) else {}
        sender = str(email_address.get("address") or "").strip()
        sender_name = str(email_address.get("name") or "").strip()
        subject = str(item.get("subject") or "").strip()
        body_preview = str(item.get("bodyPreview") or "").strip()
        body = item.get("body") if isinstance(item.get("body"), dict) else {}
        body_content = str(body.get("content") or "").strip()

        if not _contains_oai_keyword(sender, sender_name, subject, body_preview, body_content):
            continue

        code = _extract_otp_from_parts(subject, body_preview, body_content)
        if code and code not in ignored_codes:
            return code

    return None


def create_ms_mail_g_mailbox(
    proxies: Any = None,
    thread_id: int = 0,
) -> Optional[TempMailbox]:
    account = take_imap_ms_account()
    if not account:
        logger.error(
            f"[线程 {thread_id}] [错误] 没有可用的微软 Graph 邮箱账号，"
            f"请检查 ms_emails.txt 文件是否存在且格式正确"
        )
        return None

    try:
        access_token, _new_refresh_token, granted_scope = _exchange_graph_token(account, proxies=proxies)
        _graph_request_json(
            url=f"{MICROSOFT_GRAPH_BASE_URL}/me/mailFolders",
            access_token=access_token,
            proxies=proxies,
            params={
                "$top": "10",
                "$select": "id,displayName,totalItemCount,unreadItemCount",
            },
        )
    except Exception as exc:
        logger.error(f"[线程 {thread_id}] [错误] 微软 Graph 邮箱 {account.email} 连接失败: {exc}")
        return None

    logger.info(
        f"[线程 {thread_id}] [信息] 使用微软 Graph 邮箱: {account.email} "
        f"(scope={granted_scope})"
    )

    return TempMailbox(
        email=account.email,
        provider="ms_mail_g",
        api_base=MICROSOFT_GRAPH_BASE_URL,
        domain=account.email.split("@", 1)[-1] if "@" in account.email else "",
        password=account.password,
        config_name="ms_mail_g:graph",
        oauth_client_id=account.client_id,
        oauth_refresh_token=account.refresh_token,
        source_removed=True,
    )


def list_ms_mail_g_message_ids(
    *,
    email_addr: str,
    password: str,
    client_id: str,
    refresh_token: str,
    proxies: Any = None,
) -> Set[str]:
    _ = password
    account = MicrosoftImapAccount(
        email=email_addr,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
    )

    try:
        access_token, _new_refresh_token, _granted_scope = _exchange_graph_token(account, proxies=proxies)
    except Exception as exc:
        logger.warning(f"[MS_MAIL_G] 获取 Graph 消息快照失败 ({email_addr}): {exc}")
        return set()

    ids = _fetch_folder_snapshot_ids(
        access_token=access_token,
        folder_name="INBOX",
        top=30,
        proxies=proxies,
    )
    ids.update(
        _fetch_folder_snapshot_ids(
            access_token=access_token,
            folder_name="JUNK",
            top=20,
            proxies=proxies,
        )
    )
    return ids


def poll_ms_mail_g_oai_code(
    *,
    email_addr: str,
    password: str,
    client_id: str,
    refresh_token: str,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    seen_ids: Set[str] = set(str(x).strip() for x in (skip_message_ids or set()) if str(x).strip())
    ignored_codes: Set[str] = set(str(x).strip() for x in (skip_codes or set()) if str(x).strip())

    account = MicrosoftImapAccount(
        email=email_addr,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
    )

    logger.info(f"[线程 {thread_id}] [信息] 正在等待邮箱 {email_addr} 的验证码 (MS_MAIL_G)")
    reset_mailbox_wait_diagnostics("ms_mail_g", email_addr)

    max_polls = 40
    poll_interval = 5

    for _ in range(max_polls):
        if _runtime_stop_requested():
            logger.info(f"[线程 {thread_id}] [信息] 收到停止信号，停止等待验证码 (MS_MAIL_G)")
            return ""
        increment_mailbox_wait_poll("ms_mail_g", email_addr)
        try:
            access_token, new_refresh_token, _granted_scope = _exchange_graph_token(account, proxies=proxies)
            if new_refresh_token and new_refresh_token != account.refresh_token:
                account = MicrosoftImapAccount(
                    email=account.email,
                    password=account.password,
                    client_id=account.client_id,
                    refresh_token=new_refresh_token,
                )

            code = _scan_folder_for_otp(
                access_token=access_token,
                folder_name="INBOX",
                seen_ids=seen_ids,
                ignored_codes=ignored_codes,
                top=20,
                proxies=proxies,
            )

            if not code:
                code = _scan_folder_for_otp(
                    access_token=access_token,
                    folder_name="JUNK",
                    seen_ids=seen_ids,
                    ignored_codes=ignored_codes,
                    top=20,
                    proxies=proxies,
                )

            total_scanned = len(seen_ids)
            note_mailbox_messages_scanned("ms_mail_g", email_addr, total_scanned)

            if code:
                mark_mailbox_wait_matched("ms_mail_g", email_addr, code=code)
                logger.info(f"[线程 {thread_id}] [信息] 已收到验证码: {code} (MS_MAIL_G)")
                return code
        except Exception as exc:
            logger.warning(f"[MS_MAIL_G] 轮询异常 ({email_addr}): {exc}")

        if _runtime_stop_requested():
            logger.info(f"[线程 {thread_id}] [信息] 收到停止信号，停止等待验证码 (MS_MAIL_G)")
            return ""
        time.sleep(poll_interval)

    mark_mailbox_wait_timeout(
        "ms_mail_g",
        email_addr,
        reason="mailbox_timeout_no_message" if not seen_ids else "mailbox_timeout_no_match",
    )
    logger.warning(f"[线程 {thread_id}] [警告] 等待超时，未收到验证码 (MS_MAIL_G)")
    return ""
