# -*- coding: utf-8 -*-
"""Unified Microsoft mail provider.

Strategy:
1. Microsoft Graph `.default` first
2. Fallback to IMAP XOAUTH2 automatically
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional, Set

from .imap_mail import (
    DEFAULT_MS_IMAP_PORT,
    MicrosoftImapAccount,
    _connect_imap_ms,
    _fetch_recent_message_ids,
    _find_junk_folder,
    _scan_folder_for_otp as _scan_folder_for_otp_imap,
    take_imap_ms_account,
)
from .ms_mail_g import (
    _exchange_graph_token,
    _fetch_folder_snapshot_ids,
    _scan_folder_for_otp as _scan_folder_for_otp_graph,
)
from .diagnostics import (
    increment_mailbox_wait_poll,
    mark_mailbox_wait_matched,
    mark_mailbox_wait_timeout,
    note_mailbox_messages_scanned,
    reset_mailbox_wait_diagnostics,
)
from .providers import TempMailbox

logger = logging.getLogger("openai_register")


def _build_account(
    *,
    email_addr: str,
    password: str,
    client_id: str,
    refresh_token: str,
) -> MicrosoftImapAccount:
    return MicrosoftImapAccount(
        email=email_addr,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
    )


def _try_graph_snapshot_ids(account: MicrosoftImapAccount, proxies: Any = None) -> Set[str]:
    access_token, _new_refresh_token, _granted_scope = _exchange_graph_token(account, proxies=proxies)
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


def _try_imap_snapshot_ids(account: MicrosoftImapAccount) -> Set[str]:
    conn = _connect_imap_ms(account)
    if not conn:
        return set()
    try:
        ids = _fetch_recent_message_ids(conn, "INBOX", limit=30)
        junk_folder = _find_junk_folder(conn)
        if junk_folder:
            ids.update(_fetch_recent_message_ids(conn, junk_folder, limit=20))
        return ids
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def create_ms_mail_mailbox(
    proxies: Any = None,
    thread_id: int = 0,
) -> Optional[TempMailbox]:
    account = take_imap_ms_account()
    if not account:
        logger.error(
            f"[线程 {thread_id}] [错误] 没有可用的微软邮箱账号，"
            f"请检查 ms_emails.txt 文件是否存在且格式正确"
        )
        return None

    mode = ""
    try:
        _try_graph_snapshot_ids(account, proxies=proxies)
        mode = "graph"
    except Exception as graph_exc:
        logger.warning(f"[线程 {thread_id}] [警告] Microsoft Graph 预检查失败，自动降级 IMAP: {graph_exc}")
        ids = _try_imap_snapshot_ids(account)
        if not ids and ids != set():
            pass
        conn = _connect_imap_ms(account)
        if not conn:
            logger.error(f"[线程 {thread_id}] [错误] 微软邮箱 {account.email} Graph/IMAP 都连接失败")
            return None
        try:
            mode = "imap"
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    logger.info(f"[线程 {thread_id}] [信息] 使用微软邮箱: {account.email} (mode={mode})")
    return TempMailbox(
        email=account.email,
        provider="ms_mail",
        api_base="microsoft",
        domain=account.email.split("@", 1)[-1] if "@" in account.email else "",
        password=account.password,
        config_name=f"ms_mail:{mode}",
        imap_port=DEFAULT_MS_IMAP_PORT,
        oauth_client_id=account.client_id,
        oauth_refresh_token=account.refresh_token,
        source_removed=True,
    )


def list_ms_mail_message_ids(
    *,
    email_addr: str,
    password: str,
    client_id: str,
    refresh_token: str,
    proxies: Any = None,
) -> Set[str]:
    account = _build_account(
        email_addr=email_addr,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
    )

    try:
        return _try_graph_snapshot_ids(account, proxies=proxies)
    except Exception as graph_exc:
        logger.warning(f"[MS_MAIL] Graph 快照失败，自动降级 IMAP ({email_addr}): {graph_exc}")
        return _try_imap_snapshot_ids(account)


def poll_ms_mail_oai_code(
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
    account = _build_account(
        email_addr=email_addr,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
    )

    logger.info(f"[线程 {thread_id}] [信息] 正在等待邮箱 {email_addr} 的验证码 (MS_MAIL)")
    reset_mailbox_wait_diagnostics("ms_mail", email_addr)

    max_polls = 40
    poll_interval = 5

    for _ in range(max_polls):
        increment_mailbox_wait_poll("ms_mail", email_addr)
        code = ""
        try:
            access_token, new_refresh_token, _granted_scope = _exchange_graph_token(account, proxies=proxies)
            if new_refresh_token and new_refresh_token != account.refresh_token:
                account = MicrosoftImapAccount(
                    email=account.email,
                    password=account.password,
                    client_id=account.client_id,
                    refresh_token=new_refresh_token,
                )
            code = _scan_folder_for_otp_graph(
                access_token=access_token,
                folder_name="INBOX",
                seen_ids=seen_ids,
                ignored_codes=ignored_codes,
                top=20,
                proxies=proxies,
            ) or _scan_folder_for_otp_graph(
                access_token=access_token,
                folder_name="JUNK",
                seen_ids=seen_ids,
                ignored_codes=ignored_codes,
                top=20,
                proxies=proxies,
            ) or ""
        except Exception as graph_exc:
            logger.warning(f"[MS_MAIL] Graph 轮询失败，自动降级 IMAP ({email_addr}): {graph_exc}")
            conn = _connect_imap_ms(account)
            if conn:
                try:
                    code = _scan_folder_for_otp_imap(conn, "INBOX", seen_ids, ignored_codes, limit=20) or ""
                    if not code:
                        junk_folder = _find_junk_folder(conn)
                        if junk_folder:
                            code = _scan_folder_for_otp_imap(conn, junk_folder, seen_ids, ignored_codes, limit=20) or ""
                finally:
                    try:
                        conn.logout()
                    except Exception:
                        pass

        total_scanned = len(seen_ids)
        note_mailbox_messages_scanned("ms_mail", email_addr, total_scanned)
        if code:
            mark_mailbox_wait_matched("ms_mail", email_addr, code=code)
            logger.info(f"[线程 {thread_id}] [信息] 已收到验证码: {code} (MS_MAIL)")
            return code
        time.sleep(poll_interval)

    mark_mailbox_wait_timeout(
        "ms_mail",
        email_addr,
        reason="mailbox_timeout_no_message" if not seen_ids else "mailbox_timeout_no_match",
    )
    logger.warning(f"[线程 {thread_id}] [警告] 等待超时，未收到验证码 (MS_MAIL)")
    return ""
