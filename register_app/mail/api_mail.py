from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from datetime import datetime
from dataclasses import dataclass
from typing import Any, List, Optional, Set

from curl_cffi import requests

from .diagnostics import (
    increment_mailbox_wait_poll,
    mark_mailbox_wait_matched,
    mark_mailbox_wait_timeout,
    note_mailbox_messages_scanned,
    reset_mailbox_wait_diagnostics,
)
from .providers import TempMailbox, _contains_mail_keyword, _extract_otp_from_parts

logger = logging.getLogger("openai_register")

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_API_EMAILS_FILE = os.path.join(_SCRIPT_DIR, "api_emails.txt")
DEFAULT_API_MAIL_TIMEOUT_SECONDS = 180


@dataclass(frozen=True)
class ApiMailAccount:
    email: str
    password: str
    api_url: str
    source_file: str = ""
    source_line: str = ""


_account_lock = threading.Lock()
_account_index = 0
_accounts: List[ApiMailAccount] = []
_accounts_loaded = False


def _load_api_emails_file(filepath: str = DEFAULT_API_EMAILS_FILE) -> List[ApiMailAccount]:
    path = str(filepath or "").strip()
    if not path or not os.path.exists(path):
        logger.warning(f"[API_MAIL] 账号文件不存在: {path}")
        return []

    accounts: List[ApiMailAccount] = []
    try:
        with open(path, "r", encoding="utf-8") as file_obj:
            for line_no, raw_line in enumerate(file_obj, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("----")
                if len(parts) < 3:
                    logger.warning(f"[API_MAIL] api_emails.txt 第 {line_no} 行格式无效，已跳过: {line}")
                    continue
                email = parts[0].strip()
                password = parts[1].strip()
                api_url = parts[2].strip()
                if not email or not password or not api_url:
                    logger.warning(f"[API_MAIL] api_emails.txt 第 {line_no} 行存在空字段，已跳过")
                    continue
                accounts.append(ApiMailAccount(email=email, password=password, api_url=api_url))
    except Exception as exc:
        logger.warning(f"[API_MAIL] 读取账号文件失败: {exc}")
        return []

    if accounts:
        logger.info(f"[API_MAIL] 已加载 {len(accounts)} 个 API 邮箱账号")
    else:
        logger.warning(f"[API_MAIL] 账号文件中没有有效账号: {path}")
    return accounts


def _ensure_accounts_loaded() -> None:
    global _accounts, _accounts_loaded
    if _accounts_loaded:
        return
    with _account_lock:
        if _accounts_loaded:
            return
        _accounts = _load_api_emails_file()
        _accounts_loaded = True


def reload_api_mail_accounts() -> None:
    global _accounts, _accounts_loaded, _account_index
    with _account_lock:
        _accounts = _load_api_emails_file()
        _accounts_loaded = True
        _account_index = 0


def remove_api_mail_account(email_addr: str, password: str, api_url: str, filepath: str = DEFAULT_API_EMAILS_FILE) -> bool:
    path = str(filepath or "").strip()
    if not path or not os.path.exists(path):
        return False

    email_value = str(email_addr or "").strip()
    password_value = str(password or "").strip()
    api_value = str(api_url or "").strip()
    removed = False
    with _account_lock:
        try:
            with open(path, "r", encoding="utf-8") as file_obj:
                lines = file_obj.readlines()
            new_lines: List[str] = []
            for raw_line in lines:
                line = raw_line.strip()
                if not removed and line and not line.startswith("#"):
                    parts = line.split("----")
                    if len(parts) >= 3:
                        if parts[0].strip() == email_value and parts[1].strip() == password_value and parts[2].strip() == api_value:
                            removed = True
                            continue
                new_lines.append(raw_line)
            if removed:
                with open(path, "w", encoding="utf-8") as file_obj:
                    file_obj.writelines(new_lines)
                global _accounts, _accounts_loaded, _account_index
                _accounts = _load_api_emails_file(path)
                _accounts_loaded = True
                _account_index = 0
                logger.info(f"[API_MAIL] 已从 api_emails.txt 删除已处理账号: {email_value}")
        except Exception as exc:
            logger.warning(f"[API_MAIL] 删除账号失败 ({email_value}): {exc}")
            return False
    return removed


def select_api_mail_account() -> Optional[ApiMailAccount]:
    global _account_index
    _ensure_accounts_loaded()
    with _account_lock:
        if not _accounts:
            return None
        index = _account_index % len(_accounts)
        account = _accounts[index]
        _account_index = (index + 1) % len(_accounts)
        return account


def take_api_mail_account(filepath: str = DEFAULT_API_EMAILS_FILE) -> Optional[ApiMailAccount]:
    path = str(filepath or "").strip()
    if not path or not os.path.exists(path):
        logger.warning(f"[API_MAIL] 账号文件不存在: {path}")
        return None

    with _account_lock:
        try:
            with open(path, "r", encoding="utf-8") as file_obj:
                lines = file_obj.readlines()

            selected_account: Optional[ApiMailAccount] = None
            new_lines: List[str] = []
            for line_no, raw_line in enumerate(lines, start=1):
                line = raw_line.strip()
                if selected_account is None and line and not line.startswith("#"):
                    parts = line.split("----")
                    if len(parts) < 3:
                        logger.warning(f"[API_MAIL] api_emails.txt 第 {line_no} 行格式无效，已跳过: {line}")
                        new_lines.append(raw_line)
                        continue
                    email = parts[0].strip()
                    password = parts[1].strip()
                    api_url = parts[2].strip()
                    if not email or not password or not api_url:
                        logger.warning(f"[API_MAIL] api_emails.txt 第 {line_no} 行存在空字段，已跳过")
                        new_lines.append(raw_line)
                        continue
                    selected_account = ApiMailAccount(
                        email=email,
                        password=password,
                        api_url=api_url,
                        source_file=path,
                        source_line=line,
                    )
                    continue
                new_lines.append(raw_line)

            if selected_account is None:
                return None

            with open(path, "w", encoding="utf-8") as file_obj:
                file_obj.writelines(new_lines)

            global _accounts, _accounts_loaded, _account_index
            _accounts = _load_api_emails_file(path)
            _accounts_loaded = True
            _account_index = 0
            logger.info(f"[API_MAIL] 已领取并移除账号: {selected_account.email}")
            return selected_account
        except Exception as exc:
            logger.warning(f"[API_MAIL] 领取账号失败: {exc}")
            return None


def return_api_mail_account(
    email_addr: str,
    password: str,
    api_url: str,
    *,
    filepath: str = DEFAULT_API_EMAILS_FILE,
    source_line: str = "",
) -> bool:
    path = str(filepath or "").strip()
    if not path:
        return False

    line = str(source_line or "").strip()
    if not line:
        line = f"{str(email_addr or '').strip()}----{str(password or '').strip()}----{str(api_url or '').strip()}"
    if not line:
        return False

    with _account_lock:
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "a", encoding="utf-8") as file_obj:
                file_obj.write(line + "\n")
            global _accounts, _accounts_loaded, _account_index
            _accounts = _load_api_emails_file(path)
            _accounts_loaded = True
            _account_index = 0
            logger.info(f"[API_MAIL] 已将账号放回未使用池: {email_addr}")
            return True
        except Exception as exc:
            logger.warning(f"[API_MAIL] 放回账号失败 ({email_addr}): {exc}")
            return False


def _fetch_api_mail_content(api_url: str, proxies: Any = None, timeout: int = 15) -> str:
    started_at = time.time()
    safe_api = str(api_url or "").strip()
    if len(safe_api) > 96:
        safe_api = safe_api[:96] + "..."
    logger.info(
        f"[API_MAIL] 开始请求取件接口: time={datetime.now().astimezone().isoformat(timespec='seconds')} "
        f"timeout={int(timeout)}s api={safe_api}"
    )
    resp = requests.get(api_url, proxies=proxies, impersonate="chrome", timeout=timeout)
    elapsed_ms = int((time.time() - started_at) * 1000)
    if resp.status_code != 200:
        logger.warning(
            f"[API_MAIL] 取件接口返回异常: status={resp.status_code} elapsed_ms={elapsed_ms} api={safe_api}"
        )
        raise RuntimeError(f"api mail get failed: HTTP {resp.status_code}")
    content = str(getattr(resp, "text", "") or "").strip()
    logger.info(
        f"[API_MAIL] 取件接口请求成功: elapsed_ms={elapsed_ms} body_len={len(content)} api={safe_api}"
    )
    return content


def _message_id_from_content(content: str) -> str:
    return hashlib.sha1(str(content or "").encode("utf-8", errors="ignore")).hexdigest()


def create_api_mailbox(proxies: Any = None, thread_id: int = 0) -> Optional[TempMailbox]:
    account = take_api_mail_account()
    if not account:
        logger.error(f"[线程 {thread_id}] [错误] 没有可用的 API 邮箱账号，请检查 api_emails.txt")
        return None
    logger.info(f"[线程 {thread_id}] [信息] 使用 API 邮箱: {account.email}")
    return TempMailbox(
        email=account.email,
        provider="api_mail",
        api_base=account.api_url,
        password=account.password,
        config_name="api_mail",
        source_removed=True,
        source_file=account.source_file,
        source_line=account.source_line,
    )


def list_api_message_ids(*, email_addr: str, password: str, api_url: str, proxies: Any = None) -> Set[str]:
    _ = email_addr, password
    try:
        content = _fetch_api_mail_content(
            api_url,
            proxies=proxies,
            timeout=DEFAULT_API_MAIL_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.warning(f"[API_MAIL] 获取消息快照失败: {exc}")
        return set()
    if not content:
        return set()
    return {_message_id_from_content(content)}


def poll_api_oai_code(
    *,
    email_addr: str,
    password: str,
    api_url: str,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    _ = password
    seen_ids: Set[str] = set(str(x).strip() for x in (skip_message_ids or set()) if str(x).strip())
    ignored_codes: Set[str] = set(str(x).strip() for x in (skip_codes or set()) if str(x).strip())
    logger.info(f"[线程 {thread_id}] [信息] 正在等待邮箱 {email_addr} 的验证码 (API_MAIL)")
    reset_mailbox_wait_diagnostics("api_mail", email_addr)

    max_polls = 40
    poll_interval = 5
    for _poll_round in range(max_polls):
        increment_mailbox_wait_poll("api_mail", email_addr)
        try:
            content = _fetch_api_mail_content(
                api_url,
                proxies=proxies,
                timeout=DEFAULT_API_MAIL_TIMEOUT_SECONDS,
            )
            if not content:
                time.sleep(poll_interval)
                continue
            msg_id = _message_id_from_content(content)
            if msg_id in seen_ids:
                note_mailbox_messages_scanned("api_mail", email_addr, len(seen_ids))
                time.sleep(poll_interval)
                continue
            seen_ids.add(msg_id)
            note_mailbox_messages_scanned("api_mail", email_addr, len(seen_ids))
            if not _contains_mail_keyword(content):
                time.sleep(poll_interval)
                continue
            code = _extract_otp_from_parts(content)
            if code and code not in ignored_codes:
                mark_mailbox_wait_matched("api_mail", email_addr, code=code)
                logger.info(f"[线程 {thread_id}] [信息] 已收到验证码: {code} (API_MAIL)")
                return code
        except Exception as exc:
            logger.warning(f"[API_MAIL] 轮询异常 ({email_addr}): {exc}")
        time.sleep(poll_interval)

    mark_mailbox_wait_timeout(
        "api_mail",
        email_addr,
        reason="mailbox_timeout_no_message" if not seen_ids else "mailbox_timeout_no_match",
    )
    logger.warning(f"[线程 {thread_id}] [警告] 等待超时，未收到验证码 (API_MAIL)")
    return ""
