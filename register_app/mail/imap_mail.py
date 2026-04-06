# -*- coding: utf-8 -*-
"""IMAP 邮箱提供商：通过 IMAP 协议从真实邮箱（如新浪邮箱）收取 OpenAI 验证码。

邮箱账号从项目根目录的 emails.txt 文件中读取，格式为：
    邮箱地址----授权码
每行一个账号。

支持同时扫描收件箱（INBOX）和垃圾箱（Junk / Spam 等常见文件夹名），
以兼容不同邮箱服务商将 OpenAI 邮件归类到不同位置的情况。
"""
from __future__ import annotations

import email as email_lib
import imaplib
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from email.header import decode_header
from typing import Any, Dict, List, Optional, Set

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

# ---------------------------------------------------------------------------
# 默认 IMAP 配置
# ---------------------------------------------------------------------------
DEFAULT_IMAP_HOST = "imap.sina.com"
DEFAULT_IMAP_PORT = 993
DEFAULT_IMAP_SSL = True
DEFAULT_EMAILS_FILE = os.path.join(_SCRIPT_DIR, "emails.txt")

OTP_CODE_PATTERN = re.compile(r"(?<!\d)(\d{6})(?!\d)")

# 垃圾箱常见文件夹名（不同邮箱服务商可能不同）
JUNK_FOLDER_CANDIDATES = [
    "Junk",
    "&V4NXPpCuTvY-",      # 新浪邮箱的"垃圾邮件"文件夹 UTF-7 编码
    "SPAM",
    "Spam",
    "&5765NV8K-",          # 另一种中文"垃圾邮件"的 UTF-7 编码
    "Bulk Mail",
    "Bulk",
    "&Xn9USpCuTvY-",      # QQ 邮箱"垃圾邮件"
    "Junk E-mail",
    "Junk Email",
]

# ---------------------------------------------------------------------------
# 邮箱账号池管理
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ImapAccount:
    email: str
    auth_code: str
    imap_host: str = DEFAULT_IMAP_HOST
    imap_port: int = DEFAULT_IMAP_PORT
    use_ssl: bool = DEFAULT_IMAP_SSL


_imap_account_lock = threading.Lock()
_imap_account_index = 0
_imap_accounts: List[ImapAccount] = []
_imap_accounts_loaded = False


def _load_emails_file(filepath: str = DEFAULT_EMAILS_FILE) -> List[ImapAccount]:
    """从 emails.txt 文件加载邮箱账号列表。

    文件格式：每行一个账号，格式为 邮箱地址----授权码
    支持 # 开头的注释行和空行。
    也支持扩展格式：邮箱地址----授权码----IMAP服务器----端口
    """
    path = str(filepath or "").strip()
    if not path or not os.path.exists(path):
        logger.warning(f"[IMAP] 邮箱账号文件不存在: {path}")
        return []

    accounts: List[ImapAccount] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split("----")
                if len(parts) < 2:
                    logger.warning(f"[IMAP] emails.txt 第 {line_no} 行格式无效，已跳过: {line}")
                    continue

                email_addr = parts[0].strip()
                auth_code = parts[1].strip()
                if not email_addr or not auth_code:
                    logger.warning(f"[IMAP] emails.txt 第 {line_no} 行邮箱或授权码为空，已跳过")
                    continue

                imap_host = parts[2].strip() if len(parts) > 2 and parts[2].strip() else DEFAULT_IMAP_HOST
                imap_port = DEFAULT_IMAP_PORT
                if len(parts) > 3 and parts[3].strip():
                    try:
                        imap_port = int(parts[3].strip())
                    except ValueError:
                        pass

                accounts.append(ImapAccount(
                    email=email_addr,
                    auth_code=auth_code,
                    imap_host=imap_host,
                    imap_port=imap_port,
                ))
    except Exception as e:
        logger.warning(f"[IMAP] 读取邮箱账号文件失败: {e}")
        return []

    if accounts:
        logger.info(f"[IMAP] 已加载 {len(accounts)} 个邮箱账号")
    else:
        logger.warning(f"[IMAP] 邮箱账号文件中没有有效账号: {path}")

    return accounts


def _ensure_accounts_loaded() -> None:
    """确保邮箱账号已加载（懒加载）。"""
    global _imap_accounts, _imap_accounts_loaded
    if _imap_accounts_loaded:
        return
    with _imap_account_lock:
        if _imap_accounts_loaded:
            return
        _imap_accounts = _load_emails_file()
        _imap_accounts_loaded = True


def reload_imap_accounts() -> None:
    """强制重新加载邮箱账号文件。"""
    global _imap_accounts, _imap_accounts_loaded, _imap_account_index
    with _imap_account_lock:
        _imap_accounts = _load_emails_file()
        _imap_accounts_loaded = True
        _imap_account_index = 0


def remove_imap_account(
    email_addr: str,
    auth_code: str,
    filepath: str = DEFAULT_EMAILS_FILE,
) -> bool:
    """从 emails.txt 删除一个已处理的 IMAP 账号，并重载账号池。"""
    path = str(filepath or "").strip()
    email_value = str(email_addr or "").strip()
    auth_value = str(auth_code or "").strip()
    if not path or not email_value or not auth_value or not os.path.exists(path):
        return False

    removed = False
    with _imap_account_lock:
        try:
            with open(path, "r", encoding="utf-8") as file_obj:
                lines = file_obj.readlines()

            new_lines: List[str] = []
            for raw_line in lines:
                line = raw_line.strip()
                if not removed and line and not line.startswith("#"):
                    parts = line.split("----")
                    if len(parts) >= 2:
                        candidate_email = parts[0].strip()
                        candidate_auth = parts[1].strip()
                        if candidate_email == email_value and candidate_auth == auth_value:
                            removed = True
                            continue
                new_lines.append(raw_line)

            if removed:
                with open(path, "w", encoding="utf-8") as file_obj:
                    file_obj.writelines(new_lines)

                global _imap_accounts, _imap_accounts_loaded, _imap_account_index
                _imap_accounts = _load_emails_file(path)
                _imap_accounts_loaded = True
                _imap_account_index = 0
                logger.info(f"[IMAP] 已从 emails.txt 删除已处理账号: {email_value}")
        except Exception as exc:
            logger.warning(f"[IMAP] 删除 emails.txt 账号失败 ({email_value}): {exc}")
            return False

    return removed


def get_imap_accounts() -> List[ImapAccount]:
    """获取当前已加载的 IMAP 邮箱账号列表。"""
    _ensure_accounts_loaded()
    return list(_imap_accounts)


def select_imap_account() -> Optional[ImapAccount]:
    """轮询选择下一个可用的 IMAP 邮箱账号。"""
    global _imap_account_index
    _ensure_accounts_loaded()

    with _imap_account_lock:
        if not _imap_accounts:
            return None
        index = _imap_account_index % len(_imap_accounts)
        account = _imap_accounts[index]
        _imap_account_index = (index + 1) % len(_imap_accounts)
        return account


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _log_waiting_code_start(thread_id: int, email_addr: str) -> None:
    logger.info(f"[线程 {thread_id}] [信息] 正在等待邮箱 {email_addr} 的验证码 (IMAP)")


def _log_waiting_code_success(thread_id: int, code: str) -> None:
    logger.info(f"[线程 {thread_id}] [信息] 已收到验证码: {code} (IMAP)")


def _log_waiting_code_timeout(thread_id: int) -> None:
    logger.warning(f"[线程 {thread_id}] [警告] 等待超时，未收到验证码 (IMAP)")


def _contains_oai_keyword(*parts: Any) -> bool:
    """检查文本中是否包含 OpenAI / ChatGPT 关键词。"""
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        lowered = text.lower()
        if "openai" in lowered or "chatgpt" in lowered:
            return True
    return False


def _extract_otp_from_parts(*parts: Any) -> str:
    """从文本中提取 6 位数字验证码。"""
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        match = OTP_CODE_PATTERN.search(text)
        if match:
            return match.group(1)
    return ""


def _decode_mime_header(value: str) -> str:
    """解码 MIME 邮件头。"""
    parts = []
    for chunk, charset in decode_header(str(value or "")):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(str(chunk))
    return "".join(parts)


def _extract_email_text(msg: email_lib.message.Message) -> str:
    """从邮件消息中提取纯文本内容。"""
    parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        decoded = payload.decode(charset, errors="replace")
                    except Exception:
                        decoded = payload.decode("utf-8", errors="replace")
                    parts.append(decoded)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                decoded = payload.decode("utf-8", errors="replace")
            parts.append(decoded)

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# IMAP 连接与邮件获取
# ---------------------------------------------------------------------------

def _connect_imap(account: ImapAccount) -> Optional[imaplib.IMAP4_SSL]:
    """建立 IMAP 连接并登录。"""
    try:
        if account.use_ssl:
            conn = imaplib.IMAP4_SSL(account.imap_host, account.imap_port)
        else:
            conn = imaplib.IMAP4(account.imap_host, account.imap_port)

        conn.login(account.email, account.auth_code)
        return conn
    except Exception as e:
        logger.warning(f"[IMAP] 连接或登录失败 ({account.email}@{account.imap_host}): {e}")
        return None


def _find_junk_folder(conn: imaplib.IMAP4_SSL) -> Optional[str]:
    """尝试找到垃圾箱文件夹名称。"""
    try:
        status, folder_list = conn.list()
        if status != "OK" or not folder_list:
            return None

        available_folders: List[str] = []
        for item in folder_list:
            if isinstance(item, bytes):
                item = item.decode("utf-8", errors="replace")
            # 解析 IMAP LIST 响应，提取文件夹名
            # 格式类似: (\HasNoChildren) "/" "INBOX"
            match = re.search(r'"([^"]*)"$|(\S+)$', str(item))
            if match:
                folder_name = match.group(1) or match.group(2)
                if folder_name:
                    available_folders.append(folder_name)

        # 按优先级匹配垃圾箱文件夹
        for candidate in JUNK_FOLDER_CANDIDATES:
            for folder in available_folders:
                if folder == candidate or folder.lower() == candidate.lower():
                    return folder

        return None
    except Exception as e:
        logger.debug(f"[IMAP] 查找垃圾箱文件夹失败: {e}")
        return None


def _fetch_recent_message_ids(
    conn: imaplib.IMAP4_SSL,
    folder: str = "INBOX",
    limit: int = 20,
) -> Set[str]:
    """获取指定文件夹中最近的邮件 UID 集合。"""
    ids: Set[str] = set()
    try:
        status, _ = conn.select(folder, readonly=True)
        if status != "OK":
            return ids

        # 搜索最近的邮件
        status, data = conn.search(None, "ALL")
        if status != "OK" or not data or not data[0]:
            return ids

        msg_nums = data[0].split()
        # 只取最近的 limit 封
        recent_nums = msg_nums[-limit:] if len(msg_nums) > limit else msg_nums
        for num in recent_nums:
            uid = num.decode("utf-8") if isinstance(num, bytes) else str(num)
            ids.add(f"{folder}:{uid}")

    except Exception as e:
        logger.debug(f"[IMAP] 获取 {folder} 邮件列表失败: {e}")

    return ids


def _scan_folder_for_otp(
    conn: imaplib.IMAP4_SSL,
    folder: str,
    seen_ids: Set[str],
    ignored_codes: Set[str],
    limit: int = 20,
) -> Optional[str]:
    """扫描指定文件夹中的邮件，查找 OpenAI 验证码。

    Returns:
        验证码字符串，未找到则返回 None。
    """
    try:
        status, _ = conn.select(folder, readonly=True)
        if status != "OK":
            return None

        # 搜索所有邮件
        status, data = conn.search(None, "ALL")
        if status != "OK" or not data or not data[0]:
            return None

        msg_nums = data[0].split()
        # 从最新的开始扫描
        recent_nums = list(reversed(msg_nums[-limit:] if len(msg_nums) > limit else msg_nums))

        for num in recent_nums:
            uid = num.decode("utf-8") if isinstance(num, bytes) else str(num)
            msg_key = f"{folder}:{uid}"
            if msg_key in seen_ids:
                continue
            seen_ids.add(msg_key)

            try:
                status, msg_data = conn.fetch(num, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue

                raw_email = msg_data[0][1] if isinstance(msg_data[0], tuple) else None
                if not raw_email:
                    continue

                msg = email_lib.message_from_bytes(raw_email)
                subject = _decode_mime_header(msg.get("Subject", ""))
                sender = _decode_mime_header(msg.get("From", ""))
                body = _extract_email_text(msg)

                if not _contains_oai_keyword(sender, subject, body):
                    continue

                code = _extract_otp_from_parts(subject, body)
                if code and code not in ignored_codes:
                    return code

            except Exception as e:
                logger.debug(f"[IMAP] 读取邮件 {msg_key} 失败: {e}")
                continue

    except Exception as e:
        logger.debug(f"[IMAP] 扫描文件夹 {folder} 失败: {e}")

    return None


# ---------------------------------------------------------------------------
# 公开接口：创建邮箱、列出消息、轮询验证码
# ---------------------------------------------------------------------------

def create_imap_mailbox(
    proxies: Any = None, thread_id: int = 0
) -> Optional[TempMailbox]:
    """从 emails.txt 中选取一个邮箱账号，创建 IMAP 类型的 TempMailbox。

    注意：proxies 参数在 IMAP 模式下不使用（IMAP 直连），保留仅为接口兼容。
    """
    account = select_imap_account()
    if not account:
        logger.error(
            f"[线程 {thread_id}] [错误] 没有可用的 IMAP 邮箱账号，"
            f"请检查 emails.txt 文件是否存在且格式正确"
        )
        return None

    # 测试连接是否可用
    conn = _connect_imap(account)
    if not conn:
        logger.error(
            f"[线程 {thread_id}] [错误] IMAP 邮箱 {account.email} 连接失败"
        )
        return None

    try:
        conn.logout()
    except Exception:
        pass

    logger.info(
        f"[线程 {thread_id}] [信息] 使用 IMAP 邮箱: {account.email} "
        f"(服务器: {account.imap_host}:{account.imap_port})"
    )

    return TempMailbox(
        email=account.email,
        provider="imap",
        token=account.auth_code,
        api_base=account.imap_host,
        domain=account.email.split("@", 1)[-1] if "@" in account.email else "",
        password=account.auth_code,
        config_name=f"imap:{account.imap_host}",
    )


def list_imap_message_ids(
    *, email_addr: str, auth_code: str, imap_host: str = DEFAULT_IMAP_HOST,
    imap_port: int = DEFAULT_IMAP_PORT, proxies: Any = None,
) -> Set[str]:
    """获取 IMAP 邮箱中当前已有的消息 ID 快照（收件箱 + 垃圾箱）。"""
    account = ImapAccount(
        email=email_addr,
        auth_code=auth_code,
        imap_host=imap_host,
        imap_port=imap_port,
    )
    conn = _connect_imap(account)
    if not conn:
        return set()

    try:
        ids = _fetch_recent_message_ids(conn, "INBOX", limit=30)

        junk_folder = _find_junk_folder(conn)
        if junk_folder:
            junk_ids = _fetch_recent_message_ids(conn, junk_folder, limit=20)
            ids.update(junk_ids)

        return ids
    except Exception as e:
        logger.debug(f"[IMAP] 获取消息快照失败 ({email_addr}): {e}")
        return set()
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def poll_imap_oai_code(
    *,
    email_addr: str,
    auth_code: str,
    imap_host: str = DEFAULT_IMAP_HOST,
    imap_port: int = DEFAULT_IMAP_PORT,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    """轮询 IMAP 邮箱，等待并获取 OpenAI 验证码。

    同时扫描收件箱（INBOX）和垃圾箱，以兼容邮件被归类到不同位置的情况。
    """
    seen_ids: Set[str] = set(str(x).strip() for x in (skip_message_ids or set()) if str(x).strip())
    ignored_codes: Set[str] = set(str(x).strip() for x in (skip_codes or set()) if str(x).strip())

    account = ImapAccount(
        email=email_addr,
        auth_code=auth_code,
        imap_host=imap_host,
        imap_port=imap_port,
    )

    _log_waiting_code_start(thread_id, email_addr)
    reset_mailbox_wait_diagnostics("imap", email_addr)

    max_polls = 40
    poll_interval = 5  # 每次轮询间隔秒数

    for poll_round in range(max_polls):
        increment_mailbox_wait_poll("imap", email_addr)

        conn = _connect_imap(account)
        if not conn:
            time.sleep(poll_interval)
            continue

        try:
            # 1. 先扫描收件箱
            code = _scan_folder_for_otp(conn, "INBOX", seen_ids, ignored_codes, limit=20)
            inbox_count = len(seen_ids)

            # 2. 再扫描垃圾箱
            if not code:
                junk_folder = _find_junk_folder(conn)
                if junk_folder:
                    code = _scan_folder_for_otp(conn, junk_folder, seen_ids, ignored_codes, limit=20)

            total_scanned = len(seen_ids)
            note_mailbox_messages_scanned("imap", email_addr, total_scanned)

            if code:
                mark_mailbox_wait_matched("imap", email_addr, code=code)
                _log_waiting_code_success(thread_id, code)
                return code

        except Exception as e:
            logger.debug(f"[IMAP] 轮询异常 ({email_addr}): {e}")
        finally:
            try:
                conn.logout()
            except Exception:
                pass

        time.sleep(poll_interval)

    mark_mailbox_wait_timeout(
        "imap",
        email_addr,
        reason="mailbox_timeout_no_message" if not seen_ids else "mailbox_timeout_no_match",
    )
    _log_waiting_code_timeout(thread_id)
    return ""
