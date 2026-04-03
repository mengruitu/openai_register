"""Shared runtime types, logging, and persistence helpers."""

from __future__ import annotations

import json
import logging
import os
import random
import re
import shutil
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Callable, Optional

DEFAULT_TOKEN_CHECK_WORKERS = 2
DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS = 900
DEFAULT_TOKEN_REFRESH_SKEW_SECONDS = 300
ACCOUNTS_FILE_MAX_BYTES = 50 * 1024 * 1024  # 50 MB
ACCOUNTS_FILE_BACKUP_COUNT = 5
# 检测到库存缺口时的最短重试间隔（秒），避免等满整个 monitor_interval
SHORTAGE_FAST_RETRY_SECONDS = 60
# 检测到缺口但补号全部失败时的等待间隔（秒），防止空转
SHORTAGE_FAIL_RETRY_SECONDS = 120

output_lock = threading.Lock()

_LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "register.log")
_LOG_MAX_BYTES = 50 * 1024 * 1024
_LOG_BACKUP_COUNT = 5

os.makedirs(_LOG_DIR, exist_ok=True)

logger = logging.getLogger("openai_register")
logger.setLevel(logging.DEBUG)

_log_file_abs = os.path.abspath(_LOG_FILE)
if not any(
    isinstance(handler, logging.FileHandler)
    and os.path.abspath(getattr(handler, "baseFilename", "")) == _log_file_abs
    for handler in logger.handlers
):
    file_handler = RotatingFileHandler(
        _LOG_FILE,
        maxBytes=_LOG_MAX_BYTES,
        backupCount=_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT))
    logger.addHandler(file_handler)

if not any(type(handler) is logging.StreamHandler for handler in logger.handlers):
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(
        logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT)
    )
    logger.addHandler(console_handler)

RegisterRunner = Callable[..., tuple[Optional[tuple[str, str]], str]]
ReloadCfmailHook = Callable[[], None]


@dataclass(frozen=True)
class MonitorCycleResult:
    completed_at: datetime
    active_count: int
    pool_count: int
    active_target: int
    pool_target: int
    active_shortage: int
    pool_shortage: int
    attempted_replenish: bool
    register_target: int
    replenished_count: int
    deleted_count: int
    active_deleted_count: int
    pool_deleted_count: int
    moved_to_active_count: int
    active_check_failed: int
    pool_check_failed: int


@dataclass(frozen=True)
class TokenUsageCheck:
    used_percent: Optional[int]
    should_delete: bool
    check_failed: bool
    reason: str = ""
    refreshed: bool = False


def log_info(message: str) -> None:
    logger.info(message)


def log_warn(message: str) -> None:
    logger.warning(message)


def log_error(message: str) -> None:
    logger.error(message)


def _safe_token_filename(email: str, thread_id: int) -> str:
    raw = (email or "").strip().lower()
    if not raw:
        return f"unknown_{thread_id}_{int(time.time())}.json"

    safe = re.sub(r"[^0-9a-zA-Z@._-]", "_", raw).strip("._")
    if not safe:
        safe = f"unknown_{thread_id}_{int(time.time())}"
    return f"{safe}.json"


def _build_unique_path(directory: str, base_name: str) -> str:
    path = os.path.join(directory, base_name)
    if not os.path.exists(path):
        return path

    stem, ext = os.path.splitext(base_name)
    return os.path.join(
        directory,
        f"{stem}_{int(time.time())}_{random.randint(1000, 9999)}{ext}",
    )


def _build_token_output_path(token_dir: str, email: str, thread_id: int) -> str:
    return _build_unique_path(token_dir, _safe_token_filename(email, thread_id))


def list_json_files(directory: str) -> list[str]:
    if not os.path.isdir(directory):
        return []

    files: list[str] = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if name.endswith(".json") and os.path.isfile(path):
            files.append(path)
    return files


def count_json_files(directory: str) -> int:
    return len(list_json_files(directory))


def _rotate_accounts_file(file_path: str) -> None:
    try:
        if not os.path.isfile(file_path):
            return
        if os.path.getsize(file_path) < ACCOUNTS_FILE_MAX_BYTES:
            return
    except OSError:
        return

    oldest = f"{file_path}.{ACCOUNTS_FILE_BACKUP_COUNT}"
    if os.path.isfile(oldest):
        try:
            os.remove(oldest)
        except OSError:
            pass

    for index in range(ACCOUNTS_FILE_BACKUP_COUNT - 1, 0, -1):
        src = f"{file_path}.{index}"
        dst = f"{file_path}.{index + 1}"
        if os.path.isfile(src):
            try:
                shutil.move(src, dst)
            except OSError:
                pass

    try:
        shutil.move(file_path, f"{file_path}.1")
    except OSError:
        pass


def persist_registration_result(
    token_json: str,
    password: str,
    thread_id: int,
    token_dir: str,
) -> tuple[str, str]:
    try:
        token_data = json.loads(token_json)
        raw_email = str(token_data.get("email") or "unknown")
        refresh_token = str(token_data.get("refresh_token") or "")
    except Exception:
        raw_email = "unknown"
        refresh_token = ""

    os.makedirs(token_dir, exist_ok=True)
    file_name = _build_token_output_path(token_dir, raw_email, thread_id)
    with open(file_name, "w", encoding="utf-8") as file_obj:
        file_obj.write(token_json)

    os.makedirs("output", exist_ok=True)
    accounts_path = os.path.join("output", "accounts.txt")
    with output_lock:
        _rotate_accounts_file(accounts_path)
        with open(accounts_path, "a", encoding="utf-8") as file_obj:
            file_obj.write(f"{raw_email}----{password}----{refresh_token}\n")

    return file_name, raw_email


__all__ = [
    "ACCOUNTS_FILE_BACKUP_COUNT",
    "ACCOUNTS_FILE_MAX_BYTES",
    "DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS",
    "DEFAULT_TOKEN_CHECK_WORKERS",
    "DEFAULT_TOKEN_REFRESH_SKEW_SECONDS",
    "MonitorCycleResult",
    "RegisterRunner",
    "ReloadCfmailHook",
    "SHORTAGE_FAIL_RETRY_SECONDS",
    "SHORTAGE_FAST_RETRY_SECONDS",
    "TokenUsageCheck",
    "_build_token_output_path",
    "_build_unique_path",
    "count_json_files",
    "list_json_files",
    "log_error",
    "log_info",
    "log_warn",
    "logger",
    "persist_registration_result",
]
