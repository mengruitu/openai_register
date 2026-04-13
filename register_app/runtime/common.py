"""Shared runtime types, logging, and persistence helpers."""

from __future__ import annotations

from collections import Counter
import json
import logging
import os
import random
import re
import shutil
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Optional

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

RegisterRunner = Callable[..., tuple[Optional[tuple[str, str]], str, Any]]
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


@dataclass
class RegisterModeStats:
    provider_key: str
    configured_threads: int
    token_dir: str
    initial_mailbox_total: int = 0
    remaining_mailbox_total: int = 0
    max_mailboxes_to_use: int = 0
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    attempt_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    environment_failure_count: int = 0
    generated_files_count: int = 0
    last_success_email: str = ""
    last_output_file: str = ""
    thread_attempts: Counter[int] = field(default_factory=Counter)
    thread_successes: Counter[int] = field(default_factory=Counter)
    thread_failures: Counter[int] = field(default_factory=Counter)
    thread_environment_failures: Counter[int] = field(default_factory=Counter)
    success_providers: Counter[str] = field(default_factory=Counter)
    failure_providers: Counter[str] = field(default_factory=Counter)
    failure_reasons: Counter[str] = field(default_factory=Counter)
    consumed_mailbox_count: int = 0
    reserved_mailbox_slots: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_success(
        self,
        *,
        thread_id: int,
        used_provider: str,
        email: str,
        output_file: str,
    ) -> None:
        provider = str(used_provider or "").strip() or "unknown"
        with self._lock:
            self.attempt_count += 1
            self.success_count += 1
            self.generated_files_count += 1
            self.last_success_email = str(email or "").strip()
            self.last_output_file = str(output_file or "").strip()
            self.thread_attempts[thread_id] += 1
            self.thread_successes[thread_id] += 1
            self.success_providers[provider] += 1

    def record_environment_failure(
        self,
        *,
        thread_id: int,
        used_provider: str,
        reason: str = "",
    ) -> None:
        provider = str(used_provider or "").strip() or "unknown"
        failure_reason = str(reason or "").strip() or "environment_failure"
        with self._lock:
            self.environment_failure_count += 1
            self.thread_environment_failures[thread_id] += 1
            self.failure_providers[provider] += 1
            self.failure_reasons[failure_reason] += 1

    def record_failure(
        self,
        *,
        thread_id: int,
        used_provider: str,
        reason: str = "",
    ) -> None:
        provider = str(used_provider or "").strip() or "unknown"
        failure_reason = str(reason or "").strip() or "unknown_failure"
        with self._lock:
            self.attempt_count += 1
            self.failure_count += 1
            self.thread_attempts[thread_id] += 1
            self.thread_failures[thread_id] += 1
            self.failure_providers[provider] += 1
            self.failure_reasons[failure_reason] += 1

    def try_reserve_mailbox_slot(self) -> bool:
        with self._lock:
            if self.max_mailboxes_to_use <= 0:
                return True
            if self.consumed_mailbox_count + self.reserved_mailbox_slots >= self.max_mailboxes_to_use:
                return False
            self.reserved_mailbox_slots += 1
            return True

    def complete_mailbox_slot(self, *, consumed: bool) -> None:
        with self._lock:
            if self.max_mailboxes_to_use > 0 and self.reserved_mailbox_slots > 0:
                self.reserved_mailbox_slots -= 1
            if consumed:
                self.consumed_mailbox_count += 1

    def set_remaining_mailboxes(self, remaining: int) -> None:
        with self._lock:
            self.remaining_mailbox_total = max(0, int(remaining))

    def mark_finished(self) -> None:
        with self._lock:
            self.finished_at = time.time()

    @staticmethod
    def _display_width(value: str) -> int:
        width = 0
        for ch in str(value):
            width += 2 if unicodedata.east_asian_width(ch) in {"W", "F"} else 1
        return width

    @classmethod
    def _pad_cell(cls, value: str, width: int) -> str:
        text = str(value)
        padding = max(0, width - cls._display_width(text))
        return text + (" " * padding)

    @classmethod
    def _format_table(cls, headers: list[str], rows: list[list[str]]) -> list[str]:
        widths = [cls._display_width(str(item)) for item in headers]
        for row in rows:
            for index, item in enumerate(row):
                widths[index] = max(widths[index], cls._display_width(str(item)))

        def _line(left: str, fill: str, mid: str, right: str) -> str:
            return left + mid.join(fill * (width + 2) for width in widths) + right

        def _row(items: list[str]) -> str:
            return "| " + " | ".join(cls._pad_cell(str(item), widths[index]) for index, item in enumerate(items)) + " |"

        output = [_line("+", "-", "+", "+"), _row(headers), _line("+", "-", "+", "+")]
        for row in rows:
            output.append(_row(row))
        output.append(_line("+", "-", "+", "+"))
        return output

    def summary_lines(self) -> list[str]:
        with self._lock:
            started_ts = self.started_at
            finished_ts = self.finished_at or time.time()
            started_at_text = datetime.fromtimestamp(started_ts).astimezone().isoformat(timespec="seconds")
            finished_at_text = datetime.fromtimestamp(finished_ts).astimezone().isoformat(timespec="seconds")
            duration_seconds = max(0, int(finished_ts - started_ts))
            used_mailboxes = max(0, int(self.initial_mailbox_total) - int(self.remaining_mailbox_total))
            mailbox_failures = max(0, used_mailboxes - self.success_count)
            mailbox_success_rate = (self.success_count / used_mailboxes * 100.0) if used_mailboxes > 0 else 0.0
            thread_ids = sorted(
                set(self.thread_attempts)
                | set(self.thread_successes)
                | set(self.thread_failures)
                | set(self.thread_environment_failures)
            )
            lines = ["========== 注册模式统计 =========="]

            summary_rows = [[
                self.provider_key,
                str(self.configured_threads),
                str(self.initial_mailbox_total),
                str(self.remaining_mailbox_total),
                str(used_mailboxes),
                str(self.success_count),
                str(mailbox_failures),
                str(self.environment_failure_count),
                f"{mailbox_success_rate:.1f}%",
                str(self.generated_files_count),
                f"{duration_seconds}s",
            ]]
            lines.append("总览：")
            lines.extend(
                self._format_table(
                    ["服务", "线程", "初始邮箱", "剩余邮箱", "已消耗", "成功", "耗邮箱失败", "环境失败", "成功率", "JSON", "耗时"],
                    summary_rows,
                )
            )
            lines.append(f"开始：{started_at_text}")
            lines.append(f"结束：{finished_at_text}")
            if self.last_success_email:
                lines.append(f"最后成功邮箱：{self.last_success_email}")
            if self.failure_reasons:
                reason_summary = ", ".join(
                    f"{reason}={count}" for reason, count in self.failure_reasons.most_common(3)
                )
                lines.append(f"主要失败原因：{reason_summary}")
            if thread_ids:
                thread_rows = [
                    [
                        str(tid),
                        str(self.thread_attempts.get(tid, 0)),
                        str(self.thread_successes.get(tid, 0)),
                        str(self.thread_failures.get(tid, 0)),
                        str(self.thread_environment_failures.get(tid, 0)),
                    ]
                    for tid in thread_ids
                ]
                lines.append("线程明细：")
                lines.extend(self._format_table(["线程", "尝试", "成功", "耗邮箱失败", "环境失败"], thread_rows))
            lines.append("================================")
            return lines


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
