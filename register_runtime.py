import base64
import builtins
import concurrent.futures
import json
import logging
import os
import random
import re
import shutil
import threading
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Dict, List, Optional, Tuple

from curl_cffi import requests

from register_auth import CLIENT_ID, TOKEN_URL, _post_form
from register_notifications import build_monitor_summary_message, send_dingtalk_alert

DEFAULT_TOKEN_CHECK_WORKERS = 2
TOKEN_USAGE_CACHE_TTL_SECONDS = 600
TOKEN_USAGE_CACHE_MAX_SIZE = 512
DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS = 900
DEFAULT_TOKEN_REFRESH_SKEW_SECONDS = 300
ACCOUNTS_FILE_MAX_BYTES = 50 * 1024 * 1024  # 50 MB
ACCOUNTS_FILE_BACKUP_COUNT = 5
# 检测到库存缺口时的最短重试间隔（秒），避免等满整个 monitor_interval
SHORTAGE_FAST_RETRY_SECONDS = 60
# 检测到缺口但补号全部失败时的等待间隔（秒），防止空转
SHORTAGE_FAIL_RETRY_SECONDS = 120

output_lock = threading.Lock()
_token_usage_cache_lock = threading.Lock()
TOKEN_USAGE_CACHE: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# 日志配置：使用 RotatingFileHandler 实现自动轮转，同时保留控制台输出
# ---------------------------------------------------------------------------
_LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "register.log")
_LOG_MAX_BYTES = 50 * 1024 * 1024  # 单个日志文件最大 50 MB
_LOG_BACKUP_COUNT = 5  # 最多保留 5 个旧日志文件

os.makedirs(_LOG_DIR, exist_ok=True)

logger = logging.getLogger("openai_register")
logger.setLevel(logging.DEBUG)

# 文件 Handler —— 自动轮转
_file_handler = RotatingFileHandler(
    _LOG_FILE,
    maxBytes=_LOG_MAX_BYTES,
    backupCount=_LOG_BACKUP_COUNT,
    encoding="utf-8",
)
_file_handler.setLevel(logging.DEBUG)
_file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT))
logger.addHandler(_file_handler)

# 控制台 Handler
_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT))
logger.addHandler(_console_handler)

RegisterRunner = Callable[..., Tuple[Optional[Tuple[str, str]], str]]
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
    base_name = _safe_token_filename(email, thread_id)
    return _build_unique_path(token_dir, base_name)


def list_json_files(directory: str) -> List[str]:
    if not os.path.isdir(directory):
        return []

    files = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if name.endswith(".json") and os.path.isfile(path):
            files.append(path)
    return files


def count_json_files(directory: str) -> int:
    return len(list_json_files(directory))


def _token_usage_file_signature(file_path: str) -> Tuple[int, int]:
    stat = os.stat(file_path)
    return int(stat.st_mtime_ns), int(stat.st_size)


def _jwt_claims_no_verify(token: str) -> Dict[str, Any]:
    if not token or token.count(".") < 2:
        return {}

    payload_b64 = token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _extract_account_identity(token_data: Dict[str, Any]) -> Tuple[str, str]:
    id_token = str(token_data.get("id_token") or "").strip()
    access_token = str(token_data.get("access_token") or "").strip()
    claims = _jwt_claims_no_verify(id_token) or _jwt_claims_no_verify(access_token)
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    profile_claims = claims.get("https://api.openai.com/profile") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or token_data.get("account_id") or "").strip()
    email = str(claims.get("email") or profile_claims.get("email") or token_data.get("email") or "").strip()
    return account_id, email


def _token_expired_soon(token_data: Dict[str, Any], skew_seconds: int) -> bool:
    access_token = str(token_data.get("access_token") or "").strip()
    access_claims = _jwt_claims_no_verify(access_token)
    now = int(time.time())

    exp_value = access_claims.get("exp")
    try:
        if int(exp_value) <= now + max(0, skew_seconds):
            return True
        return False
    except (TypeError, ValueError):
        pass

    expired_value = str(token_data.get("expired") or "").strip()
    if not expired_value:
        return False

    try:
        expired_at = datetime.strptime(expired_value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False

    return int(expired_at.timestamp()) <= now + max(0, skew_seconds)


def _persist_token_data(file_path: str, token_data: Dict[str, Any]) -> None:
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(token_data, f, ensure_ascii=False, separators=(",", ":"))


def _extract_error_code_and_message(resp: Any) -> Tuple[str, str]:
    try:
        payload = resp.json()
    except Exception:
        payload = {}

    if isinstance(payload, dict):
        error_obj = payload.get("error")
        if isinstance(error_obj, dict):
            code = str(error_obj.get("code") or error_obj.get("error") or "").strip()
            message = str(
                error_obj.get("message")
                or error_obj.get("description")
                or error_obj.get("error_description")
                or ""
            ).strip()
            return code, message

        code = str(payload.get("code") or payload.get("error") or "").strip()
        message = str(
            payload.get("message") or payload.get("error_description") or ""
        ).strip()
        return code, message

    return "", str(getattr(resp, "text", "") or "").strip()


def _refresh_access_token(
    file_path: str,
    token_data: Dict[str, Any],
    timeout: int,
) -> Tuple[bool, Dict[str, Any], bool, str]:
    refresh_token = str(token_data.get("refresh_token") or "").strip()
    if not refresh_token:
        return False, token_data, True, "缺少 refresh_token，无法刷新 access_token"

    try:
        resp = requests.post(
            TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_token,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
            },
            impersonate="chrome",
            timeout=timeout,
        )
    except Exception as exc:
        try:
            payload = _post_form(
                TOKEN_URL,
                {
                    "grant_type": "refresh_token",
                    "client_id": CLIENT_ID,
                    "refresh_token": refresh_token,
                },
                timeout=timeout,
            )
        except Exception as fallback_exc:
            error_text = str(fallback_exc or exc)
            is_auth_invalid = any(
                marker in error_text.lower()
                for marker in (
                    "invalid_grant",
                    "invalid_refresh",
                    "refresh_token_reused",
                    "token_expired",
                    "token exchange failed: 401",
                )
            )
            return False, token_data, is_auth_invalid, f"刷新 access_token 失败: {error_text}"
    else:
        if resp.status_code != 200:
            error_code, error_message = _extract_error_code_and_message(resp)
            detail = error_code or error_message or "未知错误"
            is_auth_invalid = resp.status_code in {400, 401} and any(
                marker in f"{error_code} {error_message}".lower()
                for marker in (
                    "invalid_grant",
                    "invalid_refresh",
                    "refresh_token_reused",
                    "token_expired",
                    "unauthorized",
                )
            )
            return (
                False,
                token_data,
                is_auth_invalid,
                f"刷新 access_token 失败，状态码: {resp.status_code}，详情: {detail}",
            )

        try:
            payload = resp.json()
        except Exception as exc:
            return False, token_data, False, f"刷新 access_token 响应解析失败: {exc}"

    new_access_token = str(payload.get("access_token") or "").strip()
    if not new_access_token:
        return False, token_data, False, "刷新 access_token 成功但响应缺少 access_token"

    updated_data = dict(token_data)
    updated_data["access_token"] = new_access_token

    new_refresh_token = str(payload.get("refresh_token") or "").strip()
    if new_refresh_token:
        updated_data["refresh_token"] = new_refresh_token

    new_id_token = str(payload.get("id_token") or "").strip()
    if new_id_token:
        updated_data["id_token"] = new_id_token

    account_id, email = _extract_account_identity(updated_data)
    if account_id:
        updated_data["account_id"] = account_id
    if email:
        updated_data["email"] = email

    now = int(time.time())
    updated_data["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    try:
        expires_in = int(float(payload.get("expires_in") or 0))
    except (TypeError, ValueError):
        expires_in = 0
    if expires_in > 0:
        updated_data["expired"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + expires_in)
        )

    try:
        _persist_token_data(file_path, updated_data)
    except Exception as exc:
        return False, token_data, False, f"刷新 access_token 后写回文件失败: {exc}"

    return True, updated_data, False, "access_token 已刷新"


def _request_used_percent(
    file_path: str,
    token_data: Dict[str, Any],
    timeout: int,
) -> Tuple[Optional[int], bool, str]:
    access_token = str(token_data.get("access_token") or "").strip()
    account_id = str(token_data.get("account_id") or "").strip()
    if not access_token or not account_id:
        return None, True, "缺少 access_token 或 account_id"

    try:
        resp = requests.get(
            "https://chatgpt.com/backend-api/wham/usage",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
                "Chatgpt-Account-Id": account_id,
            },
            impersonate="chrome",
            timeout=timeout,
        )
    except Exception as exc:
        return None, False, f"额度查询异常: {exc}"

    if resp.status_code != 200:
        error_code, error_message = _extract_error_code_and_message(resp)
        detail = error_code or error_message or "未知错误"
        is_auth_invalid = resp.status_code == 401 and any(
            marker in f"{error_code} {error_message}".lower()
            for marker in (
                "token_expired",
                "authentication token",
                "unauthorized",
                "account_deactivated",
                "deactivated",
                "account_disabled",
                "account_not_found",
            )
        )
        return None, is_auth_invalid, f"额度查询失败，状态码: {resp.status_code}，详情: {detail}"

    try:
        payload = resp.json()
    except Exception as exc:
        return None, False, f"额度查询响应解析失败: {exc}"

    used_percent = (((payload or {}).get("rate_limit") or {}).get("primary_window") or {}).get(
        "used_percent"
    )
    if used_percent is None:
        return None, False, "额度结果缺少 used_percent"

    try:
        return int(float(used_percent)), False, ""
    except (TypeError, ValueError):
        return None, False, f"额度结果中的 used_percent 非法: {used_percent}"


def _get_cached_token_usage_check(
    file_path: str,
) -> Tuple[bool, Optional[TokenUsageCheck], Optional[Tuple[int, int]]]:
    now = time.time()
    try:
        signature = _token_usage_file_signature(file_path)
    except OSError as exc:
        log_error(f"读取 {os.path.basename(file_path)} 失败: {exc}")
        return True, None, None

    with _token_usage_cache_lock:
        cached = TOKEN_USAGE_CACHE.get(file_path)
        if (
            cached
            and cached.get("signature") == signature
            and now - float(cached.get("checked_at") or 0) <= TOKEN_USAGE_CACHE_TTL_SECONDS
        ):
            return True, cached.get("result"), signature

    return False, None, signature


def _store_cached_token_usage_check(
    file_path: str,
    signature: Optional[Tuple[int, int]],
    result: Optional[TokenUsageCheck],
) -> None:
    if signature is None:
        return

    if result is None:
        with _token_usage_cache_lock:
            TOKEN_USAGE_CACHE.pop(file_path, None)
        return

    now = time.time()
    with _token_usage_cache_lock:
        TOKEN_USAGE_CACHE[file_path] = {
            "signature": signature,
            "result": result,
            "checked_at": now,
        }
        if len(TOKEN_USAGE_CACHE) > TOKEN_USAGE_CACHE_MAX_SIZE:
            # 第一轮：按 TTL 清理过期项
            expire_before = now - (TOKEN_USAGE_CACHE_TTL_SECONDS * 2)
            for cached_path, cached in list(TOKEN_USAGE_CACHE.items()):
                if float(cached.get("checked_at") or 0) < expire_before:
                    TOKEN_USAGE_CACHE.pop(cached_path, None)
            # 第二轮：如仍超限，按 LRU 淘汰最旧条目直到回到硬上限
            if len(TOKEN_USAGE_CACHE) > TOKEN_USAGE_CACHE_MAX_SIZE:
                sorted_keys = sorted(
                    TOKEN_USAGE_CACHE.keys(),
                    key=lambda k: float(TOKEN_USAGE_CACHE[k].get("checked_at") or 0),
                )
                to_remove = len(TOKEN_USAGE_CACHE) - TOKEN_USAGE_CACHE_MAX_SIZE
                for key in sorted_keys[:to_remove]:
                    TOKEN_USAGE_CACHE.pop(key, None)


def get_token_usage_check(file_path: str, timeout: int) -> TokenUsageCheck:
    has_cached, cached_value, signature = _get_cached_token_usage_check(file_path)
    if has_cached:
        return cached_value or TokenUsageCheck(
            used_percent=None,
            should_delete=False,
            check_failed=True,
            reason="额度查询缓存缺失",
        )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        result = TokenUsageCheck(
            used_percent=None,
            should_delete=True,
            check_failed=True,
            reason=f"读取失败: {exc}",
        )
        _store_cached_token_usage_check(file_path, signature, result)
        return result

    refreshed = False
    if (
        not str(data.get("access_token") or "").strip()
        or not str(data.get("account_id") or "").strip()
        or _token_expired_soon(data, DEFAULT_TOKEN_REFRESH_SKEW_SECONDS)
    ):
        is_refreshed, data, should_delete, reason = _refresh_access_token(
            file_path, data, timeout
        )
        refreshed = is_refreshed
        if not is_refreshed:
            result = TokenUsageCheck(
                used_percent=None,
                should_delete=should_delete,
                check_failed=True,
                reason=reason,
                refreshed=False,
            )
            _store_cached_token_usage_check(file_path, signature, result)
            return result

    used_percent, is_auth_invalid, reason = _request_used_percent(file_path, data, timeout)
    if used_percent is None and is_auth_invalid and not refreshed:
        is_refreshed, data, should_delete, refresh_reason = _refresh_access_token(
            file_path, data, timeout
        )
        refreshed = is_refreshed
        if is_refreshed:
            used_percent, is_auth_invalid, reason = _request_used_percent(
                file_path, data, timeout
            )
        else:
            result = TokenUsageCheck(
                used_percent=None,
                should_delete=should_delete,
                check_failed=True,
                reason=refresh_reason,
                refreshed=False,
            )
            _store_cached_token_usage_check(file_path, signature, result)
            return result

    if used_percent is not None:
        result = TokenUsageCheck(
            used_percent=used_percent,
            should_delete=False,
            check_failed=False,
            refreshed=refreshed,
        )
    else:
        result = TokenUsageCheck(
            used_percent=None,
            should_delete=is_auth_invalid,
            check_failed=True,
            reason=reason,
            refreshed=refreshed,
        )

    _store_cached_token_usage_check(file_path, signature, result)
    return result


def _rotate_accounts_file(file_path: str) -> None:
    """当 accounts.txt 超过大小上限时，自动归档为 .1/.2/... 文件。"""
    try:
        if not os.path.isfile(file_path):
            return
        if os.path.getsize(file_path) < ACCOUNTS_FILE_MAX_BYTES:
            return
    except OSError:
        return

    # 删除最旧的备份
    oldest = f"{file_path}.{ACCOUNTS_FILE_BACKUP_COUNT}"
    if os.path.isfile(oldest):
        try:
            os.remove(oldest)
        except OSError:
            pass

    # 依次重命名 .4 -> .5, .3 -> .4, ...
    for i in range(ACCOUNTS_FILE_BACKUP_COUNT - 1, 0, -1):
        src = f"{file_path}.{i}"
        dst = f"{file_path}.{i + 1}"
        if os.path.isfile(src):
            try:
                shutil.move(src, dst)
            except OSError:
                pass

    # 当前文件 -> .1
    try:
        shutil.move(file_path, f"{file_path}.1")
    except OSError:
        pass


def persist_registration_result(
    token_json: str, password: str, thread_id: int, token_dir: str
) -> Tuple[str, str]:
    try:
        token_data = json.loads(token_json)
        raw_email = str(token_data.get("email") or "unknown")
        refresh_token = str(token_data.get("refresh_token") or "")
    except Exception:
        raw_email = "unknown"
        refresh_token = ""

    os.makedirs(token_dir, exist_ok=True)
    file_name = _build_token_output_path(token_dir, raw_email, thread_id)
    with open(file_name, "w", encoding="utf-8") as f:
        f.write(token_json)

    os.makedirs("output", exist_ok=True)
    accounts_path = os.path.join("output", "accounts.txt")
    with output_lock:
        _rotate_accounts_file(accounts_path)
        with open(accounts_path, "a", encoding="utf-8") as f:
            f.write(f"{raw_email}----{password}----{refresh_token}\n")

    return file_name, raw_email


def _process_single_usage_check(
    file_path: str,
    label: str,
    usage_threshold: int,
) -> Tuple[str, int, int, int]:
    """处理单个文件的额度检查结果，返回 (action, kept, deleted, failed)。"""
    kept = 0
    deleted = 0
    failed = 0
    usage_check = TOKEN_USAGE_PENDING.get(file_path)
    if usage_check is None:
        return "skip", 0, 0, 0

    used_percent = usage_check.used_percent

    if used_percent is None:
        if usage_check.check_failed:
            failed = 1
        if usage_check.should_delete:
            log_warn(
                f"删除 {label} 中的 {os.path.basename(file_path)}，"
                f"{usage_check.reason or '额度查询失败'}"
            )
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
            deleted = 1
        else:
            kept = 1
            log_warn(
                f"保留 {label} 中的 {os.path.basename(file_path)}，"
                f"本轮额度查询失败，暂不删除："
                f"{usage_check.reason or '未知原因'}"
            )
    elif used_percent >= usage_threshold:
        log_info(
            f"删除 {label} 中的 {os.path.basename(file_path)}，"
            f"已用比例 {used_percent}% >= {usage_threshold}%"
        )
        try:
            os.remove(file_path)
        except FileNotFoundError:
            pass
        deleted = 1
    else:
        kept = 1

    return "done", kept, deleted, failed


# 临时字典，用于在小批量并发中传递检查结果
TOKEN_USAGE_PENDING: Dict[str, TokenUsageCheck] = {}


def _check_and_store(file_path: str, timeout: int) -> None:
    """在线程中执行检查并将结果存入临时字典。"""
    try:
        result = get_token_usage_check(file_path, timeout)
    except Exception as exc:
        result = TokenUsageCheck(
            used_percent=None,
            should_delete=False,
            check_failed=True,
            reason=f"并发额度查询异常: {exc}",
        )
    TOKEN_USAGE_PENDING[file_path] = result


def _cleanup_tokens_in_dir(
    directory: str,
    label: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
) -> Tuple[int, int, int]:
    """小批量并发检查账号并立即处理，兼顾速度与内存。

    每批最多 token_check_workers 个文件并发请求，检查完立即处理结果
    并释放资源，然后再进入下一批。同一时刻内存中最多只有一批的数据。
    """
    deleted_count = 0
    kept_count = 0
    check_failed = 0

    file_paths = list_json_files(directory)
    batch_size = max(1, int(token_check_workers or 1))

    for batch_start in range(0, len(file_paths), batch_size):
        batch = file_paths[batch_start: batch_start + batch_size]
        TOKEN_USAGE_PENDING.clear()

        # 并发检查本批次文件
        if len(batch) == 1:
            _check_and_store(batch[0], curl_timeout)
        else:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(batch),
            ) as executor:
                futures = [
                    executor.submit(_check_and_store, fp, curl_timeout)
                    for fp in batch
                ]
                concurrent.futures.wait(futures)

        # 立即处理本批次结果并释放
        for file_path in batch:
            __, k, d, f = _process_single_usage_check(
                file_path, label, usage_threshold,
            )
            kept_count += k
            deleted_count += d
            check_failed += f

        TOKEN_USAGE_PENDING.clear()

        # 批次间按配置间隔控制请求频率
        if request_interval > 0 and batch_start + batch_size < len(file_paths):
            time.sleep(request_interval)

    return kept_count, deleted_count, check_failed


def cleanup_active_tokens(
    active_dir: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
) -> Tuple[int, int, int]:
    return _cleanup_tokens_in_dir(
        active_dir,
        "A",
        usage_threshold,
        request_interval,
        curl_timeout,
        token_check_workers,
    )


def cleanup_pool_tokens(
    pool_dir: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
) -> Tuple[int, int, int]:
    return _cleanup_tokens_in_dir(
        pool_dir,
        "B",
        usage_threshold,
        request_interval,
        curl_timeout,
        token_check_workers,
    )


def move_pool_tokens_to_active(
    active_dir: str,
    pool_dir: str,
    active_target: int,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
) -> Tuple[int, int]:
    """小批量并发检查 B 目录账号并按需搬移到 A。

    每批最多 token_check_workers 个文件并发请求，检查完立即处理
    并释放资源，然后再进入下一批。搬移够数后立即停止。
    """
    current_active = count_json_files(active_dir)
    needed = max(active_target - current_active, 0)
    if needed <= 0:
        return 0, 0

    moved_count = 0
    deleted_count = 0
    pool_files = list_json_files(pool_dir)
    random.shuffle(pool_files)
    batch_size = max(1, int(token_check_workers or 1))

    for batch_start in range(0, len(pool_files), batch_size):
        if moved_count >= needed:
            break

        batch = pool_files[batch_start: batch_start + batch_size]
        TOKEN_USAGE_PENDING.clear()

        # 并发检查本批次文件
        if len(batch) == 1:
            _check_and_store(batch[0], curl_timeout)
        else:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(batch),
            ) as executor:
                futures = [
                    executor.submit(_check_and_store, fp, curl_timeout)
                    for fp in batch
                ]
                concurrent.futures.wait(futures)

        # 立即处理本批次结果
        for file_path in batch:
            if moved_count >= needed:
                break

            usage_check = TOKEN_USAGE_PENDING.get(file_path)
            if usage_check is None:
                continue
            used_percent = usage_check.used_percent

            if used_percent is None:
                if usage_check.should_delete:
                    log_warn(
                        f"删除 B 中的 {os.path.basename(file_path)}，"
                        f"{usage_check.reason or '额度查询失败'}"
                    )
                    try:
                        os.remove(file_path)
                    except FileNotFoundError:
                        pass
                    deleted_count += 1
                else:
                    log_warn(
                        f"跳过从 B 补充 {os.path.basename(file_path)}，"
                        f"本轮额度查询失败，暂不删除："
                        f"{usage_check.reason or '未知原因'}"
                    )
            elif used_percent >= usage_threshold:
                log_info(
                    f"删除 B 中的 {os.path.basename(file_path)}，"
                    f"已用比例 {used_percent}% >= {usage_threshold}%"
                )
                try:
                    os.remove(file_path)
                except FileNotFoundError:
                    pass
                deleted_count += 1
            else:
                destination = _build_unique_path(
                    active_dir, os.path.basename(file_path),
                )
                os.replace(file_path, destination)
                moved_count += 1
                log_info(f"从 B 补充到 A: {os.path.basename(destination)}")

        TOKEN_USAGE_PENDING.clear()

        # 批次间按配置间隔控制请求频率
        if request_interval > 0 and batch_start + batch_size < len(pool_files):
            time.sleep(request_interval)

    return moved_count, deleted_count


def register_single_account(
    proxy: Optional[str],
    provider_key: str,
    thread_id: int,
    mailtm_base: str,
    token_dir: str,
    register_runner: RegisterRunner,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> bool:
    try:
        result, _used_provider = register_runner(
            proxy,
            provider_key,
            thread_id,
            mailtm_base,
            dingtalk_webhook=dingtalk_webhook,
            dingtalk_fallback_interval_seconds=dingtalk_fallback_interval_seconds,
        )
        if not result:
            log_warn(f"补号任务 #{thread_id} 失败")
            return False

        token_json, password = result
        persist_registration_result(token_json, password, thread_id, token_dir)
        return True
    except Exception as exc:
        log_error(f"补号任务 #{thread_id} 异常: {exc}")
        return False


def register_accounts(
    target_count: int,
    proxy: Optional[str],
    provider_key: str,
    mailtm_base: str,
    token_dir: str,
    batch_size: int,
    register_openai_concurrency: int,
    register_start_delay_seconds: float,
    auto_continue_non_us: bool,
    register_runner: RegisterRunner,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> int:
    if target_count <= 0:
        return 0

    if auto_continue_non_us and getattr(builtins, "yasal_bypass_ip_choice", None) is None:
        builtins.yasal_bypass_ip_choice = True

    success_count = 0
    attempts = 0
    batch_size = max(1, batch_size)
    register_openai_concurrency = max(1, register_openai_concurrency)
    register_start_delay_seconds = max(0.0, float(register_start_delay_seconds))
    max_attempts = max(target_count * 4, target_count + batch_size)

    while success_count < target_count and attempts < max_attempts:
        current_batch_size = min(
            batch_size,
            register_openai_concurrency,
            target_count - success_count,
            max_attempts - attempts,
        )
        batch_results: List[bool] = []
        batch_results_lock = threading.Lock()
        threads = []

        for index in range(current_batch_size):
            current_thread_id = attempts + index + 1

            def _task(tid: int = current_thread_id) -> None:
                is_success = register_single_account(
                    proxy,
                    provider_key,
                    tid,
                    mailtm_base,
                    token_dir,
                    register_runner,
                    dingtalk_webhook,
                    dingtalk_fallback_interval_seconds,
                )
                with batch_results_lock:
                    batch_results.append(is_success)

            thread = threading.Thread(target=_task)
            thread.daemon = True
            thread.start()
            threads.append(thread)
            if register_start_delay_seconds > 0 and index + 1 < current_batch_size:
                time.sleep(register_start_delay_seconds)

        for thread in threads:
            thread.join()

        attempts += current_batch_size
        batch_success = sum(1 for item in batch_results if item)
        success_count += batch_success
        log_info(
            f"补号批次完成：本批成功 {batch_success} 个，累计成功 {success_count}/{target_count}"
        )

        if batch_success == 0 and success_count < target_count:
            time.sleep(10)

    if success_count < target_count:
        log_warn(f"目标补号 {target_count} 个，实际仅补充成功 {success_count} 个")

    return success_count


def run_monitor_cycle(args: Any, register_runner: RegisterRunner) -> MonitorCycleResult:
    os.makedirs(args.active_token_dir, exist_ok=True)
    os.makedirs(args.token_dir, exist_ok=True)

    log_info("========== 开始执行账号检测 ==========")
    kept_count, deleted_count, check_failed = cleanup_active_tokens(
        args.active_token_dir,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
        args.token_check_workers,
    )
    log_info(f"A 清理完成：保留 {kept_count}，删除 {deleted_count}，查询失败 {check_failed}")

    pool_kept_count, pool_deleted_count, pool_check_failed = cleanup_pool_tokens(
        args.token_dir,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
        args.token_check_workers,
    )
    log_info(
        f"B 清理完成：保留 {pool_kept_count}，删除 {pool_deleted_count}，查询失败 {pool_check_failed}"
    )

    moved_before_register, deleted_from_pool_before = move_pool_tokens_to_active(
        args.active_token_dir,
        args.token_dir,
        args.active_min_count,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
        args.token_check_workers,
    )
    if moved_before_register > 0:
        log_info(f"首次从 B 补充到 A 共 {moved_before_register} 个")

    active_count = count_json_files(args.active_token_dir)
    pool_count = count_json_files(args.token_dir)
    active_shortage = max(args.active_min_count - active_count, 0)
    pool_shortage = max(args.pool_min_count - pool_count, 0)
    register_target = active_shortage + pool_shortage
    log_info(
        f"当前库存统计：A={active_count}/{args.active_min_count}（缺 {active_shortage}），"
        f"B={pool_count}/{args.pool_min_count}（缺 {pool_shortage}）"
    )
    replenished_count = 0
    replenished_to_active = 0
    replenished_to_pool = 0
    moved_after_register = 0
    deleted_from_pool_after = 0

    if register_target > 0:
        log_warn(
            f"检测到库存不足：A={active_count}/{args.active_min_count}，B={pool_count}/{args.pool_min_count}，准备补号 {register_target} 个"
        )
        if active_shortage > 0:
            log_info(
                f"A 目录存在缺口，优先直补 A：计划补 {active_shortage} 个到 {args.active_token_dir}"
            )
            replenished_to_active = register_accounts(
                active_shortage,
                args.proxy,
                args.mail_provider,
                args.mailtm_api_base,
                args.active_token_dir,
                args.register_batch_size,
                args.register_openai_concurrency,
                args.register_start_delay_seconds,
                args.auto_continue_non_us,
                register_runner,
                args.dingtalk_webhook,
                args.dingtalk_fallback_interval,
            )
            replenished_count += replenished_to_active
            log_info(
                f"A 直补完成：计划补 {active_shortage} 个，实际成功 {replenished_to_active} 个"
            )
            active_count = count_json_files(args.active_token_dir)
            pool_count = count_json_files(args.token_dir)

        remaining_active_shortage = max(args.active_min_count - active_count, 0)
        remaining_pool_shortage = max(args.pool_min_count - pool_count, 0)
        remaining_register_target = remaining_active_shortage + remaining_pool_shortage
        if remaining_register_target > 0:
            log_info(
                f"继续补充 B 目录：A 剩余缺口 {remaining_active_shortage}，"
                f"B 剩余缺口 {remaining_pool_shortage}，计划补 {remaining_register_target} 个到 {args.token_dir}"
            )
            replenished_to_pool = register_accounts(
                remaining_register_target,
                args.proxy,
                args.mail_provider,
                args.mailtm_api_base,
                args.token_dir,
                args.register_batch_size,
                args.register_openai_concurrency,
                args.register_start_delay_seconds,
                args.auto_continue_non_us,
                register_runner,
                args.dingtalk_webhook,
                args.dingtalk_fallback_interval,
            )
            replenished_count += replenished_to_pool

        log_info(
            f"注册补号完成：总计划补 {register_target} 个，"
            f"A 直补成功 {replenished_to_active} 个，"
            f"B 补号成功 {replenished_to_pool} 个，"
            f"总成功 {replenished_count} 个"
        )
        if replenished_count > 0:
            moved_after_register, deleted_from_pool_after = move_pool_tokens_to_active(
                args.active_token_dir,
                args.token_dir,
                args.active_min_count,
                args.usage_threshold,
                args.request_interval,
                args.curl_timeout,
                args.token_check_workers,
            )
            if moved_after_register > 0:
                log_info(f"补号后再次从 B 补充到 A 共 {moved_after_register} 个")
    else:
        log_info(
            f"A/B 均已达标：A={active_count}/{args.active_min_count}，B={pool_count}/{args.pool_min_count}，本轮不补号"
        )

    final_active_count = count_json_files(args.active_token_dir)
    final_pool_count = count_json_files(args.token_dir)
    final_active_shortage = max(args.active_min_count - final_active_count, 0)
    final_pool_shortage = max(args.pool_min_count - final_pool_count, 0)
    total_deleted_count = (
        deleted_count
        + pool_deleted_count
        + deleted_from_pool_before
        + deleted_from_pool_after
    )
    log_info(
        f"本轮汇总：删 A={deleted_count}，删 B={pool_deleted_count + deleted_from_pool_before + deleted_from_pool_after}，"
        f"B→A={moved_before_register + moved_after_register}，注册成功={replenished_count}"
    )
    log_info(
        f"检测结束：A={final_active_count}/{args.active_min_count}（缺 {final_active_shortage}），"
        f"B={final_pool_count}/{args.pool_min_count}（缺 {final_pool_shortage}），补号={replenished_count}"
    )
    log_info("========== 账号检测执行完成 ==========")
    return MonitorCycleResult(
        completed_at=datetime.now(),
        active_count=final_active_count,
        pool_count=final_pool_count,
        active_target=args.active_min_count,
        pool_target=args.pool_min_count,
        active_shortage=final_active_shortage,
        pool_shortage=final_pool_shortage,
        attempted_replenish=register_target > 0,
        register_target=register_target,
        replenished_count=replenished_count,
        deleted_count=total_deleted_count,
        active_deleted_count=deleted_count,
        pool_deleted_count=pool_deleted_count + deleted_from_pool_before + deleted_from_pool_after,
        moved_to_active_count=moved_before_register + moved_after_register,
        active_check_failed=check_failed,
        pool_check_failed=pool_check_failed,
    )


def worker(
    thread_id: int,
    proxy: Optional[str],
    once: bool,
    sleep_min: int,
    sleep_max: int,
    failure_sleep_seconds: int,
    provider_key: str,
    mailtm_base: str,
    token_dir: str,
    register_runner: RegisterRunner,
    reload_cfmail_accounts: Optional[ReloadCfmailHook] = None,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> None:
    count = 0
    while True:
        if provider_key == "cfmail" and reload_cfmail_accounts:
            reload_cfmail_accounts()
        count += 1
        logger.info(
            f"[线程 {thread_id}] 开始第 {count} 次任务（邮箱服务: {provider_key}）"
        )

        try:
            result, used_provider = register_runner(
                proxy,
                provider_key,
                thread_id,
                mailtm_base,
                dingtalk_webhook=dingtalk_webhook,
                dingtalk_fallback_interval_seconds=dingtalk_fallback_interval_seconds,
            )

            is_success = False

            if result:
                token_json, password = result
                file_name, raw_email = persist_registration_result(
                    token_json,
                    password,
                    thread_id,
                    token_dir,
                )

                logger.info(
                    f"[线程 {thread_id}] 账号信息已追加到 output/accounts.txt，"
                    f"Token 已保存到: {file_name}（邮箱服务: {used_provider}）"
                )
                is_success = True
            else:
                logger.warning(f"[线程 {thread_id}] 本轮任务未成功")

        except Exception as e:
            logger.error(f"[线程 {thread_id}] 发生未捕获异常: {e}")
            logger.error(f"[线程 {thread_id}] {traceback.format_exc()}")
            is_success = False

        if once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        if not is_success:
            logger.info(
                f"[线程 {thread_id}] 本轮失败，额外等待 {failure_sleep_seconds} 秒后重试"
            )
            wait_time += max(0, failure_sleep_seconds)

        time.sleep(wait_time)


def run_monitor_loop(
    args: Any,
    register_runner: RegisterRunner,
    reload_cfmail_accounts: Optional[ReloadCfmailHook] = None,
) -> None:
    pending_results: List[MonitorCycleResult] = []
    summary_started_at = time.time()
    while True:
        if args.mail_provider == "cfmail" and reload_cfmail_accounts:
            reload_cfmail_accounts()
        cycle_started_at = time.time()
        try:
            cycle_result = run_monitor_cycle(args, register_runner)
            pending_results.append(cycle_result)
        except Exception as exc:
            log_error(f"检测循环异常: {exc}")
            cycle_result = None

        should_send_summary = False
        now_ts = time.time()
        if pending_results:
            if args.monitor_once:
                should_send_summary = True
            elif now_ts - summary_started_at >= args.dingtalk_summary_interval:
                should_send_summary = True

        if should_send_summary:
            summary_message = build_monitor_summary_message(pending_results)
            if summary_message:
                send_dingtalk_alert(args.dingtalk_webhook, summary_message)
                log_info(
                    f"已发送钉钉汇总通知，共汇总 {len(pending_results)} 轮检测结果"
                )
            pending_results = []
            summary_started_at = now_ts

        if args.monitor_once:
            break

        elapsed_seconds = int(time.time() - cycle_started_at)

        # 如果上一轮检测到仍有缺口（账号不足），缩短等待间隔以加快补号响应
        has_shortage = (
            cycle_result is not None
            and (cycle_result.active_shortage > 0 or cycle_result.pool_shortage > 0)
        )
        if has_shortage:
            attempted_but_failed = (
                cycle_result.attempted_replenish and cycle_result.replenished_count == 0
            )
            if attempted_but_failed:
                # 尝试补号但全部失败 → 适当延长，防止空转
                target_interval = max(
                    SHORTAGE_FAIL_RETRY_SECONDS,
                    args.monitor_interval // 3,
                )
            else:
                # 有缺口（可能部分补上了）→ 快速重试
                target_interval = max(
                    SHORTAGE_FAST_RETRY_SECONDS,
                    args.monitor_interval // 5,
                )
            sleep_seconds = max(1, target_interval - elapsed_seconds)
            log_info(
                f"检测到库存缺口（A 缺 {cycle_result.active_shortage}，"
                f"B 缺 {cycle_result.pool_shortage}），缩短等待间隔，"
                f"{sleep_seconds} 秒后进入下一轮检测"
            )
        else:
            sleep_seconds = max(1, args.monitor_interval - elapsed_seconds)
            log_info(f"等待 {sleep_seconds} 秒后进入下一轮检测")
        time.sleep(sleep_seconds)
