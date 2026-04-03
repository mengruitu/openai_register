"""Token refresh, quota checks, cleanup, and pool movement helpers."""

from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import random
import threading
import time
from datetime import datetime
from typing import Any, Optional

from curl_cffi import requests

from ..auth.oauth import CLIENT_ID, TOKEN_URL, _post_form
from .common import (
    DEFAULT_TOKEN_CHECK_WORKERS,
    DEFAULT_TOKEN_REFRESH_SKEW_SECONDS,
    TokenUsageCheck,
    _build_unique_path,
    count_json_files,
    list_json_files,
    log_error,
    log_info,
    log_warn,
)
from ..auth.session_refresh import TokenRefreshManager

TOKEN_USAGE_CACHE_TTL_SECONDS = 600
TOKEN_USAGE_CACHE_MAX_SIZE = 512

_token_usage_cache_lock = threading.Lock()
TOKEN_USAGE_CACHE: dict[str, dict[str, Any]] = {}
TOKEN_USAGE_PENDING: dict[str, TokenUsageCheck] = {}


def _token_usage_file_signature(file_path: str) -> tuple[int, int]:
    stat = os.stat(file_path)
    return int(stat.st_mtime_ns), int(stat.st_size)


def _jwt_claims_no_verify(token: str) -> dict[str, Any]:
    if not token or token.count(".") < 2:
        return {}

    payload_b64 = token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _extract_account_identity(token_data: dict[str, Any]) -> tuple[str, str]:
    id_token = str(token_data.get("id_token") or "").strip()
    access_token = str(token_data.get("access_token") or "").strip()
    claims = _jwt_claims_no_verify(id_token) or _jwt_claims_no_verify(access_token)
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    profile_claims = claims.get("https://api.openai.com/profile") or {}
    account_id = str(
        auth_claims.get("chatgpt_account_id") or token_data.get("account_id") or ""
    ).strip()
    email = str(
        claims.get("email") or profile_claims.get("email") or token_data.get("email") or ""
    ).strip()
    return account_id, email


def _token_expired_soon(token_data: dict[str, Any], skew_seconds: int) -> bool:
    access_token = str(token_data.get("access_token") or "").strip()
    access_claims = _jwt_claims_no_verify(access_token)
    now_ts = int(time.time())

    exp_value = access_claims.get("exp")
    try:
        return int(exp_value) <= now_ts + max(0, skew_seconds)
    except (TypeError, ValueError):
        pass

    expired_value = str(token_data.get("expired") or "").strip()
    if not expired_value:
        return False

    try:
        expired_at = datetime.strptime(expired_value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False

    return int(expired_at.timestamp()) <= now_ts + max(0, skew_seconds)


def _persist_token_data(file_path: str, token_data: dict[str, Any]) -> None:
    with open(file_path, "w", encoding="utf-8") as file_obj:
        json.dump(token_data, file_obj, ensure_ascii=False, separators=(",", ":"))


def _resolve_runtime_proxy(
    explicit_proxy: Optional[str],
    token_data: Optional[dict[str, Any]] = None,
) -> Optional[str]:
    proxy_url = str(explicit_proxy or "").strip()
    if proxy_url:
        return proxy_url
    if token_data:
        proxy_url = str(token_data.get("registration_proxy_url") or "").strip()
        if proxy_url:
            return proxy_url
    return None


def _build_runtime_proxies(proxy_url: Optional[str]) -> Optional[dict[str, str]]:
    normalized = str(proxy_url or "").strip()
    if not normalized:
        return None
    return {"http": normalized, "https": normalized}


def _extract_error_code_and_message(resp: Any) -> tuple[str, str]:
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
        message = str(payload.get("message") or payload.get("error_description") or "").strip()
        return code, message

    return "", str(getattr(resp, "text", "") or "").strip()


def _refresh_access_token(
    file_path: str,
    token_data: dict[str, Any],
    timeout: int,
    proxy: Optional[str] = None,
) -> tuple[bool, dict[str, Any], bool, str]:
    refresh_token = str(token_data.get("refresh_token") or "").strip()
    session_token = str(token_data.get("session_token") or "").strip()
    oauth_client_id = str(token_data.get("client_id") or CLIENT_ID).strip() or CLIENT_ID
    runtime_proxy_url = _resolve_runtime_proxy(proxy, token_data)
    runtime_proxies = _build_runtime_proxies(runtime_proxy_url)
    if not refresh_token:
        if session_token:
            session_refresh = TokenRefreshManager(proxy_url=runtime_proxy_url).refresh_by_session_token(session_token)
            if session_refresh.success:
                updated_data = dict(token_data)
                updated_data["access_token"] = session_refresh.access_token
                updated_data["session_token"] = session_refresh.session_token or session_token
                if session_refresh.account_id:
                    updated_data["account_id"] = session_refresh.account_id
                if session_refresh.email:
                    updated_data["email"] = session_refresh.email
                updated_data["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                if session_refresh.expires_at is not None:
                    updated_data["expired"] = session_refresh.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                try:
                    _persist_token_data(file_path, updated_data)
                except Exception as exc:
                    return False, token_data, False, f"session_token 刷新成功但写回文件失败: {exc}"
                return True, updated_data, False, "access_token 已通过 session_token 刷新"
            return (
                False,
                token_data,
                True,
                session_refresh.error_message or "缺少 refresh_token，且 session_token 刷新失败",
            )
        return False, token_data, True, "缺少 refresh_token，无法刷新 access_token"

    try:
        resp = requests.post(
            TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": oauth_client_id,
                "refresh_token": refresh_token,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
            },
            impersonate="chrome",
            proxies=runtime_proxies,
            timeout=timeout,
        )
    except Exception as exc:
        try:
            payload = _post_form(
                TOKEN_URL,
                {
                    "grant_type": "refresh_token",
                    "client_id": oauth_client_id,
                    "refresh_token": refresh_token,
                },
                timeout=timeout,
                proxies=runtime_proxies,
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
            if is_auth_invalid and session_token:
                session_refresh = TokenRefreshManager(proxy_url=runtime_proxy_url).refresh_by_session_token(session_token)
                if session_refresh.success:
                    updated_data = dict(token_data)
                    updated_data["access_token"] = session_refresh.access_token
                    updated_data["session_token"] = session_refresh.session_token or session_token
                    if session_refresh.account_id:
                        updated_data["account_id"] = session_refresh.account_id
                    if session_refresh.email:
                        updated_data["email"] = session_refresh.email
                    updated_data["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    if session_refresh.expires_at is not None:
                        updated_data["expired"] = session_refresh.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                    try:
                        _persist_token_data(file_path, updated_data)
                    except Exception as write_exc:
                        return False, token_data, False, f"session_token 回退刷新成功但写回失败: {write_exc}"
                    return True, updated_data, False, "access_token 已通过 session_token 回退刷新"
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
            if is_auth_invalid and session_token:
                session_refresh = TokenRefreshManager(proxy_url=runtime_proxy_url).refresh_by_session_token(session_token)
                if session_refresh.success:
                    updated_data = dict(token_data)
                    updated_data["access_token"] = session_refresh.access_token
                    updated_data["session_token"] = session_refresh.session_token or session_token
                    if session_refresh.account_id:
                        updated_data["account_id"] = session_refresh.account_id
                    if session_refresh.email:
                        updated_data["email"] = session_refresh.email
                    updated_data["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    if session_refresh.expires_at is not None:
                        updated_data["expired"] = session_refresh.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                    try:
                        _persist_token_data(file_path, updated_data)
                    except Exception as write_exc:
                        return False, token_data, False, f"session_token 回退刷新成功但写回失败: {write_exc}"
                    return True, updated_data, False, "access_token 已通过 session_token 回退刷新"
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

    now_ts = int(time.time())
    updated_data["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts))

    try:
        expires_in = int(float(payload.get("expires_in") or 0))
    except (TypeError, ValueError):
        expires_in = 0
    if expires_in > 0:
        updated_data["expired"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts + expires_in))

    try:
        _persist_token_data(file_path, updated_data)
    except Exception as exc:
        return False, token_data, False, f"刷新 access_token 后写回文件失败: {exc}"

    return True, updated_data, False, "access_token 已刷新"


def _request_used_percent(
    file_path: str,
    token_data: dict[str, Any],
    timeout: int,
    proxy: Optional[str] = None,
) -> tuple[Optional[int], bool, str]:
    access_token = str(token_data.get("access_token") or "").strip()
    account_id = str(token_data.get("account_id") or "").strip()
    if not access_token or not account_id:
        return None, True, "缺少 access_token 或 account_id"
    runtime_proxy_url = _resolve_runtime_proxy(proxy, token_data)
    runtime_proxies = _build_runtime_proxies(runtime_proxy_url)

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
            proxies=runtime_proxies,
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


def _cache_proxy_key(proxy: Optional[str]) -> str:
    return str(proxy or "").strip()


def _get_cached_token_usage_check(
    file_path: str,
    proxy: Optional[str],
) -> tuple[bool, Optional[TokenUsageCheck], Optional[tuple[int, int]]]:
    now_ts = time.time()
    try:
        signature = _token_usage_file_signature(file_path)
    except OSError as exc:
        log_error(f"读取 {os.path.basename(file_path)} 失败: {exc}")
        return True, None, None

    proxy_key = _cache_proxy_key(proxy)
    with _token_usage_cache_lock:
        cached = TOKEN_USAGE_CACHE.get(file_path)
        if (
            cached
            and cached.get("signature") == signature
            and cached.get("proxy_key") == proxy_key
            and now_ts - float(cached.get("checked_at") or 0) <= TOKEN_USAGE_CACHE_TTL_SECONDS
        ):
            return True, cached.get("result"), signature

    return False, None, signature


def _store_cached_token_usage_check(
    file_path: str,
    signature: Optional[tuple[int, int]],
    result: Optional[TokenUsageCheck],
    proxy: Optional[str],
) -> None:
    if signature is None:
        return

    if result is None:
        with _token_usage_cache_lock:
            TOKEN_USAGE_CACHE.pop(file_path, None)
        return

    now_ts = time.time()
    with _token_usage_cache_lock:
        TOKEN_USAGE_CACHE[file_path] = {
            "signature": signature,
            "result": result,
            "checked_at": now_ts,
            "proxy_key": _cache_proxy_key(proxy),
        }
        if len(TOKEN_USAGE_CACHE) > TOKEN_USAGE_CACHE_MAX_SIZE:
            expire_before = now_ts - (TOKEN_USAGE_CACHE_TTL_SECONDS * 2)
            for cached_path, cached in list(TOKEN_USAGE_CACHE.items()):
                if float(cached.get("checked_at") or 0) < expire_before:
                    TOKEN_USAGE_CACHE.pop(cached_path, None)
            if len(TOKEN_USAGE_CACHE) > TOKEN_USAGE_CACHE_MAX_SIZE:
                sorted_keys = sorted(
                    TOKEN_USAGE_CACHE.keys(),
                    key=lambda key: float(TOKEN_USAGE_CACHE[key].get("checked_at") or 0),
                )
                to_remove = len(TOKEN_USAGE_CACHE) - TOKEN_USAGE_CACHE_MAX_SIZE
                for key in sorted_keys[:to_remove]:
                    TOKEN_USAGE_CACHE.pop(key, None)


def get_token_usage_check(
    file_path: str,
    timeout: int,
    proxy: Optional[str] = None,
) -> TokenUsageCheck:
    has_cached, cached_value, signature = _get_cached_token_usage_check(file_path, proxy)
    if has_cached:
        return cached_value or TokenUsageCheck(
            used_percent=None,
            should_delete=False,
            check_failed=True,
            reason="额度查询缓存缺失",
        )

    try:
        with open(file_path, "r", encoding="utf-8") as file_obj:
            data = json.load(file_obj)
    except Exception as exc:
        result = TokenUsageCheck(
            used_percent=None,
            should_delete=True,
            check_failed=True,
            reason=f"读取失败: {exc}",
        )
        _store_cached_token_usage_check(file_path, signature, result, proxy)
        return result

    refreshed = False
    if (
        not str(data.get("access_token") or "").strip()
        or not str(data.get("account_id") or "").strip()
        or _token_expired_soon(data, DEFAULT_TOKEN_REFRESH_SKEW_SECONDS)
    ):
        is_refreshed, data, should_delete, reason = _refresh_access_token(
            file_path,
            data,
            timeout,
            proxy,
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
            _store_cached_token_usage_check(file_path, signature, result, proxy)
            return result

    used_percent, is_auth_invalid, reason = _request_used_percent(
        file_path,
        data,
        timeout,
        proxy,
    )
    if used_percent is None and is_auth_invalid and not refreshed:
        is_refreshed, data, should_delete, refresh_reason = _refresh_access_token(
            file_path,
            data,
            timeout,
            proxy,
        )
        refreshed = is_refreshed
        if is_refreshed:
            used_percent, is_auth_invalid, reason = _request_used_percent(
                file_path,
                data,
                timeout,
                proxy,
            )
        else:
            result = TokenUsageCheck(
                used_percent=None,
                should_delete=should_delete,
                check_failed=True,
                reason=refresh_reason,
                refreshed=False,
            )
            _store_cached_token_usage_check(file_path, signature, result, proxy)
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

    _store_cached_token_usage_check(file_path, signature, result, proxy)
    return result


def _process_single_usage_check(
    file_path: str,
    label: str,
    usage_threshold: int,
    pending: Optional[dict[str, TokenUsageCheck]] = None,
) -> tuple[str, int, int, int]:
    kept = 0
    deleted = 0
    failed = 0
    source = pending if pending is not None else TOKEN_USAGE_PENDING
    usage_check = source.get(file_path)
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


def _check_and_store(
    file_path: str,
    timeout: int,
    proxy: Optional[str] = None,
    pending: Optional[dict[str, TokenUsageCheck]] = None,
) -> None:
    try:
        result = get_token_usage_check(file_path, timeout, proxy)
    except Exception as exc:
        result = TokenUsageCheck(
            used_percent=None,
            should_delete=False,
            check_failed=True,
            reason=f"并发额度查询异常: {exc}",
        )
    target = pending if pending is not None else TOKEN_USAGE_PENDING
    target[file_path] = result


def _cleanup_tokens_in_dir(
    directory: str,
    label: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
    proxy: Optional[str] = None,
) -> tuple[int, int, int]:
    deleted_count = 0
    kept_count = 0
    check_failed = 0

    file_paths = list_json_files(directory)
    batch_size = max(1, int(token_check_workers or 1))

    for batch_start in range(0, len(file_paths), batch_size):
        batch_t0 = time.monotonic()
        batch = file_paths[batch_start : batch_start + batch_size]
        pending: dict[str, TokenUsageCheck] = {}

        if len(batch) == 1:
            _check_and_store(batch[0], curl_timeout, proxy, pending)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(batch)) as executor:
                futures = [
                    executor.submit(_check_and_store, file_path, curl_timeout, proxy, pending)
                    for file_path in batch
                ]
                concurrent.futures.wait(futures)

        for file_path in batch:
            _, kept, deleted, failed = _process_single_usage_check(
                file_path,
                label,
                usage_threshold,
                pending,
            )
            kept_count += kept
            deleted_count += deleted
            check_failed += failed

        del pending

        if request_interval > 0 and batch_start + batch_size < len(file_paths):
            elapsed = time.monotonic() - batch_t0
            remaining = request_interval - elapsed
            if remaining > 0:
                time.sleep(remaining)

    return kept_count, deleted_count, check_failed


def cleanup_active_tokens(
    active_dir: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
    proxy: Optional[str] = None,
) -> tuple[int, int, int]:
    return _cleanup_tokens_in_dir(
        active_dir,
        "A",
        usage_threshold,
        request_interval,
        curl_timeout,
        token_check_workers,
        proxy,
    )


def cleanup_pool_tokens(
    pool_dir: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
    proxy: Optional[str] = None,
) -> tuple[int, int, int]:
    return _cleanup_tokens_in_dir(
        pool_dir,
        "B",
        usage_threshold,
        request_interval,
        curl_timeout,
        token_check_workers,
        proxy,
    )


def move_pool_tokens_to_active(
    active_dir: str,
    pool_dir: str,
    active_target: int,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
    token_check_workers: int = DEFAULT_TOKEN_CHECK_WORKERS,
    proxy: Optional[str] = None,
) -> tuple[int, int]:
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

        batch_t0 = time.monotonic()
        batch = pool_files[batch_start : batch_start + batch_size]
        pending: dict[str, TokenUsageCheck] = {}

        if len(batch) == 1:
            _check_and_store(batch[0], curl_timeout, proxy, pending)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(batch)) as executor:
                futures = [
                    executor.submit(_check_and_store, file_path, curl_timeout, proxy, pending)
                    for file_path in batch
                ]
                concurrent.futures.wait(futures)

        for file_path in batch:
            if moved_count >= needed:
                break

            usage_check = pending.get(file_path)
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
                destination = _build_unique_path(active_dir, os.path.basename(file_path))
                os.replace(file_path, destination)
                moved_count += 1
                log_info(f"从 B 补充到 A: {os.path.basename(destination)}")

        del pending

        if request_interval > 0 and batch_start + batch_size < len(pool_files):
            elapsed = time.monotonic() - batch_t0
            remaining = request_interval - elapsed
            if remaining > 0:
                time.sleep(remaining)

    return moved_count, deleted_count


__all__ = [
    "DEFAULT_TOKEN_CHECK_WORKERS",
    "TOKEN_USAGE_CACHE",
    "TOKEN_USAGE_CACHE_MAX_SIZE",
    "TOKEN_USAGE_CACHE_TTL_SECONDS",
    "TOKEN_USAGE_PENDING",
    "cleanup_active_tokens",
    "cleanup_pool_tokens",
    "get_token_usage_check",
    "move_pool_tokens_to_active",
]
