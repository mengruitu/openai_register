# -*- coding: utf-8 -*-
"""Shared file-backed proxy pool with cross-process coordination."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
import fcntl
import hashlib
import json
import logging
import os
import socket
import tempfile
import threading
import time
import uuid
from typing import Any, Iterator, Optional
from urllib.parse import urlparse

from .config import (
    DEFAULT_PROXY_POOL_CONSUMERS_PATH,
    DEFAULT_PROXY_POOL_CONSUMER_TTL_SECONDS,
    DEFAULT_PROXY_POOL_HEARTBEAT_INTERVAL_SECONDS,
    DEFAULT_PROXY_POOL_STATE_PATH,
    DEFAULT_PROXY_POOL_TARGET_MULTIPLIER,
)
from .proxy import fetch_proxies_from_api, generate_proxy_pool_candidates

logger = logging.getLogger("openai_register")

_POOL_SCHEMA_VERSION = 1
_CONSUMERS_SCHEMA_VERSION = 1
_RUNTIME_LOCK = threading.Lock()
_RUNTIME: Optional["ProxyPoolRuntime"] = None


class ProxyPoolExhaustedError(RuntimeError):
    """Raised when no proxy can be leased from the pool."""


@dataclass(frozen=True)
class ProxyPoolConfig:
    enabled: bool = False
    state_path: str = DEFAULT_PROXY_POOL_STATE_PATH
    consumers_path: str = DEFAULT_PROXY_POOL_CONSUMERS_PATH
    consumer_ttl_seconds: int = DEFAULT_PROXY_POOL_CONSUMER_TTL_SECONDS
    heartbeat_interval_seconds: int = DEFAULT_PROXY_POOL_HEARTBEAT_INTERVAL_SECONDS
    target_multiplier: int = DEFAULT_PROXY_POOL_TARGET_MULTIPLIER


@dataclass
class ProxyPoolRuntime:
    config: ProxyPoolConfig
    mode: str
    desired_threads: int
    proxy_api_url: str
    proxy_api_scheme: str
    static_proxy_url: str = ""
    consumer_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    pid: int = field(default_factory=os.getpid)
    host: str = field(default_factory=socket.gethostname)
    started_at: float = field(default_factory=time.time)
    stop_event: threading.Event = field(default_factory=threading.Event, repr=False)
    heartbeat_thread: Optional[threading.Thread] = field(default=None, repr=False)


def build_proxy_pool_config_from_args(args: object) -> ProxyPoolConfig:
    return ProxyPoolConfig(
        enabled=bool(getattr(args, "proxy_pool_enabled", False)),
        state_path=str(getattr(args, "proxy_pool_state_path", DEFAULT_PROXY_POOL_STATE_PATH) or "").strip()
        or DEFAULT_PROXY_POOL_STATE_PATH,
        consumers_path=str(
            getattr(args, "proxy_pool_consumers_path", DEFAULT_PROXY_POOL_CONSUMERS_PATH) or ""
        ).strip()
        or DEFAULT_PROXY_POOL_CONSUMERS_PATH,
        consumer_ttl_seconds=max(
            1,
            int(
                getattr(
                    args,
                    "proxy_pool_consumer_ttl_seconds",
                    DEFAULT_PROXY_POOL_CONSUMER_TTL_SECONDS,
                )
                or 0
            ),
        ),
        heartbeat_interval_seconds=max(
            1,
            int(
                getattr(
                    args,
                    "proxy_pool_heartbeat_interval_seconds",
                    DEFAULT_PROXY_POOL_HEARTBEAT_INTERVAL_SECONDS,
                )
                or 0
            ),
        ),
        target_multiplier=max(
            1,
            int(
                getattr(
                    args,
                    "proxy_pool_target_multiplier",
                    DEFAULT_PROXY_POOL_TARGET_MULTIPLIER,
                )
                or 0
            ),
        ),
    )


def _lock_path(config: ProxyPoolConfig) -> str:
    base_dir = os.path.dirname(os.path.abspath(config.state_path)) or os.getcwd()
    return os.path.join(base_dir, "proxy_pool.lock")


def _pool_state_default() -> dict[str, Any]:
    return {
        "schema_version": _POOL_SCHEMA_VERSION,
        "updated_at": "",
        "proxies": [],
        "last_refill_at": "",
        "last_refill_added": 0,
        "source_mode": "",
        "source_signature": "",
    }


def _consumers_state_default() -> dict[str, Any]:
    return {
        "schema_version": _CONSUMERS_SCHEMA_VERSION,
        "updated_at": "",
        "consumers": {},
    }


def _iso_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _ensure_parent_directory(path: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)


def _proxy_log_host(proxy_url: str) -> str:
    parsed = urlparse(str(proxy_url or "").strip())
    if parsed.hostname and parsed.port:
        return f"{parsed.hostname}:{parsed.port}"
    if parsed.hostname:
        return parsed.hostname
    return parsed.netloc or str(proxy_url or "").strip()


@contextmanager
def _exclusive_lock(config: ProxyPoolConfig) -> Iterator[None]:
    lock_path = _lock_path(config)
    _ensure_parent_directory(lock_path)
    with open(lock_path, "a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _load_json_file(path: str, default: dict[str, Any]) -> dict[str, Any]:
    _ensure_parent_directory(path)
    if not os.path.isfile(path):
        return dict(default)
    try:
        with open(path, "r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        if not isinstance(payload, dict):
            return dict(default)
        return payload
    except Exception as exc:
        logger.warning("读取代理池状态文件失败，已回退为空状态：path=%s error=%s", path, exc)
        return dict(default)


def _atomic_write_json(path: str, payload: dict[str, Any]) -> None:
    _ensure_parent_directory(path)
    directory = os.path.dirname(os.path.abspath(path)) or os.getcwd()
    fd, temp_path = tempfile.mkstemp(prefix=".proxy-pool-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False, indent=2, sort_keys=True)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def _normalize_pool_state(raw: dict[str, Any]) -> dict[str, Any]:
    payload = _pool_state_default()
    proxies = raw.get("proxies")
    if isinstance(proxies, list):
        deduped: list[str] = []
        seen: set[str] = set()
        for item in proxies:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        payload["proxies"] = deduped
    payload["last_refill_at"] = str(raw.get("last_refill_at") or "").strip()
    try:
        payload["last_refill_added"] = max(0, int(raw.get("last_refill_added") or 0))
    except Exception:
        payload["last_refill_added"] = 0
    payload["source_mode"] = str(raw.get("source_mode") or "").strip()
    payload["source_signature"] = str(raw.get("source_signature") or "").strip()
    payload["updated_at"] = str(raw.get("updated_at") or "").strip()
    return payload


def _build_source_identity(
    *,
    proxy_api_url: str,
    proxy_api_scheme: str,
    static_proxy_url: str,
) -> tuple[str, str]:
    static_proxy = str(static_proxy_url or "").strip()
    api_url = str(proxy_api_url or "").strip()
    api_scheme = str(proxy_api_scheme or "http").strip().lower() or "http"

    if static_proxy:
        raw = f"static:{static_proxy}"
        return "static", hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()
    if api_url:
        raw = f"api:{api_scheme}:{api_url}"
        return "api", hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()
    return "", ""


def _sync_pool_source(pool_state: dict[str, Any], runtime: ProxyPoolRuntime) -> bool:
    source_mode, source_signature = _build_source_identity(
        proxy_api_url=runtime.proxy_api_url,
        proxy_api_scheme=runtime.proxy_api_scheme,
        static_proxy_url=runtime.static_proxy_url,
    )
    current_mode = str(pool_state.get("source_mode") or "").strip()
    current_signature = str(pool_state.get("source_signature") or "").strip()
    changed = current_mode != source_mode or current_signature != source_signature
    if not changed:
        return False

    cached_count = len(pool_state.get("proxies") or [])
    if cached_count > 0:
        logger.info(
            "[proxy_pool] 检测到代理来源切换，已清空旧缓存：old_mode=%s new_mode=%s cached=%s",
            current_mode or "unknown",
            source_mode or "unknown",
            cached_count,
        )
    pool_state["proxies"] = []
    pool_state["last_refill_at"] = ""
    pool_state["last_refill_added"] = 0
    pool_state["source_mode"] = source_mode
    pool_state["source_signature"] = source_signature
    return True


def _normalize_consumers_state(raw: dict[str, Any]) -> dict[str, Any]:
    payload = _consumers_state_default()
    consumers = raw.get("consumers")
    if not isinstance(consumers, dict):
        return payload

    normalized_consumers: dict[str, dict[str, Any]] = {}
    for consumer_id, item in consumers.items():
        if not isinstance(item, dict):
            continue
        key = str(consumer_id or "").strip()
        if not key:
            continue
        try:
            desired_threads = max(1, int(item.get("desired_threads") or 0))
            heartbeat_at = float(item.get("heartbeat_at") or 0.0)
            pid = int(item.get("pid") or 0)
        except Exception:
            continue
        normalized_consumers[key] = {
            "consumer_id": key,
            "pid": pid,
            "mode": str(item.get("mode") or "").strip(),
            "desired_threads": desired_threads,
            "heartbeat_at": heartbeat_at,
            "started_at": float(item.get("started_at") or 0.0),
            "host": str(item.get("host") or "").strip(),
        }

    payload["consumers"] = normalized_consumers
    payload["updated_at"] = str(raw.get("updated_at") or "").strip()
    return payload


def _load_pool_state(path: str) -> dict[str, Any]:
    return _normalize_pool_state(_load_json_file(path, _pool_state_default()))


def _load_consumers_state(path: str) -> dict[str, Any]:
    return _normalize_consumers_state(_load_json_file(path, _consumers_state_default()))


def _save_pool_state(config: ProxyPoolConfig, payload: dict[str, Any]) -> None:
    payload["updated_at"] = _iso_now()
    _atomic_write_json(config.state_path, payload)


def _save_consumers_state(config: ProxyPoolConfig, payload: dict[str, Any]) -> None:
    payload["updated_at"] = _iso_now()
    _atomic_write_json(config.consumers_path, payload)


def _prune_consumers(consumers_state: dict[str, Any], config: ProxyPoolConfig, now_ts: float) -> bool:
    threshold = max(1.0, float(config.consumer_ttl_seconds))
    consumers = consumers_state.get("consumers") or {}
    removed = False
    stale_ids = [
        consumer_id
        for consumer_id, item in consumers.items()
        if now_ts - float(item.get("heartbeat_at") or 0.0) > threshold
    ]
    for consumer_id in stale_ids:
        consumers.pop(consumer_id, None)
        removed = True
    return removed


def _upsert_consumer(consumers_state: dict[str, Any], runtime: ProxyPoolRuntime, now_ts: float) -> None:
    consumers = consumers_state.setdefault("consumers", {})
    consumers[runtime.consumer_id] = {
        "consumer_id": runtime.consumer_id,
        "pid": runtime.pid,
        "mode": runtime.mode,
        "desired_threads": max(1, int(runtime.desired_threads)),
        "heartbeat_at": now_ts,
        "started_at": float(runtime.started_at),
        "host": runtime.host,
    }


def _total_desired_threads(consumers_state: dict[str, Any]) -> int:
    consumers = consumers_state.get("consumers") or {}
    total = 0
    for item in consumers.values():
        try:
            total += max(1, int(item.get("desired_threads") or 0))
        except Exception:
            continue
    return max(0, total)


def _leader_consumer_id(consumers_state: dict[str, Any]) -> str:
    consumers = consumers_state.get("consumers") or {}
    if not consumers:
        return ""
    return sorted(consumers.keys())[0]


def _merge_proxies(existing: list[str], incoming: list[str]) -> tuple[list[str], int]:
    merged: list[str] = []
    seen: set[str] = set()
    for item in existing:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        merged.append(value)
    added = 0
    for item in incoming:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        merged.append(value)
        added += 1
    return merged, added


def _fetch_batch(
    api_url: str,
    *,
    default_scheme: str,
    timeout: int,
    batch_size: int,
    static_proxy_url: str = "",
) -> list[str]:
    size = max(1, int(batch_size or 1))
    if str(static_proxy_url or "").strip():
        return generate_proxy_pool_candidates(static_proxy_url, size)
    return fetch_proxies_from_api(
        api_url,
        default_scheme=default_scheme,
        timeout=timeout,
        batch_size=size,
    )


def _lease_or_refill_locked(
    runtime: ProxyPoolRuntime,
    *,
    timeout: int,
    force_refill: bool,
) -> tuple[Optional[str], int, int]:
    config = runtime.config
    now_ts = time.time()
    consumers_state = _load_consumers_state(config.consumers_path)
    pool_state = _load_pool_state(config.state_path)
    pool_state_changed = _sync_pool_source(pool_state, runtime)

    consumers_changed = _prune_consumers(consumers_state, config, now_ts)
    existing_consumer = (consumers_state.get("consumers") or {}).get(runtime.consumer_id)
    if existing_consumer is None:
        _upsert_consumer(consumers_state, runtime, now_ts)
        consumers_changed = True

    total_threads = max(1, _total_desired_threads(consumers_state))
    target_count = max(1, int(config.target_multiplier) * total_threads)
    available = list(pool_state.get("proxies") or [])

    if not available and force_refill and (runtime.proxy_api_url or runtime.static_proxy_url):
        batch_size = max(1, target_count - len(available))
        fetched = _fetch_batch(
            runtime.proxy_api_url,
            default_scheme=runtime.proxy_api_scheme,
            timeout=timeout,
            batch_size=batch_size,
            static_proxy_url=runtime.static_proxy_url,
        )
        merged, added = _merge_proxies(available, fetched)
        available = merged
        pool_state["proxies"] = available
        pool_state["last_refill_at"] = _iso_now()
        pool_state["last_refill_added"] = added
        _save_pool_state(config, pool_state)
        pool_state_changed = False
        if added > 0:
            logger.info(
                "[proxy_pool] 已同步补货：added=%s available=%s target=%s",
                added,
                len(available),
                target_count,
            )

    leased_proxy = None
    if available:
        leased_proxy = available.pop(0)
        pool_state["proxies"] = available
        _save_pool_state(config, pool_state)
        pool_state_changed = False

    if pool_state_changed:
        _save_pool_state(config, pool_state)

    if consumers_changed:
        _save_consumers_state(config, consumers_state)
    return leased_proxy, len(available), target_count


def _maintain_pool_once(runtime: ProxyPoolRuntime, *, timeout: int) -> None:
    config = runtime.config
    with _exclusive_lock(config):
        now_ts = time.time()
        consumers_state = _load_consumers_state(config.consumers_path)
        pool_state = _load_pool_state(config.state_path)
        pool_state_changed = _sync_pool_source(pool_state, runtime)

        consumers_changed = _prune_consumers(consumers_state, config, now_ts)
        _upsert_consumer(consumers_state, runtime, now_ts)
        consumers_changed = True

        total_threads = max(1, _total_desired_threads(consumers_state))
        target_count = max(1, int(config.target_multiplier) * total_threads)
        available = list(pool_state.get("proxies") or [])
        leader_id = _leader_consumer_id(consumers_state)

        if (
            leader_id == runtime.consumer_id
            and (runtime.proxy_api_url or runtime.static_proxy_url)
            and len(available) < target_count
        ):
            batch_size = max(1, target_count - len(available))
            fetched = _fetch_batch(
                runtime.proxy_api_url,
                default_scheme=runtime.proxy_api_scheme,
                timeout=timeout,
                batch_size=batch_size,
                static_proxy_url=runtime.static_proxy_url,
            )
            merged, added = _merge_proxies(available, fetched)
            available = merged
            pool_state["proxies"] = available
            pool_state["last_refill_at"] = _iso_now()
            pool_state["last_refill_added"] = added
            _save_pool_state(config, pool_state)
            pool_state_changed = False
            if added > 0:
                logger.info(
                    "[proxy_pool] 已后台补货：added=%s available=%s target=%s",
                    added,
                    len(available),
                    target_count,
                )

        if pool_state_changed:
            _save_pool_state(config, pool_state)
        if consumers_changed:
            _save_consumers_state(config, consumers_state)


def _heartbeat_loop(runtime: ProxyPoolRuntime) -> None:
    interval = max(1, int(runtime.config.heartbeat_interval_seconds))
    while not runtime.stop_event.wait(interval):
        try:
            _maintain_pool_once(runtime, timeout=15)
        except Exception as exc:
            logger.warning("[proxy_pool] 心跳/补货异常：consumer=%s error=%s", runtime.consumer_id, exc)


def initialize_proxy_pool_runtime(
    config: ProxyPoolConfig,
    *,
    mode: str,
    desired_threads: int,
    proxy_api_url: str,
    proxy_api_scheme: str,
    static_proxy_url: str = "",
) -> Optional[ProxyPoolRuntime]:
    global _RUNTIME
    if not config.enabled:
        return None
    if not str(proxy_api_url or "").strip() and not str(static_proxy_url or "").strip():
        logger.warning("[proxy_pool] 已启用共享池，但未配置 proxy_api_url 或静态会话代理；将跳过初始化")
        return None

    runtime = ProxyPoolRuntime(
        config=config,
        mode=str(mode or "").strip() or "unknown",
        desired_threads=max(1, int(desired_threads or 1)),
        proxy_api_url=str(proxy_api_url or "").strip(),
        proxy_api_scheme=str(proxy_api_scheme or "http").strip().lower() or "http",
        static_proxy_url=str(static_proxy_url or "").strip(),
    )

    existing_runtime = None
    with _RUNTIME_LOCK:
        existing_runtime = _RUNTIME
    if existing_runtime is not None:
        shutdown_proxy_pool_runtime()
    with _RUNTIME_LOCK:
        _RUNTIME = runtime

    with _exclusive_lock(config):
        now_ts = time.time()
        consumers_state = _load_consumers_state(config.consumers_path)
        _prune_consumers(consumers_state, config, now_ts)
        _upsert_consumer(consumers_state, runtime, now_ts)
        _save_consumers_state(config, consumers_state)

    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(runtime,),
        name=f"proxy-pool-{runtime.consumer_id[:8]}",
        daemon=True,
    )
    runtime.heartbeat_thread = heartbeat_thread
    heartbeat_thread.start()
    logger.info(
        "[proxy_pool] 已初始化：consumer=%s mode=%s desired_threads=%s",
        runtime.consumer_id,
        runtime.mode,
        runtime.desired_threads,
    )
    return runtime


def shutdown_proxy_pool_runtime() -> None:
    with _RUNTIME_LOCK:
        global _RUNTIME
        runtime = _RUNTIME
        _RUNTIME = None

    if runtime is None:
        return

    runtime.stop_event.set()
    heartbeat_thread = runtime.heartbeat_thread
    if heartbeat_thread is not None and heartbeat_thread.is_alive():
        heartbeat_thread.join(timeout=max(1, int(runtime.config.heartbeat_interval_seconds)))

    with _exclusive_lock(runtime.config):
        consumers_state = _load_consumers_state(runtime.config.consumers_path)
        consumers = consumers_state.get("consumers") or {}
        if runtime.consumer_id in consumers:
            consumers.pop(runtime.consumer_id, None)
            _save_consumers_state(runtime.config, consumers_state)

    logger.info("[proxy_pool] 已注销：consumer=%s", runtime.consumer_id)


def proxy_pool_runtime_enabled() -> bool:
    with _RUNTIME_LOCK:
        return _RUNTIME is not None and _RUNTIME.config.enabled


def lease_proxy_from_pool(
    *,
    timeout: int = 15,
) -> str:
    with _RUNTIME_LOCK:
        runtime = _RUNTIME

    if runtime is None or not runtime.config.enabled:
        raise ProxyPoolExhaustedError("proxy pool runtime is not initialized")

    try:
        with _exclusive_lock(runtime.config):
            proxy, available_count, target_count = _lease_or_refill_locked(
                runtime,
                timeout=timeout,
                force_refill=True,
            )
    except Exception as exc:
        raise ProxyPoolExhaustedError(str(exc)) from exc

    if not proxy:
        raise ProxyPoolExhaustedError("proxy pool empty and refill failed")

    logger.info(
        "[proxy_pool] 已领用代理：consumer=%s available=%s target=%s proxy=%s",
        runtime.consumer_id,
        available_count,
        target_count,
        _proxy_log_host(proxy),
    )
    return proxy


def build_proxy_pool_snapshot() -> dict[str, Any]:
    with _RUNTIME_LOCK:
        runtime = _RUNTIME

    if runtime is None:
        return {
            "enabled": False,
            "runtime_active": False,
        }

    with _exclusive_lock(runtime.config):
        consumers_state = _load_consumers_state(runtime.config.consumers_path)
        pool_state = _load_pool_state(runtime.config.state_path)
        now_ts = time.time()
        _prune_consumers(consumers_state, runtime.config, now_ts)
        total_threads = _total_desired_threads(consumers_state)
        target_count = max(1, int(runtime.config.target_multiplier) * max(1, total_threads))
        leader_id = _leader_consumer_id(consumers_state)

    return {
        "enabled": True,
        "runtime_active": True,
        "consumer_id": runtime.consumer_id,
        "mode": runtime.mode,
        "desired_threads": runtime.desired_threads,
        "state_path": runtime.config.state_path,
        "consumers_path": runtime.config.consumers_path,
        "available_count": len(pool_state.get("proxies") or []),
        "target_count": target_count,
        "active_consumer_count": len((consumers_state.get("consumers") or {}).keys()),
        "total_desired_threads": total_threads,
        "leader_consumer_id": leader_id,
        "last_refill_at": str(pool_state.get("last_refill_at") or "").strip(),
        "last_refill_added": int(pool_state.get("last_refill_added") or 0),
    }


__all__ = [
    "ProxyPoolConfig",
    "ProxyPoolExhaustedError",
    "build_proxy_pool_config_from_args",
    "build_proxy_pool_snapshot",
    "initialize_proxy_pool_runtime",
    "lease_proxy_from_pool",
    "proxy_pool_runtime_enabled",
    "shutdown_proxy_pool_runtime",
]
