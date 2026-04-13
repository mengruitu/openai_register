"""Proxy resolution helpers."""

from __future__ import annotations

import json
import logging
import secrets
from typing import Optional
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlsplit, urlunsplit
from urllib.request import Request, urlopen

logger = logging.getLogger("openai_register")


def _format_auth_proxy(raw_value: str, *, default_scheme: str = "http") -> str:
    """Convert user:password@host:port into proxy URL."""
    value = str(raw_value or "").strip()
    if not value or "@" not in value:
        return ""

    credentials, host_port = value.rsplit("@", 1)
    if ":" not in credentials or ":" not in host_port:
        return ""

    user, password = credentials.split(":", 1)
    host, port = host_port.rsplit(":", 1)
    user = user.strip()
    password = password.strip()
    host = host.strip()
    port = port.strip()
    if not user or not password or not host or not port:
        return ""

    scheme = str(default_scheme or "http").strip().lower() or "http"
    return f"{scheme}://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"


def _format_colon_proxy(raw_value: str, *, default_scheme: str = "http") -> str:
    """Convert host:port:user:password into proxy URL."""
    parts = str(raw_value or "").strip().split(":")
    if len(parts) != 4:
        return ""

    host, port, user, password = (item.strip() for item in parts)
    if not host or not port or not user or not password:
        return ""

    scheme = str(default_scheme or "http").strip().lower() or "http"
    return f"{scheme}://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"


def normalize_proxy_value(proxy_value: str, *, default_scheme: str = "http") -> str:
    """Normalize raw proxy text into a requests-compatible proxy URL."""
    value = str(proxy_value or "").strip()
    if not value:
        return ""

    if "://" in value:
        return value

    auth_proxy = _format_auth_proxy(value, default_scheme=default_scheme)
    if auth_proxy:
        return auth_proxy

    colon_proxy = _format_colon_proxy(value, default_scheme=default_scheme)
    if colon_proxy:
        return colon_proxy

    scheme = str(default_scheme or "http").strip().lower() or "http"
    return f"{scheme}://{value}"


def _proxy_log_host(proxy_url: str) -> str:
    parsed = urlparse(str(proxy_url or "").strip())
    if parsed.hostname and parsed.port:
        return f"{parsed.hostname}:{parsed.port}"
    if parsed.hostname:
        return parsed.hostname
    return parsed.netloc or str(proxy_url or "").strip()


def _format_proxy_netloc(
    *,
    username: str = "",
    password: str = "",
    hostname: str = "",
    port: int | None = None,
) -> str:
    host = str(hostname or "").strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    auth = ""
    if username:
        auth = quote(username, safe="")
        if password:
            auth += f":{quote(password, safe='')}"
        auth += "@"
    if port is None:
        return f"{auth}{host}"
    return f"{auth}{host}:{int(port)}"


def _is_valid_proxy_url(proxy_url: str) -> bool:
    value = str(proxy_url or "").strip()
    if not value:
        return False
    try:
        parsed = urlparse(value)
        if not parsed.hostname:
            return False
        if parsed.port is None:
            return False
    except Exception:
        return False
    return True


def supports_generated_proxy_pool(proxy_url: str) -> bool:
    """Return True when a Resin-style auth proxy can synthesize sticky sessions."""
    value = str(proxy_url or "").strip()
    if not value:
        return False
    try:
        parsed = urlparse(value)
    except Exception:
        return False

    username = unquote(str(parsed.username or "")).strip()
    password = unquote(str(parsed.password or "")).strip()
    platform = username.split(".", 1)[0].strip() if username else ""
    return bool(
        platform
        and password
        and parsed.hostname
        and parsed.port is not None
        and str(parsed.scheme or "").strip()
    )


def build_generated_proxy(proxy_url: str, *, session_name: str | None = None) -> str:
    """Build a Resin sticky-session proxy URL from a base auth proxy URL."""
    parsed = urlparse(str(proxy_url or "").strip())
    username = unquote(str(parsed.username or "")).strip()
    password = unquote(str(parsed.password or "")).strip()
    platform = username.split(".", 1)[0].strip() if username else ""
    if not (
        platform
        and password
        and parsed.hostname
        and parsed.port is not None
        and str(parsed.scheme or "").strip()
    ):
        raise ValueError("proxy url does not support generated sticky sessions")

    sticky_name = str(session_name or "").strip() or f"s{secrets.token_hex(8)}"
    sticky_username = f"{platform}.{sticky_name}"
    netloc = _format_proxy_netloc(
        username=sticky_username,
        password=password,
        hostname=str(parsed.hostname or "").strip(),
        port=parsed.port,
    )
    path = parsed.path if parsed.path not in {"", "/"} else ""
    return urlunsplit((parsed.scheme, netloc, path, parsed.query, parsed.fragment))


def generate_proxy_pool_candidates(proxy_url: str, count: int) -> list[str]:
    """Generate unique sticky-session proxy URLs from a base Resin proxy."""
    size = max(1, int(count or 1))
    seen: set[str] = set()
    generated: list[str] = []
    while len(generated) < size:
        candidate = build_generated_proxy(proxy_url)
        if candidate in seen:
            continue
        seen.add(candidate)
        generated.append(candidate)
    return generated


def build_proxy_api_request_url(api_url: str, batch_size: int) -> str:
    target = str(api_url or "").strip()
    if not target:
        return ""

    size = max(1, int(batch_size or 1))
    split = urlsplit(target)
    query_items = parse_qsl(split.query, keep_blank_values=True)
    replaced = False
    normalized_items: list[tuple[str, str]] = []
    for key, value in query_items:
        if key == "num":
            normalized_items.append((key, str(size)))
            replaced = True
        else:
            normalized_items.append((key, value))
    if not replaced:
        normalized_items.append(("num", str(size)))

    return urlunsplit(
        (
            split.scheme,
            split.netloc,
            split.path,
            urlencode(normalized_items),
            split.fragment,
        )
    )


def _extract_proxy_candidates(raw_text: str, *, default_scheme: str = "http") -> list[str]:
    text = str(raw_text or "").strip()
    if not text:
        return []

    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(text)
        except Exception:
            payload = None
        if isinstance(payload, dict):
            message = (
                payload.get("msg")
                or payload.get("message")
                or payload.get("error")
                or payload.get("detail")
                or str(payload)
            )
            raise RuntimeError(f"proxy api returned json response: {str(message)[:200]}")
        if isinstance(payload, list):
            lines = [str(item or "").strip() for item in payload]
        else:
            lines = text.splitlines()
    else:
        lines = text.splitlines()

    candidates: list[str] = []
    seen: set[str] = set()
    for raw_line in lines:
        line = str(raw_line or "").strip()
        if not line:
            continue
        proxy_url = normalize_proxy_value(line, default_scheme=default_scheme)
        if not _is_valid_proxy_url(proxy_url):
            continue
        if proxy_url in seen:
            continue
        seen.add(proxy_url)
        candidates.append(proxy_url)
    return candidates


def fetch_proxies_from_api(
    api_url: str,
    *,
    default_scheme: str = "http",
    timeout: int = 15,
    batch_size: int = 1,
) -> list[str]:
    """Fetch one or more proxy endpoints from an HTTP API."""
    target = str(api_url or "").strip()
    if not target:
        return []

    request_url = build_proxy_api_request_url(target, batch_size)
    if not request_url:
        return []

    request = Request(request_url, headers={"User-Agent": "openai_register/1.0"})
    with urlopen(request, timeout=max(1, int(timeout))) as resp:
        raw = resp.read().decode("utf-8", errors="replace").strip()

    if not raw:
        raise RuntimeError("proxy api returned empty response")

    proxies = _extract_proxy_candidates(raw, default_scheme=default_scheme)
    if not proxies:
        snippet = raw[:200].replace("\n", "\\n")
        raise RuntimeError(f"proxy api returned no valid proxies: {snippet}")
    return proxies


def fetch_proxy_from_api(api_url: str, *, default_scheme: str = "http", timeout: int = 15) -> str:
    """Fetch a fresh proxy endpoint from an HTTP API."""
    proxies = fetch_proxies_from_api(
        api_url,
        default_scheme=default_scheme,
        timeout=timeout,
        batch_size=1,
    )
    if not proxies:
        raise RuntimeError("proxy api returned no usable proxy")
    return proxies[0]


def resolve_registration_proxy(
    static_proxy: Optional[str],
    proxy_api_url: Optional[str] = None,
    *,
    proxy_api_scheme: str = "http",
    proxy_pool_enabled: bool = False,
    timeout: int = 15,
) -> Optional[str]:
    """Resolve proxy for a single registration attempt."""
    if proxy_pool_enabled:
        from .proxy_pool import lease_proxy_from_pool, proxy_pool_runtime_enabled

        if proxy_pool_runtime_enabled():
            proxy = lease_proxy_from_pool(timeout=timeout)
            host = _proxy_log_host(proxy)
            logger.info(f"[proxy_pool] leased proxy: {host}")
            return proxy

    api_url = str(proxy_api_url or "").strip()
    if api_url:
        proxy = fetch_proxy_from_api(api_url, default_scheme=proxy_api_scheme, timeout=timeout)
        host = _proxy_log_host(proxy)
        logger.info(f"[proxy] fetched new proxy from api: {host}")
        return proxy

    proxy = normalize_proxy_value(str(static_proxy or "").strip(), default_scheme=proxy_api_scheme)
    return proxy or None
