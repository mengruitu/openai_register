"""Proxy resolution helpers."""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

logger = logging.getLogger("openai_register")


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

    colon_proxy = _format_colon_proxy(value, default_scheme=default_scheme)
    if colon_proxy:
        return colon_proxy

    if "://" in value:
        return value
    scheme = str(default_scheme or "http").strip().lower() or "http"
    return f"{scheme}://{value}"


def fetch_proxy_from_api(api_url: str, *, default_scheme: str = "http", timeout: int = 15) -> str:
    """Fetch a fresh proxy endpoint from an HTTP API."""
    target = str(api_url or "").strip()
    if not target:
        return ""

    request = Request(target, headers={"User-Agent": "openai_register/1.0"})
    with urlopen(request, timeout=max(1, int(timeout))) as resp:
        raw = resp.read().decode("utf-8", errors="replace").strip()

    if not raw:
        raise RuntimeError("proxy api returned empty response")

    first_line = raw.splitlines()[0].strip()
    if not first_line:
        raise RuntimeError("proxy api returned invalid response")

    return normalize_proxy_value(first_line, default_scheme=default_scheme)


def resolve_registration_proxy(
    static_proxy: Optional[str],
    proxy_api_url: Optional[str] = None,
    *,
    proxy_api_scheme: str = "http",
    timeout: int = 15,
) -> Optional[str]:
    """Resolve proxy for a single registration attempt."""
    api_url = str(proxy_api_url or "").strip()
    if api_url:
        proxy = fetch_proxy_from_api(api_url, default_scheme=proxy_api_scheme, timeout=timeout)
        host = urlparse(proxy).netloc or proxy
        logger.info(f"[proxy] fetched new proxy from api: {host}")
        return proxy

    proxy = normalize_proxy_value(str(static_proxy or "").strip(), default_scheme=proxy_api_scheme)
    return proxy or None
