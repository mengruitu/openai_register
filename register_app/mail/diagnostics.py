"""Mailbox OTP wait diagnostics helpers."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict

_LOCK = threading.RLock()
_STATE: Dict[str, Dict[str, Any]] = {}


def _key(provider: str, email: str) -> str:
    return f"{str(provider or '').strip().lower()}::{str(email or '').strip().lower()}"


def reset_mailbox_wait_diagnostics(provider: str, email: str, **extra: Any) -> None:
    now = time.time()
    payload: Dict[str, Any] = {
        "provider": str(provider or "").strip().lower(),
        "email": str(email or "").strip(),
        "started_at": now,
        "poll_count": 0,
        "message_scan_count": 0,
        "first_message_seen_at": None,
        "matched_message_at": None,
        "aborted": False,
        "abort_reason": "",
        "outcome": "",
    }
    payload.update({key: value for key, value in extra.items() if value is not None})
    with _LOCK:
        _STATE[_key(provider, email)] = payload


def update_mailbox_wait_diagnostics(provider: str, email: str, **updates: Any) -> None:
    diag_key = _key(provider, email)
    now = time.time()
    with _LOCK:
        payload = dict(_STATE.get(diag_key) or {})
        if not payload:
            payload = {
                "provider": str(provider or "").strip().lower(),
                "email": str(email or "").strip(),
                "started_at": now,
                "poll_count": 0,
                "message_scan_count": 0,
                "first_message_seen_at": None,
                "matched_message_at": None,
                "aborted": False,
                "abort_reason": "",
                "outcome": "",
            }
        payload.update({key: value for key, value in updates.items() if value is not None})
        _STATE[diag_key] = payload


def increment_mailbox_wait_poll(provider: str, email: str, count: int = 1) -> None:
    diag_key = _key(provider, email)
    with _LOCK:
        payload = dict(_STATE.get(diag_key) or {})
        payload["provider"] = str(provider or "").strip().lower()
        payload["email"] = str(email or "").strip()
        payload["started_at"] = payload.get("started_at") or time.time()
        payload["poll_count"] = int(payload.get("poll_count") or 0) + max(0, int(count))
        _STATE[diag_key] = payload


def note_mailbox_messages_scanned(provider: str, email: str, scanned_count: int) -> None:
    diag_key = _key(provider, email)
    now = time.time()
    scanned = max(0, int(scanned_count or 0))
    with _LOCK:
        payload = dict(_STATE.get(diag_key) or {})
        payload["provider"] = str(provider or "").strip().lower()
        payload["email"] = str(email or "").strip()
        payload["started_at"] = payload.get("started_at") or now
        payload["message_scan_count"] = int(payload.get("message_scan_count") or 0) + scanned
        if scanned > 0 and not payload.get("first_message_seen_at"):
            payload["first_message_seen_at"] = now
        _STATE[diag_key] = payload


def mark_mailbox_wait_matched(provider: str, email: str, *, code: str = "") -> None:
    update_mailbox_wait_diagnostics(
        provider,
        email,
        matched_message_at=time.time(),
        matched_code=str(code or "").strip(),
        outcome="matched",
    )


def mark_mailbox_wait_timeout(provider: str, email: str, *, reason: str = "") -> None:
    update_mailbox_wait_diagnostics(
        provider,
        email,
        timeout_at=time.time(),
        timeout_reason=str(reason or "").strip(),
        outcome="timeout",
    )


def mark_mailbox_wait_aborted(provider: str, email: str, *, reason: str = "") -> None:
    update_mailbox_wait_diagnostics(
        provider,
        email,
        aborted=True,
        abort_reason=str(reason or "").strip(),
        aborted_at=time.time(),
        outcome="aborted",
    )


def get_mailbox_wait_diagnostics(provider: str, email: str) -> Dict[str, Any]:
    with _LOCK:
        return dict(_STATE.get(_key(provider, email)) or {})
