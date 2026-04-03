"""Lightweight mailbox dedupe store."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import threading


def _normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


@dataclass(frozen=True)
class MailboxDedupeEvent:
    timestamp: str
    action: str
    email: str
    reason: str = ""


class MailboxDedupeStore:
    def __init__(self, *, state_file: Path) -> None:
        self.state_file = Path(state_file)
        self._lock = threading.RLock()
        self._loaded = False
        self._seen: set[str] = set()
        self._inflight: set[str] = set()

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        if self.state_file.exists():
            for raw_line in self.state_file.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                email = _normalize_email(str(payload.get("email") or ""))
                if email:
                    self._seen.add(email)
        self._loaded = True

    def _append_event(self, action: str, email: str, *, reason: str = "") -> None:
        event = MailboxDedupeEvent(
            timestamp=datetime.now().astimezone().isoformat(timespec="seconds"),
            action=action,
            email=email,
            reason=reason,
        )
        with self.state_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.__dict__, ensure_ascii=False) + "\n")

    def reserve(self, email: str) -> bool:
        normalized = _normalize_email(email)
        if not normalized:
            return False
        with self._lock:
            self._ensure_loaded()
            if normalized in self._inflight or normalized in self._seen:
                self._seen.add(normalized)
                return False
            self._seen.add(normalized)
            self._inflight.add(normalized)
            self._append_event("reserve", normalized)
            return True

    def release(self, email: str) -> None:
        normalized = _normalize_email(email)
        if not normalized:
            return
        with self._lock:
            self._inflight.discard(normalized)

    def mark(self, email: str, *, reason: str) -> None:
        normalized = _normalize_email(email)
        if not normalized:
            return
        with self._lock:
            self._ensure_loaded()
            self._seen.add(normalized)
            self._append_event("mark", normalized, reason=reason)


_STORE: MailboxDedupeStore | None = None
_STORE_LOCK = threading.Lock()


def get_mailbox_dedupe_store() -> MailboxDedupeStore:
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:
            _STORE = MailboxDedupeStore(
                state_file=Path.cwd() / "state" / "seen_mailboxes.jsonl"
            )
        return _STORE
