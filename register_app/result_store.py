"""Persistence helpers for non-success registration outcomes."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime
from typing import Any

from .workspace_context import get_workspace_context

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OUTPUT_DIR = os.path.join(_BASE_DIR, "output")
_LOCK = threading.Lock()

SUCCESS_NO_TOKEN_FILE = os.path.join(_OUTPUT_DIR, "register_success_no_token.txt")
REGISTER_FAILED_FILE = os.path.join(_OUTPUT_DIR, "register_failed.txt")


def _resolve_output_dir() -> str:
    context = get_workspace_context()
    if context and context.output_dir:
        return str(context.output_dir).strip()
    return _OUTPUT_DIR


def _success_no_token_file() -> str:
    return os.path.join(_resolve_output_dir(), "register_success_no_token.txt")


def _register_failed_file() -> str:
    return os.path.join(_resolve_output_dir(), "register_failed.txt")


def _append_line(path: str, payload: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _LOCK:
        with open(path, "a", encoding="utf-8") as file_obj:
            file_obj.write(json.dumps(payload, ensure_ascii=False) + "\n")


def append_success_no_token(payload: dict[str, Any]) -> None:
    record = {
        "logged_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        **(payload or {}),
    }
    _append_line(_success_no_token_file(), record)


def append_register_failed(payload: dict[str, Any]) -> None:
    record = {
        "logged_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        **(payload or {}),
    }
    _append_line(_register_failed_file(), record)
