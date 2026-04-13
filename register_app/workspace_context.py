# -*- coding: utf-8 -*-
"""Workspace runtime context for web panel isolation."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

_LOCAL = threading.local()


@dataclass(frozen=True)
class WorkspaceContext:
    workspace_id: str
    root_dir: str
    ms_emails_file: str
    output_dir: str
    logs_dir: str


def get_workspace_context() -> Optional[WorkspaceContext]:
    return getattr(_LOCAL, "workspace_context", None)


def set_workspace_context(context: Optional[WorkspaceContext]) -> None:
    _LOCAL.workspace_context = context


def get_workspace_id() -> str:
    context = get_workspace_context()
    return context.workspace_id if context else ""


@contextmanager
def use_workspace_context(context: WorkspaceContext) -> Iterator[WorkspaceContext]:
    previous = get_workspace_context()
    set_workspace_context(context)
    try:
        yield context
    finally:
        set_workspace_context(previous)
