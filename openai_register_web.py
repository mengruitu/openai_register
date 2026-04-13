#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft-only registration web panel."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import logging
import mimetypes
import os
import random
import secrets
import shutil
import threading
import time
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from curl_cffi import requests

from register_app.mail.providers import MAILTM_BASE
from register_app.proxy import resolve_registration_proxy
from register_app.registration import run_with_fallback_detailed
from register_app.runtime.common import _build_token_output_path, count_json_files, logger
from register_app.workspace_context import WorkspaceContext, get_workspace_id, use_workspace_context


HOST = "0.0.0.0"
PORT = 1113
WORKSPACE_ROOT = Path("/root/openai_register/web_data/workspaces")
MAX_THREADS_PER_WORKSPACE = 3
MAX_GLOBAL_THREADS = 6
WORKSPACE_COOKIE = "openai_register_workspace"
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
MAILBOX_EXHAUSTED_ERROR_CODES = {
    "mailbox_unavailable",
    "mailbox_duplicate_exhausted",
}
DEFAULT_WORKSPACE_CONFIG = {
    "proxy": "",
    "proxy_api_url": "",
    "proxy_api_scheme": "http",
    "register_openai_concurrency": 1,
    "register_start_delay_seconds": 1.0,
    "failure_sleep_seconds": 20,
    "sleep_min": 10,
    "sleep_max": 20,
    "once": False,
    "mail_provider_label": "Microsoft (Graph -> IMAP fallback)",
}
STATE_FILE_NAME = "state.json"
WORKSPACE_LOG_FILE = "panel.log"
RECENT_LOG_LINES = 200


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _utc_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")


def _safe_workspace_id(value: str) -> str:
    return "".join(ch for ch in str(value or "") if ch.isalnum() or ch in {"-", "_"})[:64]


def _workspace_paths(workspace_id: str) -> dict[str, Path]:
    root = WORKSPACE_ROOT / workspace_id
    return {
        "root": root,
        "ms_emails": root / "ms_emails.txt",
        "auths": root / "auths",
        "exports": root / "exports",
        "logs": root / "logs",
        "output": root / "output",
        "state": root / STATE_FILE_NAME,
        "accounts": root / "output" / "accounts.txt",
        "log_file": root / "logs" / WORKSPACE_LOG_FILE,
    }


def _ensure_workspace_dirs(workspace_id: str) -> dict[str, Path]:
    paths = _workspace_paths(workspace_id)
    for key in ("root", "auths", "exports", "logs", "output"):
        paths[key].mkdir(parents=True, exist_ok=True)
    if not paths["ms_emails"].exists():
        paths["ms_emails"].write_text("", encoding="utf-8")
    return paths


def _default_state(workspace_id: str) -> dict[str, Any]:
    return {
        "workspace_id": workspace_id,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "config": dict(DEFAULT_WORKSPACE_CONFIG),
        "last_task": {
            "status": "idle",
            "started_at": "",
            "finished_at": "",
            "desired_threads": 0,
            "success_count": 0,
            "failure_count": 0,
            "attempt_count": 0,
            "produced_files": 0,
            "last_error": "",
            "stop_requested": False,
            "duration_seconds": 0,
        },
    }


def _load_workspace_state(workspace_id: str) -> dict[str, Any]:
    paths = _ensure_workspace_dirs(workspace_id)
    if not paths["state"].exists():
        state = _default_state(workspace_id)
        _save_workspace_state(workspace_id, state)
        return state
    try:
        state = json.loads(paths["state"].read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise ValueError("state is not object")
    except Exception:
        state = _default_state(workspace_id)
        _save_workspace_state(workspace_id, state)
        return state
    config = state.get("config")
    merged_config = dict(DEFAULT_WORKSPACE_CONFIG)
    if isinstance(config, dict):
        merged_config.update({k: config[k] for k in config if k in merged_config})
    state["config"] = merged_config
    state.setdefault("last_task", _default_state(workspace_id)["last_task"])
    state["workspace_id"] = workspace_id
    return state


def _save_workspace_state(workspace_id: str, state: dict[str, Any]) -> None:
    paths = _ensure_workspace_dirs(workspace_id)
    payload = dict(state)
    payload["workspace_id"] = workspace_id
    payload["updated_at"] = _now_iso()
    paths["state"].write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _tail_lines(file_path: Path, limit: int = RECENT_LOG_LINES) -> list[str]:
    if not file_path.exists():
        return []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    return lines[-max(1, limit):]


def _append_workspace_log(workspace_id: str, message: str) -> None:
    paths = _ensure_workspace_dirs(workspace_id)
    raw = str(message or "").strip()
    if raw.startswith("[") and "] [" in raw:
        line = raw
    else:
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {raw}"
    with paths["log_file"].open("a", encoding="utf-8") as file_obj:
        file_obj.write(line + "\n")


def _count_ms_emails(workspace_id: str) -> int:
    path = _ensure_workspace_dirs(workspace_id)["ms_emails"]
    total = 0
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            total += 1
    return total


def _export_files(workspace_id: str) -> list[dict[str, Any]]:
    exports_dir = _ensure_workspace_dirs(workspace_id)["exports"]
    results: list[dict[str, Any]] = []
    for path in sorted(exports_dir.glob("*.zip"), key=lambda item: item.stat().st_mtime, reverse=True):
        stat = path.stat()
        results.append(
            {
                "name": path.name,
                "size": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds"),
            }
        )
    return results[:20]


def _test_proxy_config(config: dict[str, Any]) -> dict[str, Any]:
    runtime_proxy = resolve_registration_proxy(
        str(config.get("proxy") or "").strip() or None,
        str(config.get("proxy_api_url") or "").strip() or None,
        proxy_api_scheme=str(config.get("proxy_api_scheme") or "http").strip() or "http",
    )
    if not runtime_proxy:
        return {"ok": False, "message": "当前未配置可用代理"}

    resp = requests.get(
        TRACE_URL,
        proxies={"http": runtime_proxy, "https": runtime_proxy},
        impersonate="chrome",
        timeout=10,
    )
    if resp.status_code != 200:
        return {"ok": False, "message": f"代理测试失败：HTTP {resp.status_code}"}

    trace: dict[str, str] = {}
    for line in str(resp.text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        trace[key.strip()] = value.strip()

    return {
        "ok": True,
        "proxy": runtime_proxy,
        "ip": trace.get("ip") or "",
        "loc": trace.get("loc") or "",
    }


def _workspace_context_for_id(workspace_id: str) -> WorkspaceContext:
    paths = _ensure_workspace_dirs(workspace_id)
    return WorkspaceContext(
        workspace_id=workspace_id,
        root_dir=str(paths["root"]),
        ms_emails_file=str(paths["ms_emails"]),
        output_dir=str(paths["output"]),
        logs_dir=str(paths["logs"]),
    )


class WorkspaceLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        workspace_id = get_workspace_id()
        if not workspace_id:
            return
        try:
            message = self.format(record)
            _append_workspace_log(workspace_id, message)
        except Exception:
            pass


_workspace_log_handler = WorkspaceLogHandler()
_workspace_log_handler.setLevel(logging.INFO)
_workspace_log_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
if _workspace_log_handler not in logger.handlers:
    logger.addHandler(_workspace_log_handler)


@dataclass
class RegistrationJob:
    workspace_id: str
    desired_threads: int
    config: dict[str, Any]

    def __post_init__(self) -> None:
        self.stop_event = threading.Event()
        self.status_lock = threading.Lock()
        self.threads: list[threading.Thread] = []
        self.status = "starting"
        self.started_at = time.time()
        self.finished_at = 0.0
        self.success_count = 0
        self.failure_count = 0
        self.attempt_count = 0
        self.produced_files = 0
        self.last_error = ""
        self.stop_requested = False
        self.controller_thread = threading.Thread(target=self._run_controller, daemon=True)

    def start(self) -> None:
        _append_workspace_log(self.workspace_id, f"启动注册任务，线程数={self.desired_threads}")
        self.controller_thread.start()

    def request_stop(self) -> None:
        with self.status_lock:
            self.stop_requested = True
            if self.status in {"starting", "running"}:
                self.status = "stopping"
        self.stop_event.set()
        _append_workspace_log(self.workspace_id, "已请求停止当前注册任务，正在等待线程退出")

    def snapshot(self) -> dict[str, Any]:
        with self.status_lock:
            duration = int((self.finished_at or time.time()) - self.started_at) if self.started_at else 0
            return {
                "status": self.status,
                "started_at": datetime.fromtimestamp(self.started_at).astimezone().isoformat(timespec="seconds") if self.started_at else "",
                "finished_at": datetime.fromtimestamp(self.finished_at).astimezone().isoformat(timespec="seconds") if self.finished_at else "",
                "desired_threads": self.desired_threads,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "attempt_count": self.attempt_count,
                "produced_files": self.produced_files,
                "last_error": self.last_error,
                "stop_requested": self.stop_requested,
                "duration_seconds": duration,
            }

    def _record_result(self, *, success: bool, produced_file: bool = False, last_error: str = "") -> None:
        with self.status_lock:
            self.attempt_count += 1
            if success:
                self.success_count += 1
                if produced_file:
                    self.produced_files += 1
                self.last_error = ""
            else:
                self.failure_count += 1
                self.last_error = str(last_error or "").strip()

    def _save_success_result(self, token_json: str, password: str, thread_id: int) -> None:
        paths = _ensure_workspace_dirs(self.workspace_id)
        try:
            token_data = json.loads(token_json)
            raw_email = str(token_data.get("email") or "unknown").strip() or "unknown"
            refresh_token = str(token_data.get("refresh_token") or "").strip()
        except Exception:
            token_data = {}
            raw_email = "unknown"
            refresh_token = ""

        token_path = _build_token_output_path(str(paths["auths"]), raw_email, thread_id)
        with open(token_path, "w", encoding="utf-8") as file_obj:
            file_obj.write(token_json)

        with paths["accounts"].open("a", encoding="utf-8") as file_obj:
            file_obj.write(f"{raw_email}----{password}----{refresh_token}\n")

        self._record_result(success=True, produced_file=True)
        _append_workspace_log(self.workspace_id, f"注册成功：{raw_email}，已保存 {os.path.basename(token_path)}")

    def _run_attempt(self, thread_id: int) -> bool:
        runtime_proxy = resolve_registration_proxy(
            str(self.config.get("proxy") or "").strip() or None,
            str(self.config.get("proxy_api_url") or "").strip() or None,
            proxy_api_scheme=str(self.config.get("proxy_api_scheme") or "http").strip() or "http",
        )
        result, used_provider, attempt = run_with_fallback_detailed(
            runtime_proxy,
            "ms_mail",
            thread_id,
            MAILTM_BASE,
            dingtalk_webhook="",
            dingtalk_fallback_interval_seconds=0,
        )
        if not result:
            error_code = str(getattr(attempt, "error_code", "") or "registration_failed")
            self._record_result(success=False, last_error=f"{error_code}:{used_provider}")
            _append_workspace_log(self.workspace_id, f"[线程 {thread_id}] 注册失败（provider={used_provider}, error={error_code}）")
            if error_code in MAILBOX_EXHAUSTED_ERROR_CODES:
                self.stop_event.set()
            return False

        token_json, password = result
        self._save_success_result(token_json, password, thread_id)
        return True

    def _worker_loop(self, thread_index: int) -> None:
        context = _workspace_context_for_id(self.workspace_id)
        once = bool(self.config.get("once"))
        sleep_min = max(1, int(self.config.get("sleep_min", 10)))
        sleep_max = max(sleep_min, int(self.config.get("sleep_max", 20)))
        failure_sleep = max(0, int(self.config.get("failure_sleep_seconds", 20)))

        with use_workspace_context(context):
            while not self.stop_event.is_set():
                is_success = False
                try:
                    is_success = self._run_attempt(thread_index)
                except Exception as exc:
                    self._record_result(success=False, last_error=str(exc))
                    _append_workspace_log(self.workspace_id, f"[线程 {thread_index}] 发生异常: {exc}")

                if once:
                    break

                wait_seconds = random.randint(sleep_min, sleep_max)
                if not is_success:
                    wait_seconds += failure_sleep
                if self.stop_event.wait(wait_seconds):
                    break

    def _run_controller(self) -> None:
        with self.status_lock:
            self.status = "running"
        start_delay = max(0.0, float(self.config.get("register_start_delay_seconds", 1.0)))

        try:
            for index in range(self.desired_threads):
                if self.stop_event.is_set():
                    break
                thread = threading.Thread(target=self._worker_loop, args=(index + 1,), daemon=True)
                thread.start()
                self.threads.append(thread)
                if start_delay > 0 and index + 1 < self.desired_threads:
                    if self.stop_event.wait(start_delay):
                        break

            for thread in self.threads:
                thread.join()
        finally:
            with self.status_lock:
                if self.stop_requested:
                    self.status = "stopped"
                elif self.failure_count > 0 and self.success_count == 0 and bool(self.config.get("once")):
                    self.status = "failed"
                else:
                    self.status = "completed"
                self.finished_at = time.time()
            _append_workspace_log(self.workspace_id, f"注册任务结束：status={self.status} success={self.success_count} failure={self.failure_count}")
            registry.finish_job(self.workspace_id, self)


class JobRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, RegistrationJob] = {}

    def active_threads(self) -> int:
        with self._lock:
            return sum(job.desired_threads for job in self._jobs.values() if job.snapshot()["status"] in {"starting", "running", "stopping"})

    def get_job(self, workspace_id: str) -> Optional[RegistrationJob]:
        with self._lock:
            return self._jobs.get(workspace_id)

    def start_job(self, workspace_id: str, config: dict[str, Any]) -> RegistrationJob:
        desired_threads = max(1, min(MAX_THREADS_PER_WORKSPACE, int(config.get("register_openai_concurrency", 1) or 1)))
        with self._lock:
            existing = self._jobs.get(workspace_id)
            if existing and existing.snapshot()["status"] in {"starting", "running", "stopping"}:
                raise RuntimeError("当前工作区已有注册任务在运行")
            projected = sum(job.desired_threads for job in self._jobs.values() if job.snapshot()["status"] in {"starting", "running", "stopping"}) + desired_threads
            if projected > MAX_GLOBAL_THREADS:
                raise RuntimeError(f"当前资源已满，全局线程上限为 {MAX_GLOBAL_THREADS}")
            job = RegistrationJob(workspace_id=workspace_id, desired_threads=desired_threads, config=config)
            self._jobs[workspace_id] = job
        job.start()
        return job

    def finish_job(self, workspace_id: str, job: RegistrationJob) -> None:
        state = _load_workspace_state(workspace_id)
        state["last_task"] = job.snapshot()
        _save_workspace_state(workspace_id, state)
        with self._lock:
            current = self._jobs.get(workspace_id)
            if current is job:
                self._jobs.pop(workspace_id, None)


registry = JobRegistry()


def _workspace_status(workspace_id: str) -> dict[str, Any]:
    state = _load_workspace_state(workspace_id)
    paths = _ensure_workspace_dirs(workspace_id)
    active_job = registry.get_job(workspace_id)
    task = active_job.snapshot() if active_job else state.get("last_task") or _default_state(workspace_id)["last_task"]
    return {
        "workspace_id": workspace_id,
        "mail_mode": "Microsoft (Graph -> IMAP fallback)",
        "config": state.get("config") or dict(DEFAULT_WORKSPACE_CONFIG),
        "counts": {
            "ms_email_count": _count_ms_emails(workspace_id),
            "auth_json_count": count_json_files(str(paths["auths"])),
            "export_zip_count": len(_export_files(workspace_id)),
        },
        "task": task,
        "recent_exports": _export_files(workspace_id),
        "global": {
            "max_threads_per_workspace": MAX_THREADS_PER_WORKSPACE,
            "max_global_threads": MAX_GLOBAL_THREADS,
            "active_threads": registry.active_threads(),
        },
    }


def _validate_ms_email_lines(content: str) -> tuple[list[str], list[dict[str, Any]]]:
    valid_lines: list[str] = []
    errors: list[dict[str, Any]] = []
    for line_no, raw in enumerate(str(content or "").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split("----")
        if len(parts) < 4:
            errors.append({"line": line_no, "error": "字段数量不足，需为 邮箱----密码----client_id----refresh_token"})
            continue
        email, password, client_id, refresh_token = parts[0].strip(), parts[1].strip(), parts[2].strip(), "----".join(parts[3:]).strip()
        if not email or not password or not client_id or not refresh_token:
            errors.append({"line": line_no, "error": "存在空字段"})
            continue
        valid_lines.append(f"{email}----{password}----{client_id}----{refresh_token}")
    return valid_lines, errors


def _render_json(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200, *, set_cookie: str = "") -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    if set_cookie:
        handler.send_header("Set-Cookie", set_cookie)
    handler.end_headers()
    handler.wfile.write(body)


def _render_text(handler: BaseHTTPRequestHandler, text: str, status: int = 200, *, content_type: str = "text/html; charset=utf-8", set_cookie: str = "") -> None:
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    if set_cookie:
        handler.send_header("Set-Cookie", set_cookie)
    handler.end_headers()
    handler.wfile.write(body)


def _render_file(handler: BaseHTTPRequestHandler, file_path: Path, *, set_cookie: str = "") -> None:
    if not file_path.exists() or not file_path.is_file():
        _render_json(handler, {"ok": False, "message": "文件不存在"}, 404, set_cookie=set_cookie)
        return
    data = file_path.read_bytes()
    mime_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    handler.send_response(200)
    handler.send_header("Content-Type", mime_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
    if set_cookie:
        handler.send_header("Set-Cookie", set_cookie)
    handler.end_headers()
    handler.wfile.write(data)


def _parse_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    try:
        payload = json.loads(raw.decode("utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _workspace_cookie_value(handler: BaseHTTPRequestHandler) -> tuple[str, str]:
    cookie_header = str(handler.headers.get("Cookie") or "")
    workspace_id = ""
    for part in cookie_header.split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key.strip() == WORKSPACE_COOKIE:
            workspace_id = _safe_workspace_id(value.strip())
            break
    created = ""
    if not workspace_id:
        workspace_id = secrets.token_urlsafe(18)
        created = f"{WORKSPACE_COOKIE}={workspace_id}; Path=/; HttpOnly; SameSite=Lax"
    _ensure_workspace_dirs(workspace_id)
    return workspace_id, created


def _main_page(workspace_id: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>微软注册面板</title>
  <style>
    :root {{
      --bg: #f3efe6;
      --paper: #fffaf0;
      --ink: #1f2937;
      --muted: #6b7280;
      --line: #d8cfbf;
      --accent: #14532d;
      --accent-soft: #d9f99d;
      --warn: #7c2d12;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Georgia, "Times New Roman", serif; background: linear-gradient(160deg, #efe4d1 0%, #f9f4eb 50%, #e7ecef 100%); color: var(--ink); }}
    .wrap {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
    .hero {{ display: grid; gap: 12px; margin-bottom: 20px; }}
    .hero h1 {{ margin: 0; font-size: 34px; }}
    .hero p {{ margin: 0; color: var(--muted); }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
    .card {{ background: rgba(255,250,240,0.9); border: 1px solid var(--line); border-radius: 18px; padding: 18px; box-shadow: 0 14px 36px rgba(27,31,35,0.08); backdrop-filter: blur(8px); }}
    .card h2 {{ margin: 0 0 12px; font-size: 20px; }}
    .card h3 {{ margin: 12px 0 8px; font-size: 16px; }}
    .row {{ display: grid; gap: 8px; margin-bottom: 12px; }}
    .row.two {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
    label {{ font-size: 13px; color: var(--muted); }}
    input, select, textarea, button {{ width: 100%; font: inherit; border-radius: 12px; border: 1px solid var(--line); }}
    input, select, textarea {{ padding: 10px 12px; background: #fff; }}
    textarea {{ min-height: 160px; resize: vertical; }}
    button {{ padding: 11px 14px; cursor: pointer; background: #fff; }}
    button.primary {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
    button.soft {{ background: var(--accent-soft); border-color: #b8d36b; }}
    button.warn {{ background: #fef2f2; border-color: #fecaca; color: var(--warn); }}
    .stats {{ display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 10px; }}
    .stat {{ padding: 12px; border-radius: 14px; background: #fff; border: 1px solid var(--line); }}
    .stat strong {{ display: block; font-size: 24px; }}
    .muted {{ color: var(--muted); }}
    .logs {{ white-space: pre-wrap; background: #141313; color: #efe7db; border-radius: 14px; padding: 14px; min-height: 280px; max-height: 480px; overflow: auto; font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }}
    .toolbar {{ display: flex; gap: 10px; flex-wrap: wrap; }}
    .toolbar a {{ color: var(--accent); text-decoration: none; font-weight: 600; }}
    .pill {{ display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 999px; background: #fff; border: 1px solid var(--line); font-size: 12px; }}
    .list {{ display: grid; gap: 10px; }}
    .item {{ border: 1px solid var(--line); border-radius: 12px; padding: 12px; background: #fff; }}
    .footer {{ margin-top: 22px; color: var(--muted); font-size: 13px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div class="pill">工作空间：<code>{html.escape(workspace_id)}</code></div>
      <h1>微软注册面板</h1>
      <p>仅支持微软账号导入，后台固定使用 Microsoft Graph 优先，失败自动降级到 IMAP。</p>
      <div class="toolbar">
        <a href="/logs">查看日志</a>
        <a href="/exports">导出历史</a>
      </div>
    </div>

    <div class="grid">
      <section class="card">
        <h2>统计面板</h2>
        <div class="stats">
          <div class="stat"><span class="muted">邮箱数</span><strong id="stat-mails">0</strong></div>
          <div class="stat"><span class="muted">成功 JSON</span><strong id="stat-json">0</strong></div>
          <div class="stat"><span class="muted">任务状态</span><strong id="stat-status">idle</strong></div>
          <div class="stat"><span class="muted">全局线程</span><strong id="stat-threads">0/6</strong></div>
        </div>
        <div class="row two">
          <div class="stat"><span class="muted">成功数</span><strong id="stat-success">0</strong></div>
          <div class="stat"><span class="muted">失败数</span><strong id="stat-failure">0</strong></div>
        </div>
        <div class="row">
          <div class="item">
            <div class="muted">最近错误</div>
            <div id="stat-error">-</div>
          </div>
        </div>
      </section>

      <section class="card">
        <h2>微软邮箱导入</h2>
        <div class="row">
          <label>文件上传（客户端读取后覆盖当前工作区）</label>
          <input id="file-input" type="file" accept=".txt">
        </div>
        <div class="row">
          <label>或直接粘贴账号内容</label>
          <textarea id="import-content" placeholder="邮箱----密码----client_id----refresh_token"></textarea>
        </div>
        <div class="row">
          <button class="primary" onclick="importEmails()">覆盖导入当前工作区</button>
        </div>
        <div class="row muted" id="import-result"></div>
      </section>

      <section class="card">
        <h2>代理设置</h2>
        <div class="row">
          <label>静态代理</label>
          <input id="cfg-proxy" placeholder="http://127.0.0.1:7890">
        </div>
        <div class="row">
          <label>代理 API</label>
          <input id="cfg-proxy-api-url" placeholder="https://...">
        </div>
        <div class="row two">
          <div>
            <label>代理 API 协议</label>
            <select id="cfg-proxy-api-scheme">
              <option value="http">http</option>
              <option value="socks5">socks5</option>
              <option value="socks5h">socks5h</option>
            </select>
          </div>
          <div style="display:flex;align-items:flex-end;">
            <button class="soft" onclick="testProxy()">测试代理</button>
          </div>
        </div>
        <div class="row muted" id="proxy-test-result"></div>
      </section>

      <section class="card">
        <h2>注册设置</h2>
        <div class="row two">
          <div>
            <label>线程数 (1-3)</label>
            <input id="cfg-concurrency" type="number" min="1" max="3">
          </div>
          <div>
            <label>启动错峰秒数</label>
            <input id="cfg-start-delay" type="number" min="0" step="0.5">
          </div>
        </div>
        <div class="row two">
          <div>
            <label>失败额外等待秒数</label>
            <input id="cfg-failure-sleep" type="number" min="0">
          </div>
          <div>
            <label>是否单次运行</label>
            <select id="cfg-once">
              <option value="false">持续注册</option>
              <option value="true">单次运行</option>
            </select>
          </div>
        </div>
        <div class="row two">
          <div>
            <label>成功后的随机等待最小值</label>
            <input id="cfg-sleep-min" type="number" min="1">
          </div>
          <div>
            <label>成功后的随机等待最大值</label>
            <input id="cfg-sleep-max" type="number" min="1">
          </div>
        </div>
        <div class="toolbar">
          <button class="primary" onclick="saveConfig()">保存设置</button>
          <button class="primary" onclick="startRegister()">启动注册</button>
          <button class="warn" onclick="stopRegister()">停止注册</button>
          <button onclick="exportZip()">导出成功 JSON 为 ZIP</button>
        </div>
        <div class="row muted" id="action-result"></div>
      </section>
    </div>

    <section class="card" style="margin-top:16px;">
      <h2>最近日志</h2>
      <div class="logs" id="logs">加载中...</div>
    </section>

    <section class="card" style="margin-top:16px;">
      <h2>最近导出</h2>
      <div class="list" id="exports-list"><div class="muted">暂无导出</div></div>
    </section>

    <div class="footer">该面板仅管理当前浏览器对应的匿名工作空间数据，不共享给其他浏览器。</div>
  </div>

  <script>
    async function api(path, options={{}}) {{
      const resp = await fetch(path, {{
        ...options,
        headers: {{
          'Content-Type': 'application/json',
          ...(options.headers || {{}})
        }}
      }});
      const data = await resp.json().catch(() => ({{ ok: false, message: '响应不是 JSON' }}));
      if (!resp.ok) throw new Error(data.message || ('HTTP ' + resp.status));
      return data;
    }}

    function setText(id, value) {{
      document.getElementById(id).textContent = value;
    }}

    function renderExports(items) {{
      const box = document.getElementById('exports-list');
      if (!items || !items.length) {{
        box.innerHTML = '<div class="muted">暂无导出</div>';
        return;
      }}
      box.innerHTML = items.map(item => `
        <div class="item">
          <div><strong>${{item.name}}</strong></div>
          <div class="muted">大小：${{item.size}} 字节 · 时间：${{item.modified_at}}</div>
          <div style="margin-top:8px;"><a href="/api/export/download/${{encodeURIComponent(item.name)}}" target="_blank">下载</a></div>
        </div>
      `).join('');
    }}

    async function refreshStatus() {{
      try {{
        const data = await api('/api/status', {{ method: 'GET', headers: {{ 'Content-Type': 'application/json' }} }});
        const cfg = data.config || {{}};
        const counts = data.counts || {{}};
        const task = data.task || {{}};
        const global = data.global || {{}};
        setText('stat-mails', counts.ms_email_count || 0);
        setText('stat-json', counts.auth_json_count || 0);
        setText('stat-status', task.status || 'idle');
        setText('stat-threads', `${{global.active_threads || 0}}/${{global.max_global_threads || 6}}`);
        setText('stat-success', task.success_count || 0);
        setText('stat-failure', task.failure_count || 0);
        setText('stat-error', task.last_error || '-');
        document.getElementById('cfg-proxy').value = cfg.proxy || '';
        document.getElementById('cfg-proxy-api-url').value = cfg.proxy_api_url || '';
        document.getElementById('cfg-proxy-api-scheme').value = cfg.proxy_api_scheme || 'http';
        document.getElementById('cfg-concurrency').value = cfg.register_openai_concurrency || 1;
        document.getElementById('cfg-start-delay').value = cfg.register_start_delay_seconds ?? 1;
        document.getElementById('cfg-failure-sleep').value = cfg.failure_sleep_seconds ?? 20;
        document.getElementById('cfg-once').value = String(Boolean(cfg.once));
        document.getElementById('cfg-sleep-min').value = cfg.sleep_min ?? 10;
        document.getElementById('cfg-sleep-max').value = cfg.sleep_max ?? 20;
        renderExports(data.recent_exports || []);
      }} catch (err) {{
        setText('action-result', err.message);
      }}
    }}

    async function refreshLogs() {{
      try {{
        const data = await api('/api/register/logs', {{ method: 'GET', headers: {{ 'Content-Type': 'application/json' }} }});
        document.getElementById('logs').textContent = (data.lines || []).join('\\n') || '暂无日志';
      }} catch (err) {{
        document.getElementById('logs').textContent = err.message;
      }}
    }}

    async function importEmails() {{
      let content = document.getElementById('import-content').value;
      const file = document.getElementById('file-input').files[0];
      if (file) {{
        content = await file.text();
      }}
      try {{
        const data = await api('/api/import/ms-emails', {{
          method: 'POST',
          body: JSON.stringify({{ content }})
        }});
        setText('import-result', data.message || '导入成功');
        await refreshStatus();
      }} catch (err) {{
        setText('import-result', err.message);
      }}
    }}

    async function saveConfig() {{
      const payload = {{
        proxy: document.getElementById('cfg-proxy').value.trim(),
        proxy_api_url: document.getElementById('cfg-proxy-api-url').value.trim(),
        proxy_api_scheme: document.getElementById('cfg-proxy-api-scheme').value.trim(),
        register_openai_concurrency: Number(document.getElementById('cfg-concurrency').value || 1),
        register_start_delay_seconds: Number(document.getElementById('cfg-start-delay').value || 0),
        failure_sleep_seconds: Number(document.getElementById('cfg-failure-sleep').value || 20),
        once: document.getElementById('cfg-once').value === 'true',
        sleep_min: Number(document.getElementById('cfg-sleep-min').value || 10),
        sleep_max: Number(document.getElementById('cfg-sleep-max').value || 20)
      }};
      try {{
        const data = await api('/api/config', {{ method: 'POST', body: JSON.stringify(payload) }});
        setText('action-result', data.message || '设置已保存');
        await refreshStatus();
      }} catch (err) {{
        setText('action-result', err.message);
      }}
    }}

    async function testProxy() {{
      try {{
        await saveConfig();
        const data = await api('/api/proxy/test', {{ method: 'POST', body: JSON.stringify({{}}) }});
        setText('proxy-test-result', data.ok ? `可用：${{data.proxy}} 出口=${{data.ip || '-'}} 地区=${{data.loc || '-'}}` : (data.message || '不可用'));
      }} catch (err) {{
        setText('proxy-test-result', err.message);
      }}
    }}

    async function startRegister() {{
      try {{
        await saveConfig();
        const data = await api('/api/register/start', {{ method: 'POST', body: JSON.stringify({{}}) }});
        setText('action-result', data.message || '任务已启动');
        await refreshStatus();
      }} catch (err) {{
        setText('action-result', err.message);
      }}
    }}

    async function stopRegister() {{
      try {{
        const data = await api('/api/register/stop', {{ method: 'POST', body: JSON.stringify({{}}) }});
        setText('action-result', data.message || '已请求停止');
        await refreshStatus();
      }} catch (err) {{
        setText('action-result', err.message);
      }}
    }}

    async function exportZip() {{
      try {{
        const data = await api('/api/export/auths-zip', {{ method: 'POST', body: JSON.stringify({{}}) }});
        setText('action-result', data.message || '导出成功');
        await refreshStatus();
        if (data.download_url) {{
          window.open(data.download_url, '_blank');
        }}
      }} catch (err) {{
        setText('action-result', err.message);
      }}
    }}

    refreshStatus();
    refreshLogs();
    setInterval(refreshStatus, 5000);
    setInterval(refreshLogs, 5000);
  </script>
</body>
</html>"""


def _simple_page(title: str, body_html: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    body {{ margin: 0; padding: 24px; font-family: Georgia, serif; background: #f4efe6; color: #1f2937; }}
    .box {{ max-width: 1100px; margin: 0 auto; background: #fffaf0; border: 1px solid #d8cfbf; border-radius: 16px; padding: 20px; }}
    a {{ color: #14532d; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #141313; color: #f5efe7; border-radius: 12px; padding: 16px; font-family: Consolas, monospace; }}
  </style>
</head>
<body><div class="box">{body_html}</div></body>
</html>"""


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "OpenAIRegisterWeb/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        logger.info("WEB %s - %s", self.address_string(), format % args)

    def _workspace(self) -> tuple[str, str]:
        return _workspace_cookie_value(self)

    def do_GET(self) -> None:
        workspace_id, cookie = self._workspace()
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            return _render_text(self, _main_page(workspace_id), set_cookie=cookie)

        if path == "/logs":
            lines = _tail_lines(_ensure_workspace_dirs(workspace_id)["log_file"])
            body = "<p><a href='/'>返回控制台</a></p><h1>当前工作区日志</h1><pre>" + html.escape("\n".join(lines) or "暂无日志") + "</pre>"
            return _render_text(self, _simple_page("日志", body), set_cookie=cookie)

        if path == "/exports":
            items = _export_files(workspace_id)
            if items:
                listing = "".join(
                    f"<li><a href='/api/export/download/{html.escape(item['name'])}'>{html.escape(item['name'])}</a> · {item['size']} bytes · {html.escape(item['modified_at'])}</li>"
                    for item in items
                )
            else:
                listing = "<li>暂无导出</li>"
            body = f"<p><a href='/'>返回控制台</a></p><h1>导出历史</h1><ul>{listing}</ul>"
            return _render_text(self, _simple_page("导出历史", body), set_cookie=cookie)

        if path == "/api/workspace":
            return _render_json(self, {"ok": True, "workspace_id": workspace_id}, set_cookie=cookie)

        if path == "/api/status":
            return _render_json(self, _workspace_status(workspace_id), set_cookie=cookie)

        if path == "/api/config":
            state = _load_workspace_state(workspace_id)
            return _render_json(self, {"ok": True, "config": state.get("config") or dict(DEFAULT_WORKSPACE_CONFIG)}, set_cookie=cookie)

        if path == "/api/register/logs":
            lines = _tail_lines(_ensure_workspace_dirs(workspace_id)["log_file"])
            return _render_json(self, {"ok": True, "lines": lines}, set_cookie=cookie)

        if path.startswith("/api/export/download/"):
            file_name = os.path.basename(path.rsplit("/", 1)[-1])
            return _render_file(self, _ensure_workspace_dirs(workspace_id)["exports"] / file_name, set_cookie=cookie)

        return _render_json(self, {"ok": False, "message": "Not found"}, 404, set_cookie=cookie)

    def do_POST(self) -> None:
        workspace_id, cookie = self._workspace()
        parsed = urlparse(self.path)
        path = parsed.path
        payload = _parse_json_body(self)

        if path == "/api/import/ms-emails":
            content = str(payload.get("content") or "")
            valid_lines, errors = _validate_ms_email_lines(content)
            if not valid_lines:
                return _render_json(
                    self,
                    {"ok": False, "message": "没有可导入的有效微软邮箱账号", "errors": errors},
                    400,
                    set_cookie=cookie,
                )
            paths = _ensure_workspace_dirs(workspace_id)
            paths["ms_emails"].write_text("\n".join(valid_lines) + "\n", encoding="utf-8")
            _append_workspace_log(workspace_id, f"已覆盖导入微软邮箱账号 {len(valid_lines)} 条")
            return _render_json(
                self,
                {
                    "ok": True,
                    "message": f"已覆盖导入 {len(valid_lines)} 条微软邮箱账号",
                    "errors": errors,
                    "count": len(valid_lines),
                },
                set_cookie=cookie,
            )

        if path == "/api/config":
            state = _load_workspace_state(workspace_id)
            config = dict(state.get("config") or DEFAULT_WORKSPACE_CONFIG)
            config["proxy"] = str(payload.get("proxy") or "").strip()
            config["proxy_api_url"] = str(payload.get("proxy_api_url") or "").strip()
            config["proxy_api_scheme"] = str(payload.get("proxy_api_scheme") or "http").strip().lower() or "http"
            config["register_openai_concurrency"] = max(1, min(MAX_THREADS_PER_WORKSPACE, int(payload.get("register_openai_concurrency") or 1)))
            config["register_start_delay_seconds"] = max(0.0, float(payload.get("register_start_delay_seconds") or 0.0))
            config["failure_sleep_seconds"] = max(0, int(payload.get("failure_sleep_seconds") or 20))
            config["once"] = bool(payload.get("once"))
            config["sleep_min"] = max(1, int(payload.get("sleep_min") or 10))
            config["sleep_max"] = max(config["sleep_min"], int(payload.get("sleep_max") or 20))
            state["config"] = config
            _save_workspace_state(workspace_id, state)
            _append_workspace_log(workspace_id, "已更新工作区注册配置")
            return _render_json(self, {"ok": True, "message": "设置已保存", "config": config}, set_cookie=cookie)

        if path == "/api/proxy/test":
            config = (_load_workspace_state(workspace_id).get("config") or dict(DEFAULT_WORKSPACE_CONFIG))
            try:
                result = _test_proxy_config(config)
                if result.get("ok"):
                    _append_workspace_log(workspace_id, f"代理测试成功：{result.get('proxy')} 出口={result.get('ip')} loc={result.get('loc')}")
                else:
                    _append_workspace_log(workspace_id, f"代理测试失败：{result.get('message')}")
                return _render_json(self, result, set_cookie=cookie)
            except Exception as exc:
                return _render_json(self, {"ok": False, "message": str(exc)}, 400, set_cookie=cookie)

        if path == "/api/register/start":
            if _count_ms_emails(workspace_id) <= 0:
                return _render_json(self, {"ok": False, "message": "当前工作区没有可用微软邮箱账号，请先导入 ms_emails 数据"}, 400, set_cookie=cookie)
            state = _load_workspace_state(workspace_id)
            config = dict(state.get("config") or DEFAULT_WORKSPACE_CONFIG)
            try:
                job = registry.start_job(workspace_id, config)
            except Exception as exc:
                return _render_json(self, {"ok": False, "message": str(exc)}, 409, set_cookie=cookie)
            state["last_task"] = job.snapshot()
            _save_workspace_state(workspace_id, state)
            return _render_json(self, {"ok": True, "message": f"注册任务已启动，线程数={job.desired_threads}"}, set_cookie=cookie)

        if path == "/api/register/stop":
            job = registry.get_job(workspace_id)
            if not job:
                return _render_json(self, {"ok": False, "message": "当前工作区没有运行中的任务"}, 404, set_cookie=cookie)
            job.request_stop()
            return _render_json(self, {"ok": True, "message": "已请求停止任务，等待当前线程安全退出"}, set_cookie=cookie)

        if path == "/api/export/auths-zip":
            paths = _ensure_workspace_dirs(workspace_id)
            auth_files = sorted(paths["auths"].glob("*.json"))
            if not auth_files:
                return _render_json(self, {"ok": False, "message": "当前工作区没有可导出的成功 JSON 文件"}, 400, set_cookie=cookie)
            zip_name = f"auths-{workspace_id}-{_utc_stamp()}.zip"
            zip_path = paths["exports"] / zip_name
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for file_path in auth_files:
                    zf.write(file_path, arcname=file_path.name)
            _append_workspace_log(workspace_id, f"已导出成功 JSON 为 ZIP：{zip_name}")
            return _render_json(
                self,
                {
                    "ok": True,
                    "message": f"已导出 {len(auth_files)} 个 JSON 文件",
                    "filename": zip_name,
                    "download_url": f"/api/export/download/{zip_name}",
                },
                set_cookie=cookie,
            )

        return _render_json(self, {"ok": False, "message": "Not found"}, 404, set_cookie=cookie)


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAI Register Microsoft Web Panel")
    parser.add_argument("--host", default=HOST, help="监听地址，默认 0.0.0.0")
    parser.add_argument("--port", type=int, default=PORT, help="监听端口，默认 8080")
    args = parser.parse_args()

    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((str(args.host), int(args.port)), PanelHandler)
    logger.info(f"[WEB] 面板已启动：http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[WEB] 收到中断信号，正在退出")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
