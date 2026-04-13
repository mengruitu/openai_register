"""Lightweight doctor and status helpers for the CLI entrypoint."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from curl_cffi import requests

from .config import load_config_file
from .mail.cfmail import cfmail_account_names, get_cfmail_accounts, select_cfmail_account
from .proxy_pool import build_proxy_pool_snapshot
from .runtime import count_json_files

TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"


def _console_prefix() -> str:
    return datetime.now().astimezone().strftime("[%Y-%m-%d %H:%M:%S]")


def _print_console_line(message: str = "") -> None:
    prefix = _console_prefix()
    if message:
        print(f"{prefix} {message}")
    else:
        print(prefix)


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    summary: str
    detail: str = ""


@dataclass(frozen=True)
class DoctorReport:
    checked_at: str
    checks: list[DoctorCheck]

    @property
    def error_count(self) -> int:
        return sum(1 for item in self.checks if item.status == "error")

    @property
    def warn_count(self) -> int:
        return sum(1 for item in self.checks if item.status == "warn")


def _check_config_file(config_path: str) -> DoctorCheck:
    path = str(config_path or "").strip()
    if not path:
        return DoctorCheck("config", "warn", "未指定配置文件路径，将仅使用默认参数")
    if not os.path.exists(path):
        return DoctorCheck("config", "warn", f"配置文件不存在：{path}；将使用默认参数")
    if not os.path.isfile(path):
        return DoctorCheck("config", "error", f"配置路径不是文件：{path}")
    try:
        with open(path, "r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        if not isinstance(payload, dict):
            return DoctorCheck("config", "error", f"配置文件不是 JSON object：{path}")
        filtered = load_config_file(path)
        return DoctorCheck(
            "config",
            "ok",
            f"配置文件可读：{path}",
            detail=f"键数量={len(filtered)}",
        )
    except Exception as exc:
        return DoctorCheck("config", "error", f"读取配置文件失败：{path}", detail=str(exc))


def _touch_directory(path: str) -> tuple[bool, str]:
    try:
        os.makedirs(path, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".doctor-", dir=path, delete=True):
            pass
    except Exception as exc:
        return False, str(exc)
    return True, "ok"


def _check_directory(name: str, path: str) -> DoctorCheck:
    target = str(path or "").strip()
    if not target:
        return DoctorCheck(name, "error", f"{name} 未配置")
    ok, detail = _touch_directory(target)
    if not ok:
        return DoctorCheck(name, "error", f"{name} 不可写：{target}", detail=detail)
    count = count_json_files(target)
    return DoctorCheck(name, "ok", f"{name} 可用：{target}", detail=f"当前 json 数量={count}")


def _parse_trace(text: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for line in str(text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        payload[key.strip()] = value.strip()
    return payload


def _check_proxy(proxy: str | None) -> DoctorCheck:
    proxy_url = str(proxy or "").strip()
    if not proxy_url:
        return DoctorCheck("proxy", "warn", "未显式设置 proxy，将按当前直连环境运行")

    try:
        resp = requests.get(
            TRACE_URL,
            proxies={"http": proxy_url, "https": proxy_url},
            impersonate="chrome",
            timeout=10,
        )
    except Exception as exc:
        return DoctorCheck("proxy", "error", f"代理不可达：{proxy_url}", detail=str(exc))

    if resp.status_code != 200:
        return DoctorCheck(
            "proxy",
            "error",
            f"代理探测失败：HTTP {resp.status_code}",
            detail=str(getattr(resp, "text", "") or "")[:240],
        )

    trace = _parse_trace(getattr(resp, "text", ""))
    loc = trace.get("loc") or "unknown"
    ip = trace.get("ip") or ""
    return DoctorCheck("proxy", "ok", f"代理可用：{proxy_url}", detail=f"出口地区={loc} ip={ip}")


def _check_cfmail(args: Any) -> DoctorCheck:
    if str(args.mail_provider or "").strip().lower() != "cfmail":
        return DoctorCheck("cfmail", "skip", f"当前邮箱服务为 {args.mail_provider}，跳过 cfmail 检查")

    accounts = get_cfmail_accounts()
    if not accounts:
        return DoctorCheck(
            "cfmail",
            "error",
            f"未检测到可用 cfmail 配置：{args.cfmail_config}",
        )

    selected = select_cfmail_account(args.cfmail_profile)
    if str(args.cfmail_profile or "").strip().lower() != "auto" and selected is None:
        return DoctorCheck(
            "cfmail",
            "error",
            f"指定的 cfmail profile 不存在：{args.cfmail_profile}",
            detail=f"当前可用：{cfmail_account_names(accounts)}",
        )

    active = selected or accounts[0]
    return DoctorCheck(
        "cfmail",
        "ok",
        f"cfmail 已配置：{active.name} -> {active.email_domain}",
        detail=f"配置数={len(accounts)}",
    )


def collect_doctor_report(args: Any) -> DoctorReport:
    checks = [
        _check_config_file(args.config),
        _check_directory("active_token_dir", args.active_token_dir),
        _check_proxy(args.proxy),
        _check_cfmail(args),
    ]
    return DoctorReport(
        checked_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        checks=checks,
    )


def build_status_snapshot(args: Any) -> dict[str, Any]:
    active_count = count_json_files(args.active_token_dir)
    active_shortage = max(int(args.active_min_count) - active_count, 0)
    snapshot: dict[str, Any] = {
        "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "config_path": str(args.config or "").strip(),
        "proxy": str(args.proxy or "").strip(),
        "proxy_api_url": str(getattr(args, "proxy_api_url", "") or "").strip(),
        "proxy_api_scheme": str(getattr(args, "proxy_api_scheme", "http") or "http").strip(),
        "mail_provider": str(args.mail_provider or "").strip(),
        "active": {
            "dir": str(args.active_token_dir or "").strip(),
            "count": active_count,
            "target": int(args.active_min_count),
            "shortage": active_shortage,
        },
        "output": {
            "dir": str(args.token_dir or "").strip(),
        },
        "runtime": {
            "register_batch_size": int(args.register_batch_size),
            "register_openai_concurrency": int(args.register_openai_concurrency),
            "register_start_delay_seconds": float(args.register_start_delay_seconds),
            "monitor_interval": int(args.monitor_interval),
            "detected_total_memory_mb": int(getattr(args, "detected_total_memory_mb", 0) or 0),
        },
    }

    if bool(getattr(args, "proxy_pool_enabled", False)):
        proxy_pool_snapshot = build_proxy_pool_snapshot()
        proxy_pool_snapshot["enabled"] = True
        proxy_pool_snapshot["configured_state_path"] = str(
            getattr(args, "proxy_pool_state_path", "") or ""
        ).strip()
        proxy_pool_snapshot["configured_consumers_path"] = str(
            getattr(args, "proxy_pool_consumers_path", "") or ""
        ).strip()
        proxy_pool_snapshot["target_multiplier"] = int(
            getattr(args, "proxy_pool_target_multiplier", 0) or 0
        )
        snapshot["proxy_pool"] = proxy_pool_snapshot

    if str(args.mail_provider or "").strip().lower() == "cfmail":
        accounts = get_cfmail_accounts()
        selected = select_cfmail_account(args.cfmail_profile)
        snapshot["cfmail"] = {
            "config_path": str(args.cfmail_config or "").strip(),
            "profile_mode": str(args.cfmail_profile or "").strip(),
            "selected": getattr(selected, "name", "") if selected else "",
            "accounts": [
                {
                    "name": item.name,
                    "worker_domain": item.worker_domain,
                    "email_domain": item.email_domain,
                }
                for item in accounts
            ],
        }

    return snapshot


def print_doctor_report(report: DoctorReport, *, output_json: bool = False) -> None:
    if output_json:
        payload = {
            "checked_at": report.checked_at,
            "error_count": report.error_count,
            "warn_count": report.warn_count,
            "checks": [asdict(item) for item in report.checks],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    _print_console_line("doctor 检查结果")
    _print_console_line(f"时间：{report.checked_at}")
    for item in report.checks:
        _print_console_line(f"[{item.status.upper()}] {item.name}: {item.summary}")
        if item.detail:
            _print_console_line(f"  └─ {item.detail}")
    _print_console_line(f"汇总：error={report.error_count} warn={report.warn_count}")


def print_status_snapshot(snapshot: dict[str, Any], *, output_json: bool = False) -> None:
    if output_json:
        print(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return

    _print_console_line("当前状态")
    _print_console_line(f"时间：{snapshot.get('checked_at', '')}")
    _print_console_line(f"配置：{snapshot.get('config_path', '') or '(默认/未指定)'}")
    _print_console_line(f"代理：{snapshot.get('proxy', '') or '(未显式设置)'}")
    if snapshot.get("proxy_api_url"):
        _print_console_line(f"代理API：{snapshot.get('proxy_api_url', '')} (scheme={snapshot.get('proxy_api_scheme', 'http')})")
    if snapshot.get("proxy_pool"):
        proxy_pool = snapshot["proxy_pool"]
        _print_console_line(
            f"共享IP池：enabled={proxy_pool.get('enabled', False)} "
            f"runtime_active={proxy_pool.get('runtime_active', False)} "
            f"available={proxy_pool.get('available_count', 0)} "
            f"target={proxy_pool.get('target_count', 0)} "
            f"consumers={proxy_pool.get('active_consumer_count', 0)}"
        )
    _print_console_line(f"邮箱服务：{snapshot.get('mail_provider', '')}")

    active = snapshot.get("active") or {}
    output = snapshot.get("output") or {}
    runtime = snapshot.get("runtime") or {}
    _print_console_line(
        f"A目录：{active.get('count', 0)}/{active.get('target', 0)} "
        f"（缺 {active.get('shortage', 0)}） -> {active.get('dir', '')}"
    )
    _print_console_line(f"注册输出目录：{output.get('dir', '')}")
    _print_console_line(
        "并发："
        f"register_batch_size={runtime.get('register_batch_size', 0)}, "
        f"register_openai_concurrency={runtime.get('register_openai_concurrency', 0)}"
    )
    if snapshot.get("cfmail"):
        cfmail = snapshot["cfmail"]
        account_names = ",".join(item.get("name", "") for item in cfmail.get("accounts", []))
        _print_console_line(
            f"cfmail：profile={cfmail.get('profile_mode', '')} "
            f"selected={cfmail.get('selected', '') or '(auto)'} "
            f"accounts=[{account_names}]"
        )
