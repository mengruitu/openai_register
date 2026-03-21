# -*- coding: utf-8 -*-
"""OpenAI 自动注册与账号巡检脚本。

支持多种临时邮箱服务，自动完成注册流程并维护双目录 Token 池。
"""
import argparse
import base64
import builtins
import hashlib
import json
import math
import os
import random
import re
import secrets
import socket
import string
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from curl_cffi import requests

# 线程锁，用于串行化输出文件写入
output_lock = threading.Lock()
builtins.yasal_bypass_ip_choice = True

# ==========================================
# 临时邮箱 API (仅保留最坚挺的 Mail.tm)
# ==========================================

MAILTM_BASE = "https://api.mail.tm"
TEMPMAILLOL_BASE = "https://api.tempmail.lol/v2"
TEMPMAILIO_API = "https://api.internal.temp-mail.io/api/v3/email"
DROPMAIL_API = "https://dropmail.me/api/graphql"
# 脚本所在目录，作为默认路径的基准
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 自建 cfmail 的真实配置统一放在 cfmail_accounts.json 中
DEFAULT_CFMAIL_CONFIG_PATH = os.path.join(_SCRIPT_DIR, "cfmail_accounts.json")
DEFAULT_CFMAIL_ACCOUNTS = []
DEFAULT_CFMAIL_PROFILE_NAME = (
    str(DEFAULT_CFMAIL_ACCOUNTS[0].get("name") or "").strip()
    if DEFAULT_CFMAIL_ACCOUNTS
    else "default"
)
DEFAULT_CFMAIL_WORKER_DOMAIN = (
    str(DEFAULT_CFMAIL_ACCOUNTS[0].get("worker_domain") or "").strip()
    if DEFAULT_CFMAIL_ACCOUNTS
    else ""
)
DEFAULT_CFMAIL_EMAIL_DOMAIN = (
    str(DEFAULT_CFMAIL_ACCOUNTS[0].get("email_domain") or "").strip()
    if DEFAULT_CFMAIL_ACCOUNTS
    else ""
)
DEFAULT_CFMAIL_ADMIN_PASSWORD = (
    str(DEFAULT_CFMAIL_ACCOUNTS[0].get("admin_password") or "").strip()
    if DEFAULT_CFMAIL_ACCOUNTS
    else ""
)
DEFAULT_ACTIVE_TOKEN_DIR = os.path.join(_SCRIPT_DIR, "auths")
DEFAULT_TOKEN_OUTPUT_DIR = os.path.join(_SCRIPT_DIR, "auths_pool")
DEFAULT_MIN_ACTIVE_COUNT = 20
DEFAULT_MIN_POOL_COUNT = 50
DEFAULT_USAGE_THRESHOLD = 90
DEFAULT_CHECK_INTERVAL_SECONDS = 900
DEFAULT_DINGTALK_SUMMARY_INTERVAL_SECONDS = 10800
DEFAULT_REQUEST_INTERVAL_SECONDS = 2
DEFAULT_REGISTER_BATCH_SIZE = 3
DEFAULT_CFMAIL_FAIL_THRESHOLD = 3
DEFAULT_CFMAIL_COOLDOWN_SECONDS = 300
DEFAULT_REGISTER_FAILURE_EXTRA_SLEEP_SECONDS = 10
# 请改成你的钉钉机器人地址
DEFAULT_DINGTALK_WEBHOOK = ""


@dataclass(frozen=True)
class TempMailbox:
    email: str
    provider: str
    token: str = ""
    api_base: str = ""
    login: str = ""
    domain: str = ""
    sid_token: str = ""
    password: str = ""
    config_name: str = ""


@dataclass(frozen=True)
class CfmailAccount:
    name: str
    worker_domain: str
    email_domain: str
    admin_password: str


@dataclass(frozen=True)
class MonitorCycleResult:
    completed_at: datetime
    active_count: int
    pool_count: int
    active_target: int
    pool_target: int
    attempted_replenish: bool
    replenished_count: int
    deleted_count: int


def _load_cfmail_accounts_from_file(
    config_path: str, *, silent: bool = False
) -> List[Dict[str, Any]]:
    # 配置文件支持两种格式：
    # 1. 直接是数组 [ {...}, {...} ]
    # 2. 外层包一层对象 { "accounts": [ {...} ] }
    path = str(config_path or "").strip()
    if not path or not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        if not silent:
            print(f"[警告] 读取 cfmail 配置文件失败: {path}，错误: {e}")
        return []

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        accounts = data.get("accounts")
        if isinstance(accounts, list):
            return accounts

    if not silent:
        print(f"[警告] cfmail 配置文件格式无效: {path}")
    return []


def _mailtm_headers(*, token: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _normalize_host(value: str) -> str:
    value = str(value or "").strip()
    if value.startswith("https://"):
        value = value[len("https://") :]
    elif value.startswith("http://"):
        value = value[len("http://") :]
    return value.strip().strip("/")


def _normalize_cfmail_account(raw: Dict[str, Any]) -> Optional[CfmailAccount]:
    if not isinstance(raw, dict):
        return None

    if not raw.get("enabled", True):
        return None

    name = str(raw.get("name") or "").strip()
    worker_domain = _normalize_host(
        raw.get("worker_domain") or raw.get("WORKER_DOMAIN") or ""
    )
    email_domain = _normalize_host(
        raw.get("email_domain") or raw.get("EMAIL_DOMAIN") or ""
    )
    admin_password = str(
        raw.get("admin_password") or raw.get("ADMIN_PASSWORD") or ""
    ).strip()

    if not name or not worker_domain or not email_domain or not admin_password:
        return None

    return CfmailAccount(
        name=name,
        worker_domain=worker_domain,
        email_domain=email_domain,
        admin_password=admin_password,
    )


def _build_cfmail_accounts(raw_accounts: List[Dict[str, Any]]) -> List[CfmailAccount]:
    accounts: List[CfmailAccount] = []
    seen_names: Set[str] = set()

    for item in raw_accounts:
        account = _normalize_cfmail_account(item)
        if not account:
            continue

        key = account.name.lower()
        if key in seen_names:
            continue

        seen_names.add(key)
        accounts.append(account)

    env_worker_domain = _normalize_host(os.getenv("CFMAIL_WORKER_DOMAIN", ""))
    env_email_domain = _normalize_host(os.getenv("CFMAIL_EMAIL_DOMAIN", ""))
    env_admin_password = str(os.getenv("CFMAIL_ADMIN_PASSWORD", "")).strip()
    env_profile_name = (
        str(os.getenv("CFMAIL_PROFILE_NAME", DEFAULT_CFMAIL_PROFILE_NAME)).strip()
        or DEFAULT_CFMAIL_PROFILE_NAME
    )

    if env_worker_domain and env_email_domain and env_admin_password:
        env_account = CfmailAccount(
            name=env_profile_name,
            worker_domain=env_worker_domain,
            email_domain=env_email_domain,
            admin_password=env_admin_password,
        )
        env_key = env_account.name.lower()
        accounts = [acc for acc in accounts if acc.name.lower() != env_key]
        accounts.insert(0, env_account)

    return accounts


def _cfmail_account_names(accounts: Optional[List[CfmailAccount]] = None) -> str:
    items = accounts if accounts is not None else CFMAIL_ACCOUNTS
    return ", ".join(account.name for account in items) if items else "无"


def _refresh_cfmail_globals() -> None:
    globals()["CFMAIL_WORKER_DOMAIN"] = (
        CFMAIL_ACCOUNTS[0].worker_domain if CFMAIL_ACCOUNTS else ""
    )
    globals()["CFMAIL_EMAIL_DOMAIN"] = (
        CFMAIL_ACCOUNTS[0].email_domain if CFMAIL_ACCOUNTS else ""
    )
    globals()["CFMAIL_ADMIN_PASSWORD"] = (
        CFMAIL_ACCOUNTS[0].admin_password if CFMAIL_ACCOUNTS else ""
    )


def _prune_cfmail_failure_state(accounts: Optional[List[CfmailAccount]] = None) -> None:
    items = accounts if accounts is not None else CFMAIL_ACCOUNTS
    valid_keys = {account.name.lower() for account in items}
    with _cfmail_failure_lock:
        for key in list(CFMAIL_FAILURE_STATE.keys()):
            if key not in valid_keys:
                CFMAIL_FAILURE_STATE.pop(key, None)


def _cfmail_skip_remaining_seconds(account_name: str) -> int:
    key = str(account_name or "").strip().lower()
    if not key:
        return 0

    with _cfmail_failure_lock:
        state = CFMAIL_FAILURE_STATE.get(key) or {}
        cooldown_until = float(state.get("cooldown_until") or 0)

    remaining = int(math.ceil(cooldown_until - time.time()))
    return max(0, remaining)


def _record_cfmail_success(account_name: str) -> None:
    key = str(account_name or "").strip().lower()
    if not key:
        return

    with _cfmail_failure_lock:
        state = CFMAIL_FAILURE_STATE.setdefault(key, {"name": account_name})
        state["name"] = account_name
        state["consecutive_failures"] = 0
        state["cooldown_until"] = 0
        state["last_error"] = ""
        state["last_success_at"] = time.time()


def _record_cfmail_failure(account_name: str, reason: str = "") -> None:
    # 当某个 cfmail 配置连续失败达到阈值后，临时加入冷却期，
    # 自动轮询模式会先跳过它，避免一直撞同一个坏配置。
    key = str(account_name or "").strip().lower()
    if not key:
        return

    now = time.time()
    cooldown_seconds = max(0, int(CFMAIL_COOLDOWN_SECONDS))
    fail_threshold = max(1, int(CFMAIL_FAIL_THRESHOLD))

    with _cfmail_failure_lock:
        state = CFMAIL_FAILURE_STATE.setdefault(key, {"name": account_name})
        state["name"] = account_name
        state["consecutive_failures"] = int(state.get("consecutive_failures") or 0) + 1
        state["last_error"] = str(reason or "").strip()[:300]
        state["last_failed_at"] = now

        if state["consecutive_failures"] >= fail_threshold:
            state["cooldown_until"] = max(
                float(state.get("cooldown_until") or 0),
                now + cooldown_seconds,
            )
            state["consecutive_failures"] = 0
            cooldown_until = state["cooldown_until"]
        else:
            cooldown_until = float(state.get("cooldown_until") or 0)

    if cooldown_until > now:
        remaining = int(math.ceil(cooldown_until - now))
        print(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] cfmail 配置 {account_name} 连续失败达到阈值，已自动跳过 {remaining} 秒"
        )


def _reload_cfmail_accounts_if_needed(force: bool = False) -> bool:
    global CFMAIL_CONFIG_MTIME

    if not CFMAIL_HOT_RELOAD_ENABLED:
        return False

    config_path = str(CFMAIL_CONFIG_PATH or "").strip()
    if not config_path:
        return False

    try:
        mtime = os.path.getmtime(config_path)
    except OSError:
        return False

    # 通过 mtime 判断 JSON 是否变化。变化后热加载，无需重启脚本。
    with _cfmail_reload_lock:
        if not force and CFMAIL_CONFIG_MTIME == mtime:
            return False

        raw_accounts = _load_cfmail_accounts_from_file(config_path)
        new_accounts = _build_cfmail_accounts(raw_accounts)
        if not new_accounts:
            print(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] cfmail 配置文件热加载失败：{config_path} 中没有可用配置，保留当前配置"
            )
            CFMAIL_CONFIG_MTIME = mtime
            return False

        old_names = _cfmail_account_names()
        _set_cfmail_accounts(new_accounts)
        _prune_cfmail_failure_state(new_accounts)
        CFMAIL_CONFIG_MTIME = mtime
        new_names = _cfmail_account_names()
        if force or old_names != new_names:
            print(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [信息] cfmail 配置已热加载：{new_names}"
            )
        return True


_cfmail_account_lock = threading.Lock()
_cfmail_account_index = 0
_cfmail_reload_lock = threading.Lock()
_cfmail_failure_lock = threading.Lock()
CFMAIL_CONFIG_PATH = (
    str(os.getenv("CFMAIL_CONFIG_PATH", DEFAULT_CFMAIL_CONFIG_PATH)).strip()
    or DEFAULT_CFMAIL_CONFIG_PATH
)
CFMAIL_ACCOUNTS = _build_cfmail_accounts(
    _load_cfmail_accounts_from_file(CFMAIL_CONFIG_PATH, silent=True)
    or DEFAULT_CFMAIL_ACCOUNTS
)
CFMAIL_PROFILE_MODE = "auto"
CFMAIL_HOT_RELOAD_ENABLED = True
CFMAIL_CONFIG_MTIME = (
    os.path.getmtime(CFMAIL_CONFIG_PATH) if os.path.exists(CFMAIL_CONFIG_PATH) else None
)
# cfmail 失败熔断参数：
# - 连续失败达到阈值后，临时跳过该配置一段时间
# - 只影响 auto 轮询，不影响手动指定 --cfmail-profile
CFMAIL_FAIL_THRESHOLD = DEFAULT_CFMAIL_FAIL_THRESHOLD
CFMAIL_COOLDOWN_SECONDS = DEFAULT_CFMAIL_COOLDOWN_SECONDS
CFMAIL_FAILURE_STATE: Dict[str, Dict[str, Any]] = {}

CFMAIL_WORKER_DOMAIN = _normalize_host(
    os.getenv("CFMAIL_WORKER_DOMAIN", DEFAULT_CFMAIL_WORKER_DOMAIN)
)
CFMAIL_EMAIL_DOMAIN = _normalize_host(
    os.getenv("CFMAIL_EMAIL_DOMAIN", DEFAULT_CFMAIL_EMAIL_DOMAIN)
)
CFMAIL_ADMIN_PASSWORD = os.getenv(
    "CFMAIL_ADMIN_PASSWORD", DEFAULT_CFMAIL_ADMIN_PASSWORD
).strip()

if CFMAIL_ACCOUNTS:
    _refresh_cfmail_globals()


def _set_cfmail_accounts(accounts: List[CfmailAccount]) -> None:
    global CFMAIL_ACCOUNTS, _cfmail_account_index
    CFMAIL_ACCOUNTS = accounts
    _cfmail_account_index = 0
    _refresh_cfmail_globals()


def _select_cfmail_account(profile_name: str = "auto") -> Optional[CfmailAccount]:
    global _cfmail_account_index
    accounts = CFMAIL_ACCOUNTS
    if not accounts:
        return None

    selected_name = str(profile_name or "auto").strip()
    if selected_name and selected_name.lower() != "auto":
        selected_key = selected_name.lower()
        for account in accounts:
            if account.name.lower() == selected_key:
                remaining = _cfmail_skip_remaining_seconds(account.name)
                if remaining > 0:
                    print(
                        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] cfmail 配置 {account.name} 当前仍在冷却中，剩余 {remaining} 秒；因你已手动指定，仍继续尝试"
                    )
                return account
        return None

    # auto 模式下按顺序轮询账号；若某个配置处于冷却期，则自动跳过。
    with _cfmail_account_lock:
        start_index = _cfmail_account_index % len(accounts)
        skipped_accounts = []

        for offset in range(len(accounts)):
            index = (start_index + offset) % len(accounts)
            account = accounts[index]
            remaining = _cfmail_skip_remaining_seconds(account.name)
            if remaining > 0:
                skipped_accounts.append((account.name, remaining))
                continue

            _cfmail_account_index = (index + 1) % len(accounts)
            return account

    if skipped_accounts:
        skip_desc = ", ".join(
            f"{name}({remaining}s)" for name, remaining in skipped_accounts
        )
        print(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] 所有 cfmail 配置当前都在冷却中，暂不分配邮箱：{skip_desc}"
        )
    return None


def _cfmail_headers(*, jwt: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    return headers


def _build_request_proxies(proxy: Optional[str]) -> Any:
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def _test_single_cfmail_account(
    account: CfmailAccount, proxy: Optional[str] = None
) -> bool:
    proxies = _build_request_proxies(proxy)
    print(f"\n[cfmail测试] 开始测试配置: {account.name}")
    print(
        f"[cfmail测试] worker_domain={account.worker_domain} email_domain={account.email_domain}"
    )

    try:
        local = f"codextest{secrets.token_hex(4)}"
        create_resp = requests.post(
            f"https://{account.worker_domain}/admin/new_address",
            headers={
                "x-admin-auth": account.admin_password,
                **_cfmail_headers(use_json=True),
            },
            json={
                "enablePrefix": True,
                "name": local,
                "domain": account.email_domain,
            },
            proxies=proxies,
            impersonate="chrome",
            timeout=20,
        )
        if create_resp.status_code != 200:
            print(
                f"[cfmail测试] 失败：创建邮箱返回 {create_resp.status_code}，响应={create_resp.text[:300]}"
            )
            return False

        data = create_resp.json() if create_resp.content else {}
        address = str(data.get("address") or "").strip()
        jwt = str(data.get("jwt") or "").strip()
        if not address or not jwt:
            print(f"[cfmail测试] 失败：创建邮箱成功但返回 address/jwt 不完整")
            return False

        print(f"[cfmail测试] 创建成功: {address}")

        poll_resp = requests.get(
            f"https://{account.worker_domain}/api/mails",
            params={"limit": 5, "offset": 0},
            headers=_cfmail_headers(jwt=jwt, use_json=True),
            proxies=proxies,
            impersonate="chrome",
            timeout=20,
        )
        if poll_resp.status_code != 200:
            print(
                f"[cfmail测试] 失败：轮询接口返回 {poll_resp.status_code}，响应={poll_resp.text[:300]}"
            )
            return False

        poll_data = poll_resp.json() if poll_resp.content else {}
        count = poll_data.get("count", 0) if isinstance(poll_data, dict) else 0
        print(f"[cfmail测试] 轮询成功: count={count}")
        return True
    except Exception as e:
        print(f"[cfmail测试] 失败：{account.name} 测试异常: {e}")
        return False


def run_cfmail_self_test(
    accounts: List[CfmailAccount],
    *,
    proxy: Optional[str] = None,
    profile_name: str = "auto",
) -> bool:
    if not accounts:
        print("[cfmail测试] 未找到可用的 cfmail 配置")
        return False

    selected_accounts = accounts
    selected_name = str(profile_name or "auto").strip()
    if selected_name and selected_name.lower() != "auto":
        selected_accounts = [
            account
            for account in accounts
            if account.name.lower() == selected_name.lower()
        ]
        if not selected_accounts:
            print(
                f"[cfmail测试] 未找到指定配置: {selected_name}；当前可用配置: {_cfmail_account_names(accounts)}"
            )
            return False

    print(
        f"[cfmail测试] 共需测试 {len(selected_accounts)} 个配置: {_cfmail_account_names(selected_accounts)}"
    )
    passed = 0
    for account in selected_accounts:
        if _test_single_cfmail_account(account, proxy):
            passed += 1

    print(
        f"\n[cfmail测试] 测试完成：成功 {passed} / {len(selected_accounts)}，失败 {len(selected_accounts) - passed}"
    )
    return passed == len(selected_accounts)


def _hydra_domains(api_base: str, proxies: Any = None) -> List[str]:
    resp = requests.get(
        f"{api_base}/domains",
        headers=_mailtm_headers(),
        proxies=proxies,
        impersonate="chrome",
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"获取域名失败，状态码: {resp.status_code}")

    data = resp.json()
    domains = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("hydra:member") or data.get("items") or []
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip()
        is_active = item.get("isActive", True)
        is_private = item.get("isPrivate", False)
        if domain and is_active and not is_private:
            domains.append(domain)

    return domains


def _create_hydra_mailbox(
    *,
    api_base: str,
    provider_name: str,
    provider_key: str,
    proxies: Any = None,
    thread_id: int,
) -> Optional[TempMailbox]:
    try:
        domains = _hydra_domains(api_base, proxies)
        if not domains:
            print(f"[线程 {thread_id}] [警告] {provider_name} 没有可用域名")
            return None

        for _ in range(5):
            local = f"oc{secrets.token_hex(5)}"
            domain = random.choice(domains)
            email = f"{local}@{domain}"
            password = secrets.token_urlsafe(18)

            create_resp = requests.post(
                f"{api_base}/accounts",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )

            if create_resp.status_code not in (200, 201):
                continue

            token_resp = requests.post(
                f"{api_base}/token",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )

            if token_resp.status_code == 200:
                token = str(token_resp.json().get("token") or "").strip()
                if token:
                    return TempMailbox(
                        email=email,
                        provider=provider_key,
                        token=token,
                        api_base=api_base,
                        password=password,
                    )

        print(
            f"[线程 {thread_id}] [警告] {provider_name} 邮箱创建成功但获取 Token 失败"
        )
        return None
    except Exception as e:
        print(f"[线程 {thread_id}] [警告] 请求 {provider_name} API 出错: {e}")
        return None


def _create_tempmailio_mailbox(
    proxies: Any = None, thread_id: int = 0
) -> Optional[TempMailbox]:
    try:
        resp = requests.post(
            f"{TEMPMAILIO_API}/new",
            json={"min_name_length": 10, "max_name_length": 10},
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            email = data.get("email")
            token = data.get("token")
            if email:
                return TempMailbox(
                    email=email,
                    provider="tempmailio",
                    token=token,
                )
        print(f"[线程 {thread_id}] [警告] temp-mail.io 邮箱初始化失败")
        return None
    except Exception as e:
        print(f"[线程 {thread_id}] [警告] 请求 temp-mail.io API 出错: {e}")
        return None


def _create_tempmaillol_mailbox(
    proxies: Any = None, thread_id: int = 0
) -> Optional[TempMailbox]:
    try:
        resp = requests.post(
            f"{TEMPMAILLOL_BASE}/inbox/create",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={},
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            print(
                f"[线程 {thread_id}] [警告] Tempmail.lol 邮箱初始化失败，状态码: {resp.status_code}"
            )
            return None

        data = resp.json()
        email = str(data.get("address") or "").strip()
        token = str(data.get("token") or "").strip()
        if not email or not token:
            print(f"[线程 {thread_id}] [警告] Tempmail.lol 返回数据不完整")
            return None

        return TempMailbox(
            email=email,
            provider="tempmaillol",
            token=token,
        )
    except Exception as e:
        print(f"[线程 {thread_id}] [警告] 请求 Tempmail.lol API 出错: {e}")
        return None


def _create_dropmail_mailbox(
    proxies: Any = None, thread_id: int = 0
) -> Optional[TempMailbox]:
    try:
        query = """
        mutation {
            introduceSession {
                id, addresses { address }
            }
        }
        """
        resp = requests.post(
            DROPMAIL_API,
            json={"query": query},
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("introduceSession", {})
            session_id = data.get("id")
            addrs = data.get("addresses", [])
            if session_id and addrs:
                email = addrs[0].get("address")
                return TempMailbox(
                    email=email,
                    provider="dropmail",
                    sid_token=session_id,
                )
        print(f"[线程 {thread_id}] [警告] Dropmail 邮箱初始化失败")
        return None
    except Exception as e:
        print(f"[线程 {thread_id}] [警告] 请求 Dropmail API 出错: {e}")
        return None


def _create_cfmail_mailbox(
    proxies: Any = None, thread_id: int = 0
) -> Optional[TempMailbox]:
    # 每次创建 cfmail 邮箱前先尝试热加载配置，这样改 JSON 后下轮可直接生效。
    _reload_cfmail_accounts_if_needed()
    selected_account = _select_cfmail_account(CFMAIL_PROFILE_MODE)
    if not selected_account:
        print(
            f"[线程 {thread_id}] [错误] 自建邮箱配置不可用，请检查 {CFMAIL_CONFIG_PATH} 或 --cfmail-profile 参数；当前可用配置: {_cfmail_account_names()}"
        )
        return None

    try:
        local = f"oc{secrets.token_hex(5)}"
        worker_domain = selected_account.worker_domain
        resp = requests.post(
            f"https://{worker_domain}/admin/new_address",
            headers={
                "x-admin-auth": selected_account.admin_password,
                **_cfmail_headers(use_json=True),
            },
            json={
                "enablePrefix": True,
                "name": local,
                "domain": selected_account.email_domain,
            },
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code != 200:
            print(
                f"[线程 {thread_id}] [警告] 自建邮箱[{selected_account.name}]创建失败，状态码: {resp.status_code}，响应: {resp.text[:300]}"
            )
            _record_cfmail_failure(
                selected_account.name,
                f"new_address status={resp.status_code}",
            )
            return None

        data = resp.json()
        email = str(data.get("address") or "").strip()
        jwt = str(data.get("jwt") or "").strip()
        if not email or not jwt:
            print(f"[线程 {thread_id}] [警告] 自建邮箱[{selected_account.name}]返回数据不完整")
            _record_cfmail_failure(selected_account.name, "new_address incomplete data")
            return None

        return TempMailbox(
            email=email,
            provider="cfmail",
            token=jwt,
            api_base=f"https://{selected_account.worker_domain}",
            domain=selected_account.email_domain,
            config_name=selected_account.name,
        )
    except Exception as e:
        print(f"[线程 {thread_id}] [警告] 请求自建邮箱[{selected_account.name}] API 出错: {e}")
        _record_cfmail_failure(selected_account.name, f"new_address exception: {e}")
        return None


def get_temp_mailbox(
    provider_key: str,
    thread_id: int,
    proxies: Any = None,
    mailtm_base: str = MAILTM_BASE,
) -> Optional[TempMailbox]:
    mailbox = None
    if provider_key == "mailtm":
        mailbox = _create_hydra_mailbox(
            api_base=mailtm_base,
            provider_name="Mail.tm",
            provider_key="mailtm",
            proxies=proxies,
            thread_id=thread_id,
        )
    elif provider_key == "tempmaillol":
        mailbox = _create_tempmaillol_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "tempmailio":
        mailbox = _create_tempmailio_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "dropmail":
        mailbox = _create_dropmail_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "cfmail":
        mailbox = _create_cfmail_mailbox(proxies=proxies, thread_id=thread_id)
    else:
        print(f"[线程 {thread_id}] [错误] 不支持的临时邮箱服务: {provider_key}")
        return None

    if mailbox:
        provider_desc = provider_key
        if mailbox.provider == "cfmail" and mailbox.config_name:
            provider_desc = f"{provider_key}:{mailbox.config_name}"
        print(
            f"[线程 {thread_id}] [信息] 已绑定临时邮箱服务: {provider_desc}"
        )
        return mailbox

    print(
        f"[线程 {thread_id}] [错误] 临时邮箱服务不可用或创建失败: {provider_key}"
    )
    return None


def _poll_hydra_oai_code(
    *, api_base: str, token: str, email: str, thread_id: int, proxies: Any = None
) -> str:
    url_list = f"{api_base}/messages"
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids: Set[str] = set()

    print(
        f"[线程 {thread_id}] [*] 正在等待邮箱 {email} 的验证码...", end="", flush=True
    )

    for _ in range(40):
        print(".", end="", flush=True)
        try:
            resp = requests.get(
                url_list,
                headers=_mailtm_headers(token=token),
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue

            data = resp.json()
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                messages = data.get("hydra:member") or data.get("messages") or []
            else:
                messages = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                read_resp = requests.get(
                    f"{api_base}/messages/{msg_id}",
                    headers=_mailtm_headers(token=token),
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
                if read_resp.status_code != 200:
                    continue

                mail_data = read_resp.json()
                sender = str(
                    ((mail_data.get("from") or {}).get("address") or "")
                ).lower()
                subject = str(mail_data.get("subject") or "")
                intro = str(mail_data.get("intro") or "")
                text = str(mail_data.get("text") or "")
                html = mail_data.get("html") or ""
                if isinstance(html, list):
                    html = "\n".join(str(x) for x in html)
                content = "\n".join([subject, intro, text, str(html)])

                if "openai" not in sender and "openai" not in content.lower():
                    continue

                m = re.search(regex, content)
                if m:
                    print(
                        f"\n[线程 {thread_id}] [信息] 已收到验证码: {m.group(1)}"
                    )
                    return m.group(1)
        except Exception:
            pass

        time.sleep(3)

    print(
        f"\n[线程 {thread_id}] [警告] 等待超时，未收到验证码"
    )
    return ""


def _poll_tempmailio_oai_code(
    *, email: str, thread_id: int, proxies: Any = None
) -> str:
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids: Set[str] = set()

    print(
        f"[线程 {thread_id}] [*] 正在等待邮箱 {email} 的验证码...", end="", flush=True
    )

    for _ in range(40):
        print(".", end="", flush=True)
        try:
            resp = requests.get(
                f"{TEMPMAILIO_API}/{email}/messages",
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code == 200:
                messages = resp.json()
                for msg in messages:
                    msg_id = msg.get("id")
                    if not msg_id or msg_id in seen_ids:
                        continue
                    seen_ids.add(msg_id)

                    sender = str(msg.get("from") or "").lower()
                    subject = str(msg.get("subject") or "")
                    body = str(msg.get("body_text") or "")
                    content = "\n".join([subject, body])

                    if "openai" not in sender and "openai" not in content.lower():
                        continue

                    m = re.search(regex, content)
                    if m:
                        print(f"\n[线程 {thread_id}] [信息] 已收到验证码: {m.group(1)}")
                        return m.group(1)
        except Exception:
            pass
        time.sleep(3)

    print(f"\n[线程 {thread_id}] [警告] 等待超时，未收到验证码")
    return ""


def _poll_tempmaillol_oai_code(
    *, token: str, email: str, thread_id: int, proxies: Any = None
) -> str:
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids: Set[int] = set()

    print(
        f"[线程 {thread_id}] [*] 正在等待邮箱 {email} 的验证码...", end="", flush=True
    )

    for _ in range(40):
        print(".", end="", flush=True)
        try:
            resp = requests.get(
                f"{TEMPMAILLOL_BASE}/inbox",
                params={"token": token},
                headers={"Accept": "application/json"},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue

            data = resp.json()
            if data is None or (isinstance(data, dict) and not data):
                print(f"\n[线程 {thread_id}] [警告] 邮箱已过期")
                return ""

            email_list = data.get("emails", []) if isinstance(data, dict) else []
            if not isinstance(email_list, list):
                time.sleep(3)
                continue

            for msg in email_list:
                if not isinstance(msg, dict):
                    continue

                msg_date = int(msg.get("date") or 0)
                if not msg_date or msg_date in seen_ids:
                    continue
                seen_ids.add(msg_date)

                sender = str(msg.get("from") or "").lower()
                subject = str(msg.get("subject") or "")
                body = str(msg.get("body") or "")
                html = str(msg.get("html") or "")
                content = "\n".join([sender, subject, body, html])

                if "openai" not in sender and "openai" not in content.lower():
                    continue

                m = re.search(regex, content)
                if m:
                    print(f"\n[线程 {thread_id}] [信息] 已收到验证码: {m.group(1)}")
                    return m.group(1)
        except Exception:
            pass

        time.sleep(3)

    print(f"\n[线程 {thread_id}] [警告] 等待超时，未收到验证码")
    return ""


def _poll_dropmail_oai_code(
    *, sid_token: str, email: str, thread_id: int, proxies: Any = None
) -> str:
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids: Set[str] = set()
    query = """
    query ($id: ID!) {
        session(id: $id) {
            mails { id, rawSize, text }
        }
    }
    """

    print(
        f"[线程 {thread_id}] [*] 正在等待邮箱 {email} 的验证码...", end="", flush=True
    )

    for _ in range(40):
        print(".", end="", flush=True)
        try:
            resp = requests.post(
                DROPMAIL_API,
                json={"query": query, "variables": {"id": sid_token}},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("session", {}) or {}
                messages = data.get("mails", [])
                for msg in messages:
                    msg_id = msg.get("id")
                    if not msg_id or msg_id in seen_ids:
                        continue
                    seen_ids.add(msg_id)

                    text = str(msg.get("text") or "")
                    content = text

                    if "openai" not in content.lower():
                        continue

                    m = re.search(regex, content)
                    if m:
                        print(f"\n[线程 {thread_id}] [信息] 已收到验证码: {m.group(1)}")
                        return m.group(1)
        except Exception:
            pass
        time.sleep(3)

    print(f"\n[线程 {thread_id}] [警告] 等待超时，未收到验证码")
    return ""


def _poll_cfmail_oai_code(
    *, api_base: str, token: str, email: str, thread_id: int, proxies: Any = None
) -> str:
    api_base = str(api_base or "").strip()
    if not api_base:
        worker_domain = _normalize_host(CFMAIL_WORKER_DOMAIN)
        api_base = f"https://{worker_domain}" if worker_domain else ""
    if not api_base:
        print(f"[线程 {thread_id}] [错误] 自建邮箱 api_base 为空，无法轮询邮件")
        return ""
    seen_ids: Set[str] = set()

    print(
        f"[线程 {thread_id}] [*] 正在等待邮箱 {email} 的验证码...", end="", flush=True
    )

    for _ in range(40):
        print(".", end="", flush=True)
        try:
            resp = requests.get(
                f"{api_base}/api/mails",
                params={"limit": 10, "offset": 0},
                headers=_cfmail_headers(jwt=token, use_json=True),
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue

            data = resp.json() if resp.content else {}
            messages = data.get("results", []) if isinstance(data, dict) else []
            if not isinstance(messages, list):
                time.sleep(3)
                continue

            for msg in messages:
                if not isinstance(msg, dict):
                    continue

                msg_id = str(msg.get("id") or msg.get("createdAt") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                recipient = str(msg.get("address") or "").strip().lower()
                raw = str(msg.get("raw") or "")
                metadata = msg.get("metadata") or {}
                metadata_text = json.dumps(metadata, ensure_ascii=False)
                content = "\n".join([recipient, raw, metadata_text])

                if recipient and recipient != email.strip().lower():
                    continue
                if "openai" not in content.lower():
                    continue

                patterns = [
                    r"Subject:\s*Your ChatGPT code is\s*(\d{6})",
                    r"Your ChatGPT code is\s*(\d{6})",
                    r"temporary verification code to continue:\s*(\d{6})",
                ]
                for pattern in patterns:
                    m = re.search(pattern, content, re.I | re.S)
                    if m:
                        print(f"\n[线程 {thread_id}] [信息] 已收到验证码: {m.group(1)}")
                        return m.group(1)
        except Exception:
            pass

        time.sleep(3)

    print(f"\n[线程 {thread_id}] [警告] 等待超时，未收到验证码")
    return ""


def get_oai_code(mailbox: TempMailbox, thread_id: int, proxies: Any = None) -> str:
    if mailbox.provider == "cfmail":
        if not mailbox.token:
            print(
                f"[线程 {thread_id}] [错误] {mailbox.provider} token 为空，无法读取邮件"
            )
            return ""
        return _poll_cfmail_oai_code(
            api_base=mailbox.api_base,
            token=mailbox.token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
        )
    if mailbox.provider == "mailtm":
        if not mailbox.token:
            print(
                f"[线程 {thread_id}] [错误] {mailbox.provider} token 为空，无法读取邮件"
            )
            return ""
        return _poll_hydra_oai_code(
            api_base=mailbox.api_base,
            token=mailbox.token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
        )
    if mailbox.provider == "tempmailio":
        return _poll_tempmailio_oai_code(
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
        )
    if mailbox.provider == "tempmaillol":
        if not mailbox.token:
            print(
                f"[线程 {thread_id}] [错误] {mailbox.provider} token 为空，无法读取邮件"
            )
            return ""
        return _poll_tempmaillol_oai_code(
            token=mailbox.token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
        )
    if mailbox.provider == "dropmail":
        if not mailbox.sid_token:
            print(f"[线程 {thread_id}] [错误] {mailbox.provider} 会话标识为空，无法读取邮件")
            return ""
        return _poll_dropmail_oai_code(
            sid_token=mailbox.sid_token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
        )

    print(
        f"[线程 {thread_id}] [错误] 暂不支持该邮箱服务: {mailbox.provider}"
    )
    return ""


# ==========================================
# OAuth 授权与辅助函数
# ==========================================

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

DEFAULT_REDIRECT_URI = f"http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _extract_workspaces_from_auth_cookie(auth_cookie: str) -> List[Dict[str, Any]]:
    raw = str(auth_cookie or "").strip()
    if not raw:
        return []

    candidates = [raw]
    if "." in raw:
        candidates.extend(part for part in raw.split(".") if part)

    seen_candidates: Set[str] = set()
    for candidate in candidates:
        if candidate in seen_candidates:
            continue
        seen_candidates.add(candidate)

        data = _decode_jwt_segment(candidate)
        if not isinstance(data, dict) or not data:
            continue

        nodes = [
            data,
            data.get("session"),
            data.get("user"),
            data.get("payload"),
            data.get("claims"),
        ]
        for node in nodes:
            if not isinstance(node, dict):
                continue
            workspaces = node.get("workspaces") or []
            if isinstance(workspaces, list) and workspaces:
                return [item for item in workspaces if isinstance(item, dict)]

    return []


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _generate_password(length: int = 12) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def _post_form(url: str, data: Dict[str, str], timeout: int = 30) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.status != 200:
                raise RuntimeError(
                    f"token exchange failed: {resp.status}: {raw.decode('utf-8', 'replace')}"
                )
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(
            f"token exchange failed: {exc.code}: {raw.decode('utf-8', 'replace')}"
        ) from exc


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str
    scope: str


def _build_oauth_authorize_url(
    *,
    state: str,
    code_verifier: str,
    redirect_uri: str,
    scope: str,
    prompt: Optional[str] = "login",
) -> str:
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": _sha256_b64url_no_pad(code_verifier),
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    prompt_value = None if prompt is None else str(prompt).strip()
    if prompt_value:
        params["prompt"] = prompt_value
    return f"{AUTH_URL}?{urllib.parse.urlencode(params)}"


def _oauth_authorize_url(oauth: OAuthStart, *, prompt: Optional[str] = "login") -> str:
    return _build_oauth_authorize_url(
        state=oauth.state,
        code_verifier=oauth.code_verifier,
        redirect_uri=oauth.redirect_uri,
        scope=oauth.scope,
        prompt=prompt,
    )


def generate_oauth_url(
    *, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE
) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    auth_url = _build_oauth_authorize_url(
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        scope=scope,
        prompt="login",
    )
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        scope=scope,
    )


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
    )

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    expires_in = _to_int(token_resp.get("expires_in"))

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now = int(time.time())
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }

    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


def _extract_continue_url_from_response(resp: Any) -> str:
    base_url = str(getattr(resp, "url", "") or AUTH_URL).strip() or AUTH_URL
    headers = getattr(resp, "headers", {}) or {}

    location = str(headers.get("Location") or "").strip()
    if location:
        return urllib.parse.urljoin(base_url, location)

    try:
        payload = resp.json() if getattr(resp, "content", b"") else {}
    except Exception:
        payload = {}

    if isinstance(payload, dict):
        for key in ("continue_url", "redirect_url", "next_url", "url"):
            candidate = str(payload.get(key) or "").strip()
            if candidate:
                return urllib.parse.urljoin(base_url, candidate)

    text = str(getattr(resp, "text", "") or "")
    if not text:
        return ""

    json_like_match = re.search(
        r'"(?:continue_url|redirect_url|next_url|url)"\s*:\s*"([^"]+)"', text
    )
    if json_like_match:
        candidate = json_like_match.group(1).replace("\\/", "/").strip()
        if candidate:
            return urllib.parse.urljoin(base_url, candidate)

    callback_match = re.search(
        r"(http://localhost:1455/auth/callback[^\"'\s<>]+)", text
    )
    if callback_match:
        return callback_match.group(1).strip()

    return ""


def _follow_oauth_redirect_chain(
    session: Any,
    start_url: str,
    oauth: OAuthStart,
    thread_id: int,
    *,
    max_hops: int = 8,
) -> Optional[str]:
    current_url = str(start_url or "").strip()
    if not current_url:
        return None

    try:
        for _ in range(max_hops):
            if "code=" in current_url and "state=" in current_url:
                return submit_callback_url(
                    callback_url=current_url,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    expected_state=oauth.state,
                )

            resp = session.get(current_url, allow_redirects=False, timeout=15)
            next_url = _extract_continue_url_from_response(resp)
            if not next_url:
                break
            if "code=" in next_url and "state=" in next_url:
                return submit_callback_url(
                    callback_url=next_url,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    expected_state=oauth.state,
                )
            if next_url == current_url:
                break
            current_url = next_url
    except Exception as exc:
        print(
            f"[线程 {thread_id}] [警告] 跟随 OAuth 跳转链失败: {exc}"
        )

    return None


def _request_sentinel_token(
    *,
    did: str,
    proxies: Any,
    impersonate: str,
    thread_id: int,
) -> str:
    device_id = str(did or "").strip()
    if not device_id:
        print(f"[线程 {thread_id}] [错误] 无法获取 Device ID，Sentinel 请求已跳过")
        return ""

    body = json.dumps(
        {"p": "", "id": device_id, "flow": "authorize_continue"},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    resp = requests.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        headers={
            "origin": "https://sentinel.openai.com",
            "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
            "content-type": "text/plain;charset=UTF-8",
        },
        data=body,
        proxies=proxies,
        impersonate=impersonate,
        timeout=15,
    )
    if resp.status_code != 200:
        print(
            f"[线程 {thread_id}] [错误] Sentinel 请求失败，状态码: {resp.status_code}"
        )
        return ""

    token = str((resp.json() or {}).get("token") or "").strip()
    if not token:
        print(f"[线程 {thread_id}] [错误] Sentinel 响应里缺少 token")
    return token


def _try_token_via_existing_session(
    session: Any,
    oauth: OAuthStart,
    thread_id: int,
) -> Optional[str]:
    print(f"[线程 {thread_id}] [信息] 尝试复用当前 session 免密获取 token")
    return _follow_oauth_redirect_chain(
        session,
        _oauth_authorize_url(oauth, prompt=None),
        oauth,
        thread_id,
    )


def _try_token_via_workspace_select(
    session: Any,
    oauth: OAuthStart,
    auth_cookie: str,
    thread_id: int,
) -> Optional[str]:
    workspaces = _extract_workspaces_from_auth_cookie(auth_cookie)
    if not workspaces:
        print(
            f"[线程 {thread_id}] [警告] 授权 Cookie 存在，但暂未解析到 workspace"
        )
        return None

    workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
    if not workspace_id:
        print(f"[线程 {thread_id}] [警告] workspace 信息存在，但无法解析 workspace_id")
        return None

    select_resp = session.post(
        "https://auth.openai.com/api/accounts/workspace/select",
        headers={
            "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            "content-type": "application/json",
        },
        json={"workspace_id": workspace_id},
    )
    if select_resp.status_code != 200:
        print(
            f"[线程 {thread_id}] [警告] 选择 workspace 失败，状态码: {select_resp.status_code}"
        )
        return None

    continue_url = _extract_continue_url_from_response(select_resp)
    if not continue_url:
        print(
            f"[线程 {thread_id}] [警告] workspace/select 响应里缺少 continue_url"
        )
        return None

    print(f"[线程 {thread_id}] [信息] 已获取 workspace，继续跟随授权跳转链")
    return _follow_oauth_redirect_chain(session, continue_url, oauth, thread_id)


def _try_token_via_password_login(
    *,
    email: str,
    password: str,
    oauth: OAuthStart,
    proxies: Any,
    impersonate: str,
    thread_id: int,
) -> Optional[str]:
    account = str(email or "").strip()
    pwd = str(password or "").strip()
    if not account or not pwd:
        return None

    print(f"[线程 {thread_id}] [信息] 当前 session 未拿到 token，尝试账号密码重新登录")
    login_session = requests.Session(proxies=proxies, impersonate=impersonate)

    try:
        login_session.get(_oauth_authorize_url(oauth, prompt="login"), timeout=15)
        did = login_session.cookies.get("oai-did")
        sentinel_token = _request_sentinel_token(
            did=did,
            proxies=proxies,
            impersonate=impersonate,
            thread_id=thread_id,
        )
        if not sentinel_token:
            return None

        continue_resp = login_session.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/sign-in",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": json.dumps(
                    {
                        "p": "",
                        "t": "",
                        "c": sentinel_token,
                        "id": did,
                        "flow": "authorize_continue",
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            },
            data=json.dumps(
                {
                    "username": {"value": account, "kind": "email"},
                    "screen_hint": "login",
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )
        if continue_resp.status_code not in (200, 204):
            print(
                f"[线程 {thread_id}] [警告] 账号密码登录预处理失败，状态码: {continue_resp.status_code}"
            )
            return None

        login_resp = login_session.post(
            "https://auth.openai.com/api/accounts/user/login",
            headers={
                "referer": "https://auth.openai.com/sign-in/password",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=json.dumps(
                {"username": account, "password": pwd},
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )
        if login_resp.status_code != 200:
            print(
                f"[线程 {thread_id}] [警告] 账号密码登录失败，状态码: {login_resp.status_code}"
            )
            return None

        continue_url = _extract_continue_url_from_response(login_resp)
        if continue_url:
            token_json = _follow_oauth_redirect_chain(
                login_session, continue_url, oauth, thread_id
            )
            if token_json:
                return token_json

        auth_cookie = login_session.cookies.get("oai-client-auth-session")
        if auth_cookie:
            token_json = _try_token_via_workspace_select(
                login_session, oauth, auth_cookie, thread_id
            )
            if token_json:
                return token_json

        return _try_token_via_existing_session(login_session, oauth, thread_id)
    except Exception as exc:
        print(
            f"[线程 {thread_id}] [警告] 账号密码登录兜底失败: {exc}"
        )
        return None


# ==========================================
# 核心注册逻辑
# ==========================================


def get_auto_proxy() -> Optional[str]:
    common_ports = [7890, 1080, 10809, 10808, 8888]

    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                print(
                    f"[信息] 检测到本地代理端口可用: {port}"
                )
                return f"http://127.0.0.1:{port}"
    return None


def run(
    proxy: Optional[str], provider_key: str, thread_id: int, mailtm_base: str
) -> Optional[Tuple[str, str]]:
    # 注册主流程：
    # 1. 检测出口 / 代理
    # 2. 创建临时邮箱
    # 3. OpenAI 注册 + 收验证码
    # 4. 提取 token 并持久化
    if provider_key == "cfmail":
        _reload_cfmail_accounts_if_needed()

    proxies: Any = _build_request_proxies(proxy)
    cfmail_config_name = ""

    def _mark_cfmail_failure(reason: str, *, affect_cooldown: bool = False) -> None:
        if provider_key == "cfmail" and cfmail_config_name and affect_cooldown:
            _record_cfmail_failure(cfmail_config_name, reason)

    def _mark_cfmail_success() -> None:
        if provider_key == "cfmail" and cfmail_config_name:
            _record_cfmail_success(cfmail_config_name)

    # 与 xiaomajiang.py 保持一致，固定使用 chrome 指纹
    current_impersonate = "chrome"
    print(
        f"[线程 {thread_id}] [信息] 当前浏览器指纹: {current_impersonate}"
    )

    s = requests.Session(proxies=proxies, impersonate=current_impersonate)

    try:
        trace = s.get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
        trace = trace.text
        loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
        loc = loc_re.group(1) if loc_re else None
        print(
            f"[线程 {thread_id}] [信息] 当前出口地区: {loc}"
        )
        if loc != "US":
            if not builtins.yasal_bypass_ip_choice:
                print(f"[线程 {thread_id}] [信息] 非 US 节点，已按配置停止当前线程")
                return None

            print(
                f"[线程 {thread_id}] [信息] 当前节点地区 ({loc}) 不是 US，已默认继续执行"
            )

        if loc in ("CN", "HK"):
            if builtins.yasal_bypass_ip_choice:
                print(
                    f"[线程 {thread_id}] [警告] 当前地区 {loc} 风险较高，尝试自动检测本地代理"
                )
                if not proxy:
                    auto_p = get_auto_proxy()
                    if auto_p:
                        proxies = {"http": auto_p, "https": auto_p}
                        s.proxies = proxies
                        print(
                            f"[线程 {thread_id}] [信息] 已自动启用本地代理: {auto_p}"
                        )
                    else:
                        print(
                            f"[线程 {thread_id}] [警告] 未检测到可用本地代理端口，将继续直连"
                        )
                # 用户选择绕过，继续执行
            else:
                print(
                    f"[线程 {thread_id}] [错误] 当前节点地区 {loc} 风险过高，请更换代理后重试"
                )
                return None
    except Exception as e:
        print(
            f"[线程 {thread_id}] [错误] 网络检查失败，请确认代理可用: {e}"
        )
        return None

    mailbox = get_temp_mailbox(
        provider_key,
        thread_id,
        proxies,
        mailtm_base=mailtm_base,
    )
    if not mailbox:
        return None
    cfmail_config_name = mailbox.config_name
    email = mailbox.email
    print(
        f"[线程 {thread_id}] [*] 成功获取临时邮箱与授权: {email} ({mailbox.provider})"
    )

    oauth = generate_oauth_url()
    url = oauth.auth_url

    try:
        resp = s.get(url, timeout=15)
        did = s.cookies.get("oai-did")
        print(
            f"[线程 {thread_id}] [信息] 已获取 Device ID: {did}"
        )

        signup_body = f'{{"username":{{"value":"{email}","kind":"email"}},"screen_hint":"signup"}}'
        sen_token = _request_sentinel_token(
            did=did,
            proxies=proxies,
            impersonate=current_impersonate,
            thread_id=thread_id,
        )
        if not sen_token:
            return None

        sentinel = json.dumps(
            {
                "p": "",
                "t": "",
                "c": sen_token,
                "id": did,
                "flow": "authorize_continue",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

        signup_resp = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/create-account",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
            data=signup_body,
        )
        print(
            f"[线程 {thread_id}] [信息] 注册表单已提交，状态码: {signup_resp.status_code}"
        )
        if signup_resp.status_code in (403, 429):
            print(
                f"[线程 {thread_id}] [错误] 注册请求被拒绝（{signup_resp.status_code}）: {signup_resp.text}"
            )
            return None

        password = _generate_password()
        register_body = json.dumps(
            {
                "password": password,
                "username": email,
            }
        )
        register_resp = s.post(
            "https://auth.openai.com/api/accounts/user/register",
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=register_body,
        )
        print(
            f"[线程 {thread_id}] [信息] 密码注册请求已提交，状态码: {register_resp.status_code}"
        )
        if register_resp.status_code != 200:
            print(
                f"[线程 {thread_id}] [错误] 提交密码失败: {register_resp.text}"
            )
            return None

        otp_resp = s.get(
            "https://auth.openai.com/api/accounts/email-otp/send",
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
            },
        )
        print(
            f"[线程 {thread_id}] [信息] 验证码发送请求已提交，状态码: {otp_resp.status_code}"
        )
        if otp_resp.status_code != 200:
            print(
                f"[线程 {thread_id}] [错误] 发送验证码失败: {otp_resp.text}"
            )
            return None

        code = get_oai_code(mailbox, thread_id, proxies)
        if not code:
            _mark_cfmail_failure("email_code empty", affect_cooldown=True)
            return None

        code_body = f'{{"code":"{code}"}}'
        code_resp = s.post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            headers={
                "referer": "https://auth.openai.com/email-verification",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=code_body,
        )
        print(
            f"[线程 {thread_id}] [信息] 验证码校验结果状态码: {code_resp.status_code}"
        )

        create_account_body = '{"name":"Neo","birthdate":"2000-02-20"}'
        create_account_resp = s.post(
            "https://auth.openai.com/api/accounts/create_account",
            headers={
                "referer": "https://auth.openai.com/about-you",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=create_account_body,
        )
        create_account_status = create_account_resp.status_code
        print(
            f"[线程 {thread_id}] [信息] 创建账户接口状态码: {create_account_status}"
        )

        if create_account_status != 200:
            err_msg = create_account_resp.text
            print(
                f"[线程 {thread_id}] [错误] 创建账户失败: {err_msg}"
            )
            if "unsupported_email" in err_msg:
                print(
                    f"[线程 {thread_id}] [提示] 当前邮箱域名可能被限制，建议更换临时邮箱服务或域名"
                )
            elif "registration_disallowed" in err_msg:
                print(
                    f"[线程 {thread_id}] [提示] 当前邮箱提供商可能被风控，建议优先使用 tempmaillol"
                )
            elif "429" in str(create_account_status):
                print(
                    f"[线程 {thread_id}] [提示] 请求频率过高（429），建议更换代理或降低并发"
                )
            _mark_cfmail_failure(
                f"create_account status={create_account_status} body={err_msg[:120]}",
                affect_cooldown=(
                    "unsupported_email" in err_msg
                    or "registration_disallowed" in err_msg
                ),
            )
            return None

        auth_cookie = s.cookies.get("oai-client-auth-session")
        token_json = _try_token_via_existing_session(s, oauth, thread_id)

        if not token_json and auth_cookie:
            token_json = _try_token_via_workspace_select(
                s, oauth, auth_cookie, thread_id
            )
        elif not auth_cookie:
            print(f"[线程 {thread_id}] [警告] 当前会话中暂未拿到授权 Cookie")

        if not token_json:
            refreshed_auth_cookie = s.cookies.get("oai-client-auth-session")
            if refreshed_auth_cookie and refreshed_auth_cookie != auth_cookie:
                token_json = _try_token_via_workspace_select(
                    s, oauth, refreshed_auth_cookie, thread_id
                )

        if not token_json:
            token_json = _try_token_via_password_login(
                email=email,
                password=password,
                oauth=oauth,
                proxies=proxies,
                impersonate=current_impersonate,
                thread_id=thread_id,
            )

        if token_json:
            _mark_cfmail_success()
            return token_json, password

        print(f"[线程 {thread_id}] [错误] 已完成注册，但仍未能获取 OAuth token")
        return None

    except Exception as e:
        print(
            f"[线程 {thread_id}] [错误] 运行过程中发生异常: {e}"
        )
        print(
            f"[线程 {thread_id}] [错误] 异常详情: {traceback.format_exc()}"
        )
        print(
            f"[线程 {thread_id}] [提示] 本轮失败，下一轮将继续重试"
        )
        return None


# ==========================================
# 多线程并发执行逻辑
# ==========================================


def _safe_token_filename(email: str, thread_id: int) -> str:
    raw = (email or "").strip().lower()
    if not raw:
        return f"unknown_{thread_id}_{int(time.time())}.json"

    # 保留常见邮箱文件名字符，其他字符替换为下划线。
    safe = re.sub(r"[^0-9a-zA-Z@._-]", "_", raw).strip("._")
    if not safe:
        safe = f"unknown_{thread_id}_{int(time.time())}"
    return f"{safe}.json"


def _build_token_output_path(token_dir: str, email: str, thread_id: int) -> str:
    base_name = _safe_token_filename(email, thread_id)
    return _build_unique_path(token_dir, base_name)


def _build_unique_path(directory: str, base_name: str) -> str:
    path = os.path.join(directory, base_name)
    if not os.path.exists(path):
        return path

    stem, ext = os.path.splitext(base_name)
    return os.path.join(
        directory,
        f"{stem}_{int(time.time())}_{random.randint(1000, 9999)}{ext}",
    )


def log_info(message: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [信息] {message}")


def log_warn(message: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [警告] {message}")


def log_error(message: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [错误] {message}")


def list_json_files(directory: str) -> List[str]:
    if not os.path.isdir(directory):
        return []

    files = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if name.endswith(".json") and os.path.isfile(path):
            files.append(path)
    return files


def count_json_files(directory: str) -> int:
    return len(list_json_files(directory))


def get_used_percent(file_path: str, timeout: int) -> Optional[int]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        log_error(f"读取 {os.path.basename(file_path)} 失败: {exc}")
        return None

    access_token = str(data.get("access_token") or "").strip()
    account_id = str(data.get("account_id") or "").strip()
    if not access_token or not account_id:
        log_error(f"文件 {os.path.basename(file_path)} 缺少 access_token 或 account_id")
        return None

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
            timeout=timeout,
        )
        if resp.status_code != 200:
            log_error(
                f"文件 {os.path.basename(file_path)} 额度查询失败，状态码: {resp.status_code}"
            )
            return None

        payload = resp.json()
        used_percent = (
            ((payload or {}).get("rate_limit") or {}).get("primary_window") or {}
        ).get("used_percent")
        if used_percent is None:
            log_error(f"文件 {os.path.basename(file_path)} 额度结果缺少 used_percent")
            return None

        return int(float(used_percent))
    except Exception as exc:
        log_error(f"文件 {os.path.basename(file_path)} 额度查询异常: {exc}")
        return None


def persist_registration_result(
    token_json: str, password: str, thread_id: int, token_dir: str
) -> Tuple[str, str]:
    try:
        token_data = json.loads(token_json)
        raw_email = str(token_data.get("email") or "unknown")
        refresh_token = str(token_data.get("refresh_token") or "")
    except Exception:
        raw_email = "unknown"
        refresh_token = ""

    os.makedirs(token_dir, exist_ok=True)
    file_name = _build_token_output_path(token_dir, raw_email, thread_id)
    with open(file_name, "w", encoding="utf-8") as f:
        f.write(token_json)

    os.makedirs("output", exist_ok=True)
    with output_lock:
        with open("output/accounts.txt", "a", encoding="utf-8") as f:
            f.write(f"{raw_email}----{password}----{refresh_token}\n")

    return file_name, raw_email


def _cleanup_tokens_in_dir(
    directory: str,
    label: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
) -> Tuple[int, int, int]:
    """清理指定目录中的失效 Token 文件。

    :param directory: 要清理的目录路径
    :param label: 日志标签（如 "A" 或 "B"）
    :param usage_threshold: 已用比例阈值
    :param request_interval: 每次请求间隔秒数
    :param curl_timeout: 额度查询超时秒数
    :return: (kept_count, deleted_count, check_failed)
    """
    deleted_count = 0
    kept_count = 0
    check_failed = 0

    for file_path in list_json_files(directory):
        used_percent = get_used_percent(file_path, curl_timeout)
        if used_percent is None:
            log_warn(f"删除 {label} 中的 {os.path.basename(file_path)}，额度查询失败")
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
            deleted_count += 1
            check_failed += 1
        elif used_percent >= usage_threshold:
            log_info(
                f"删除 {label} 中的 {os.path.basename(file_path)}，已用比例 {used_percent}% >= {usage_threshold}%"
            )
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
            deleted_count += 1
        else:
            kept_count += 1
            log_info(
                f"保留 {label} 中的 {os.path.basename(file_path)}，已用比例 {used_percent}%"
            )

        if request_interval > 0:
            time.sleep(request_interval)

    return kept_count, deleted_count, check_failed


def cleanup_active_tokens(
    active_dir: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
) -> Tuple[int, int, int]:
    return _cleanup_tokens_in_dir(active_dir, "A", usage_threshold, request_interval, curl_timeout)


def cleanup_pool_tokens(
    pool_dir: str,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
) -> Tuple[int, int, int]:
    return _cleanup_tokens_in_dir(pool_dir, "B", usage_threshold, request_interval, curl_timeout)


def move_pool_tokens_to_active(
    active_dir: str,
    pool_dir: str,
    active_target: int,
    usage_threshold: int,
    request_interval: int,
    curl_timeout: int,
) -> Tuple[int, int]:
    current_active = count_json_files(active_dir)
    needed = max(active_target - current_active, 0)
    if needed <= 0:
        return 0, 0

    moved_count = 0
    deleted_count = 0
    pool_files = list_json_files(pool_dir)
    random.shuffle(pool_files)

    for file_path in pool_files:
        if moved_count >= needed:
            break

        used_percent = get_used_percent(file_path, curl_timeout)
        if used_percent is None:
            log_warn(f"删除 B 中的 {os.path.basename(file_path)}，额度查询失败")
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
            deleted_count += 1
        elif used_percent >= usage_threshold:
            log_info(
                f"删除 B 中的 {os.path.basename(file_path)}，已用比例 {used_percent}% >= {usage_threshold}%"
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
            log_info(
                f"从 B 补充到 A: {os.path.basename(destination)}，已补 {moved_count}/{needed}"
            )

        if request_interval > 0:
            time.sleep(request_interval)

    return moved_count, deleted_count


def register_single_account(
    proxy: Optional[str],
    provider_key: str,
    thread_id: int,
    mailtm_base: str,
    token_dir: str,
) -> bool:
    try:
        result = run(proxy, provider_key, thread_id, mailtm_base)
        if not result:
            log_warn(f"补号任务 #{thread_id} 失败")
            return False

        token_json, password = result
        file_name, raw_email = persist_registration_result(
            token_json, password, thread_id, token_dir
        )
        log_info(f"补号成功: {raw_email} -> {file_name}")
        return True
    except Exception as exc:
        log_error(f"补号任务 #{thread_id} 异常: {exc}")
        return False


def register_accounts(
    target_count: int,
    proxy: Optional[str],
    provider_key: str,
    mailtm_base: str,
    token_dir: str,
    batch_size: int,
    auto_continue_non_us: bool,
) -> int:
    if target_count <= 0:
        return 0

    if auto_continue_non_us and builtins.yasal_bypass_ip_choice is None:
        builtins.yasal_bypass_ip_choice = True

    success_count = 0
    attempts = 0
    batch_size = max(1, batch_size)
    max_attempts = max(target_count * 4, target_count + batch_size)

    while success_count < target_count and attempts < max_attempts:
        current_batch_size = min(
            batch_size,
            target_count - success_count,
            max_attempts - attempts,
        )
        batch_results: List[bool] = []
        batch_results_lock = threading.Lock()
        threads = []

        for index in range(current_batch_size):
            current_thread_id = attempts + index + 1

            def _task(tid: int = current_thread_id) -> None:
                is_success = register_single_account(
                    proxy,
                    provider_key,
                    tid,
                    mailtm_base,
                    token_dir,
                )
                with batch_results_lock:
                    batch_results.append(is_success)

            thread = threading.Thread(target=_task)
            thread.daemon = True
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        attempts += current_batch_size
        batch_success = sum(1 for item in batch_results if item)
        success_count += batch_success
        log_info(
            f"补号批次完成：本批成功 {batch_success} 个，累计成功 {success_count}/{target_count}"
        )

        if batch_success == 0 and success_count < target_count:
            time.sleep(10)

    if success_count < target_count:
        log_warn(f"目标补号 {target_count} 个，实际仅补充成功 {success_count} 个")

    return success_count


def build_monitor_dingtalk_message(
    active_count: int,
    pool_count: int,
    active_target: int,
    pool_target: int,
    attempted_replenish: bool,
    replenished_count: int,
    deleted_count: int,
) -> str:
    status_text = "达标" if active_count >= active_target and pool_count >= pool_target else "未达标"
    replenish_text = "是" if attempted_replenish else "否"
    return (
        "授权文件告警\n"
        f"正在使用：{active_count}\n"
        f"库存剩余：{pool_count}\n"
        f"是否补充账号：{replenish_text}\n"
        f"补充了几个：{replenished_count}\n"
        f"删除授权文件：{deleted_count}\n"
        f"正在使用目标：{active_target}\n"
        f"库存目标：{pool_target}\n"
        f"当前状态：{status_text}"
    )


def build_monitor_summary_message(results: List[MonitorCycleResult]) -> str:
    if not results:
        return ""

    first_result = results[0]
    last_result = results[-1]
    total_replenished = sum(item.replenished_count for item in results)
    total_deleted = sum(item.deleted_count for item in results)
    replenish_rounds = sum(1 for item in results if item.attempted_replenish)
    unmet_rounds = sum(
        1
        for item in results
        if item.active_count < item.active_target or item.pool_count < item.pool_target
    )
    min_active = min(item.active_count for item in results)
    min_pool = min(item.pool_count for item in results)
    max_active = max(item.active_count for item in results)
    max_pool = max(item.pool_count for item in results)

    return (
        "授权文件汇总\n"
        f"统计周期：{first_result.completed_at.strftime('%m-%d %H:%M')} ~ {last_result.completed_at.strftime('%m-%d %H:%M')}\n"
        f"巡检次数：{len(results)}\n"
        f"触发补号：{replenish_rounds} 次\n"
        f"补充总数：{total_replenished}\n"
        f"删除授权文件：{total_deleted}\n"
        f"未达标轮次：{unmet_rounds}\n"
        f"A目录区间：{min_active} ~ {max_active}\n"
        f"B目录区间：{min_pool} ~ {max_pool}\n"
        f"最新A目录：{last_result.active_count}/{last_result.active_target}\n"
        f"最新B目录：{last_result.pool_count}/{last_result.pool_target}\n"
        f"最新状态：{'达标' if last_result.active_count >= last_result.active_target and last_result.pool_count >= last_result.pool_target else '未达标'}"
    )
 

def send_dingtalk_alert(webhook: str, message: str) -> None:
    if not webhook:
        return

    payload = {
        "msgtype": "text",
        "text": {"content": f"CLI变动\n{message}"},
    }
    try:
        resp = requests.post(
            webhook,
            json=payload,
            impersonate="chrome",
            timeout=10,
        )
        if resp.status_code != 200:
            log_error(f"发送钉钉提醒失败，状态码: {resp.status_code}")
    except Exception as exc:
        log_error(f"发送钉钉提醒异常: {exc}")


def run_monitor_cycle(args: argparse.Namespace) -> MonitorCycleResult:
    # 巡检模式单轮逻辑：
    # 1. 清理 A 目录失效账号
    # 2. 清理 B 目录失效账号
    # 3. 尝试从 B 目录补到 A
    # 4. 若 A/B 总量仍不足，再触发注册补号
    os.makedirs(args.active_token_dir, exist_ok=True)
    os.makedirs(args.token_dir, exist_ok=True)

    log_info("========== 开始执行账号检测 ==========")
    kept_count, deleted_count, check_failed = cleanup_active_tokens(
        args.active_token_dir,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
    )
    log_info(
        f"A 清理完成：保留 {kept_count}，删除 {deleted_count}，查询失败 {check_failed}"
    )

    pool_kept_count, pool_deleted_count, pool_check_failed = cleanup_pool_tokens(
        args.token_dir,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
    )
    log_info(
        f"B 清理完成：保留 {pool_kept_count}，删除 {pool_deleted_count}，查询失败 {pool_check_failed}"
    )

    moved_before_register, deleted_from_pool_before = move_pool_tokens_to_active(
        args.active_token_dir,
        args.token_dir,
        args.active_min_count,
        args.usage_threshold,
        args.request_interval,
        args.curl_timeout,
    )
    if moved_before_register > 0:
        log_info(f"首次从 B 补充到 A 共 {moved_before_register} 个")
    else:
        log_info("首次从 B 补充到 A：本轮无需补充或 B 中无可补账号")

    active_count = count_json_files(args.active_token_dir)
    pool_count = count_json_files(args.token_dir)
    active_shortage = max(args.active_min_count - active_count, 0)
    pool_shortage = max(args.pool_min_count - pool_count, 0)
    register_target = active_shortage + pool_shortage
    log_info(
        f"当前库存统计：A={active_count}/{args.active_min_count}（缺 {active_shortage}），"
        f"B={pool_count}/{args.pool_min_count}（缺 {pool_shortage}）"
    )
    replenished_count = 0
    moved_after_register = 0
    deleted_from_pool_after = 0

    if register_target > 0:
        log_warn(
            f"检测到库存不足：A={active_count}/{args.active_min_count}，B={pool_count}/{args.pool_min_count}，准备补号 {register_target} 个"
        )
        replenished_count = register_accounts(
            register_target,
            args.proxy,
            args.mail_provider,
            args.mailtm_api_base,
            args.token_dir,
            args.register_batch_size,
            args.auto_continue_non_us,
        )
        log_info(
            f"注册补号完成：计划补 {register_target} 个，实际成功 {replenished_count} 个"
        )
        if replenished_count > 0:
            moved_after_register, deleted_from_pool_after = move_pool_tokens_to_active(
                args.active_token_dir,
                args.token_dir,
                args.active_min_count,
                args.usage_threshold,
                args.request_interval,
                args.curl_timeout,
            )
            if moved_after_register > 0:
                log_info(f"补号后再次从 B 补充到 A 共 {moved_after_register} 个")
            else:
                log_info("补号后再次从 B 补充到 A：A 已达标或新号暂未补入 A")
    else:
        log_info(
            f"A/B 均已达标：A={active_count}/{args.active_min_count}，B={pool_count}/{args.pool_min_count}，本轮不补号"
        )

    final_active_count = count_json_files(args.active_token_dir)
    final_pool_count = count_json_files(args.token_dir)
    final_active_shortage = max(args.active_min_count - final_active_count, 0)
    final_pool_shortage = max(args.pool_min_count - final_pool_count, 0)
    total_deleted_count = (
        deleted_count
        + pool_deleted_count
        + deleted_from_pool_before
        + deleted_from_pool_after
    )
    log_info(
        f"本轮汇总：删 A={deleted_count}，删 B={pool_deleted_count + deleted_from_pool_before + deleted_from_pool_after}，"
        f"B→A={moved_before_register + moved_after_register}，注册成功={replenished_count}"
    )
    log_info(
        f"检测结束：A={final_active_count}/{args.active_min_count}（缺 {final_active_shortage}），"
        f"B={final_pool_count}/{args.pool_min_count}（缺 {final_pool_shortage}），补号={replenished_count}"
    )
    log_info("========== 账号检测执行完成 ==========")
    return MonitorCycleResult(
        completed_at=datetime.now(),
        active_count=final_active_count,
        pool_count=final_pool_count,
        active_target=args.active_min_count,
        pool_target=args.pool_min_count,
        attempted_replenish=register_target > 0,
        replenished_count=replenished_count,
        deleted_count=total_deleted_count,
    )


def worker(
    thread_id: int,
    proxy: Optional[str],
    once: bool,
    sleep_min: int,
    sleep_max: int,
    failure_sleep_seconds: int,
    provider_key: str,
    mailtm_base: str,
    token_dir: str,
) -> None:
    count = 0
    while True:
        if provider_key == "cfmail":
            _reload_cfmail_accounts_if_needed()
        count += 1
        print(
            f"\n[{datetime.now().strftime('%H:%M:%S')}] [线程 {thread_id}] [信息] 开始第 {count} 次任务（邮箱服务: {provider_key}）"
        )

        try:
            result = run(proxy, provider_key, thread_id, mailtm_base)

            is_success = False

            if result:
                token_json, password = result
                file_name, raw_email = persist_registration_result(
                    token_json,
                    password,
                    thread_id,
                    token_dir,
                )

                print(
                    f"[线程 {thread_id}] [成功] 账号信息已追加到 output/accounts.txt，Token 已保存到: {file_name}"
                )
                is_success = True
            else:
                print(
                    f"[线程 {thread_id}] [失败] 本轮任务未成功"
                )

        except Exception as e:
            print(f"[线程 {thread_id}] [错误] 发生未捕获异常: {e}")
            print(f"[线程 {thread_id}] [错误] {traceback.format_exc()}")
            is_success = False

        if once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        if not is_success:
            print(
                f"[线程 {thread_id}] [提示] 本轮失败，额外等待 {failure_sleep_seconds} 秒后重试"
            )
            wait_time += max(0, failure_sleep_seconds)

        print(
            f"[线程 {thread_id}] [信息] 等待 {wait_time} 秒后继续"
        )
        time.sleep(wait_time)


def run_monitor_loop(args: argparse.Namespace) -> None:
    pending_results: List[MonitorCycleResult] = []
    summary_started_at = time.time()
    while True:
        if args.mail_provider == "cfmail":
            _reload_cfmail_accounts_if_needed()
        cycle_started_at = time.time()
        try:
            cycle_result = run_monitor_cycle(args)
            pending_results.append(cycle_result)
        except Exception as exc:
            log_error(f"检测循环异常: {exc}")
            cycle_result = None

        should_send_summary = False
        now_ts = time.time()
        if pending_results:
            if args.monitor_once:
                should_send_summary = True
            elif now_ts - summary_started_at >= args.dingtalk_summary_interval:
                should_send_summary = True

        if should_send_summary:
            summary_message = build_monitor_summary_message(pending_results)
            if summary_message:
                send_dingtalk_alert(args.dingtalk_webhook, summary_message)
                log_info(
                    f"已发送钉钉汇总通知，共汇总 {len(pending_results)} 轮检测结果"
                )
            pending_results = []
            summary_started_at = now_ts

        if args.monitor_once:
            break

        elapsed_seconds = int(time.time() - cycle_started_at)
        sleep_seconds = max(1, args.monitor_interval - elapsed_seconds)
        log_info(f"等待 {sleep_seconds} 秒后进入下一轮检测")
        time.sleep(sleep_seconds)


def _load_config_file(config_path: str) -> dict:
    """加载 JSON 配置文件，返回配置字典。文件不存在则返回空字典。"""
    if not config_path or not os.path.isfile(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        # 过滤掉以 _ 开头的注释字段
        return {k: v for k, v in data.items() if not k.startswith("_")}
    except Exception as exc:
        print(f"[警告] 读取配置文件 {config_path} 失败: {exc}")
        return {}


# 配置文件中的 key 到 argparse dest 的映射
_CONFIG_KEY_MAP = {
    "proxy": "proxy",
    "mail_provider": "mail_provider",
    "cfmail_profile": "cfmail_profile",
    "cfmail_config": "cfmail_config",
    "cfmail_worker_domain": "cfmail_worker_domain",
    "cfmail_email_domain": "cfmail_email_domain",
    "cfmail_admin_password": "cfmail_admin_password",
    "cfmail_profile_name": "cfmail_profile_name",
    "mailtm_api_base": "mailtm_api_base",
    "token_dir": "token_dir",
    "active_token_dir": "active_token_dir",
    "active_min_count": "active_min_count",
    "pool_min_count": "pool_min_count",
    "usage_threshold": "usage_threshold",
    "request_interval": "request_interval",
    "curl_timeout": "curl_timeout",
    "monitor_interval": "monitor_interval",
    "register_batch_size": "register_batch_size",
    "dingtalk_webhook": "dingtalk_webhook",
    "dingtalk_summary_interval": "dingtalk_summary_interval",
    "sleep_min": "sleep_min",
    "sleep_max": "sleep_max",
    "failure_sleep_seconds": "failure_sleep_seconds",
    "cfmail_fail_threshold": "cfmail_fail_threshold",
    "cfmail_cooldown_seconds": "cfmail_cooldown_seconds",
}

# 布尔型参数（配置文件里 true/false）
_CONFIG_BOOL_KEYS = {
    "monitor", "monitor_once", "register_only",
    "auto_continue_non_us", "once", "test_cfmail",
}

DEFAULT_CONFIG_PATH = os.path.join(_SCRIPT_DIR, "monitor_config.json")


def _apply_config_to_args(args: argparse.Namespace, config: dict) -> None:
    """将配置文件中的值填入 args，仅当命令行未显式指定时生效。"""
    for config_key, arg_dest in _CONFIG_KEY_MAP.items():
        if config_key not in config:
            continue
        # 仅当 argparse 使用了默认值时才覆盖（命令行显式指定的优先）
        current_val = getattr(args, arg_dest, None)
        default_val = getattr(args, f"_default_{arg_dest}", current_val)
        if current_val == default_val:
            setattr(args, arg_dest, config[config_key])

    for bool_key in _CONFIG_BOOL_KEYS:
        if bool_key not in config:
            continue
        current_val = getattr(args, bool_key, False)
        if not current_val:
            setattr(args, bool_key, bool(config[bool_key]))


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAI 自动注册与账号巡检脚本")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"JSON 配置文件路径，默认 {DEFAULT_CONFIG_PATH}",
    )
    parser.add_argument(
        "--proxy", default=None, help="代理地址，如 http://127.0.0.1:7890"
    )
    parser.add_argument("--once", action="store_true", help="注册模式只运行一次")
    parser.add_argument(
        "--sleep-min", type=int, default=10, help="注册循环最短等待秒数"
    )
    parser.add_argument(
        "--sleep-max", type=int, default=30, help="注册循环最长等待秒数"
    )
    parser.add_argument(
        "--failure-sleep-seconds",
        type=int,
        default=DEFAULT_REGISTER_FAILURE_EXTRA_SLEEP_SECONDS,
        help="注册失败后额外等待秒数",
    )
    parser.add_argument(
        "--mail-provider",
        default="cfmail",
        choices=["cfmail", "tempmaillol", "mailtm", "tempmailio", "dropmail"],
        help="邮箱服务（cfmail / tempmaillol / mailtm / tempmailio / dropmail）",
    )
    parser.add_argument(
        "--cfmail-profile",
        default="auto",
        help="自建邮箱配置名；auto 表示按 cfmail 配置文件中的顺序轮询",
    )
    parser.add_argument(
        "--cfmail-config",
        default=CFMAIL_CONFIG_PATH,
        help="cfmail 邮箱配置 JSON 文件路径",
    )
    parser.add_argument(
        "--cfmail-worker-domain",
        default=None,
        help="临时覆盖自建邮箱后端域名，如 apimail.example.com",
    )
    parser.add_argument(
        "--cfmail-email-domain",
        default=None,
        help="临时覆盖自建邮箱域名，如 example.com",
    )
    parser.add_argument(
        "--cfmail-admin-password",
        default=None,
        help="临时覆盖自建邮箱后台管理员密码",
    )
    parser.add_argument(
        "--cfmail-profile-name",
        default="custom",
        help="临时覆盖自建邮箱配置时使用的配置名",
    )
    parser.add_argument(
        "--mailtm-api-base",
        default=MAILTM_BASE,
        help="Mail.tm API 地址（可替换为兼容 Mail.tm 的自建服务）",
    )
    parser.add_argument(
        "--token-dir",
        default=DEFAULT_TOKEN_OUTPUT_DIR,
        help="B 目录 / Token 输出目录",
    )
    parser.add_argument(
        "--active-token-dir",
        default=DEFAULT_ACTIVE_TOKEN_DIR,
        help="A 目录，当前正在使用的账号目录",
    )
    parser.add_argument(
        "--active-min-count",
        type=int,
        default=DEFAULT_MIN_ACTIVE_COUNT,
        help="A 目录最少保留数量",
    )
    parser.add_argument(
        "--pool-min-count",
        type=int,
        default=DEFAULT_MIN_POOL_COUNT,
        help="B 目录最少保留数量",
    )
    parser.add_argument(
        "--usage-threshold",
        type=int,
        default=DEFAULT_USAGE_THRESHOLD,
        help="账号已用比例达到该值后视为不可用",
    )
    parser.add_argument(
        "--request-interval",
        type=int,
        default=DEFAULT_REQUEST_INTERVAL_SECONDS,
        help="检测账号时每次请求之间的等待秒数",
    )
    parser.add_argument(
        "--curl-timeout",
        type=int,
        default=15,
        help="额度检测接口超时时间（秒）",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="持续巡检模式：每隔一段时间检查 A/B 数量并自动补号",
    )
    parser.add_argument(
        "--monitor-once",
        action="store_true",
        help="巡检模式只执行一轮",
    )
    parser.add_argument(
        "--register-only",
        action="store_true",
        help="仅执行原来的注册逻辑，不做 A/B 检测",
    )
    parser.add_argument(
        "--monitor-interval",
        type=int,
        default=DEFAULT_CHECK_INTERVAL_SECONDS,
        help="巡检间隔秒数，默认 900 秒（15 分钟）",
    )
    parser.add_argument(
        "--register-batch-size",
        type=int,
        default=DEFAULT_REGISTER_BATCH_SIZE,
        help="巡检补号时每批并发注册数量",
    )
    parser.add_argument(
        "--dingtalk-webhook",
        default=DEFAULT_DINGTALK_WEBHOOK,
        help="钉钉机器人 Webhook，留空则不发送提醒",
    )
    parser.add_argument(
        "--dingtalk-summary-interval",
        type=int,
        default=DEFAULT_DINGTALK_SUMMARY_INTERVAL_SECONDS,
        help="钉钉汇总发送间隔秒数，默认 10800 秒（3 小时）",
    )
    parser.add_argument(
        "--auto-continue-non-us",
        action="store_true",
        help="非 US 出口时自动继续，适合无人值守巡检",
    )
    parser.add_argument(
        "--test-cfmail",
        action="store_true",
        help="仅测试 cfmail 配置是否可创建邮箱并可轮询，不执行注册",
    )
    parser.add_argument(
        "--cfmail-fail-threshold",
        type=int,
        default=DEFAULT_CFMAIL_FAIL_THRESHOLD,
        help="cfmail 连续失败达到该阈值后进入冷却",
    )
    parser.add_argument(
        "--cfmail-cooldown-seconds",
        type=int,
        default=DEFAULT_CFMAIL_COOLDOWN_SECONDS,
        help="cfmail 自动冷却时长（秒）",
    )
    args = parser.parse_args()

    # 保存 argparse 的默认值，用于判断命令行是否显式传参
    for action in parser._actions:
        if hasattr(action, "dest") and action.dest != "help":
            setattr(args, f"_default_{action.dest}", action.default)

    # 加载配置文件（命令行参数优先于配置文件）
    config = _load_config_file(args.config)
    if config:
        print(f"[信息] 已加载配置文件: {args.config}")
        _apply_config_to_args(args, config)

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)
    args.failure_sleep_seconds = max(0, args.failure_sleep_seconds)
    args.active_min_count = max(1, args.active_min_count)
    args.pool_min_count = max(0, args.pool_min_count)
    args.usage_threshold = max(1, args.usage_threshold)
    args.request_interval = max(0, args.request_interval)
    args.curl_timeout = max(1, args.curl_timeout)
    args.monitor_interval = max(1, args.monitor_interval)
    args.dingtalk_summary_interval = max(1, args.dingtalk_summary_interval)
    args.register_batch_size = max(1, args.register_batch_size)
    args.cfmail_fail_threshold = max(1, args.cfmail_fail_threshold)
    args.cfmail_cooldown_seconds = max(0, args.cfmail_cooldown_seconds)
    args.cfmail_profile = str(args.cfmail_profile or "auto").strip() or "auto"
    args.cfmail_profile_name = (
        str(args.cfmail_profile_name or "custom").strip() or "custom"
    )
    args.cfmail_config = (
        str(args.cfmail_config or DEFAULT_CFMAIL_CONFIG_PATH).strip()
        or DEFAULT_CFMAIL_CONFIG_PATH
    )

    has_cfmail_override = any(
        [
            args.cfmail_worker_domain,
            args.cfmail_email_domain,
            args.cfmail_admin_password,
        ]
    )
    if has_cfmail_override and not all(
        [
            args.cfmail_worker_domain,
            args.cfmail_email_domain,
            args.cfmail_admin_password,
        ]
    ):
        parser.error(
            "--cfmail-worker-domain / --cfmail-email-domain / --cfmail-admin-password 需要同时提供"
        )

    if has_cfmail_override:
        configured_cfmail_accounts = [
            CfmailAccount(
                name=args.cfmail_profile_name,
                worker_domain=_normalize_host(args.cfmail_worker_domain),
                email_domain=_normalize_host(args.cfmail_email_domain),
                admin_password=str(args.cfmail_admin_password or "").strip(),
            )
        ]
    else:
        configured_cfmail_accounts = _build_cfmail_accounts(
            _load_cfmail_accounts_from_file(args.cfmail_config) or DEFAULT_CFMAIL_ACCOUNTS
        )

    _set_cfmail_accounts(configured_cfmail_accounts)
    globals()["CFMAIL_PROFILE_MODE"] = args.cfmail_profile
    globals()["CFMAIL_CONFIG_PATH"] = args.cfmail_config
    globals()["CFMAIL_HOT_RELOAD_ENABLED"] = not has_cfmail_override
    globals()["CFMAIL_FAIL_THRESHOLD"] = args.cfmail_fail_threshold
    globals()["CFMAIL_COOLDOWN_SECONDS"] = args.cfmail_cooldown_seconds
    globals()["CFMAIL_CONFIG_MTIME"] = (
        os.path.getmtime(args.cfmail_config)
        if os.path.exists(args.cfmail_config)
        else None
    )
    _prune_cfmail_failure_state()

    if args.mail_provider == "cfmail" and not CFMAIL_ACCOUNTS:
        parser.error(
            "未配置可用的 cfmail 邮箱，请先在 cfmail 配置文件中添加，或通过 --cfmail-worker-domain 等参数临时指定"
        )

    if (
        args.mail_provider == "cfmail"
        and args.cfmail_profile.lower() != "auto"
        and not _select_cfmail_account(args.cfmail_profile)
    ):
        parser.error(
            f"--cfmail-profile 指定的配置不存在：{args.cfmail_profile}；当前可用配置: {_cfmail_account_names()}"
        )

    if args.test_cfmail:
        ok = run_cfmail_self_test(
            CFMAIL_ACCOUNTS,
            proxy=args.proxy,
            profile_name=args.cfmail_profile,
        )
        sys.exit(0 if ok else 1)

    # 默认行为：
    # - 直接执行脚本：跑一轮巡检（monitor_once）
    # - --monitor：持续巡检
    # - --register-only：跳过巡检，直接进入原始注册模式
    run_single_monitor = not args.register_only and not args.monitor

    if args.monitor or args.monitor_once or run_single_monitor:
        if args.auto_continue_non_us or not sys.stdin.isatty():
            builtins.yasal_bypass_ip_choice = True

        if run_single_monitor and not args.monitor and not args.monitor_once:
            args.monitor_once = True

        cfmail_desc = ""
        if args.mail_provider == "cfmail":
            cfmail_desc = (
                f"，cfmail配置文件={args.cfmail_config}，cfmail配置={_cfmail_account_names()}，选择={args.cfmail_profile}"
            )
        log_info(
            f"巡检模式启动：A目录={args.active_token_dir}，B目录={args.token_dir}，A阈值={args.active_min_count}，B阈值={args.pool_min_count}，巡检间隔={args.monitor_interval}秒，钉钉汇总间隔={args.dingtalk_summary_interval}秒{cfmail_desc}"
        )
        run_monitor_loop(args)
        return

    if args.auto_continue_non_us:
        builtins.yasal_bypass_ip_choice = True

    startup_message = (
        f"[信息] 脚本启动：3 线程并发，邮箱服务={args.mail_provider}，Token目录={args.token_dir}"
    )
    if args.mail_provider == "cfmail":
        startup_message += (
            f"，cfmail配置文件={args.cfmail_config}，cfmail配置={_cfmail_account_names()}，选择={args.cfmail_profile}"
        )
    print(startup_message)

    providers_list = [args.mail_provider, args.mail_provider, args.mail_provider]
    threads = []

    for i in range(1, 4):
        provider_key = providers_list[i - 1]
        t = threading.Thread(
            target=worker,
            args=(
                i,
                args.proxy,
                args.once,
                sleep_min,
                sleep_max,
                args.failure_sleep_seconds,
                provider_key,
                args.mailtm_api_base,
                args.token_dir,
            ),
        )
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
            if not any(t.is_alive() for t in threads):
                print("\n[信息] 所有线程已执行完成，任务结束")
                break
    except KeyboardInterrupt:
        print("\n[信息] 收到中断信号，准备退出")


if __name__ == "__main__":
    main()
