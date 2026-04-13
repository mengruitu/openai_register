# -*- coding: utf-8 -*-
"""Token 提取策略模块。

封装了从 OpenAI/ChatGPT 获取 Token 的多种策略：
1. 复用当前 session 免密获取
2. 从 Cookie / client_auth_session_dump 中解析 workspace 后提交获取
3. 通过 ChatGPT session 接口兜底获取
4. 使用 session_token 直接刷新 access_token
5. 账号密码重新登录获取（支持 organization 选择）
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Set

from curl_cffi import requests

from .oauth import (
    AUTH_URL,
    CHATGPT_SESSION_URL,
    DEFAULT_SESSION_FALLBACK_EXPIRES_IN_SECONDS,
    OAuthStart,
    RETRYABLE_GATEWAY_STATUSES,
    SESSION_API_REQUEST_TIMEOUT_SECONDS,
    _normalize_code_values,
    _parse_json_object,
    _session_fallback_expired_at,
    extract_continue_url_from_response,
    extract_workspaces_from_auth_cookie,
    follow_oauth_redirect_chain,
    oauth_authorize_url,
    post_email_otp_validate,
    prime_oauth_session,
    response_text_preview,
    submit_callback_url,
)
from ..mail.providers import TempMailbox
from ..sentinel import request_sentinel_header
from .session_refresh import TokenRefreshManager

logger = logging.getLogger("openai_register")


def _proxy_url_from_proxies(proxies: Any) -> str:
    if isinstance(proxies, str):
        return str(proxies or "").strip()
    if isinstance(proxies, dict):
        for key in ("https", "http"):
            candidate = str(proxies.get(key) or "").strip()
            if candidate:
                return candidate
    return ""


def _auth_url(url: str) -> str:
    candidate = str(url or "").strip()
    if not candidate:
        return ""
    return urllib.parse.urljoin(AUTH_URL, candidate)


def _extract_callback_url(value: str) -> str:
    candidate = _auth_url(value)
    if not candidate:
        return ""
    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    code = str((query.get("code") or [""])[0] or "").strip()
    state = str((query.get("state") or [""])[0] or "").strip()
    if code and state:
        return candidate
    return ""


def _extract_callback_url_from_exception(exc: Exception) -> str:
    matched = re.search(r"(https?://localhost[^\s'\"\\]+)", str(exc or ""))
    if not matched:
        return ""
    return _extract_callback_url(matched.group(1))


def _extract_session_token(session: Any) -> str:
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        return ""
    for cookie_name in ("__Secure-next-auth.session-token", "next-auth.session-token"):
        try:
            cookie_value = str(cookies.get(cookie_name) or "").strip()
        except Exception:
            cookie_value = ""
        if cookie_value:
            return cookie_value
    jar = getattr(cookies, "jar", None)
    if jar is None:
        return ""
    for item in list(jar):
        name = str(getattr(item, "name", "") or "").strip()
        if name not in {"__Secure-next-auth.session-token", "next-auth.session-token"}:
            continue
        value = str(getattr(item, "value", "") or "").strip()
        if value:
            return value
    return ""


def _response_header_value(resp: Any, key: str) -> str:
    headers = getattr(resp, "headers", None)
    if not headers:
        return ""
    try:
        value = headers.get(key)
        if value:
            return str(value).strip()
    except Exception:
        pass
    try:
        for header_key, header_value in headers.items():
            if str(header_key).strip().lower() == key.lower():
                return str(header_value).strip()
    except Exception:
        pass
    return ""


def _response_json_object(resp: Any) -> Dict[str, Any]:
    if resp is None:
        return {}
    try:
        payload = resp.json() if getattr(resp, "content", b"") else {}
    except Exception:
        payload = _parse_json_object(str(getattr(resp, "text", "") or ""))
    return payload if isinstance(payload, dict) else {}


def _response_debug_snapshot(resp: Any, *, preview_limit: int = 240) -> Dict[str, Any]:
    if resp is None:
        return {"status_code": "no_response"}

    payload = _response_json_object(resp)
    snapshot: Dict[str, Any] = {
        "status_code": getattr(resp, "status_code", "unknown"),
        "final_url": str(getattr(resp, "url", "") or "").strip(),
        "content_type": _response_header_value(resp, "content-type"),
        "location": _response_header_value(resp, "location"),
        "preview": response_text_preview(resp, limit=preview_limit),
    }

    continue_url = extract_continue_url_from_response(resp)
    if continue_url:
        snapshot["continue_url"] = continue_url

    page_obj = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    page_type = str(page_obj.get("type") or "").strip()
    if page_type:
        snapshot["page_type"] = page_type

    error_obj = payload.get("error") if isinstance(payload.get("error"), dict) else {}
    error_code = str(
        error_obj.get("code")
        or error_obj.get("error")
        or payload.get("code")
        or payload.get("error")
        or ""
    ).strip()
    error_message = str(
        error_obj.get("message")
        or error_obj.get("description")
        or error_obj.get("error_description")
        or payload.get("message")
        or payload.get("error_description")
        or ""
    ).strip()
    if error_code:
        snapshot["error_code"] = error_code
    if error_message:
        snapshot["error_message"] = error_message

    return snapshot


def _session_cookie_snapshot(session: Any) -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {
        "oai_did_present": False,
        "auth_cookie_present": False,
        "session_token_present": False,
        "cookie_names": [],
        "auth_cookie_workspace_count": 0,
    }
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        return snapshot

    cookie_names: List[str] = []
    jar = getattr(cookies, "jar", None)
    if jar is not None:
        try:
            for item in list(jar):
                name = str(getattr(item, "name", "") or "").strip()
                if name:
                    cookie_names.append(name)
        except Exception:
            pass

    auth_cookie = str(cookies.get("oai-client-auth-session") or "").strip()
    auth_cookie_workspaces = extract_workspaces_from_auth_cookie(auth_cookie) if auth_cookie else []
    session_token = _extract_session_token(session)
    oai_did = str(cookies.get("oai-did") or "").strip()

    snapshot["oai_did_present"] = bool(oai_did)
    snapshot["auth_cookie_present"] = bool(auth_cookie)
    snapshot["session_token_present"] = bool(session_token)
    snapshot["cookie_names"] = sorted(set(cookie_names))[:20]
    snapshot["auth_cookie_workspace_count"] = len(auth_cookie_workspaces)
    return snapshot


def _build_session_refresh_token_json(
    session_token: str,
    refresh_result: Any,
) -> str:
    now = int(time.time())
    expired = (
        refresh_result.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        if getattr(refresh_result, "expires_at", None) is not None
        else time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(now + DEFAULT_SESSION_FALLBACK_EXPIRES_IN_SECONDS),
        )
    )
    payload = {
        "id_token": "",
        "access_token": str(getattr(refresh_result, "access_token", "") or "").strip(),
        "refresh_token": str(getattr(refresh_result, "refresh_token", "") or "").strip(),
        "account_id": str(getattr(refresh_result, "account_id", "") or "").strip(),
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "email": str(getattr(refresh_result, "email", "") or "").strip(),
        "type": "session_token_refresh",
        "expired": expired,
        "session_token": str(getattr(refresh_result, "session_token", "") or session_token).strip(),
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _refresh_tokens_from_session_cookie(
    session: Any,
    *,
    thread_id: int,
    proxy_url: str = "",
) -> Optional[str]:
    session_token = _extract_session_token(session)
    if not session_token:
        return None
    logger.info(f"[线程 {thread_id}] [信息] 检测到 next-auth session_token，尝试直接刷新 access_token")
    refresh_result = TokenRefreshManager(proxy_url=proxy_url or None).refresh_by_session_token(session_token)
    if not refresh_result.success:
        logger.warning(
            f"[线程 {thread_id}] [警告] session token refresh failed: {refresh_result.error_message or 'unknown'}"
        )
        return None
    logger.info(f"[线程 {thread_id}] [信息] session token refresh succeeded")
    return _build_session_refresh_token_json(session_token, refresh_result)


def _decode_oauth_session_cookie(session: Any) -> Dict[str, Any]:
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        return {}
    jar = getattr(cookies, "jar", None)
    cookie_items = list(jar) if jar is not None else []
    raw_cookie = str(cookies.get("oai-client-auth-session") or "").strip()
    if raw_cookie:
        cookie_items.insert(0, type("CookieItem", (), {"name": "oai-client-auth-session", "value": raw_cookie})())
    for item in cookie_items:
        name = str(getattr(item, "name", "") or "").strip()
        if "oai-client-auth-session" not in name:
            continue
        raw_value = str(getattr(item, "value", "") or "").strip()
        if not raw_value:
            continue
        candidates = [raw_value]
        try:
            from urllib.parse import unquote

            decoded = unquote(raw_value)
            if decoded != raw_value:
                candidates.append(decoded)
        except Exception:
            pass
        for candidate in candidates:
            try:
                value = candidate
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                part = value.split(".")[0] if "." in value else value
                pad = "=" * ((4 - (len(part) % 4)) % 4)
                decoded = base64.urlsafe_b64decode((part + pad).encode("ascii"))
                data = json.loads(decoded.decode("utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                continue
    return {}


def _fetch_client_auth_session_dump(session: Any, thread_id: int) -> Dict[str, Any]:
    try:
        resp = session.get(
            "https://auth.openai.com/api/accounts/client_auth_session_dump",
            headers={
                "accept": "application/json",
                "referer": "https://auth.openai.com/add-phone",
            },
            timeout=15,
        )
    except Exception as exc:
        logger.warning(f"[线程 {thread_id}] [警告] client_auth_session_dump 请求失败: {exc}")
        return {}

    if resp.status_code != 200:
        logger.warning(
            f"[线程 {thread_id}] [警告] client_auth_session_dump 状态异常: {resp.status_code}，"
            f"摘要: {response_text_preview(resp)}"
        )
        return {}

    try:
        payload = resp.json() if resp.content else {}
    except Exception:
        payload = _parse_json_object(getattr(resp, "text", ""))

    session_payload = payload.get("client_auth_session") if isinstance(payload, dict) else None
    return session_payload if isinstance(session_payload, dict) else {}


def _load_oauth_session_payload(session: Any, thread_id: int) -> Dict[str, Any]:
    cookie_payload = _decode_oauth_session_cookie(session)
    workspaces = cookie_payload.get("workspaces") or []
    if isinstance(workspaces, list) and workspaces:
        return cookie_payload
    dump_payload = _fetch_client_auth_session_dump(session, thread_id)
    dump_workspaces = dump_payload.get("workspaces") if isinstance(dump_payload, dict) else None
    if isinstance(dump_workspaces, list) and dump_workspaces:
        return dump_payload
    return cookie_payload or dump_payload or {}


def _try_workspace_and_org_selection(
    session: Any,
    oauth: OAuthStart,
    workspace_id: str,
    thread_id: int,
    proxies: Any = None,
) -> Optional[str]:
    select_resp = session.post(
        "https://auth.openai.com/api/accounts/workspace/select",
        headers={
            "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            "content-type": "application/json",
            "accept": "application/json",
        },
        json={"workspace_id": workspace_id},
    )
    if select_resp.status_code != 200:
        continue_url = extract_continue_url_from_response(select_resp)
        logger.warning(
            f"[线程 {thread_id}] [警告] 选择 workspace 失败，状态码: {select_resp.status_code}，"
            f"continue_url={continue_url or '(empty)'}，摘要: {response_text_preview(select_resp)}"
        )
        continue_url = extract_continue_url_from_response(select_resp)
        if continue_url:
            token_json = follow_oauth_redirect_chain(session, continue_url, oauth, thread_id, proxies=proxies)
            if not token_json:
                logger.warning(
                    f"[线程 {thread_id}] [警告] workspace/select 失败后继续跟随 continue_url，但仍未获取到 token"
                )
            return token_json
        return None

    try:
        select_payload = select_resp.json() if select_resp.content else {}
    except Exception:
        select_payload = {}

    orgs = ((select_payload.get("data") or {}).get("orgs") or []) if isinstance(select_payload, dict) else []
    if isinstance(orgs, list) and orgs:
        first_org = orgs[0] or {}
        org_id = str(first_org.get("id") or "").strip()
        projects = first_org.get("projects") or []
        project_id = ""
        if isinstance(projects, list) and projects:
            project_id = str((projects[0] or {}).get("id") or "").strip()
        if org_id:
            org_body: Dict[str, str] = {"org_id": org_id}
            if project_id:
                org_body["project_id"] = project_id
            org_resp = session.post(
                "https://auth.openai.com/api/accounts/organization/select",
                headers={
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "content-type": "application/json",
                    "accept": "application/json",
                },
                json=org_body,
            )
            if org_resp.status_code == 200 or 300 <= org_resp.status_code < 400:
                org_continue_url = extract_continue_url_from_response(org_resp)
                if org_continue_url:
                    token_json = follow_oauth_redirect_chain(
                        session,
                        org_continue_url,
                        oauth,
                        thread_id,
                        proxies=proxies,
                    )
                    if not token_json:
                        logger.warning(
                            f"[线程 {thread_id}] [警告] organization/select 已返回 continue_url，但跳转链仍未获取到 token"
                        )
                    return token_json
            logger.warning(
                f"[线程 {thread_id}] [警告] 选择 organization 失败，状态码: {org_resp.status_code}，"
                f"摘要: {response_text_preview(org_resp)}"
            )

    continue_url = extract_continue_url_from_response(select_resp)
    if not continue_url:
        logger.warning(f"[线程 {thread_id}] [警告] workspace/select 响应里缺少 continue_url")
        return None

    logger.info(f"[线程 {thread_id}] [信息] 已获取 workspace，继续跟随授权跳转链")
    token_json = follow_oauth_redirect_chain(session, continue_url, oauth, thread_id, proxies=proxies)
    if not token_json:
        logger.warning(
            f"[线程 {thread_id}] [警告] workspace/select 已返回 continue_url，但授权跳转链未获取到 token"
        )
    return token_json


# ---------------------------------------------------------------------------
# 策略 1: 复用当前 session 免密获取 token
# ---------------------------------------------------------------------------


def try_token_via_existing_session(
    session: Any,
    oauth: OAuthStart,
    thread_id: int,
    proxies: Any = None,
) -> Optional[str]:
    """尝试复用当前 session 免密获取 token。"""
    logger.info(f"[线程 {thread_id}] [信息] 尝试复用当前 session 免密获取 token")
    token_json = follow_oauth_redirect_chain(
        session,
        oauth_authorize_url(oauth, prompt=None),
        oauth,
        thread_id,
        proxies=proxies, 
    )
    if not token_json:
        logger.warning(f"[线程 {thread_id}] [警告] 复用当前 session 的授权跳转链未获取到 token")
    return token_json


def try_token_via_continue_url(
    session: Any,
    oauth: OAuthStart,
    continue_url: str,
    thread_id: int,
    proxies: Any = None,
) -> Optional[str]:
    """尝试直接跟随某个 continue_url 获取 token。"""
    candidate = str(continue_url or "").strip()
    if not candidate:
        return None
    logger.info(f"[线程 {thread_id}] [信息] 尝试直接跟随 continue_url 获取 token")
    callback_url = _extract_callback_url(candidate)
    if callback_url:
        try:
            return submit_callback_url(
                callback_url=callback_url,
                expected_state=oauth.state,
                code_verifier=oauth.code_verifier,
                redirect_uri=oauth.redirect_uri,
                proxies=proxies,
            )
        except Exception as exc:
            logger.warning(f"[线程 {thread_id}] [警告] continue_url 直接回调换 token 失败: {exc}")
    token_json = follow_oauth_redirect_chain(session, candidate, oauth, thread_id, proxies=proxies)
    if not token_json:
        logger.warning(
            f"[线程 {thread_id}] [警告] continue_url 授权跳转链未获取到 token: {candidate}"
        )
    return token_json


def try_token_via_session_cookie(
    session: Any,
    thread_id: int,
    *,
    proxy_url: str = "",
) -> Optional[str]:
    """尝试通过 next-auth session_token 直接刷新 access_token。"""
    return _refresh_tokens_from_session_cookie(
        session,
        thread_id=thread_id,
        proxy_url=proxy_url,
    )


# ---------------------------------------------------------------------------
# 策略 2: 从 Cookie / dump 中解析 workspace 后提交获取
# ---------------------------------------------------------------------------


def try_token_via_workspace_select(
    session: Any,
    oauth: OAuthStart,
    auth_cookie: str,
    thread_id: int,
    proxies: Any = None,
) -> Optional[str]:
    """从授权 Cookie / dump 中解析 workspace 并选择后获取 token。"""
    workspaces = extract_workspaces_from_auth_cookie(auth_cookie)
    if not workspaces:
        session_payload = _load_oauth_session_payload(session, thread_id)
        workspaces = [
            item
            for item in (session_payload.get("workspaces") or [])
            if isinstance(item, dict)
        ]
    if not workspaces:
        logger.warning(f"[线程 {thread_id}] [警告] 授权 Cookie 存在，但暂未解析到 workspace")
        return None

    selected_workspace = workspaces[0] or {}
    workspace_id = str(selected_workspace.get("id") or "").strip()
    if not workspace_id:
        logger.warning(f"[线程 {thread_id}] [警告] workspace 信息存在，但无法解析 workspace_id")
        return None

    workspace_kind = str(selected_workspace.get("kind") or "").strip() or "unknown"
    workspace_name = str(selected_workspace.get("name") or "").strip() or "(null)"
    logger.info(
        f"[线程 {thread_id}] [信息] 已解析 workspace: count={len(workspaces)}, "
        f"id={workspace_id}, kind={workspace_kind}, name={workspace_name}"
    )
    token_json = _try_workspace_and_org_selection(session, oauth, workspace_id, thread_id, proxies=proxies)
    if not token_json:
        logger.warning(
            f"[线程 {thread_id}] [警告] workspace 解析成功，但 workspace/select 流程最终未获取到 token"
        )
    return token_json


# ---------------------------------------------------------------------------
# 策略 3: 通过 ChatGPT session 接口兜底获取
# ---------------------------------------------------------------------------


def try_token_via_session_api(session: Any, thread_id: int) -> Optional[str]:
    """通过 chatgpt session 接口兜底提取 token。"""
    logger.info(f"[线程 {thread_id}] [信息] 尝试通过 chatgpt session 接口兜底提取 token")

    try:
        resp = session.get(
            CHATGPT_SESSION_URL,
            headers={
                "accept": "application/json,text/plain,*/*",
                "referer": "https://chatgpt.com/",
            },
            timeout=SESSION_API_REQUEST_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.warning(f"[线程 {thread_id}] [警告] 读取 chatgpt session 接口失败: {exc}")
        return None

    if resp.status_code != 200:
        logger.warning(
            f"[线程 {thread_id}] [警告] chatgpt session 接口状态异常: {resp.status_code}，"
            f"摘要: {response_text_preview(resp)}"
        )
        return None

    try:
        payload = resp.json() if resp.content else {}
    except Exception:
        payload = _parse_json_object(getattr(resp, "text", ""))

    if not isinstance(payload, dict) or not payload:
        logger.warning(f"[线程 {thread_id}] [警告] chatgpt session 接口未返回有效 JSON")
        return None

    access_token = str(payload.get("accessToken") or "").strip()
    if not access_token:
        logger.warning(f"[线程 {thread_id}] [警告] chatgpt session 接口响应中缺少 accessToken")
        return None

    user_info = payload.get("user") if isinstance(payload.get("user"), dict) else {}
    account_info = payload.get("account") if isinstance(payload.get("account"), dict) else {}
    session_token = str(payload.get("sessionToken") or "").strip()
    email = str(user_info.get("email") or "").strip()
    account_id = str(
        user_info.get("id")
        or account_info.get("id")
        or ""
    ).strip()
    now = int(time.time())

    config = {
        "id_token": "",
        "access_token": access_token,
        "refresh_token": "",
        "account_id": account_id,
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "email": email,
        "type": "chatgpt_session_fallback",
        "expired": _session_fallback_expired_at(payload),
    }
    if session_token:
        config["session_token"] = session_token

    plan_type = str(account_info.get("planType") or "").strip()
    if plan_type:
        config["plan_type"] = plan_type

    logger.info(
        f"[线程 {thread_id}] [信息] 已通过 chatgpt session 接口提取 access_token"
        f"{f'，email={email}' if email else ''}"
        f"{f'，account_id={account_id}' if account_id else ''}"
    )
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# 策略 4: 账号密码重新登录获取
# ---------------------------------------------------------------------------


def try_token_via_password_login(
    *,
    email: str,
    password: str,
    mailbox: Optional[TempMailbox] = None,
    used_codes: Optional[Set[str]] = None,
    oauth: OAuthStart,
    proxies: Any,
    impersonate: str,
    thread_id: int,
    get_oai_code_fn: Callable[..., str],
    get_mailbox_message_snapshot_fn: Callable[..., Set[str]],
    debug_sink: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """使用账号密码重新登录以获取 token。"""
    account = str(email or "").strip()
    pwd = str(password or "").strip()
    if not account or not pwd:
        return None

    proxy_url = _proxy_url_from_proxies(proxies)
    logger.info(f"[线程 {thread_id}] [信息] 当前 session 未拿到 token，尝试账号密码重新登录")
    login_session = requests.Session(proxies=proxies, impersonate=impersonate)
    ignored_codes = _normalize_code_values(used_codes)
    debug_state = debug_sink if isinstance(debug_sink, dict) else {}
    debug_steps = debug_state.setdefault("steps", [])
    debug_state["proxy_url"] = proxy_url
    debug_state["impersonate"] = impersonate
    debug_state["mailbox_present"] = mailbox is not None
    debug_state["used_code_count"] = len(ignored_codes)

    def _record_debug(stage: str, status: str, message: str = "", **fields: Any) -> None:
        entry: Dict[str, Any] = {"stage": stage, "status": status}
        if message:
            entry["message"] = message
        for key, value in fields.items():
            if value is None:
                continue
            if value == "":
                continue
            if value == []:
                continue
            if value == {}:
                continue
            entry[key] = value
        debug_steps.append(entry)

    def _set_final_error(code: str, message: str = "", **fields: Any) -> None:
        debug_state["final_error_code"] = str(code or "").strip()
        if message:
            debug_state["final_error_message"] = str(message or "").strip()
        for key, value in fields.items():
            if value is None:
                continue
            if value == "":
                continue
            if value == []:
                continue
            if value == {}:
                continue
            debug_state[key] = value

    def _bootstrap_login_session() -> str:
        prime_oauth_session(
            login_session,
            oauth_authorize_url(oauth, prompt="login"),
            thread_id,
        )
        return str(login_session.cookies.get("oai-did") or "").strip()

    try:
        did = _bootstrap_login_session()
        _record_debug(
            "oauth_prime",
            "ok" if did else "error",
            did_present=bool(did),
            session=_session_cookie_snapshot(login_session),
        )
        if not did:
            _set_final_error(
                "login_device_id_missing",
                "密码登录 OAuth 初始化后未获取到 oai-did",
                session=_session_cookie_snapshot(login_session),
            )
            logger.warning(f"[线程 {thread_id}] [警告] 账号密码重登录未获取到 oai-did")
            return None
        sentinel_header = request_sentinel_header(
            did=did,
            proxies=proxies,
            impersonate=impersonate,
            thread_id=thread_id,
            flow="authorize_continue",
        )
        if not sentinel_header:
            _record_debug("authorize_continue_sentinel", "error", did_present=True)
            _set_final_error(
                "login_sentinel_missing",
                "密码登录 authorize_continue 未获取到 sentinel token",
                session=_session_cookie_snapshot(login_session),
            )
            logger.warning(f"[线程 {thread_id}] [警告] 账号密码重登录未获取到 authorize_continue sentinel token")
            return None

        continue_resp = login_session.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/sign-in",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel_header,
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
        _record_debug(
            "authorize_continue",
            "ok" if continue_resp.status_code in (200, 204) else "error",
            response=_response_debug_snapshot(continue_resp),
            session=_session_cookie_snapshot(login_session),
        )
        if continue_resp.status_code == 400 and "invalid_auth_step" in str(getattr(continue_resp, "text", "") or "").lower():
            logger.info(f"[线程 {thread_id}] [信息] 登录预处理遇到 invalid_auth_step，重建认证上下文后重试一次")
            _record_debug(
                "authorize_continue_invalid_auth_step",
                "warn",
                response=_response_debug_snapshot(continue_resp),
            )
            did = _bootstrap_login_session()
            _record_debug(
                "oauth_prime_retry",
                "ok" if did else "error",
                did_present=bool(did),
                session=_session_cookie_snapshot(login_session),
            )
            if not did:
                _set_final_error(
                    "login_device_id_missing_retry",
                    "重试密码登录 OAuth 初始化后未获取到 oai-did",
                    session=_session_cookie_snapshot(login_session),
                )
                logger.warning(f"[线程 {thread_id}] [警告] 账号密码重登录重试后仍未获取到 oai-did")
                return None
            sentinel_header = request_sentinel_header(
                did=did,
                proxies=proxies,
                impersonate=impersonate,
                thread_id=thread_id,
                flow="authorize_continue",
            )
            if not sentinel_header:
                _set_final_error(
                    "login_sentinel_missing_retry",
                    "重试密码登录 authorize_continue 未获取到 sentinel token",
                    session=_session_cookie_snapshot(login_session),
                )
                logger.warning(f"[线程 {thread_id}] [警告] 账号密码重登录重试后仍未获取到 authorize_continue sentinel token")
                return None
            continue_resp = login_session.post(
                "https://auth.openai.com/api/accounts/authorize/continue",
                headers={
                    "referer": "https://auth.openai.com/sign-in",
                    "accept": "application/json",
                    "content-type": "application/json",
                    "openai-sentinel-token": sentinel_header,
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
            _record_debug(
                "authorize_continue_retry",
                "ok" if continue_resp.status_code in (200, 204) else "error",
                response=_response_debug_snapshot(continue_resp),
                session=_session_cookie_snapshot(login_session),
            )
        if continue_resp.status_code not in (200, 204):
            logger.warning(
                f"[线程 {thread_id}] [警告] 账号密码登录预处理失败，状态码: {continue_resp.status_code}，"
                f"摘要: {response_text_preview(continue_resp)}"
            )
            _set_final_error(
                "login_authorize_continue_failed",
                "账号密码登录预处理失败",
                response=_response_debug_snapshot(continue_resp),
                session=_session_cookie_snapshot(login_session),
            )
            return None

        existing_message_ids = (
            get_mailbox_message_snapshot_fn(mailbox, thread_id, proxies) if mailbox else set()
        )
        password_headers = {
            "referer": "https://auth.openai.com/log-in/password",
            "accept": "application/json",
            "content-type": "application/json",
        }
        password_sentinel = request_sentinel_header(
            did=did,
            proxies=proxies,
            impersonate=impersonate,
            thread_id=thread_id,
            flow="password_verify",
        )
        if password_sentinel:
            password_headers["openai-sentinel-token"] = password_sentinel
        else:
            _record_debug("password_verify_sentinel", "warn", did_present=bool(did))

        login_resp = login_session.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=password_headers,
            data=json.dumps(
                {"password": pwd},
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )
        if login_resp.status_code != 200:
            logger.warning(
                f"[线程 {thread_id}] [警告] 账号密码登录失败，状态码: {login_resp.status_code}，"
                f"摘要: {response_text_preview(login_resp)}"
            )
            _record_debug(
                "password_verify",
                "error",
                response=_response_debug_snapshot(login_resp),
                session=_session_cookie_snapshot(login_session),
            )
            _set_final_error(
                "login_password_verify_failed",
                "账号密码登录失败",
                response=_response_debug_snapshot(login_resp),
                session=_session_cookie_snapshot(login_session),
            )
            return None

        try:
            login_payload = login_resp.json() if login_resp.content else {}
        except Exception:
            login_payload = {}

        login_page = login_payload.get("page") or {}
        page_type = str(login_page.get("type") or "").strip()
        continue_url = extract_continue_url_from_response(login_resp)
        need_oauth_otp = (
            page_type == "email_otp_verification"
            or "email-verification" in str(continue_url or "")
            or "email-otp" in str(continue_url or "")
        )
        _record_debug(
            "password_verify",
            "ok",
            page_type=page_type or "(empty)",
            need_oauth_otp=need_oauth_otp,
            continue_url=continue_url or "",
            response=_response_debug_snapshot(login_resp),
            session=_session_cookie_snapshot(login_session),
        )

        if need_oauth_otp:
            token_json = try_token_via_session_cookie(
                login_session,
                thread_id,
                proxy_url=proxy_url,
            )
            if token_json:
                _record_debug("session_cookie_refresh", "ok", source="password_login_pre_otp")
                return token_json

            if not mailbox:
                logger.warning(
                    f"[线程 {thread_id}] [警告] 密码登录后需要邮箱验证码，但当前没有可用邮箱上下文"
                )
                _set_final_error(
                    "login_email_otp_missing_mailbox",
                    "密码登录后需要邮箱验证码，但当前没有邮箱上下文",
                    continue_url=continue_url or "",
                    session=_session_cookie_snapshot(login_session),
                )
                return None

            logger.info(f"[线程 {thread_id}] [信息] OpenAI 已自动发送登录验证码邮件，开始等待新邮件")
            login_otp_resp = None
            for otp_attempt in range(2):
                login_code = get_oai_code_fn(
                    mailbox,
                    thread_id,
                    proxies,
                    skip_message_ids=existing_message_ids,
                    skip_codes=ignored_codes,
                )
                if not login_code:
                    logger.warning(f"[线程 {thread_id}] [警告] 未能获取登录阶段邮箱验证码")
                    _record_debug(
                        "login_email_otp_wait",
                        "error",
                        attempt=otp_attempt + 1,
                        existing_message_ids=len(existing_message_ids),
                    )
                    _set_final_error(
                        "login_email_otp_missing",
                        "未能获取登录阶段邮箱验证码",
                        attempt=otp_attempt + 1,
                        session=_session_cookie_snapshot(login_session),
                    )
                    return None

                login_otp_resp = post_email_otp_validate(
                    login_session,
                    code=login_code,
                    thread_id=thread_id,
                    stage_label="登录阶段",
                )
                if login_otp_resp and login_otp_resp.status_code == 200:
                    continue_url = extract_continue_url_from_response(login_otp_resp)
                    _record_debug(
                        "login_email_otp_validate",
                        "ok",
                        attempt=otp_attempt + 1,
                        response=_response_debug_snapshot(login_otp_resp),
                        continue_url=continue_url or "",
                        session=_session_cookie_snapshot(login_session),
                    )
                    token_json = try_token_via_session_cookie(
                        login_session,
                        thread_id,
                        proxy_url=proxy_url,
                    )
                    if token_json:
                        _record_debug("session_cookie_refresh", "ok", source="password_login_post_otp")
                        return token_json
                    break

                status_code = getattr(login_otp_resp, "status_code", "unknown")
                if status_code not in RETRYABLE_GATEWAY_STATUSES:
                    ignored_codes.add(login_code)
                logger.warning(
                    f"[线程 {thread_id}] [警告] 登录阶段邮箱验证码校验失败，状态码: {status_code}，"
                    f"摘要: {response_text_preview(login_otp_resp)}"
                )
                _record_debug(
                    "login_email_otp_validate",
                    "error",
                    attempt=otp_attempt + 1,
                    response=_response_debug_snapshot(login_otp_resp),
                    session=_session_cookie_snapshot(login_session),
                )
                if status_code == 401 and otp_attempt == 0:
                    logger.info(f"[线程 {thread_id}] [信息] 登录验证码可能命中旧邮件，准备重新等待新验证码")
                    time.sleep(2)
                    continue
                _set_final_error(
                    "login_email_otp_validate_failed",
                    "登录阶段邮箱验证码校验失败",
                    attempt=otp_attempt + 1,
                    response=_response_debug_snapshot(login_otp_resp),
                    session=_session_cookie_snapshot(login_session),
                )
                return None

            if not login_otp_resp or login_otp_resp.status_code != 200:
                _set_final_error(
                    "login_email_otp_validate_failed",
                    "登录阶段邮箱验证码校验未成功结束",
                    session=_session_cookie_snapshot(login_session),
                )
                return None

        auth_cookie = str(login_session.cookies.get("oai-client-auth-session") or "").strip()
        _record_debug(
            "post_login_session_state",
            "info",
            continue_url=continue_url or "",
            session=_session_cookie_snapshot(login_session),
        )
        if auth_cookie:
            token_json = try_token_via_workspace_select(
                login_session, oauth, auth_cookie, thread_id, proxies=proxies
            )
            if token_json:
                _record_debug("workspace_select", "ok")
                return token_json
            _record_debug(
                "workspace_select",
                "warn",
                result="no_token",
                session=_session_cookie_snapshot(login_session),
            )
        else:
            _record_debug("workspace_select", "warn", message="auth_cookie_missing")

        if continue_url:
            token_json = try_token_via_continue_url(
                login_session, oauth, continue_url, thread_id, proxies=proxies
            )
            if token_json:
                _record_debug("continue_url", "ok", continue_url=continue_url)
                return token_json
            _record_debug(
                "continue_url",
                "warn",
                continue_url=continue_url,
                callback_url_present=bool(_extract_callback_url(continue_url)),
                session=_session_cookie_snapshot(login_session),
            )
        else:
            _record_debug("continue_url", "warn", message="continue_url_missing")

        auth_cookie = str(login_session.cookies.get("oai-client-auth-session") or "").strip()
        if auth_cookie:
            token_json = try_token_via_workspace_select(
                login_session, oauth, auth_cookie, thread_id, proxies=proxies
            )
            if token_json:
                _record_debug("workspace_select_retry", "ok")
                return token_json
            _record_debug(
                "workspace_select_retry",
                "warn",
                result="no_token",
                session=_session_cookie_snapshot(login_session),
            )

        token_json = try_token_via_session_cookie(
            login_session,
            thread_id,
            proxy_url=proxy_url,
        )
        if token_json:
            _record_debug("session_cookie_refresh", "ok", source="final_fallback")
            return token_json
        _record_debug(
            "session_cookie_refresh",
            "warn",
            message="session_token_refresh_failed_or_missing",
            session=_session_cookie_snapshot(login_session),
        )

        token_json = try_token_via_existing_session(login_session, oauth, thread_id, proxies=proxies)
        if token_json:
            _record_debug("existing_session", "ok")
            return token_json

        _record_debug(
            "existing_session",
            "error",
            message="all_token_strategies_failed",
            session=_session_cookie_snapshot(login_session),
        )
        _set_final_error(
            "all_token_strategies_failed",
            "密码重登录已完成，但 workspace/select、continue_url、session cookie、existing session 均未获取到 token",
            continue_url=continue_url or "",
            session=_session_cookie_snapshot(login_session),
        )
        logger.warning(
            f"[线程 {thread_id}] [警告] 密码重登录已完成，但所有 token 提取策略均失败；"
            f"final_session={json.dumps(_session_cookie_snapshot(login_session), ensure_ascii=False)}"
        )
        return None
    except Exception as exc:
        callback_url = _extract_callback_url_from_exception(exc)
        if callback_url:
            try:
                return submit_callback_url(
                    callback_url=callback_url,
                    expected_state=oauth.state,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    proxies=proxies,
                )
            except Exception:
                pass
        _set_final_error(
            "password_login_exception",
            str(exc),
            callback_url=callback_url or "",
            session=_session_cookie_snapshot(login_session),
        )
        logger.warning(f"[线程 {thread_id}] [警告] 账号密码登录兜底失败: {exc}")
        return None
