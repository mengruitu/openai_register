# -*- coding: utf-8 -*-
"""Token 提取策略模块。

封装了从 OpenAI 获取 Token 的五种策略：
1. try_token_via_existing_session — 复用当前会话免密获取
2. try_token_via_workspace_select — 从 Cookie 中解析 workspace 后提交获取
3. try_token_via_session_api — 通过 ChatGPT session 接口兜底获取
4. try_token_via_password_login — 账号密码重新登录获取
5. try_token_via_passwordless_login — Passwordless OTP 登录绕过 add_phone 获取
"""
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set

from curl_cffi import requests

from register_auth import (
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
    generate_oauth_url,
    oauth_authorize_url,
    post_email_otp_validate,
    prime_oauth_session,
    response_text_preview,
    submit_callback_url,
)
from register_mailboxes import TempMailbox
from register_sentinel import request_sentinel_header

logger = logging.getLogger("openai_register")


# ---------------------------------------------------------------------------
# 策略 1: 复用当前 session 免密获取 token
# ---------------------------------------------------------------------------


def try_token_via_existing_session(
    session: Any,
    oauth: OAuthStart,
    thread_id: int,
) -> Optional[str]:
    """尝试复用当前 session 免密获取 token。"""
    logger.info(f"[线程 {thread_id}] [信息] 尝试复用当前 session 免密获取 token")
    return follow_oauth_redirect_chain(
        session,
        oauth_authorize_url(oauth, prompt=None),
        oauth,
        thread_id,
    )


# ---------------------------------------------------------------------------
# 策略 2: 从 Cookie 中解析 workspace 后提交获取
# ---------------------------------------------------------------------------


def try_token_via_workspace_select(
    session: Any,
    oauth: OAuthStart,
    auth_cookie: str,
    thread_id: int,
) -> Optional[str]:
    """从授权 Cookie 中解析 workspace 并选择后获取 token。"""
    workspaces = extract_workspaces_from_auth_cookie(auth_cookie)
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

    select_resp = session.post(
        "https://auth.openai.com/api/accounts/workspace/select",
        headers={
            "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            "content-type": "application/json",
        },
        json={"workspace_id": workspace_id},
    )
    if select_resp.status_code != 200:
        logger.warning(f"[线程 {thread_id}] [警告] 选择 workspace 失败，状态码: {select_resp.status_code}")
        return None

    continue_url = extract_continue_url_from_response(select_resp)
    if not continue_url:
        logger.warning(f"[线程 {thread_id}] [警告] workspace/select 响应里缺少 continue_url")
        return None

    logger.info(f"[线程 {thread_id}] [信息] 已获取 workspace，继续跟随授权跳转链")
    return follow_oauth_redirect_chain(session, continue_url, oauth, thread_id)


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
) -> Optional[str]:
    """使用账号密码重新登录以获取 token。"""
    account = str(email or "").strip()
    pwd = str(password or "").strip()
    if not account or not pwd:
        return None

    logger.info(f"[线程 {thread_id}] [信息] 当前 session 未拿到 token，尝试账号密码重新登录")
    login_session = requests.Session(proxies=proxies, impersonate=impersonate)
    ignored_codes = _normalize_code_values(used_codes)

    try:
        prime_oauth_session(
            login_session,
            oauth_authorize_url(oauth, prompt="login"),
            thread_id,
        )
        did = login_session.cookies.get("oai-did")
        sentinel_header = request_sentinel_header(
            did=did,
            proxies=proxies,
            impersonate=impersonate,
            thread_id=thread_id,
        )
        if not sentinel_header:
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
        if continue_resp.status_code not in (200, 204):
            logger.warning(
                f"[线程 {thread_id}] [警告] 账号密码登录预处理失败，状态码: {continue_resp.status_code}"
            )
            return None

        existing_message_ids = (
            get_mailbox_message_snapshot_fn(mailbox, thread_id, proxies) if mailbox else set()
        )
        login_resp = login_session.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers={
                "referer": "https://auth.openai.com/log-in/password",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=json.dumps(
                {"password": pwd},
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )
        if login_resp.status_code != 200:
            logger.warning(f"[线程 {thread_id}] [警告] 账号密码登录失败，状态码: {login_resp.status_code}")
            return None

        try:
            login_payload = login_resp.json() if login_resp.content else {}
        except Exception:
            login_payload = {}

        login_page = login_payload.get("page") or {}
        page_type = str(login_page.get("type") or "").strip()
        continue_url = extract_continue_url_from_response(login_resp)

        if page_type == "email_otp_verification":
            if not mailbox:
                logger.warning(
                    f"[线程 {thread_id}] [警告] 密码登录后需要邮箱验证码，但当前没有可用邮箱上下文"
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
                    return None

                login_otp_resp = post_email_otp_validate(
                    login_session,
                    code=login_code,
                    thread_id=thread_id,
                    stage_label="登录阶段",
                )
                if login_otp_resp and login_otp_resp.status_code == 200:
                    continue_url = extract_continue_url_from_response(login_otp_resp)
                    break

                status_code = getattr(login_otp_resp, "status_code", "unknown")
                if status_code not in RETRYABLE_GATEWAY_STATUSES:
                    ignored_codes.add(login_code)
                logger.warning(
                    f"[线程 {thread_id}] [警告] 登录阶段邮箱验证码校验失败，状态码: {status_code}"
                )
                if status_code == 401 and otp_attempt == 0:
                    logger.info(f"[线程 {thread_id}] [信息] 登录验证码可能命中旧邮件，准备重新等待新验证码")
                    time.sleep(2)
                    continue
                return None

            if not login_otp_resp or login_otp_resp.status_code != 200:
                return None

        auth_cookie = login_session.cookies.get("oai-client-auth-session")
        if auth_cookie:
            token_json = try_token_via_workspace_select(
                login_session, oauth, auth_cookie, thread_id
            )
            if token_json:
                return token_json

        if continue_url:
            token_json = follow_oauth_redirect_chain(
                login_session, continue_url, oauth, thread_id
            )
            if token_json:
                return token_json

        auth_cookie = login_session.cookies.get("oai-client-auth-session")
        if auth_cookie:
            token_json = try_token_via_workspace_select(
                login_session, oauth, auth_cookie, thread_id
            )
            if token_json:
                return token_json

        return try_token_via_existing_session(login_session, oauth, thread_id)
    except Exception as exc:
        logger.warning(f"[线程 {thread_id}] [警告] 账号密码登录兜底失败: {exc}")
        return None


# ---------------------------------------------------------------------------
# 内部辅助: 登录场景主动触发 email OTP
# ---------------------------------------------------------------------------


def _send_email_otp_for_login(session: Any, thread_id: int) -> bool:
    """主动触发登录场景的 email OTP，先尝试 POST 再尝试 GET。

    OpenAI 的 email-otp/send 接口在不同场景下接受不同的 HTTP 方法：
    - 注册阶段通常使用 GET（无 body）
    - 登录阶段可能接受 POST（带 intent=login）
    本函数同时兼容两种方式，确保触发成功。
    """
    otp_send_url = "https://auth.openai.com/api/accounts/email-otp/send"
    common_headers = {
        "referer": "https://auth.openai.com/log-in/password",
        "accept": "application/json",
    }

    # 尝试 1: POST + intent=login
    try:
        post_resp = session.post(
            otp_send_url,
            headers={
                **common_headers,
                "content-type": "application/json",
            },
            data=json.dumps(
                {"intent": "login"},
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )
        if post_resp.status_code in (200, 204):
            logger.info(
                f"[线程 {thread_id}] [信息] email-otp/send (POST) 成功"
            )
            return True
        logger.info(
            f"[线程 {thread_id}] [信息] email-otp/send (POST) 状态码: {post_resp.status_code}，"
            "尝试 GET 方式"
        )
    except Exception as exc:
        logger.info(
            f"[线程 {thread_id}] [信息] email-otp/send (POST) 异常: {exc}，尝试 GET 方式"
        )

    # 尝试 2: GET（与注册流程一致）
    try:
        get_resp = session.get(
            otp_send_url,
            headers=common_headers,
        )
        if get_resp.status_code in (200, 204):
            logger.info(
                f"[线程 {thread_id}] [信息] email-otp/send (GET) 成功"
            )
            return True
        logger.warning(
            f"[线程 {thread_id}] [警告] email-otp/send (GET) 也失败，"
            f"状态码: {get_resp.status_code}"
        )
    except Exception as exc:
        logger.warning(
            f"[线程 {thread_id}] [警告] email-otp/send (GET) 异常: {exc}"
        )

    return False


# ---------------------------------------------------------------------------
# 策略 5: Passwordless OTP 登录绕过 add_phone
# ---------------------------------------------------------------------------


def try_token_via_passwordless_login(
    *,
    email: str,
    mailbox: Optional[TempMailbox] = None,
    used_codes: Optional[Set[str]] = None,
    proxies: Any,
    impersonate: str,
    thread_id: int,
    get_oai_code_fn: Callable[..., str],
    get_mailbox_message_snapshot_fn: Callable[..., Set[str]],
) -> Optional[str]:
    """通过 passwordless OTP 方式重新登录以绕过 add_phone 页面。

    核心思路（参考社区方案）：
    1. 新开一个全新的 OAuth session 和全新的 PKCE 参数
    2. 用刚注册好的邮箱走 screen_hint=login 流程
    3. 不依赖密码页，直接触发一次 passwordless OTP
    4. 再收一遍新的验证码，校验后读取 continue_url
    5. 实际访问 continue_url，让服务端重新签发带 workspace 的 Cookie
    """
    account = str(email or "").strip()
    if not account:
        return None
    if not mailbox:
        logger.warning(
            f"[线程 {thread_id}] [警告] passwordless 登录需要邮箱上下文，但未提供"
        )
        return None

    logger.info(
        f"[线程 {thread_id}] [信息] 尝试 passwordless OTP 登录绕过 add_phone"
    )
    ignored_codes = _normalize_code_values(used_codes)

    # 全新 session + 全新 PKCE 参数
    pwless_session = requests.Session(proxies=proxies, impersonate=impersonate)
    pwless_oauth = generate_oauth_url()

    try:
        # Step 1: 初始化 OAuth session
        prime_oauth_session(
            pwless_session,
            oauth_authorize_url(pwless_oauth, prompt="login"),
            thread_id,
        )
        did = pwless_session.cookies.get("oai-did")
        sentinel_header = request_sentinel_header(
            did=did,
            proxies=proxies,
            impersonate=impersonate,
            thread_id=thread_id,
        )
        if not sentinel_header:
            logger.warning(
                f"[线程 {thread_id}] [警告] passwordless 登录获取 sentinel 失败"
            )
            return None

        # Step 2: 提交邮箱，使用 screen_hint=login 触发 passwordless OTP
        # 先记录当前已有的邮件消息 ID，以便后续只关注新邮件
        existing_message_ids = get_mailbox_message_snapshot_fn(
            mailbox, thread_id, proxies
        )

        continue_resp = pwless_session.post(
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
        if continue_resp.status_code not in (200, 204):
            logger.warning(
                f"[线程 {thread_id}] [警告] passwordless 登录 authorize/continue 失败，"
                f"状态码: {continue_resp.status_code}"
            )
            return None

        # 分析响应，判断页面类型
        try:
            continue_payload = continue_resp.json() if continue_resp.content else {}
        except Exception:
            continue_payload = {}

        page_info = continue_payload.get("page") or {}
        page_type = str(page_info.get("type") or "").strip()
        continue_url = extract_continue_url_from_response(continue_resp)

        logger.info(
            f"[线程 {thread_id}] [信息] passwordless 登录响应 page.type={page_type or 'empty'}"
        )

        # Step 3: 如果服务端不是直接返回 email_otp_verification，需要主动触发 OTP
        otp_needs_manual_send = page_type != "email_otp_verification"
        if otp_needs_manual_send:
            if page_type in ("login_password", "password"):
                logger.info(
                    f"[线程 {thread_id}] [信息] passwordless 登录跳到密码页，主动请求发送 OTP"
                )
            elif page_type:
                logger.info(
                    f"[线程 {thread_id}] [信息] passwordless 登录遇到非预期页面类型: {page_type}，"
                    "主动请求发送 OTP"
                )
            else:
                logger.info(
                    f"[线程 {thread_id}] [信息] passwordless 登录 page.type 为空，"
                    "主动请求发送 OTP"
                )
            otp_sent = _send_email_otp_for_login(pwless_session, thread_id)
            if not otp_sent and page_type in ("login_password", "password"):
                # 密码页场景下 OTP 发送失败则终止，其他页面类型仍尝试继续等邮件
                return None

        # Step 4: 等待并收取新的验证码
        logger.info(
            f"[线程 {thread_id}] [信息] passwordless 登录等待邮箱验证码"
        )
        pwless_otp_resp = None
        for otp_attempt in range(2):
            login_code = get_oai_code_fn(
                mailbox,
                thread_id,
                proxies,
                skip_message_ids=existing_message_ids,
                skip_codes=ignored_codes,
            )
            if not login_code:
                logger.warning(
                    f"[线程 {thread_id}] [警告] passwordless 登录未能获取邮箱验证码"
                )
                return None

            # Step 5: 校验验证码
            pwless_otp_resp = post_email_otp_validate(
                pwless_session,
                code=login_code,
                thread_id=thread_id,
                stage_label="passwordless 登录",
            )
            if pwless_otp_resp and pwless_otp_resp.status_code == 200:
                continue_url = extract_continue_url_from_response(pwless_otp_resp)
                logger.info(
                    f"[线程 {thread_id}] [信息] passwordless 登录验证码校验成功"
                )
                break

            status_code = getattr(pwless_otp_resp, "status_code", "unknown")
            if status_code not in RETRYABLE_GATEWAY_STATUSES:
                ignored_codes.add(login_code)
            logger.warning(
                f"[线程 {thread_id}] [警告] passwordless 登录验证码校验失败，"
                f"状态码: {status_code}"
            )
            if status_code == 401 and otp_attempt == 0:
                logger.info(
                    f"[线程 {thread_id}] [信息] passwordless 验证码可能命中旧邮件，准备重试"
                )
                time.sleep(2)
                continue
            return None

        if not pwless_otp_resp or pwless_otp_resp.status_code != 200:
            return None

        # Step 6: 尝试从 Cookie 中解析 workspace
        auth_cookie = pwless_session.cookies.get("oai-client-auth-session")
        if auth_cookie:
            token_json = try_token_via_workspace_select(
                pwless_session, pwless_oauth, auth_cookie, thread_id
            )
            if token_json:
                logger.info(
                    f"[线程 {thread_id}] [信息] passwordless 登录通过 workspace 成功获取 token"
                )
                return token_json

        # Step 7: 跟随 continue_url 拿到带 workspace 的 Cookie
        if continue_url:
            token_json = follow_oauth_redirect_chain(
                pwless_session, continue_url, pwless_oauth, thread_id
            )
            if token_json:
                logger.info(
                    f"[线程 {thread_id}] [信息] passwordless 登录通过 redirect chain 成功获取 token"
                )
                return token_json

        # Step 8: 再次检查 Cookie（redirect chain 可能刷新了 Cookie）
        auth_cookie = pwless_session.cookies.get("oai-client-auth-session")
        if auth_cookie:
            token_json = try_token_via_workspace_select(
                pwless_session, pwless_oauth, auth_cookie, thread_id
            )
            if token_json:
                logger.info(
                    f"[线程 {thread_id}] [信息] passwordless 登录二次 workspace 解析成功"
                )
                return token_json

        # Step 9: 兜底尝试 session 复用
        token_json = try_token_via_existing_session(
            pwless_session, pwless_oauth, thread_id
        )
        if token_json:
            logger.info(
                f"[线程 {thread_id}] [信息] passwordless 登录通过 session 复用获取 token"
            )
            return token_json

        logger.warning(
            f"[线程 {thread_id}] [警告] passwordless 登录未能提取到 token"
        )
        return None

    except Exception as exc:
        logger.warning(
            f"[线程 {thread_id}] [警告] passwordless 登录异常: {exc}"
        )
        return None
