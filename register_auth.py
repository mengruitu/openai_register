import base64
import hashlib
import json
import logging
import random
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence, Set

from curl_cffi import requests

from register_mailboxes import TempMailbox

logger = logging.getLogger("openai_register")

RETRYABLE_GATEWAY_STATUSES = {502, 503, 504}
EMAIL_OTP_VALIDATE_MAX_ATTEMPTS = 3
EMAIL_OTP_VALIDATE_RETRY_DELAY_SECONDS = 2
AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"
WEB_SIGNIN_REFERER = "https://chatgpt.com/auth/login"
WEB_SIGNUP_MAX_ATTEMPTS = 3
WEB_SIGNUP_RETRY_DELAY_SECONDS = 2
WEB_SIGNUP_REQUEST_TIMEOUT_SECONDS = 20
PRIME_OAUTH_MAX_REQUEST_ATTEMPTS = 3
PRIME_OAUTH_RETRY_DELAY_SECONDS = 2
PRIME_OAUTH_REQUEST_TIMEOUT_SECONDS = 20
CHATGPT_SESSION_URL = "https://chatgpt.com/api/auth/session"
SESSION_API_REQUEST_TIMEOUT_SECONDS = 15
DEFAULT_SESSION_FALLBACK_EXPIRES_IN_SECONDS = 1800
SENTINEL_FRAME_URL = (
    "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6"
)
SENTINEL_SDK_URL = "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js"
SENTINEL_DOCUMENT_KEYS = ("visibilityState", "readyState", "documentURI", "location")
SENTINEL_WINDOW_KEYS = ("location", "document", "navigator", "origin", "window")
SENTINEL_SCRIPT_SOURCES = (SENTINEL_SDK_URL, SENTINEL_FRAME_URL)
SENTINEL_POW_PREFIX = "gAAAAAB"
SENTINEL_POW_SUFFIX = "~S"
SENTINEL_POW_MAX_ATTEMPTS = 500000
SENTINEL_POW_TIMEOUT_SECONDS = 20
SENTINEL_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
)
SENTINEL_DEFAULT_JS_HEAP_SIZE_LIMIT = 4294705152
SENTINEL_DEFAULT_SCREEN_SUM = 3000
SENTINEL_DEFAULT_LANGUAGE = "en-US"
SENTINEL_DEFAULT_LANGUAGES = "en-US,en"
SENTINEL_DEFAULT_HARDWARE_CONCURRENCY = 8
SENTINEL_MINUS_SIGN = "\u2212"
SENTINEL_WEEKDAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
SENTINEL_MONTH_NAMES = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str
    scope: str


def _normalize_code_values(code_values: Optional[Set[str]] = None) -> Set[str]:
    if not code_values:
        return set()
    normalized: Set[str] = set()
    for item in code_values:
        value = str(item or "").strip()
        if value:
            normalized.add(value)
    return normalized


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    parsed = urllib.parse.urlparse(callback_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    def get1(k: str) -> str:
        vals = query.get(k) or fragment.get(k) or [""]
        return vals[0] if vals else ""

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


def extract_workspaces_from_auth_cookie(auth_cookie: str) -> List[Dict[str, Any]]:
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


def build_oauth_authorize_url(
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


def oauth_authorize_url(oauth: OAuthStart, *, prompt: Optional[str] = "login") -> str:
    return build_oauth_authorize_url(
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
    auth_url = build_oauth_authorize_url(
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


def bootstrap_web_signup_start_url(session: Any, thread_id: int) -> str:
    attempts = max(1, WEB_SIGNUP_MAX_ATTEMPTS)
    for attempt in range(1, attempts + 1):
        try:
            csrf_resp = session.get(
                "https://chatgpt.com/api/auth/csrf",
                headers={"referer": WEB_SIGNIN_REFERER, "accept": "application/json"},
                timeout=WEB_SIGNUP_REQUEST_TIMEOUT_SECONDS,
            )
            if csrf_resp.status_code != 200:
                logger.error(
                    f"[线程 {thread_id}] [错误] 获取 web signup csrf 失败，状态码: {csrf_resp.status_code}"
                )
                if attempt < attempts:
                    time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue

            csrf_token = str((csrf_resp.json() or {}).get("csrfToken") or "").strip()
            if not csrf_token:
                logger.error(f"[线程 {thread_id}] [错误] web signup csrfToken 为空")
                if attempt < attempts:
                    time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue

            ext_oai_did = str(uuid.uuid4())
            auth_session_logging_id = str(uuid.uuid4())
            query = urllib.parse.urlencode(
                {
                    "prompt": "login",
                    "screen_hint": "login_or_signup",
                    "ext-oai-did": ext_oai_did,
                    "auth_session_logging_id": auth_session_logging_id,
                }
            )
            signin_resp = session.post(
                f"https://chatgpt.com/api/auth/signin/openai?{query}",
                headers={
                    "referer": WEB_SIGNIN_REFERER,
                    "accept": "application/json",
                    "content-type": "application/x-www-form-urlencoded",
                },
                data=urllib.parse.urlencode(
                    {
                        "callbackUrl": "/",
                        "csrfToken": csrf_token,
                        "json": "true",
                    }
                ),
                timeout=WEB_SIGNUP_REQUEST_TIMEOUT_SECONDS,
            )
            if signin_resp.status_code != 200:
                logger.error(
                    f"[线程 {thread_id}] [错误] web signup signin/openai 失败，状态码: {signin_resp.status_code}"
                )
                if attempt < attempts:
                    time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue

            start_url = str((signin_resp.json() or {}).get("url") or "").strip()
            if not start_url:
                logger.error(f"[线程 {thread_id}] [错误] web signup 未返回授权地址")
                if attempt < attempts:
                    time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue

            logger.info(f"[线程 {thread_id}] [信息] 已获取 web signup 授权入口")
            return start_url
        except Exception as exc:
            if attempt < attempts:
                logger.warning(
                    f"[线程 {thread_id}] [警告] 获取 web signup 授权入口失败，第 {attempt}/{attempts} 次尝试异常: {exc}；"
                    f"{WEB_SIGNUP_RETRY_DELAY_SECONDS} 秒后重试"
                )
                time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue
            logger.error(f"[线程 {thread_id}] [错误] 获取 web signup 授权入口失败: {exc}")
            return ""

    return ""


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


def extract_continue_url_from_response(resp: Any) -> str:
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


def response_text_preview(resp: Any, limit: int = 240) -> str:
    text = str(getattr(resp, "text", "") or "").strip()
    if not text:
        return ""
    compact = re.sub(r"\s+", " ", text)
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _parse_json_object(raw_text: str) -> Dict[str, Any]:
    content = str(raw_text or "").strip()
    if not content:
        return {}

    candidates = [content]
    match = re.search(r"\{.*\}", content, re.S)
    if match:
        candidates.append(match.group(0))

    seen: Set[str] = set()
    for candidate in candidates:
        candidate = str(candidate or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            payload = json.loads(candidate)
        except Exception:
            continue
        if isinstance(payload, dict):
            return payload

    return {}


def _session_fallback_expired_at(payload: Dict[str, Any]) -> str:
    expires = str(payload.get("expires") or "").strip()
    if expires:
        return expires

    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() + DEFAULT_SESSION_FALLBACK_EXPIRES_IN_SECONDS),
    )


def try_token_via_session_api(session: Any, thread_id: int) -> Optional[str]:
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


def post_email_otp_validate(
    session: Any,
    *,
    code: str,
    thread_id: int,
    stage_label: str,
    max_attempts: int = EMAIL_OTP_VALIDATE_MAX_ATTEMPTS,
    retry_delay_seconds: int = EMAIL_OTP_VALIDATE_RETRY_DELAY_SECONDS,
) -> Optional[Any]:
    payload = json.dumps(
        {"code": str(code or "").strip()},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    attempts = max(1, max_attempts)
    delay_seconds = max(0, int(retry_delay_seconds))
    last_resp = None

    for attempt in range(1, attempts + 1):
        try:
            last_resp = session.post(
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers={
                    "referer": "https://auth.openai.com/email-verification",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=payload,
            )
        except Exception as exc:
            if attempt < attempts:
                logger.warning(
                    f"[线程 {thread_id}] [警告] {stage_label}邮箱验证码校验异常，"
                    f"第 {attempt}/{attempts} 次尝试失败: {exc}；"
                    f"{delay_seconds} 秒后重试"
                )
                time.sleep(delay_seconds)
                continue
            logger.error(f"[线程 {thread_id}] [错误] {stage_label}邮箱验证码校验异常: {exc}")
            return None

        status_code = getattr(last_resp, "status_code", 0)
        if status_code == 200:
            return last_resp

        if status_code in RETRYABLE_GATEWAY_STATUSES and attempt < attempts:
            preview = response_text_preview(last_resp)
            logger.warning(
                f"[线程 {thread_id}] [警告] {stage_label}邮箱验证码校验遇到网关波动，"
                f"状态码: {status_code}，第 {attempt}/{attempts} 次尝试；"
                f"{delay_seconds} 秒后重试。响应摘要: {preview}"
            )
            time.sleep(delay_seconds)
            continue

        return last_resp

    return last_resp


def follow_oauth_redirect_chain(
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
            next_url = extract_continue_url_from_response(resp)
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
        logger.warning(f"[线程 {thread_id}] [警告] 跟随 OAuth 跳转链失败: {exc}")

    return None


def prime_oauth_session(
    session: Any,
    start_url: str,
    thread_id: int,
    *,
    max_hops: int = 6,
) -> Any:
    current_url = str(start_url or "").strip()
    last_resp = None
    if not current_url:
        return None

    for _ in range(max_hops):
        last_exc = None
        for attempt in range(1, PRIME_OAUTH_MAX_REQUEST_ATTEMPTS + 1):
            try:
                last_resp = session.get(
                    current_url,
                    timeout=PRIME_OAUTH_REQUEST_TIMEOUT_SECONDS,
                    allow_redirects=False,
                )
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                if attempt < PRIME_OAUTH_MAX_REQUEST_ATTEMPTS:
                    logger.warning(
                        f"[线程 {thread_id}] [警告] OAuth 初始化请求失败，第 {attempt}/{PRIME_OAUTH_MAX_REQUEST_ATTEMPTS} 次重试: {exc}"
                    )
                    time.sleep(PRIME_OAUTH_RETRY_DELAY_SECONDS)
        if last_exc is not None:
            raise last_exc

        next_url = extract_continue_url_from_response(last_resp)
        if not next_url:
            return last_resp

        parsed = urllib.parse.urlparse(next_url)
        if (
            parsed.scheme == "http"
            and parsed.hostname in ("localhost", "127.0.0.1")
            and "/auth/callback" in parsed.path
        ):
            logger.info(
                f"[线程 {thread_id}] [信息] OAuth 初始化已到达本地 callback 边界，停止继续自动跳转"
            )
            return last_resp

        current_url = next_url

    return last_resp


def _sentinel_js_now_string() -> str:
    now = datetime.now().astimezone()
    offset = now.strftime("%z")
    if len(offset) == 5:
        offset = f"{offset[:3]}:{offset[3:]}"
    return (
        f"{SENTINEL_WEEKDAY_NAMES[now.weekday()]} "
        f"{SENTINEL_MONTH_NAMES[now.month - 1]} "
        f"{now.day:02d} {now.year:04d} "
        f"{now.hour:02d}:{now.minute:02d}:{now.second:02d} "
        f"GMT{offset or '+00:00'}"
    )


def _sentinel_b64_json(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _sentinel_hash_hex(value: str) -> str:
    hashed = 2166136261
    for ch in str(value or ""):
        hashed ^= ord(ch)
        hashed = (hashed * 16777619) & 0xFFFFFFFF
    hashed ^= hashed >> 16
    hashed = (hashed * 2246822507) & 0xFFFFFFFF
    hashed ^= hashed >> 13
    hashed = (hashed * 3266489909) & 0xFFFFFFFF
    hashed ^= hashed >> 16
    return f"{hashed & 0xFFFFFFFF:08x}"


def _sentinel_query_keys_signature() -> str:
    return ",".join(
        urllib.parse.parse_qs(
            urllib.parse.urlparse(SENTINEL_FRAME_URL).query,
            keep_blank_values=True,
        ).keys()
    )


def _sentinel_random_choice(values: Sequence[str], default: str = "") -> str:
    if not values:
        return default
    return random.choice(values)


def _build_sentinel_pow_fingerprint() -> List[Any]:
    navigator_values = {
        "vendor": "Google Inc.",
        "platform": "Win32",
        "languages": SENTINEL_DEFAULT_LANGUAGES,
        "language": SENTINEL_DEFAULT_LANGUAGE,
        "userAgent": SENTINEL_DEFAULT_USER_AGENT,
        "hardwareConcurrency": str(SENTINEL_DEFAULT_HARDWARE_CONCURRENCY),
    }
    nav_key = _sentinel_random_choice(tuple(navigator_values.keys()), "userAgent")
    perf_now_ms = time.perf_counter() * 1000
    time_origin_ms = int(time.time() * 1000 - perf_now_ms)
    return [
        SENTINEL_DEFAULT_SCREEN_SUM,
        _sentinel_js_now_string(),
        SENTINEL_DEFAULT_JS_HEAP_SIZE_LIMIT,
        random.random(),
        SENTINEL_DEFAULT_USER_AGENT,
        _sentinel_random_choice(SENTINEL_SCRIPT_SOURCES, SENTINEL_SDK_URL),
        _sentinel_random_choice(SENTINEL_SCRIPT_SOURCES, SENTINEL_SDK_URL),
        SENTINEL_DEFAULT_LANGUAGE,
        SENTINEL_DEFAULT_LANGUAGES,
        random.random(),
        (
            f"{nav_key}{SENTINEL_MINUS_SIGN}"
            f"{navigator_values.get(nav_key, SENTINEL_DEFAULT_USER_AGENT)}"
        ),
        _sentinel_random_choice(SENTINEL_DOCUMENT_KEYS, "visibilityState"),
        _sentinel_random_choice(SENTINEL_WINDOW_KEYS, "location"),
        perf_now_ms,
        str(uuid.uuid4()),
        _sentinel_query_keys_signature(),
        SENTINEL_DEFAULT_HARDWARE_CONCURRENCY,
        time_origin_ms,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]


def solve_sentinel_pow(*, seed: str, difficulty: str, thread_id: int) -> str:
    seed_text = str(seed or "").strip()
    target = str(difficulty or "").strip().lower()
    if not seed_text or not target:
        return ""

    perf_counter = time.perf_counter
    hash_hex = _sentinel_hash_hex
    encode_candidate = _sentinel_b64_json
    started_at = perf_counter()
    candidate = _build_sentinel_pow_fingerprint()
    prefix_len = len(target)
    timeout = SENTINEL_POW_TIMEOUT_SECONDS

    for attempt in range(SENTINEL_POW_MAX_ATTEMPTS):
        elapsed = perf_counter() - started_at
        if elapsed >= timeout:
            elapsed_ms = round(elapsed * 1000)
            logger.error(
                f"[线程 {thread_id}] [错误] Sentinel POW 求解超时（{timeout}秒），难度={target}，"
                f"已尝试 {attempt + 1} 次，耗时 {elapsed_ms} ms"
            )
            return ""

        candidate[3] = attempt
        candidate[9] = round((perf_counter() - started_at) * 1000)
        encoded = encode_candidate(candidate)
        if hash_hex(seed_text + encoded)[:prefix_len] <= target:
            elapsed_ms = round((perf_counter() - started_at) * 1000)
            logger.info(
                f"[线程 {thread_id}] [信息] Sentinel POW 求解成功，难度={target}，"
                f"尝试 {attempt + 1} 次，耗时 {elapsed_ms} ms"
            )
            return f"{SENTINEL_POW_PREFIX}{encoded}{SENTINEL_POW_SUFFIX}"

    elapsed_ms = round((perf_counter() - started_at) * 1000)
    logger.error(
        f"[线程 {thread_id}] [错误] Sentinel POW 求解失败，难度={target}，"
        f"已尝试 {SENTINEL_POW_MAX_ATTEMPTS} 次，耗时 {elapsed_ms} ms"
    )
    return ""


def request_sentinel_header(
    *,
    did: str,
    proxies: Any,
    impersonate: str,
    thread_id: int,
    flow: str = "authorize_continue",
) -> str:
    device_id = str(did or "").strip()
    if not device_id:
        logger.error(f"[线程 {thread_id}] [错误] 无法获取 Device ID，Sentinel 请求已跳过")
        return ""

    flow_name = str(flow or "authorize_continue").strip() or "authorize_continue"

    body = json.dumps(
        {"p": "", "id": device_id, "flow": flow_name},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    resp = requests.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        headers={
            "origin": "https://sentinel.openai.com",
            "referer": SENTINEL_FRAME_URL,
            "content-type": "text/plain;charset=UTF-8",
        },
        data=body,
        proxies=proxies,
        impersonate=impersonate,
        timeout=15,
    )
    if resp.status_code != 200:
        logger.error(f"[线程 {thread_id}] [错误] Sentinel 请求失败，状态码: {resp.status_code}")
        return ""

    try:
        sentinel_payload = resp.json() if resp.content else {}
    except Exception as exc:
        logger.error(f"[线程 {thread_id}] [错误] Sentinel 响应解析失败: {exc}")
        return ""

    token = str((sentinel_payload or {}).get("token") or "").strip()
    if not token:
        logger.error(f"[线程 {thread_id}] [错误] Sentinel 响应里缺少 token")
        return ""

    proof = ""
    pow_config = (
        sentinel_payload.get("proofofwork")
        if isinstance(sentinel_payload, dict)
        else {}
    )
    if isinstance(pow_config, dict) and pow_config.get("required"):
        difficulty = str(pow_config.get("difficulty") or "").strip().lower()
        logger.info(
            f"[线程 {thread_id}] [信息] Sentinel 要求 POW，开始求解，难度={difficulty or 'unknown'}"
        )
        proof = solve_sentinel_pow(
            seed=str(pow_config.get("seed") or ""),
            difficulty=difficulty,
            thread_id=thread_id,
        )
        if not proof:
            return ""

    return json.dumps(
        {
            "p": proof,
            "t": "",
            "c": token,
            "id": device_id,
            "flow": flow_name,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def try_token_via_existing_session(
    session: Any,
    oauth: OAuthStart,
    thread_id: int,
) -> Optional[str]:
    logger.info(f"[线程 {thread_id}] [信息] 尝试复用当前 session 免密获取 token")
    return follow_oauth_redirect_chain(
        session,
        oauth_authorize_url(oauth, prompt=None),
        oauth,
        thread_id,
    )


def try_token_via_workspace_select(
    session: Any,
    oauth: OAuthStart,
    auth_cookie: str,
    thread_id: int,
) -> Optional[str]:
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
