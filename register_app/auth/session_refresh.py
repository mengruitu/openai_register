"""Refresh helpers for session-token / oauth refresh-token."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from typing import Dict, Optional

from curl_cffi import requests

logger = logging.getLogger("openai_register")

OPENAI_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
OPENAI_SEC_CH_UA = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
OPENAI_SEC_CH_UA_MOBILE = "?0"
OPENAI_SEC_CH_UA_PLATFORM = '"Windows"'
OPENAI_IMPERSONATE = "chrome120"
SESSION_URL = "https://chatgpt.com/api/auth/session"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
REDIRECT_URI = "http://localhost:1455/auth/callback"


@dataclass
class TokenRefreshResult:
    success: bool
    access_token: str = ""
    refresh_token: str = ""
    account_id: str = ""
    email: str = ""
    session_token: str = ""
    expires_at: Optional[datetime] = None
    error_message: str = ""


class TokenRefreshManager:
    def __init__(self, proxy_url: str | None = None) -> None:
        self.proxy_url = str(proxy_url or "").strip()

    def _proxies(self) -> Optional[Dict[str, str]]:
        if not self.proxy_url:
            return None
        return {"http": self.proxy_url, "https": self.proxy_url}

    @property
    def _default_headers(self) -> Dict[str, str]:
        return {
            "user-agent": OPENAI_USER_AGENT,
            "accept-language": "en-US,en;q=0.9",
            "sec-ch-ua": OPENAI_SEC_CH_UA,
            "sec-ch-ua-mobile": OPENAI_SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": OPENAI_SEC_CH_UA_PLATFORM,
        }

    def refresh_by_session_token(self, session_token: str) -> TokenRefreshResult:
        token = str(session_token or "").strip()
        if not token:
            return TokenRefreshResult(success=False, error_message="session_token 为空")

        result = TokenRefreshResult(success=False, session_token=token)
        try:
            session = requests.Session(
                proxies=self._proxies(),
                impersonate=OPENAI_IMPERSONATE,
            )
            session.cookies.set(
                "__Secure-next-auth.session-token",
                token,
                domain=".chatgpt.com",
                path="/",
            )
            resp = session.get(
                SESSION_URL,
                headers={**self._default_headers, "accept": "application/json"},
                timeout=30,
            )
            if resp.status_code != 200:
                result.error_message = f"session token refresh failed: HTTP {resp.status_code}"
                return result
            data = resp.json() if resp.content else {}
            access_token = str(data.get("accessToken") or "").strip()
            if not access_token:
                result.error_message = "session token refresh failed: missing accessToken"
                return result

            expires_at = None
            expires_str = str(data.get("expires") or "").strip()
            if expires_str:
                try:
                    expires_at = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
                except ValueError:
                    expires_at = None

            user = data.get("user") or {}
            account = data.get("account") or {}
            result.success = True
            result.access_token = access_token
            result.account_id = str(
                data.get("account_id")
                or (account.get("id") if isinstance(account, dict) else "")
                or (user.get("id") if isinstance(user, dict) else "")
                or ""
            ).strip()
            result.email = str(
                (user.get("email") if isinstance(user, dict) else "")
                or data.get("email")
                or ""
            ).strip()
            result.expires_at = expires_at
            return result
        except Exception as exc:
            result.error_message = f"session token refresh exception: {exc}"
            logger.warning(result.error_message)
            return result

    def refresh_by_oauth_token(self, refresh_token: str, *, client_id: str | None = None) -> TokenRefreshResult:
        token = str(refresh_token or "").strip()
        if not token:
            return TokenRefreshResult(success=False, error_message="refresh_token 为空")

        result = TokenRefreshResult(success=False, refresh_token=token)
        try:
            resp = requests.post(
                TOKEN_URL,
                headers={
                    **self._default_headers,
                    "content-type": "application/x-www-form-urlencoded",
                    "accept": "application/json",
                },
                data={
                    "client_id": str(client_id or CLIENT_ID).strip() or CLIENT_ID,
                    "grant_type": "refresh_token",
                    "refresh_token": token,
                    "redirect_uri": REDIRECT_URI,
                },
                proxies=self._proxies(),
                impersonate=OPENAI_IMPERSONATE,
                timeout=30,
            )
            if resp.status_code != 200:
                result.error_message = f"oauth token refresh failed: HTTP {resp.status_code}"
                return result
            data = resp.json() if resp.content else {}
            access_token = str(data.get("access_token") or "").strip()
            if not access_token:
                result.error_message = "oauth token refresh failed: missing access_token"
                return result
            expires_in = 0
            try:
                expires_in = int(float(data.get("expires_in") or 0))
            except Exception:
                expires_in = 0
            result.success = True
            result.access_token = access_token
            result.refresh_token = str(data.get("refresh_token") or token).strip()
            result.expires_at = datetime.utcnow() + timedelta(seconds=max(expires_in, 0))
            return result
        except Exception as exc:
            result.error_message = f"oauth token refresh exception: {exc}"
            logger.warning(result.error_message)
            return result
