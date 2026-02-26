"""
SyntaAI MCP Server - OAuth 2.0 Authorization Server Provider

Implements OAuthAuthorizationServerProvider from the MCP Python SDK.
Acts as both auth server and resource server (standalone).

Supports:
- Dynamic Client Registration (RFC 7591)
- Authorization Code + PKCE (RFC 7636)
- Token refresh & revocation
- Discovery endpoints (RFC 8414, RFC 9728) - handled by SDK

Storage: In-memory with JSON file persistence for restarts.
"""

import json
import os
import secrets
import time
import logging
from pathlib import Path
from typing import Any

from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

logger = logging.getLogger("syntaai.oauth")

# --- Persistence helpers ---
DATA_DIR = Path(os.getenv("SYNTAAI_DATA_DIR", "/opt/mcp-server/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

CLIENTS_FILE = DATA_DIR / "oauth_clients.json"
TOKENS_FILE = DATA_DIR / "oauth_tokens.json"


def _load_json(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return {}
    return {}


def _save_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2, default=str))


# --- Pre-configured test accounts for Anthropic review ---
TEST_USERS = {
    "mcp-review@anthropic.com": {
        "password": os.getenv("REVIEW_PASSWORD", "SyntaAI-MCP-Review-2026!"),
        "name": "Anthropic MCP Review",
        "role": "reviewer",
    },
    "demo@syntaai.com": {
        "password": os.getenv("DEMO_PASSWORD", "SyntaAI-Demo-2026!"),
        "name": "SyntaAI Demo User",
        "role": "admin",
    },
}


class SyntaAIOAuthProvider(OAuthAuthorizationServerProvider):
    """
    In-memory OAuth 2.0 Authorization Server for SyntaAI MCP.
    """

    def __init__(self):
        self.clients: dict[str, dict] = {}
        self.auth_codes: dict[str, dict] = {}
        self.access_tokens: dict[str, dict] = {}
        self.refresh_tokens: dict[str, dict] = {}
        self._load_persisted_data()
        logger.info("OAuth provider initialized (%d clients)", len(self.clients))

    def _load_persisted_data(self):
        for cid, cdata in _load_json(CLIENTS_FILE).items():
            self.clients[cid] = cdata
        for tk, td in _load_json(TOKENS_FILE).items():
            if td.get("type") == "access":
                self.access_tokens[tk] = td
            elif td.get("type") == "refresh":
                self.refresh_tokens[tk] = td

    def _persist_clients(self):
        try:
            _save_json(CLIENTS_FILE, self.clients)
        except Exception as e:
            logger.warning("Failed to persist clients: %s", e)

    def _persist_tokens(self):
        try:
            all_tokens = {}
            for k, v in self.access_tokens.items():
                all_tokens[k] = {**v, "type": "access"}
            for k, v in self.refresh_tokens.items():
                all_tokens[k] = {**v, "type": "refresh"}
            _save_json(TOKENS_FILE, all_tokens)
        except Exception as e:
            logger.warning("Failed to persist tokens: %s", e)

    # --- Client Registration (RFC 7591) ---
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        client_data = self.clients.get(client_id)
        if client_data is None:
            return None
        try:
            return OAuthClientInformationFull(**client_data)
        except Exception as e:
            logger.error("Failed to deserialize client %s: %s", client_id, e)
            return None

    async def register_client(
        self, client_info: OAuthClientInformationFull
    ) -> OAuthClientInformationFull:
        client_id = f"syntaai_{secrets.token_hex(16)}"
        client_secret = secrets.token_hex(32)
        now = int(time.time())

        client_data = client_info.model_dump()
        client_data.update({
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": now,
            "client_secret_expires_at": 0,
        })
        if not client_data.get("grant_types"):
            client_data["grant_types"] = ["authorization_code", "refresh_token"]
        if not client_data.get("response_types"):
            client_data["response_types"] = ["code"]
        if not client_data.get("token_endpoint_auth_method"):
            client_data["token_endpoint_auth_method"] = "client_secret_post"

        self.clients[client_id] = client_data
        self._persist_clients()
        logger.info("Registered client: %s (%s)", client_id, client_data.get("client_name", "?"))
        return OAuthClientInformationFull(**client_data)

    # --- Authorization Endpoint ---
    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
        request: Request,
    ) -> Response:
        if request.method == "POST":
            form = await request.form()
            email = str(form.get("email", "")).strip()
            password = str(form.get("password", "")).strip()

            user = TEST_USERS.get(email)
            if user and user["password"] == password:
                code = secrets.token_hex(32)
                self.auth_codes[code] = {
                    "client_id": client.client_id,
                    "redirect_uri": str(params.redirect_uri) if params.redirect_uri else None,
                    "code_challenge": params.code_challenge,
                    "scopes": params.scopes or [],
                    "state": params.state,
                    "user_email": email,
                    "user_name": user["name"],
                    "user_role": user["role"],
                    "created_at": time.time(),
                    "expires_at": time.time() + 600,
                    "redirect_uri_provided_explicitly": str(params.redirect_uri) if params.redirect_uri else None,
                }
                logger.info("Auth code issued for %s -> client %s", email, client.client_id)

                redirect_url = str(params.redirect_uri)
                sep = "&" if "?" in redirect_url else "?"
                redirect_url += f"{sep}code={code}"
                if params.state:
                    redirect_url += f"&state={params.state}"
                return RedirectResponse(url=redirect_url, status_code=302)
            else:
                return HTMLResponse(
                    self._login_page(
                        client_name=client.client_name or "MCP Client",
                        scopes=params.scopes or [],
                        error="Invalid email or password.",
                    ),
                    status_code=200,
                )

        return HTMLResponse(
            self._login_page(
                client_name=client.client_name or "MCP Client",
                scopes=params.scopes or [],
            ),
            status_code=200,
        )

    def _login_page(self, client_name: str, scopes: list[str], error: str = "") -> str:
        scope_html = ""
        if scopes:
            items = "".join(
                f'<li style="margin:4px 0;padding:4px 8px;background:#f0f4ff;border-radius:4px;font-size:14px;">{s}</li>'
                for s in scopes
            )
            scope_html = f'''
            <div style="margin:16px 0;">
                <p style="font-size:14px;color:#555;margin-bottom:8px;">
                    <strong>{client_name}</strong> requests access to:
                </p>
                <ul style="list-style:none;padding:0;">{items}</ul>
            </div>'''

        error_html = ""
        if error:
            error_html = f'''
            <div style="background:#fee;border:1px solid #fcc;border-radius:8px;
                        padding:12px;margin-bottom:16px;color:#c33;font-size:14px;">
                {error}
            </div>'''

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SyntaAI - Sign In</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:linear-gradient(135deg,#0a1628,#1a365d,#2d4a7a);min-height:100vh;
display:flex;align-items:center;justify-content:center}}
.card{{background:#fff;border-radius:16px;padding:40px;width:100%;max-width:420px;
box-shadow:0 20px 60px rgba(0,0,0,.3)}}
.logo{{text-align:center;margin-bottom:24px}}
.logo h1{{font-size:28px;color:#1a365d;margin-bottom:4px}}
.logo p{{font-size:14px;color:#718096}}
.fg{{margin-bottom:16px}}
label{{display:block;font-size:14px;font-weight:600;color:#374151;margin-bottom:6px}}
input{{width:100%;padding:12px 16px;border:2px solid #e2e8f0;border-radius:8px;font-size:16px}}
input:focus{{outline:none;border-color:#3b82f6}}
button{{width:100%;padding:14px;background:linear-gradient(135deg,#1a365d,#2563eb);
color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer}}
button:hover{{opacity:.9}}
.hint{{margin-top:16px;padding:12px;background:#f0fdf4;border:1px solid #bbf7d0;
border-radius:8px;font-size:12px;color:#166534}}
.foot{{text-align:center;margin-top:20px;font-size:12px;color:#9ca3af}}
</style>
</head>
<body>
<div class="card">
  <div class="logo"><h1>SyntaAI</h1><p>ERP Security Platform</p></div>
  {error_html}
  <p style="font-size:14px;color:#555;margin-bottom:20px;text-align:center">
    Sign in to authorize <strong>{client_name}</strong>
  </p>
  {scope_html}
  <form method="POST">
    <div class="fg"><label for="email">Email</label>
      <input type="email" id="email" name="email" placeholder="you@company.com" required autofocus></div>
    <div class="fg"><label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="••••••••" required></div>
    <button type="submit">Authorize &amp; Continue</button>
  </form>
  <div class="hint">
    <strong>Demo Access:</strong><br>
    Email: <code>demo@syntaai.com</code><br>
    Password: <code>SyntaAI-Demo-2026!</code>
  </div>
  <div class="foot">
    By signing in you agree to SyntaAI's
    <a href="https://mcp.syntaai.com/terms" style="color:#3b82f6">Terms</a> &amp;
    <a href="https://mcp.syntaai.com/privacy" style="color:#3b82f6">Privacy Policy</a>.
  </div>
</div>
</body></html>'''

    # --- Token Exchange ---
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code_data = self.auth_codes.get(authorization_code)
        if not code_data:
            return None
        if time.time() > code_data.get("expires_at", 0):
            del self.auth_codes[authorization_code]
            return None
        if code_data["client_id"] != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            client_id=client.client_id,
            redirect_uri=code_data.get("redirect_uri_provided_explicitly"),
            redirect_uri_provided_explicitly=code_data.get("redirect_uri_provided_explicitly") is not None,
            code_challenge=code_data.get("code_challenge", ""),
            scopes=code_data.get("scopes", []),
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        code_data = self.auth_codes.pop(authorization_code.code, {})
        access_token = f"syntaai_at_{secrets.token_hex(32)}"
        refresh_token = f"syntaai_rt_{secrets.token_hex(32)}"
        expires_in = 3600
        now = time.time()

        self.access_tokens[access_token] = {
            "client_id": client.client_id,
            "user_email": code_data.get("user_email", "unknown"),
            "user_name": code_data.get("user_name", "Unknown"),
            "user_role": code_data.get("user_role", "viewer"),
            "scopes": authorization_code.scopes,
            "created_at": now,
            "expires_at": now + expires_in,
        }
        self.refresh_tokens[refresh_token] = {
            "client_id": client.client_id,
            "user_email": code_data.get("user_email", "unknown"),
            "user_name": code_data.get("user_name", "Unknown"),
            "user_role": code_data.get("user_role", "viewer"),
            "scopes": authorization_code.scopes,
            "created_at": now,
            "expires_at": now + 86400 * 30,
        }
        self._persist_tokens()
        logger.info("Tokens issued for %s", code_data.get("user_email"))
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=refresh_token,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
        )

    # --- Refresh Token ---
    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        rt = self.refresh_tokens.get(refresh_token)
        if not rt:
            return None
        if time.time() > rt.get("expires_at", 0):
            del self.refresh_tokens[refresh_token]
            self._persist_tokens()
            return None
        if rt["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=rt.get("scopes", []),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        rt_data = self.refresh_tokens.pop(refresh_token.token, {})
        new_at = f"syntaai_at_{secrets.token_hex(32)}"
        new_rt = f"syntaai_rt_{secrets.token_hex(32)}"
        expires_in = 3600
        now = time.time()
        eff_scopes = scopes if scopes else rt_data.get("scopes", [])

        self.access_tokens[new_at] = {
            "client_id": client.client_id,
            "user_email": rt_data.get("user_email", "unknown"),
            "user_name": rt_data.get("user_name", "Unknown"),
            "user_role": rt_data.get("user_role", "viewer"),
            "scopes": eff_scopes,
            "created_at": now,
            "expires_at": now + expires_in,
        }
        self.refresh_tokens[new_rt] = {
            "client_id": client.client_id,
            "user_email": rt_data.get("user_email", "unknown"),
            "user_name": rt_data.get("user_name", "Unknown"),
            "user_role": rt_data.get("user_role", "viewer"),
            "scopes": eff_scopes,
            "created_at": now,
            "expires_at": now + 86400 * 30,
        }
        self._persist_tokens()
        logger.info("Tokens refreshed for %s", rt_data.get("user_email"))
        return OAuthToken(
            access_token=new_at,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=new_rt,
            scope=" ".join(eff_scopes) if eff_scopes else None,
        )

    # --- Token Verification ---
    async def verify_access_token(self, token: str) -> dict[str, Any] | None:
        td = self.access_tokens.get(token)
        if not td:
            return None
        if time.time() > td.get("expires_at", 0):
            del self.access_tokens[token]
            self._persist_tokens()
            return None
        return {
            "sub": td["user_email"],
            "name": td["user_name"],
            "role": td["user_role"],
            "scopes": td.get("scopes", []),
            "client_id": td["client_id"],
        }

    # --- Token Revocation (RFC 7009) ---
    async def revoke_token(
        self,
        client: OAuthClientInformationFull,
        token: str,
        token_type_hint: str | None = None,
    ) -> None:
        revoked = False
        if token in self.access_tokens and self.access_tokens[token]["client_id"] == client.client_id:
            del self.access_tokens[token]
            revoked = True
        if token in self.refresh_tokens and self.refresh_tokens[token]["client_id"] == client.client_id:
            del self.refresh_tokens[token]
            revoked = True
        if revoked:
            self._persist_tokens()
            logger.info("Token revoked for client %s", client.client_id)
