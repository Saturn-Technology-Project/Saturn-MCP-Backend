from __future__ import annotations

import json
import secrets
from html import escape
from pathlib import Path
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.enums import ActorType
from app.core.http_security import allow_form_redirect, current_csp_nonce
from app.core.public_origin import public_origin
from app.core.rate_limit import registration_allowed
from app.features.execution.activity.services.audit_service import audit_service
from app.features.identity.auth.controllers.deps import SessionDep
from app.features.identity.auth.controllers.session_cookie import cookie_secure
from app.features.identity.auth.services.auth_service import OAUTH_SESSION_TTL, auth_service
from app.features.identity.auth.services.mailer import console_origin, is_english, normalize_locale, send_login_code
from app.features.identity.auth.services.mfa import mfa_service
from app.features.identity.auth.services.passkeys import passkey_service
from app.features.identity.oauth.services.oauth_service import (
    ACCESS_TTL,
    REFRESH_TTL,
    SCOPE,
    challenge_valid,
    oauth_service,
    redirect_allowed,
)
from app.features.organization.org.services.plans import profile_identity, suspended
from app.models import Agent, Policy, ToolSet, ToolSetItem

router = APIRouter(tags=["oauth"])
COOKIE = "saturn_oauth"
_ARGON2 = Path(__file__).resolve().parents[1] / "static" / "argon2.umd.min.js"
_ARGON2_BYTES: bytes | None = None
_SESSION_PURPOSE = "oauth"
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def origin_of(request: Request) -> str:
    return public_origin(request)


def _request_ok(fields: dict[str, str]) -> bool:
    return (
        fields["response_type"] == "code"
        and fields["code_challenge_method"] == "S256"
        and challenge_valid(fields["code_challenge"])
    )


def metadata(origin: str) -> dict:
    return {
        "issuer": origin,
        "authorization_endpoint": f"{origin}/oauth/authorize",
        "token_endpoint": f"{origin}/oauth/token",
        "registration_endpoint": f"{origin}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [SCOPE],
    }


def protected_resource(origin: str) -> dict:
    return {
        "resource": f"{origin}/mcp",
        "authorization_servers": [origin],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [SCOPE],
    }


# One submit per form. iOS submits a one-time-code field when it autofills it, and a tap on the
# button then sends a second request; the first one's redirect is dropped and the second fails
# because its challenge or consent session is already used. Captured first, so a form's own
# submit handler never runs for the repeat. Back/forward cache restores reset it.
_ONE_SUBMIT = (
    "document.addEventListener('submit',function(e){var f=e.target;"
    "if(f.dataset.busy==='1'){e.preventDefault();e.stopImmediatePropagation();return;}"
    "f.dataset.busy='1';},true);"
    "window.addEventListener('pageshow',function(e){if(e.persisted){"
    "document.querySelectorAll('form').forEach(function(f){f.dataset.busy='0';});}});"
)


def _page(title: str, body: str, status_code: int = 200, *, wide: bool = False, lang: str = "zh-Hant") -> HTMLResponse:
    from app.core.http_security import current_csp_nonce

    width = "520px" if wide else "420px"
    nonce = escape(current_csp_nonce())
    style_open = f'<style nonce="{nonce}">' if nonce else "<style>"
    html = f"""<!doctype html>
<html lang="{escape(lang)}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  {style_open}
    body {{ margin: 0; background: #f7f7f5; color: #111110; font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; }}
    main {{ max-width: {width}; margin: 48px auto; padding: 0 20px 48px; }}
    h1 {{ margin: 8px 0 0; font-size: 22px; font-weight: 600; letter-spacing: -0.02em; }}
    h2 {{ margin: 22px 0 0; font-size: 11px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: #8a8a84; }}
    p {{ color: #5c5c57; }}
    .kicker {{ margin: 0; font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; color: #8a8a84; }}
    .card {{ margin-top: 8px; padding: 12px 14px; border: 1px solid #e6e6e1; border-radius: 10px; background: #fff; }}
    .card strong {{ display: block; color: #111110; font-size: 14px; }}
    .card p, .note {{ margin: 4px 0 0; }}
    label {{ display: block; margin-top: 14px; font-size: 12px; color: #5c5c57; }}
    input {{ width: 100%; box-sizing: border-box; margin-top: 6px; height: 36px; border: 1px solid #e6e6e1; border-radius: 8px; background: #fff; padding: 0 10px; }}
    .legal {{ margin-top: 22px; font-size: 12px; line-height: 1.6; }}
    .legal a {{ color: #111110; }}
    .row {{ display: flex; gap: 8px; margin-top: 18px; }}
    .row button {{ flex: 1; }}
    button {{ height: 36px; border: 0; border-radius: 8px; padding: 0 14px; background: #171716; color: #f7f7f5; cursor: pointer; }}
    button.secondary {{ background: #efefe9; color: #111110; }}
    a.button {{ flex: 1; display: block; box-sizing: border-box; height: 36px; line-height: 36px; border-radius: 8px; padding: 0 14px; background: #171716; color: #f7f7f5; text-align: center; text-decoration: none; }}
    a.button.secondary {{ background: #efefe9; color: #111110; }}
    code {{ display: block; margin-top: 8px; padding: 8px 10px; border: 1px solid #e6e6e1; border-radius: 8px; background: #fff; word-break: break-all; color: #111110; }}
  </style>
</head>
<body><main>{body}</main>
<script nonce="{nonce}">{_ONE_SUBMIT}</script></body>
</html>"""
    # Sign-in and consent pages carry per-request tokens and must not be kept by a cache or
    # shown again from the browser's back button after sign-out.
    return HTMLResponse(html, status_code=status_code, headers={"Cache-Control": "no-store"})


def _hidden(fields: dict[str, str]) -> str:
    return "".join(
        f'<input type="hidden" name="{escape(key)}" value="{escape(value)}">'
        for key, value in fields.items()
        if value
    )


async def _posted(request: Request) -> dict[str, str]:
    raw = (await request.body()).decode("utf-8", errors="replace")
    return dict(parse_qsl(raw, keep_blank_values=True))


def _fields(request: Request) -> dict[str, str]:
    source = request.query_params
    return {
        "client_id": source.get("client_id", ""),
        "redirect_uri": source.get("redirect_uri", ""),
        "state": source.get("state", ""),
        "code_challenge": source.get("code_challenge", ""),
        "code_challenge_method": source.get("code_challenge_method", ""),
        "response_type": source.get("response_type", ""),
    }


def _cookie_parts(request: Request) -> tuple[str, str]:
    raw = request.cookies.get(COOKIE, "")
    token, _, csrf = raw.partition(".")
    return token, csrf


def _set_cookie(response: Response, request: Request, token: str, csrf: str) -> None:
    response.set_cookie(
        COOKIE,
        f"{token}.{csrf}",
        httponly=True,
        samesite="lax",
        max_age=3600,
        path="/oauth",
        secure=cookie_secure(request),
    )


def _redirect(uri: str, **params: str) -> RedirectResponse:
    parsed = urlparse(uri)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update({key: value for key, value in params.items() if value})
    target = urlunparse(parsed._replace(query=urlencode(query)))
    return RedirectResponse(target, status_code=303)


def _legal_links(locale: str) -> tuple[str, str]:
    if is_english(locale):
        return "https://saturn.technology/terms", "https://saturn.technology/privacy"
    return "https://saturn.technology/zh/terms", "https://saturn.technology/zh/privacy"


async def _consent_scope(session, user, client_id: str) -> dict:
    agents = await session.execute(select(Agent).where(Agent.organization_id == user.organization_id))
    agent = next(
        (
            item
            for item in agents.scalars()
            if (item.settings or {}).get("origin") == "saturn_mcp"
            and (item.settings or {}).get("client_id") == client_id
        ),
        None,
    )
    set_name = None
    approval_tools = False
    if agent is not None and agent.tool_set_id:
        tool_set = await session.get(ToolSet, agent.tool_set_id)
        if tool_set is not None and tool_set.organization_id == user.organization_id:
            set_name = tool_set.name
            items = await session.execute(select(ToolSetItem).where(ToolSetItem.tool_set_id == tool_set.id))
            approval_tools = any(item.approval for item in items.scalars())
    policies = await session.execute(
        select(Policy)
        .options(selectinload(Policy.agents))
        .where(Policy.organization_id == user.organization_id)
    )
    names: list[str] = []
    for policy in policies.scalars():
        if (policy.status or "active").lower() != "active":
            continue
        bound = list(policy.agents or [])
        if agent is None:
            applies = False
        elif not bound:
            applies = True
        else:
            applies = any(item.id == agent.id for item in bound)
        if applies:
            names.append(policy.name)
    return {
        "connected": agent is not None,
        "set_name": set_name,
        "policies": names,
        "approval_tools": approval_tools,
    }


def _destination(redirect_uri: str) -> str:
    parsed = urlparse(redirect_uri)
    if parsed.scheme in {"http", "https"}:
        return parsed.netloc.rsplit("@", 1)[-1]
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else f"{parsed.scheme}:"


def _consent_body(locale: str, client_name: str, client_id: str, identity: str, scope: dict, fields: dict[str, str], csrf: str) -> str:
    terms, privacy = _legal_links(locale)
    # The name is whatever the client registered; where the code goes is what identifies it.
    destination = _destination(fields["redirect_uri"])
    hours = max(1, int(ACCESS_TTL.total_seconds() // 3600))
    days = REFRESH_TTL.days
    set_name = scope["set_name"]
    policy_name = "、".join(scope["policies"]) if scope["policies"] else ""
    if is_english(locale):
        if scope["connected"]:
            set_label = set_name or "Not assigned"
            set_detail = (
                "This agent can use the tools and operations explicitly allowed in this set."
                if set_name
                else "No set is assigned. This agent cannot call tools until one is."
            )
            policy_label = policy_name or "None applied"
            approval_detail = "A call runs only when the rules allow it. Anything that needs approval waits for that decision."
            if scope["approval_tools"]:
                approval_detail += " Some tools in this set are marked as requiring approval."
            access = f"""<div class="card"><strong>Set: {escape(set_label)}</strong><p>{escape(set_detail)}</p></div>
        <div class="card"><strong>Policy: {escape(policy_label)}</strong><p>Saturn checks permission rules, denials, and approval requirements before a tool runs.</p></div>
        <div class="card"><strong>Approval required</strong><p>{escape(approval_detail)}</p></div>"""
        else:
            access = """<div class="card"><strong>Connection only</strong><p>This first authorization does not include a set or a policy. After the agent appears in the console, assign the tools it may use and the policy that applies. Until a set is assigned, this agent cannot call tools.</p></div>"""
        return f"""<p class="kicker">Connect to Saturn</p>
        <h1>Agent authorization request</h1>
        <h2>Requesting agent</h2>
        <div class="card"><strong>{escape(client_name)}</strong><p>Name supplied by the agent developer. Client {escape(client_id)}</p><p>After you decide, you return to <code>{escape(destination)}</code>. If you do not recognize it, deny.</p></div>
        <h2>Access requested</h2>
        {access}
        <h2>Before you connect</h2>
        <p class="note">Connecting does not grant unlimited access. Saturn checks each tool call against the granted set, the active policy, and the approval rules, and writes the call to the audit log. You can revoke this connection from the console.</p>
        <p class="note">Access lasts {hours} hour for the access token and {days} days for the refresh token, or until you revoke it.</p>
        <label>Connecting as</label>
        <code>{escape(identity)}</code>
        <p class="legal">By continuing, you acknowledge the <a href="{terms}" target="_blank" rel="noopener">Terms of Service</a> and <a href="{privacy}" target="_blank" rel="noopener">Privacy Policy</a>.</p>
        <form method="post" action="/oauth/consent">
          {_hidden(fields)}
          <input type="hidden" name="csrf" value="{escape(csrf)}">
          <div class="row">
            <button class="secondary" type="submit" name="decision" value="deny">Deny</button>
            <button type="submit" name="decision" value="allow">Authorize agent</button>
          </div>
        </form>"""
    if scope["connected"]:
        set_label = set_name or "尚未指定"
        set_detail = (
            "可使用此 Set 中明確允許的工具與操作。"
            if set_name
            else "尚未指定 Set。在指定之前，這個代理人不能呼叫工具。"
        )
        policy_label = policy_name or "尚未套用"
        approval_detail = "符合規則時才執行。需要核准的操作必須先經過核准。"
        if scope["approval_tools"]:
            approval_detail += "這個 Set 裡有工具被標成需要核准。"
        access = f"""<div class="card"><strong>Set：{escape(set_label)}</strong><p>{escape(set_detail)}</p></div>
    <div class="card"><strong>Policy：{escape(policy_label)}</strong><p>受 Saturn 的權限規則、拒絕條件與核准要求約束。</p></div>
    <div class="card"><strong>需要核准</strong><p>{escape(approval_detail)}</p></div>"""
    else:
        access = """<div class="card"><strong>僅建立連線</strong><p>首次授權還沒有 Set，也還沒有套用 Policy。代理人出現在控制台後，再指定可以使用的工具與要套用的政策。在指定 Set 之前，這個代理人不能呼叫工具。</p></div>"""
    return f"""<p class="kicker">連接 Saturn</p>
    <h1>代理人授權請求</h1>
    <h2>申請連線的代理人</h2>
    <div class="card"><strong>{escape(client_name)}</strong><p>由代理人開發者提供的名稱。識別碼 {escape(client_id)}</p><p>按下後會回到 <code>{escape(destination)}</code>。如果你不認得這個網址，請拒絕。</p></div>
    <h2>要求的存取</h2>
    {access}
    <h2>連線之前</h2>
    <p class="note">連線不代表授予無限制存取權。Saturn 會依照已授予的 Set、有效 Policy 與審批規則檢查每次工具呼叫，並寫入稽核紀錄。你可以在控制台撤銷這次連線。</p>
    <p class="note">存取權杖 {hours} 小時，重新整理權杖 {days} 天，或直到撤銷。</p>
    <label>以此身分連線</label>
    <code>{escape(identity)}</code>
    <p class="legal">繼續即表示你知悉 <a href="{terms}" target="_blank" rel="noopener">服務條款</a> 與 <a href="{privacy}" target="_blank" rel="noopener">隱私權政策</a>。</p>
    <form method="post" action="/oauth/consent">
      {_hidden(fields)}
      <input type="hidden" name="csrf" value="{escape(csrf)}">
      <div class="row">
        <button class="secondary" type="submit" name="decision" value="deny">拒絕</button>
        <button type="submit" name="decision" value="allow">授權代理人</button>
      </div>
    </form>"""


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata(request: Request) -> dict:
    return protected_resource(origin_of(request))


@router.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata(request: Request) -> dict:
    return metadata(origin_of(request))


MAX_REDIRECT_URI_LENGTH = 2048


@router.post("/oauth/register", status_code=201)
async def register_client(request: Request, session: SessionDep) -> dict:
    if not await registration_allowed(request):
        raise HTTPException(status_code=429, detail="Too many registrations", headers={"Retry-After": "600"})
    try:
        body = await request.json()
    except HTTPException:
        # The body limit. Say so instead of answering as if the body were empty.
        raise
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    name = str(body.get("client_name") or "Agent").strip()[:255] or "Agent"
    uris = body.get("redirect_uris")
    if not isinstance(uris, list) or not uris or len(uris) > 8:
        raise HTTPException(400, "redirect_uris are required")
    cleaned = []
    for item in uris:
        uri = str(item or "").strip()
        # Anyone can register a client, and each one is stored and read back on every authorize.
        if len(uri) > MAX_REDIRECT_URI_LENGTH:
            raise HTTPException(400, "redirect_uri is too long")
        if not redirect_allowed(uri):
            raise HTTPException(400, "redirect_uri must be https, localhost, or an app callback")
        cleaned.append(uri)
    client = await oauth_service.register(session, name=name, redirect_uris=cleaned)
    origin = origin_of(request)
    return {
        "client_id": client.id,
        "client_name": client.name,
        "redirect_uris": cleaned,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": SCOPE,
        "client_id_issued_at": int(client.created_at.timestamp()),
        "authorization_endpoint": f"{origin}/oauth/authorize",
        "token_endpoint": f"{origin}/oauth/token",
    }


@router.get("/oauth/argon2.js")
async def argon2_script() -> Response:
    # A plain response, not FileResponse: no Range parsing on an unauthenticated route.
    global _ARGON2_BYTES
    if _ARGON2_BYTES is None:
        _ARGON2_BYTES = _ARGON2.read_bytes()
    return Response(
        _ARGON2_BYTES,
        media_type="text/javascript",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@router.get("/oauth/authorize")
async def authorize(request: Request, session: SessionDep):
    fields = _fields(request)
    client = await oauth_service.client_for(session, fields["client_id"])
    if client is None or not oauth_service.matching_redirect(client, fields["redirect_uri"]):
        return _page("Saturn", "<h1>無法連線</h1><p>This agent is not registered, or the redirect URL does not match.</p>", 400)
    if not _request_ok(fields):
        # Render instead of redirecting: a malformed request must not turn this origin into an open redirect.
        return _page("Saturn", "<h1>無法連線</h1><p>This sign-in request is invalid. Start again from the agent.</p>", 400)
    token, _csrf = _cookie_parts(request)
    user = await auth_service.user_from_token(session, token, purpose=_SESSION_PURPOSE) if token else None
    if user is not None and suspended(user.organization):
        return _page("Saturn", "<h1>無法連線</h1><p>This organization is suspended. Agents cannot connect to it.</p>", 403)
    if user is None or user.organization is None:
        return _page(
            "Connect Agents",
            f"""<h1>連接代理人</h1>
            <p>{escape(client.name)} wants to connect to Saturn MCP. Sign in to bind it to your profile.</p>
            <form method="post" action="/oauth/login">
              {_hidden(fields)}
              <label>電子郵件 Email<input name="email" type="email" autocomplete="username" required></label>
              <label>密碼 Password<input name="password" type="password" autocomplete="current-password" required></label>
              <input type="hidden" name="legacy_v1" value="">
              <input type="hidden" name="legacy_password" value="">
              <div class="row"><button type="submit">登入 Sign in</button></div>
              <p id="login-error" role="alert"></p>
            </form>
            <script nonce="{escape(current_csp_nonce())}" src="/oauth/argon2.js"></script>
            <script nonce="{escape(current_csp_nonce())}">
              document.querySelector('form[action="/oauth/login"]').addEventListener('submit', async (event) => {{
                const form = event.currentTarget;
                const input = form.querySelector('input[name="password"]');
                const legacyV1 = form.querySelector('input[name="legacy_v1"]');
                const legacyPassword = form.querySelector('input[name="legacy_password"]');
                if (!input || input.dataset.sealed === '1') return;
                event.preventDefault();
                const raw = input.value;
                const email = String(form.querySelector('input[name="email"]').value || '').trim().toLowerCase();
                const hex = (bytes) => [...bytes].map((item) => item.toString(16).padStart(2, '0')).join('');
                const v1Bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('saturn-login-v1\\n' + raw)));
                const v1 = 'v1.' + hex(v1Bytes);
                let verifier = '';
                try {{
                  if (!window.hashwasm || typeof window.hashwasm.argon2id !== 'function') throw new Error('argon2');
                  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('saturn-argon2-salt-v1\\n' + email)));
                  const master = new Uint8Array(await window.hashwasm.argon2id({{
                    password: raw,
                    salt,
                    parallelism: 1,
                    iterations: 2,
                    memorySize: 19456,
                    hashLength: 64,
                    outputType: 'binary',
                  }}));
                  const key = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
                  const bits = new Uint8Array(await crypto.subtle.deriveBits({{
                    name: 'HKDF',
                    hash: 'SHA-256',
                    salt: new Uint8Array(32),
                    info: new TextEncoder().encode('saturn-login-v2'),
                  }}, key, 256));
                  verifier = 'v2.' + hex(bits);
                }} catch (_) {{
                  event.preventDefault();
                  const note = document.getElementById('login-error');
                  if (note) note.textContent = '無法完成登入。請重新整理後再試。 Sign-in could not finish. Reload the page and try again.';
                  form.dataset.busy = '0';
                  return;
                }}
                const probe = async (extra) => {{
                  const response = await fetch('/auth/login/migration', {{
                    method: 'POST',
                    headers: {{'content-type': 'application/json'}},
                    body: JSON.stringify({{email, password: verifier, ...extra}}),
                  }});
                  return response.ok ? response.json() : {{}};
                }};
                let body = await probe({{}});
                if (body.migration === 'v1' && verifier !== v1) {{
                  if (legacyV1) legacyV1.value = v1;
                  body = await probe({{legacy_v1: v1}});
                }}
                if ((body.migration === 'password' || body.migration === true) && legacyPassword) legacyPassword.value = raw;
                input.value = verifier;
                input.dataset.sealed = '1';
                form.submit();
              }});
            </script>""",
        )
    identity = profile_identity(user.id, user.organization_id, user.organization.kind, user.organization.plan)
    csrf = secrets.token_urlsafe(18)
    scope = await _consent_scope(session, user, client.id)
    locale = normalize_locale(user.locale)
    # Both answers to this form are a 303 to the registered redirect_uri.
    allow_form_redirect(fields["redirect_uri"])
    page = _page(
        "Authorize agent" if is_english(locale) else "授權代理人",
        _consent_body(locale, client.name, client.id, identity, scope, fields, csrf),
        wide=True,
        lang=locale,
    )
    _set_cookie(page, request, token, csrf)
    return page


def _passkey_link(fields: dict[str, str], challenge: str, *, secondary: bool = False) -> str:
    """A link to the console page that asks for the passkey.

    A passkey is bound to the console's origin, so the browser will not offer it on this page.
    The console checks it and posts the result to /oauth/login/passkey. The sign-in challenge
    travels in the fragment, which is not sent to a server or written to its logs.
    """
    target = f"{console_origin()}/connect-passkey#{urlencode({**fields, 'challenge': challenge})}"
    kind = "button secondary" if secondary else "button"
    return f'<div class="row"><a class="{kind}" href="{escape(target)}">使用 Passkey Use a passkey</a></div>'


def _passkey_page(fields: dict[str, str], challenge: str, *, after_email: bool = False) -> HTMLResponse:
    lead = (
        "Your email code is confirmed. This account also needs its passkey to sign in."
        if after_email
        else "This account signs in with a passkey."
    )
    return _page(
        "Verify sign-in",
        f"""<h1>驗證登入</h1>
            <p>{escape(lead)} Continue in the Saturn console to use it, then you return here.</p>
            {_passkey_link(fields, challenge)}""",
    )


def _code_page(fields: dict[str, str], challenge: str, method: str, *, passkey: bool = False) -> HTMLResponse:
    if method == "totp":
        lead = "Enter the 6-digit code from your authenticator app, or a backup code."
        label = "驗證器代碼 Authenticator code"
    else:
        lead = "We emailed a sign-in code. Enter it to continue."
        label = "驗證碼 Code"
    return _page(
        "Verify sign-in",
        f"""<h1>驗證登入</h1>
            <p>{escape(lead)}</p>
            <form method="post" action="/oauth/login/code">
              {_hidden(fields)}
              <input type="hidden" name="challenge" value="{escape(challenge)}">
              <input type="hidden" name="method" value="{escape(method)}">
              <label>{escape(label)}<input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
              <div class="row"><button type="submit">繼續 Continue</button></div>
            </form>
            {_passkey_link(fields, challenge, secondary=True) if passkey else ""}""",
    )


def _cross_site(request: Request):
    """Refuse a sign-in form posted from another site.

    These forms only ever come from this origin's own sign-in page. Without this, a page on any
    site could post an attacker's credentials from the victim's browser and leave the attacker's
    consent session behind; the victim's next agent would then be connected to the attacker's
    workspace. A browser states where a POST came from, and a cross-site one cannot hide it.
    Clients that send neither header are not browsers and cannot be used this way.
    """
    from app.features.identity.auth.controllers.deps import _origin_of, _trusted_origins

    site = (request.headers.get("sec-fetch-site") or "").strip().lower()
    origin = (request.headers.get("origin") or "").strip()
    foreign = site == "cross-site" or (bool(origin) and _origin_of(origin) not in _trusted_origins(request))
    if not foreign:
        return None
    return _page("Saturn", "<h1>無法連線</h1><p>Start again from the agent to sign in.</p>", 403)


async def _consent_redirect(session, request: Request, user, fields: dict[str, str]) -> RedirectResponse:
    # A short session that only the consent pages accept. It is not a console or API session.
    token, _user = await auth_service.issue_session(session, user, purpose=_SESSION_PURPOSE, ttl=OAUTH_SESSION_TTL)
    csrf = secrets.token_urlsafe(18)
    response = RedirectResponse("/oauth/authorize?" + urlencode(fields), status_code=303)
    _set_cookie(response, request, token, csrf)
    return response


def _posted_fields(form: dict[str, str]) -> dict[str, str]:
    return {key: form.get(key, "") for key in ("client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "response_type")}


@router.post("/oauth/login")
async def oauth_login(request: Request, session: SessionDep):
    from app.core.rate_limit import login_allowed, login_succeeded

    refused = _cross_site(request)
    if refused is not None:
        return refused
    form = await _posted(request)
    if not await login_allowed(request, form.get("email", "")):
        return _page("Connect Agents", "<h1>請稍後再試</h1><p>Too many sign-in attempts.</p>", 429)
    fields = _posted_fields(form)
    try:
        user = await auth_service.authenticate(
            session,
            form.get("email", ""),
            form.get("password", ""),
            legacy_password=form.get("legacy_password") or None,
            legacy_v1=form.get("legacy_v1") or None,
        )
    except HTTPException:
        return _page("Connect Agents", "<h1>登入失敗</h1><p>Email or password is incorrect.</p>", 401)
    await login_succeeded(form.get("email", ""))
    try:
        # The same factors as the console sign-in. An emailed code is never added as a fallback.
        pending = await mfa_service.start_login(session, user)
    except HTTPException as exc:
        return _page("Connect Agents", f"<h1>請稍後再試</h1><p>{escape(str(exc.detail))}</p>", exc.status_code)
    if pending is None:
        return await _consent_redirect(session, request, user, fields)
    challenge, methods, code = pending
    passkey = "passkey" in methods
    if "totp" in methods:
        return _code_page(fields, challenge, "totp", passkey=passkey)
    if "email" in methods and code is not None:
        try:
            await send_login_code(user.email, code, user.locale)
        except HTTPException as exc:
            await mfa_service.discard_login(session, challenge)
            return _page("Connect Agents", f"<h1>無法寄信</h1><p>{escape(str(exc.detail))}</p>", exc.status_code)
        return _code_page(fields, challenge, "email", passkey=passkey)
    return _passkey_page(fields, challenge)


@router.post("/oauth/login/code")
async def oauth_login_code(request: Request, session: SessionDep):
    from app.core.rate_limit import code_check_allowed

    refused = _cross_site(request)
    if refused is not None:
        return refused
    form = await _posted(request)
    fields = _posted_fields(form)
    if not await code_check_allowed(request):
        return _page("Connect Agents", "<h1>請稍後再試</h1><p>Too many sign-in attempts.</p>", 429)
    challenge = form.get("challenge", "")
    further: list[str] = []
    try:
        if form.get("method", "") == "totp":
            user = await mfa_service.finish_totp(session, challenge, form.get("code", ""))
        else:
            user, further = await mfa_service.finish_email(session, challenge, form.get("code", ""))
    except HTTPException:
        return _page("Connect Agents", "<h1>驗證失敗</h1><p>That code is incorrect or expired.</p>", 400)
    if "totp" in further:
        return _code_page(fields, challenge, "totp", passkey="passkey" in further)
    if further:
        return _passkey_page(fields, challenge, after_email=True)
    return await _consent_redirect(session, request, user, fields)


@router.post("/oauth/login/passkey")
async def oauth_login_passkey(request: Request, session: SessionDep):
    """The console posts the passkey answer here, as a page navigation, to finish the sign-in.

    The answer is signed over the console's origin and a challenge this API issued for the
    account, so a form on any other site cannot produce one.
    """
    from app.core.rate_limit import code_check_allowed

    form = await _posted(request)
    fields = _posted_fields(form)
    if not await code_check_allowed(request):
        return _page("Connect Agents", "<h1>請稍後再試</h1><p>Too many sign-in attempts.</p>", 429)
    try:
        credential = json.loads(form.get("credential", ""))
    except ValueError:
        credential = None
    try:
        if not isinstance(credential, dict):
            raise HTTPException(400, "Passkey could not be verified")
        user = await passkey_service.authenticate(session, request, form.get("challenge", ""), credential)
    except HTTPException:
        return _page(
            "Connect Agents",
            "<h1>驗證失敗</h1><p>The passkey could not be verified. Start again from the agent.</p>",
            400,
        )
    return await _consent_redirect(session, request, user, fields)


@router.post("/oauth/consent")
async def oauth_consent(request: Request, session: SessionDep):
    form = await _posted(request)
    fields = {key: form.get(key, "") for key in ("client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "response_type")}
    token, csrf = _cookie_parts(request)
    posted_csrf = form.get("csrf", "")
    if not csrf or len(csrf) != len(posted_csrf) or not secrets.compare_digest(csrf, posted_csrf):
        return _page("Saturn", "<h1>無法連線</h1><p>Sign in again to connect this agent.</p>", 400)
    user = await auth_service.user_from_token(session, token, purpose=_SESSION_PURPOSE) if token else None
    client = await oauth_service.client_for(session, fields["client_id"]) if user is not None else None
    if (
        user is None
        or user.organization is None
        or client is None
        or not oauth_service.matching_redirect(client, fields["redirect_uri"])
        or not _request_ok(fields)
    ):
        return _page("Saturn", "<h1>無法連線</h1><p>Sign in again to connect this agent.</p>", 400)
    # One consent per sign-in. The consent session ends here whatever the decision.
    await auth_service.logout(session, token)
    if form.get("decision", "") != "allow":
        denied = _redirect(fields["redirect_uri"], error="access_denied", state=fields["state"])
        denied.delete_cookie(COOKIE, path="/oauth")
        return denied
    scope = await _consent_scope(session, user, client.id)
    identity = profile_identity(user.id, user.organization_id, user.organization.kind, user.organization.plan)
    await audit_service.log(
        session,
        event="agent_authorized",
        actor_type=ActorType.USER,
        actor_id=user.id,
        organization_id=user.organization_id,
        result="allow",
        payload={
            "client_id": client.id,
            "client_name": client.name,
            "tool_set": scope["set_name"],
            "policies": scope["policies"],
            "profile_id": identity,
        },
    )
    code = await oauth_service.issue_code(
        session,
        client=client,
        user=user,
        redirect_uri=fields["redirect_uri"],
        code_challenge=fields["code_challenge"],
    )
    granted = _redirect(fields["redirect_uri"], code=code, state=fields["state"])
    granted.delete_cookie(COOKIE, path="/oauth")
    return granted


@router.post("/oauth/token")
async def oauth_token(request: Request, session: SessionDep) -> JSONResponse:
    form = await _posted(request)
    grant = form.get("grant_type", "")
    client_id = form.get("client_id", "")
    client = await oauth_service.client_for(session, client_id)
    if client is None:
        raise HTTPException(400, "invalid_client", headers=_NO_STORE)
    if grant == "authorization_code":
        issued = await oauth_service.exchange_code(
            session,
            code=form.get("code", ""),
            client_id=client_id,
            redirect_uri=form.get("redirect_uri", ""),
            code_verifier=form.get("code_verifier", ""),
        )
    elif grant == "refresh_token":
        issued = await oauth_service.refresh(
            session,
            refresh_token=form.get("refresh_token", ""),
            client_id=client_id,
        )
    else:
        raise HTTPException(400, "unsupported_grant_type", headers=_NO_STORE)
    if issued is None:
        raise HTTPException(400, "invalid_grant", headers=_NO_STORE)
    access, refresh, expires_in = issued
    return JSONResponse(
        {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": refresh,
            "scope": SCOPE,
        },
        headers=_NO_STORE,
    )
