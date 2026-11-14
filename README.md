<div align="center">

# Saturn Backend

**The API behind Saturn MCP, the hosted gateway that decides what AI agents may do.**

Agents call one MCP endpoint. Saturn shows each agent only its tool set, checks every call against policy, holds the sensitive ones for a person to approve, forwards the rest to the real MCP server with a sealed credential, and records each step.

[![License: FSL-1.1-ALv2](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue.svg)](LICENSE.md)
![Python](https://img.shields.io/badge/python-3.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.162-009688.svg?logo=fastapi&logoColor=white)
[![Test](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/actions/workflows/test.yml/badge.svg)](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/actions/workflows/test.yml)

[Features](#features) · [Architecture](#architecture) · [Quick start](#quick-start) · [Policies](#policies-and-approvals) · [Security](#security) · [Configuration](#configuration) · [Deploy](#deploy) · [中文](README_ZH.md)

</div>

---

## What it is

Saturn MCP sits between AI agents and the MCP servers they use. An agent connects to Saturn instead of to each server, signs in with OAuth, and sees only the tools its organization put in its tool set. Every call is evaluated before anything reaches the upstream server.

This repository is the API: a FastAPI app on Cloud Run with Postgres and Redis. The console at [dashboard.saturn-core.com](https://dashboard.saturn-core.com) is a separate repository ([Saturn-MCP-Frontend](https://github.com/Saturn-Technology-Project/Saturn-MCP-Frontend)), and [saturn-core.com](https://saturn-core.com) describes the product. Saturn App, the desktop agent, can be pointed at Saturn MCP like any other MCP client.

- **One endpoint per organization.** `POST /mcp` speaks MCP over HTTP (`initialize`, `tools/list`, `tools/call`). Each OAuth client that connects becomes an agent of the signed-in member.
- **Default deny.** A call with no applicable policy is denied, and a tool that has rules but no matching rule is denied.
- **Approvals bound to the exact call.** An approval covers one set of arguments under one policy version. If either changes, the approval is invalidated.
- **Sealed credentials and content.** Upstream credentials are encrypted with per-tenant keys derived from Cloud KMS. Audit content is encrypted to keys the organization holds.

The control plane starts **empty**. Bootstrap creates a platform admin only: no demo agents, tools, MCP servers, policies or credentials.

## Features

| | |
|---|---|
| **MCP gateway** | `POST /mcp` for JSON-RPC and `GET /mcp` for server-sent notifications, with `Mcp-Session-Id` sessions issued by the server. OAuth 2.1 with PKCE (`S256`) and dynamic client registration, scope `saturn.mcp`, discovered through `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`. |
| **Agents** | One agent per connected OAuth client and member (at most 25 per member, 5 per client), or created through `/agents`. Each agent has one tool set. |
| **MCP servers** | Connect an upstream server by HTTPS URL on an allowlisted host, with a static authorization header or OAuth (discovery, dynamic registration, token refresh). Its tools are discovered on connect and on refresh. |
| **Tool sets** | Named groups of discovered tools. A tool set item can be marked to always require approval. |
| **Policies** | Per-tool rules on argument values (`gt`, `gte`, `lt`, `lte`, `eq`, `ne`) with an `allow`, `approval` or `deny` decision. Validate, simulate and activate; optionally draft rules with a model you configure. |
| **Approvals** | Approval policies with a required count, group requirements, a self-approval switch, and expiry windows. Votes are recorded per member; the call runs at most once. |
| **Webhooks** | Signed `approval.granted`, `approval.rejected` and `approval.expired` events to an HTTPS endpoint, with retries and a delivery log ([`docs/webhooks.md`](docs/webhooks.md)). |
| **Organizations** | Members, invites, roles (`admin`, `operator`, `viewer`, `custom`), groups, and per-member mapping to agents and MCP servers. |
| **Credential vault** | ML-KEM-1024 and AES-256-GCM per tenant, keys derived from a Cloud KMS HMAC key. Secrets are written, never read back through the API. |
| **Activity** | An audit log of every step, with filtered JSON export. Tool arguments and upstream bodies are encrypted to the organization's ML-KEM payload key and its approved members' keys. |
| **Accounts** | Email and password, TOTP with backup codes, emailed codes, passkeys (WebAuthn), step-up re-authentication, password reset. |
| **Platform admin** | Onboard organizations, inspect members, agents, connections, MCP usage and the audit trail across tenants, without tool content. |

## Architecture

```mermaid
flowchart LR
  C["MCP client<br/><sub>an agent</sub>"] -- "OAuth bearer · /mcp" --> G
  F["Console<br/><sub>dashboard.saturn-core.com</sub>"] -- "session token" --> API
  subgraph API["Saturn Backend · FastAPI on Cloud Run"]
    G["Saturn MCP gateway"] --> P["Policy engine"]
    P --> A["Approvals"]
    A --> E["Executor"]
    E --> L["Audit log"]
    V["Credential vault"] --> E
  end
  E -- "HTTPS" --> U["Upstream MCP servers"]
  API --> DB[("Postgres")]
  API --> R[("Redis")]
  V -- "MAC sign" --> K["Cloud KMS"]
```

### Execution loop

**Run → Agent → Tool → Policy → Approval → Execute → Audit**

| Step | What happens | Code |
|---|---|---|
| **Run** | A `tools/call` opens a run and an action. An agent resubmitting an approved call sets `saturnRunId`, which every exposed tool schema carries, to the run id from the `approval_required` error. | `features/mcp/saturn`, `features/execution/runs` |
| **Agent** | The bearer token resolves to a member and an OAuth client, and the client to an agent the member owns. | `features/identity/oauth`, `features/agent` |
| **Tool** | Only active tools in the agent's tool set are listed or callable. Anything else is refused. | `features/tooling` |
| **Policy** | Every active policy that applies to the agent gives an opinion on the tool and its arguments. The most restrictive one wins. | `features/policy` |
| **Approval** | `approval_required` creates a pending approval bound to a keyed digest of the arguments, the policy version and the approval policy version. | `features/execution/approvals` |
| **Execute** | Once approved (or allowed), the call is claimed atomically and sent to the upstream MCP server with its credential from the vault. | `features/mcp/servers`, `features/credentials` |
| **Audit** | Each step (`tool_requested`, `policy_evaluated`, `approval_requested`, `approval_granted`, `execution_claimed`, `tool_executed`, …) is written to the audit log. | `features/execution/activity` |

Agent wallets and x402 payments were part of this loop earlier. Migration `039_drop_wallets_x402` removed them.

### Layout

Code is grouped by feature, then by function. A function keeps its own `models/`, `services/`, `controllers/` and, in most cases, `routes/`.

```
app/
  main.py          app, middleware and router mounts
  core/            settings, ids, enums, security headers, origin auth, rate limits
  db/              engine and bootstrap seed
  models/          ORM registry (`from app.models import …`)
  schemas.py       shared request and response models
  shared/          cross-feature association tables, pagination, runtime checks
  cli/             one-off maintenance commands (`python -m app.cli.pq1`)
  features/
    identity/      auth (sessions, MFA, passkeys), oauth (the MCP authorization server)
    organization/  org: members, invites, groups, mapping, subscription
    platform/      admin
    agent/         agents
    mcp/           servers, oauth (upstream sign-in), saturn (the gateway)
    policy/        policies, policy graph, model-drafted rules
    execution/     runs, approvals, activity (audit, payload keys)
    tooling/       tools, tool sets
    credentials/   vault
    webhooks/      endpoints, deliveries, background worker
    billing/       payments (placeholder)
```

`app/main.py` mounts each function router. HTTP handlers live in `controllers/`; `routes/` is the mount point. Postgres schema changes are Alembic migrations in `alembic/versions/`.

## Quick start

This repo is the API. The console and the admin dashboard are separate repositories.

### Requirements

- Docker with Compose, for Postgres 16, Redis 7 and the API.
- A Cloud KMS HMAC key and Google credentials that may sign with it. On startup the API derives tenant keys through KMS (`SATURN_KMS_KEY`) and stops if it cannot. Only the test suite runs without it, with a fixed local key.

### Run

```bash
cp .env.example .env
# Fill in POSTGRES_PASSWORD and REDIS_PASSWORD (for example `openssl rand -hex 16`),
# SEED_USER_EMAIL and SEED_USER_PASSWORD, and add SATURN_KMS_KEY.
docker compose up --build
```

Set `SEED_USER_EMAIL` and `SEED_USER_PASSWORD` in `.env` before the first boot. Those values create the platform admin. Do not commit them. Compose refuses to start until `POSTGRES_PASSWORD` and `REDIS_PASSWORD` are set.

- API: http://localhost:8000
- Docs: http://localhost:8000/docs (closed on Cloud Run, or anywhere with `EXPOSE_API_DOCS=false`)
- Health: `GET /health` answers `{"status":"ok"}` while the process is serving and checks nothing else, so a probe never fails because a dependency does. `GET /status` reports each service (API, database, and Redis when it is used); it always answers 200 and the result is in the body, reused for five seconds. `GET /status/history` returns each service's uptime per day for the last 90 days: the worker checks every service once a minute (the API through its public address) and counts the result into that day's row in `status_days`. The console's public `/status` page draws both
- Postgres: 127.0.0.1:5433 (user `saturn`, password `POSTGRES_PASSWORD`)
- Redis: 127.0.0.1:6379 (password `REDIS_PASSWORD`)

Postgres and Redis listen on 127.0.0.1 only. The API container runs as an unprivileged user (uid 10001), mounts the working tree and reloads on change. It applies migrations on start, unless `RUN_MIGRATIONS=false`.

## Auth and API

```bash
TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$SEED_USER_EMAIL\",\"password\":\"$SEED_USER_PASSWORD\"}" | python -c 'import sys,json; print(json.load(sys.stdin)["token"])')

curl -s localhost:8000/auth/me -H "Authorization: Bearer $TOKEN"
```

The API accepts the session token as `Authorization: Bearer` or as the `saturn_session` cookie the console uses. `/auth/login` is limited to 20 attempts per address and 10 per account in 10 minutes.

**Admins need a passkey or TOTP first.** A platform admin, or an organization admin (`team.write`), with neither a passkey nor an authenticator app gets `403 MFA setup is required` from every route except `/auth/me`, `/auth/logout`, `/auth/mfa…`, `/auth/totp…`, `/auth/passkeys…`, `/auth/reauth…` and the health checks. Either one is enough. A passkey is added from the console (`/mfa`), because it needs a browser. An authenticator app can be set up with the session token:

```bash
curl -s -X POST localhost:8000/auth/totp/setup -H "Authorization: Bearer $TOKEN"
# Add the returned otpauth_url to an authenticator app and keep the backup codes, then:
curl -s -X POST localhost:8000/auth/totp/confirm \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

From then on `/auth/login` returns `mfa_required` with a `challenge` and `methods`. When `methods` contains `totp`, finish with `POST /auth/login/totp` and `{"challenge": …, "code": …}`. The other methods are `email` (a code sent through Resend, `POST /auth/login/email`) and `passkey` (`POST /auth/login/passkey/options`, then `POST /auth/login/passkey`). For an admin who holds a passkey, `POST /auth/login/email` does not finish the sign-in: it answers `mfa_required` again with the same `challenge` and the methods still required.

The agent sign-in page (`/oauth/authorize`) accepts the same factors. A passkey is bound to the console's origin, so that page links to the console's `/connect-passkey`, which asks for the passkey and posts the answer to `POST /oauth/login/passkey`.

Other account routes: self sign-up with an emailed code (`/auth/register/code`, `/auth/register`), `/auth/forgot-password` and `/auth/reset-password`, `/auth/passkeys`, `/auth/reauth`, and `PATCH /auth/password`.

## Organizations and roles

The organization is the tenant. Users belong to one organization as employees, with per-organization access:

- `agents` / `policies` / `approvals` / `team` → `none` | `read` | `write`
- Roles: `admin`, `operator`, `viewer`, or `custom`

| Role | agents | policies | approvals | team |
|---|---|---|---|---|
| `admin` | write | write | write | write |
| `operator` | write | read | write | none |
| `viewer` | read | read | read | none |
| `custom` | chosen per member | | | |

```bash
curl -s localhost:8000/org -H "Authorization: Bearer $TOKEN"
curl -s localhost:8000/org/members -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:8000/org/invites \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"ops@saturn.ai","name":"Ops","role":"operator"}'
```

The invite link is emailed to the invitee, which needs `RESEND_API_KEY` and `RESEND_FROM`; without them the invite answers 503. The response includes the one-time `token` only in local development (`IN_PROCESS_RUNTIME=true` without `K_SERVICE`). The member sets a password with `POST /auth/accept-invite`. Only organizations of kind `organization` can invite; personal accounts cannot. An organization must keep at least one admin (`team.write`).

An invite, and `PATCH /org/members/{employee_id}`, can also limit a member to chosen agents and MCP servers. Groups (`/org/groups`) collect members for approval requirements.

### Platform admin

The bootstrap user is a platform admin (`is_platform_admin`). The Admin Dashboard uses these endpoints to onboard tenants and inspect the fleet:

```bash
curl -s localhost:8000/admin/stats -H "Authorization: Bearer $TOKEN"
curl -s localhost:8000/admin/orgs -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:8000/admin/orgs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme","admin_email":"admin@acme.test","admin_name":"Acme Admin","admin_password":"password1"}'
curl -s localhost:8000/admin/users -H "Authorization: Bearer $TOKEN"
```

`admin_password` is used only in local development and tests; in production the new admin is emailed a code to choose a password. Onboarding also creates the organization's default policy. Admin audit views (`/admin/audit`) never include tool arguments or upstream bodies.

## MCP gateway and connectors

### Connecting an agent

An MCP client is given the API's `/mcp` URL. On its first request it gets `401` with a `WWW-Authenticate` header pointing at the protected-resource metadata, registers itself at `/oauth/register`, and sends the member through `/oauth/authorize` (sign-in and consent pages served by this API) to obtain a token. Metadata, links and callback URLs come from `PUBLIC_WS_URL`, never from the request's `Host` header.

On `initialize` the client becomes an agent owned by that member. Reconnecting with the same OAuth client ID reuses its agent. A new client ID creates a separate agent whose tools must be assigned in the console, even when the registered name or callback host matches. `tools/list` returns the agent's tool set; `tools/call` runs the [execution loop](#execution-loop).

### Upstream MCP servers

```bash
curl -s -X POST localhost:8000/mcp-servers \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Context7","endpoint":"https://mcp.context7.com/mcp"}'
```

Connecting, refreshing and removing a server needs `team.write`. The endpoint must be HTTPS on port 443 with no credentials in the URL, on one of the hosts listed in `ALLOWED_MCP_HOSTS` (`app/features/mcp/servers/services/mcp_endpoint.py`), and every address it resolves to must be public. A server that asks for OAuth is connected with `POST /mcp-servers/oauth/start`: Saturn discovers its authorization server, registers a client when it can, and finishes at `${PUBLIC_WS_URL}/mcp-servers/oauth/callback`. GitHub (`api.githubcopilot.com`) and Google (`*.googleapis.com`) use preset OAuth apps from `SATURN_GITHUB_OAUTH_CLIENT_ID` / `_SECRET` and `SATURN_GOOGLE_OAUTH_CLIENT_ID` / `_SECRET`. Every URL the server's metadata points to gets the same HTTPS and public-address checks. Tokens are refreshed when they expire or the server rejects them.

Discovered tools appear under `/tools`. Group them with `/tool-sets` and assign a tool set to each agent.

## Policies and approvals

### Policies

A policy is a list of rules. Each rule names a tool, optional conditions on its arguments, and a decision: `allow`, `approval` or `deny`. Conditions compare an argument with `gt`, `gte`, `lt`, `lte`, `eq` or `ne` (`>`, `<=`, `==` and the like are accepted too), joined by AND. A policy applies to every agent in the organization, or to the agents it names, while its status is `active`.

How a decision is reached:

1. Inside a list policy the first matching rule by position decides. Inside a graph policy (one with `definition.nodes`) the most restrictive matching rule decides.
2. A policy that has rules for the tool but no match says `deny`.
3. Across policies the most restrictive opinion wins: `deny` over `approval_required` over `allow`. Positions are never compared across policies.
4. With no applicable policy at all, the call is denied, unless `POLICY_DEFAULT_DENY=false`.

A tool set item marked for approval requires approval whatever the policy says. The default policy created at onboarding allows tools whose permissions are read-only and requires approval for `write`, `admin` and `mutate`; connecting a server adds rules for its new tools to it. Existing organizations are not rewritten.

`/policies/{id}/validate`, `/simulate` and `/activate` check a policy before it takes effect. `/policies/generate` and `/policies/{id}/optimize` (each also as `/stream`) ask a model at `POLICY_LLM_BASE_URL` to propose one rule per tool. The model cannot activate a policy, tools it does not classify stay denied, and the routes are limited to 20 calls per member and 60 per organization per hour.

### Approvals

An approval policy (`/org/approval-policies`) sets how many approvals a request needs, which groups must supply them (each vote fills at most one group seat), whether the requester may approve their own request, and how long a request stays pending and how long an approved call may be resubmitted. Organization defaults are in `/org/approval-window`: 1,440 minutes each, from 1 minute to 7 days.

Rules the code enforces:

- **One vote per member.** Only active members of the required groups may vote. Without an approval policy, the requester cannot approve their own request when another approver exists.
- **Bound to the call.** Before running, the arguments are checked against the approved digest and the policy is evaluated again. Changed arguments, a changed policy version or a changed approval policy invalidate the approval (`409`). A policy that now denies rejects it.
- **At most once.** Approval moves out of pending with a conditional update, and execution is claimed and committed before the upstream call. If something fails after the upstream ran, the outcome is recorded as uncertain and not retried automatically.
- **Expiry.** A worker in the API process (`SATURN_EMBED_WORKER`) checks every 5 seconds, expires due approvals and delivers webhooks.

Reviewers use `GET /approvals` and `POST /approvals/{id}/approve`, `/reject` or `/cancel`. The agent learns the outcome from a webhook or by calling the same tool again with the same arguments and `saturnRunId`.

## Billing

Saturn is free. Every plan (`free`, `pro`, `team`, `enterprise`) has every feature, and every plan in the catalog is priced at 0.00. The plan names and checks remain so that stored plans keep parsing. `GET /org/subscription` reports an organization's plan. `GET /payments` is reserved for Stripe and returns an empty list; it does not charge or store anything.

Agent wallets and x402 payments have been removed (migration `039_drop_wallets_x402`).

Donations go through [GitHub Sponsors](https://github.com/sponsors/Saturn-Technology-Project).

## Configuration

Settings come from the environment (or `.env`); see `.env.example`. App settings, from `app/core/config.py`:

| Variable | Default | Effect |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://saturn:saturn@localhost:5432/saturn` | Database. Compose sets it from `POSTGRES_PASSWORD`. |
| `REDIS_URL` | `redis://localhost:6379/0` | Rate limits and MCP sessions. Compose sets it from `REDIS_PASSWORD`. |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `5` / `10` | Connections each process keeps, and how many more it may open under load. Instances × the sum must stay under the database's connection limit. |
| `DB_POOL_TIMEOUT` | `10` | Seconds a request waits for a free connection before it fails |
| `DB_POOL_RECYCLE` | `1800` | Seconds before a pooled connection is replaced |
| `DB_COMMAND_TIMEOUT` | `60` | Seconds one statement may run. `0` turns the limit off. |
| `LOG_LEVEL` | `INFO` | Lowest level written to stdout |
| `LOG_FORMAT` | `json` on Cloud Run, `text` elsewhere | One JSON object per line with `severity`, `request_id` and the Cloud Trace id, or plain text. Each request is logged once with method, path, status and duration; the query string is never logged. |
| `DEFAULT_ORG_ID` | `org_saturn` | ID of the bootstrap organization |
| `DEFAULT_ACTOR_ID` | `user_operator` | ID of the bootstrap platform admin |
| `SEED_USER_EMAIL` / `SEED_USER_PASSWORD` | empty | Create the platform admin on first boot; empty skips seeding. On Cloud Run the password must be 16 characters or more. |
| `SEED_USER_NAME` | `Admin` | Its display name |
| `SKIP_DB_BOOTSTRAP` | `false` | `true` skips seeding and the startup database work |
| `SESSION_TTL_DAYS` | `7` | Session lifetime; a session also ends after 24 hours without a request |
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:3001,https://dashboard.saturn-core.com` | Allowed browser origins, also trusted for cookie requests and passkeys |
| `IN_PROCESS_RUNTIME` | `false` | Local development and tests only: executes runs in process, keeps rate limits and MCP sessions in memory, returns invite tokens |
| `POLICY_DEFAULT_DENY` | `true` | Deny a call when no policy applies |
| `SATURN_EMBED_WORKER` | `true` | Run the approval-expiry and webhook worker in the API process |
| `SATURN_SECRET_PROJECT` | empty | Google Cloud project for Secret Manager; empty keeps sealed secrets in the database |
| `RESEND_API_KEY` / `RESEND_FROM` | empty | Email delivery for invites, codes and notices |
| `POLICY_LLM_BASE_URL` / `POLICY_LLM_API_KEY` / `POLICY_LLM_MODEL` | empty | OpenAI-compatible `/chat/completions` endpoint for drafted policy rules |
| `LEGACY_PASSWORD_UNTIL` | empty | ISO date after which legacy (pre-argon2) passwords stop working; empty means no end date |

Read directly from the process environment:

| Variable | Default | Effect |
|---|---|---|
| `SATURN_KMS_KEY` | none, required | Full `…/cryptoKeyVersions/N` name of the Cloud KMS MAC key that tenant keys are derived from |
| `PUBLIC_WS_URL` | the request's base URL locally; required on Cloud Run | Public origin for OAuth metadata, links and callbacks (`wss://` and `ws://` map to `https://` and `http://`) |
| `SATURN_GITHUB_OAUTH_CLIENT_ID` / `_SECRET` | unset | OAuth app for GitHub's MCP server |
| `SATURN_GOOGLE_OAUTH_CLIENT_ID` / `_SECRET` | unset | OAuth client for Google's MCP servers |
| `ORIGIN_AUTH_SECRET` | unset | Shared secret every request except `/health` must carry; required on Cloud Run |
| `ORIGIN_AUTH_SECRET_PREVIOUS` | unset | Also accepted during a rotation |
| `CONSOLE_PROXY_SECRET` | unset | Shared with the console; with it the API keys rate limits on the browser address the console forwards (`X-Saturn-Client-IP`) |
| `CONSOLE_PROXY_SECRET_PREVIOUS` | unset | Also accepted during a rotation |
| `MCP_OAUTH_COOKIE_DOMAIN` | derived | Domain for the cookie that binds an MCP sign-in to the browser that started it; by default the parent domain the console and API share |
| `SATURN_REQUIRE_BOUND_SECRETS` | unset | `true` refuses vault values sealed before they were bound to their entry (`pq2.`); set it after a reseal |
| `ORIGIN_AUTH_HEADER` | `X-Saturn-Origin-Auth` | Header that carries it |
| `EXPOSE_API_DOCS` | `true` | `false` closes `/docs`, `/redoc` and `/openapi.json`; always closed on Cloud Run |
| `K_SERVICE` | set by Cloud Run | Marks production: docs closed, origin auth and `PUBLIC_WS_URL` required, cookies always `Secure`, no invite tokens in responses |

The container also reads:

| Variable | Default | Effect |
|---|---|---|
| `RUN_MIGRATIONS` | `true` | `false` skips `alembic upgrade head` on container start (production runs it in a Cloud Run Job instead) |
| `MIGRATION_LOCK_WAIT` | `300s` | How long a migration waits for another runner's advisory lock |

## Security

This section says what the code does. [`infra/gcp/README.md`](infra/gcp/README.md) covers the deployment side: identities, Redis TLS, Cloud SQL and ingress.

### Accounts and sessions

- **Passwords** are stored as Argon2id hashes (time cost 2, 19 MiB memory, parallelism 1) and must be at least 8 characters. The OAuth sign-in page hashes the password in the browser with a vendored Argon2 build before sending it. An unknown email costs the same time as a wrong password. Accounts that still have a legacy (pre-argon2) PBKDF2 hash can sign in until `LEGACY_PASSWORD_UNTIL`, and must reset their password after it.
- **Sessions** are random tokens stored only as SHA-256 hashes. They expire after `SESSION_TTL_DAYS` or 24 hours idle. The cookie is `HttpOnly`, `SameSite=Lax` and `Secure` everywhere except plain-HTTP local runs. A state change authenticated by cookie must come from a trusted origin.
- **MFA.** TOTP (RFC 6238, 6 digits, each code accepted once, 5 attempts then a 15-minute lockout) with 8 backup codes stored as hashes; the TOTP secret is sealed in the vault. Emailed codes, offered only when TOTP is off. Passkeys through WebAuthn. Admins must have a passkey or TOTP, and an emailed code alone never signs in an admin who has one.
- **Step-up.** Changing the account email, turning off emailed codes and deleting a passkey need a sign-in within the last 10 minutes (`/auth/reauth`).

### Credential vault

Credentials and upstream OAuth tokens are sealed with ML-KEM-1024 and AES-256-GCM. Each organization, and each user for personal secrets, has its own key, derived from a MAC computed by Cloud KMS over a labeled string. The root key never leaves KMS, one tenant's key does not open another's ciphertext, and a copy of the database or of the process does not contain the root. Sealed secrets live in the database, or in Secret Manager under per-tenant hashed names when `SATURN_SECRET_PROJECT` is set. `GET /org/credentials/secrets` always answers 403: secrets go in, they do not come out.

### Audit content

Tool arguments, raw requests and upstream responses in the audit log are encrypted to the organization's ML-KEM-1024 payload key and to the keys of approved members. The server encapsulates a data key to each public key and discards it; it never stores or accepts an organization private key, a member private key or a recovery key (`/org/payload-keys`). If no key is registered, that content is not stored. Platform admin responses never receive it. When an organization has no payload key, the arguments a pending approval will run are sealed with a per-organization key derived from KMS instead, and the digest that binds an approval to them is an HMAC with a KMS-derived key, so a database copy cannot be used to confirm guesses such as an amount. The result an approved call keeps for replays is sealed the same way; `python -m app.cli.seal_results --apply` seals the ones older versions stored readable.

Changes to the rules are recorded too: creating, editing, activating, pausing or deleting a policy, changing a tool set or assigning one to an agent, inviting a member or changing their role, status or assignments, and removing an agent or MCP server. `GET /activity/changes` lists them for members with team access. These records hold ids, names and before/after states, never tool content.

### Network exposure

- **Outbound.** MCP endpoints and every URL their OAuth metadata names must be HTTPS on port 443, without credentials, not an IP literal or a metadata host, and resolve only to public addresses. MCP endpoints must also be on the allowlist. Webhook destinations are HTTPS on the standard port.
- **Inbound.** On Cloud Run every request except `/health` must carry `ORIGIN_AUTH_SECRET`, so only the edge proxy can reach the service. `/health` says only that the process is up. (`/healthz` is the same route under its older name; Cloud Run reserves that path and never passes it on.)
- **Client addresses.** uvicorn does not trust `X-Forwarded-*` from any peer but 127.0.0.1. Rate limits use `CF-Connecting-IP` only when origin auth proves the request came through Cloudflare, otherwise the rightmost `X-Forwarded-For` entry.
- **Rate limits** are counted in Redis and fail closed: if Redis cannot be reached, limited routes refuse the request.
- **Request size.** A request body over 4 MiB is refused, and over 64 KiB on the sign-in and OAuth routes, before any handler reads it.
- **Headers.** Every response carries a restrictive Content-Security-Policy (`default-src 'none'` for the API, a per-request nonce for the OAuth pages), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` and a Permissions-Policy; HTTPS responses add HSTS. Unhandled errors return a generic 500.
- **Local.** Compose binds Postgres and Redis to 127.0.0.1 and requires passwords for both.

## Tests

Python 3.12.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements-dev.txt
pytest
```

Tests run against in-memory SQLite with `IN_PROCESS_RUNTIME=true` and a fixed local vault key, so they need no Postgres, Redis, KMS or network. Pytest loads a local catalog fixture (`tests/catalog.py`) so the execution-loop tests do not depend on production seed data. DNS for MCP endpoints is stubbed to a public address.

The [Test workflow](.github/workflows/test.yml) runs on every push to `main` and every pull request: gitleaks over the tree and the full history (the binary checked against a pinned SHA-256), then the hashed install, `ruff check`, `pip-audit` on the production lock, and `pytest`. A second job applies every migration to PostgreSQL 16, then reverses and reapplies the newest one. A third builds the production image and imports the application inside it, without pushing anything. How migrations are written is in [`docs/migrations.md`](docs/migrations.md).

## Dependencies and supply chain

| File | Contents |
|---|---|
| `requirements.in` | direct production dependencies, pinned with `==` |
| `requirements-dev.in` | test-only additions (pytest, pytest-asyncio, aiosqlite) |
| `requirements.txt` | full production lock with hashes, installed in the image |
| `requirements-dev.txt` | production lock plus test tools, with hashes, installed in CI |

Everything installs with `--require-hashes`, so any package, direct or transitive, must match a hash in the lock. The image installs wheels only (`--only-binary=:all:`), so no package runs `setup.py` at build time, and it never contains the test tools. To add or bump a package, edit the `.in` file and regenerate both locks with the `uv pip compile` commands at the top of `requirements.in`; they exclude releases newer than a date about two weeks back. Commit the `.in` and `.txt` files together.

- The base image `python:3.12-slim` is pinned by digest. Every GitHub Action is pinned to a commit SHA.
- Dependabot proposes weekly updates for pip, GitHub Actions and the Docker base image.
- Vendored third-party files are listed with their versions and hashes in [`docs/vendored-assets.md`](docs/vendored-assets.md), and a test fails if one changes without the table.

## Deploy

Cloud Run + Cloud SQL + Memorystore, with Cloud KMS for the vault. The [deploy workflow](.github/workflows/deploy-cloud-run.yml) runs on every push to `main`: it runs the Test workflow, then deploys through the `production` environment, one deploy at a time.

See [`infra/gcp/README.md`](infra/gcp/README.md) for setup, every deploy variable, and the hardening runbooks (runtime service account, migration job, Redis TLS, ingress).

## License

[FSL-1.1-ALv2](LICENSE.md). Copyright Rick Weng. You may read, audit, modify and self-host this code for any purpose except offering a competing commercial service. Two years after each version is released, it also becomes available under Apache 2.0.
