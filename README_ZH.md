<div align="center">

# Saturn Backend

**Saturn MCP 的 API：決定 AI Agent 可以做什麼的託管 Gateway。**

Agent 只呼叫一個 MCP 端點。Saturn 只讓每個 Agent 看到自己的工具集，每一次呼叫都先經過政策檢查，敏感的呼叫交給人核准，其餘的帶著密封的憑證轉送到真正的 MCP 伺服器，並記錄每一個步驟。

[![License: FSL-1.1-ALv2](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue.svg)](LICENSE.md)
![Python](https://img.shields.io/badge/python-3.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.162-009688.svg?logo=fastapi&logoColor=white)
[![Test](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/actions/workflows/test.yml/badge.svg)](https://github.com/Saturn-Technology-Project/Saturn-MCP-Backend/actions/workflows/test.yml)

[功能](#功能) · [架構](#架構) · [快速開始](#快速開始) · [政策](#政策與核准) · [安全](#安全) · [設定](#設定) · [部署](#部署) · [English](README.md)

</div>

---

## 這是什麼

Saturn MCP 位在 AI Agent 與它們使用的 MCP 伺服器之間。Agent 不再直接連到各個伺服器，而是連到 Saturn，以 OAuth 登入，並且只看得到組織放進它工具集的工具。每一次呼叫在送到上游伺服器之前都會先經過評估。

這個 repository 是 API：在 Cloud Run 上執行的 FastAPI 應用程式，搭配 Postgres 與 Redis。主控台 [dashboard.saturn-core.com](https://dashboard.saturn-core.com) 是另一個 repository（[Saturn-MCP-Frontend](https://github.com/Saturn-Technology-Project/Saturn-MCP-Frontend)），產品介紹在 [saturn-core.com](https://saturn-core.com)。桌面 Agent Saturn App 也可以像其他 MCP 用戶端一樣連到 Saturn MCP。

- **每個組織一個端點。** `POST /mcp` 以 HTTP 提供 MCP（`initialize`、`tools/list`、`tools/call`）。每個連上來的 OAuth 用戶端，都會成為登入成員的一個 Agent。
- **預設拒絕。** 沒有任何適用政策的呼叫會被拒絕；某個工具有規則但沒有任何規則符合時，也會被拒絕。
- **核准綁定在那一次呼叫上。** 一次核准只涵蓋一組參數與一個政策版本。任一項改變，核准即失效。
- **憑證與內容都經過密封。** 上游憑證以從 Cloud KMS 衍生的各租戶金鑰加密。審計內容則加密給組織自己持有的金鑰。

控制平面啟動時是**空的**。Bootstrap 只會建立一位平台管理員：沒有示範用的 Agent、工具、MCP 伺服器、政策或憑證。

## 功能

| | |
|---|---|
| **MCP Gateway** | `POST /mcp` 處理 JSON-RPC，`GET /mcp` 以 server-sent events 推送通知；`Mcp-Session-Id` 工作階段只由伺服器發出。OAuth 2.1，使用 PKCE（`S256`）與動態用戶端註冊，scope 為 `saturn.mcp`，可從 `/.well-known/oauth-protected-resource` 與 `/.well-known/oauth-authorization-server` 探索。 |
| **Agent** | 每個連上來的 OAuth 用戶端與成員組合對應一個 Agent（每位成員最多 25 個，每個用戶端最多 5 個），也可以透過 `/agents` 建立。每個 Agent 有一個工具集。 |
| **MCP 伺服器** | 以 HTTPS URL 連接位於允許清單主機上的上游伺服器，使用固定的授權標頭或 OAuth（探索、動態註冊、token 更新）。連接與重新整理時會探索它的工具。 |
| **工具集** | 由探索到的工具組成的具名群組。工具集中的項目可以標記為一律需要核准。 |
| **政策** | 針對各工具、依參數值（`gt`、`gte`、`lt`、`lte`、`eq`、`ne`）設定的規則，決定 `allow`、`approval` 或 `deny`。可驗證、模擬再啟用；也可以讓你設定的模型草擬規則。 |
| **核准** | 核准策略可設定所需人數、群組要求、是否允許申請人自行核准，以及有效期限。投票依成員記錄；呼叫最多只會執行一次。 |
| **Webhook** | 將簽章過的 `approval.granted`、`approval.rejected`、`approval.expired` 事件送到 HTTPS 端點，含重試與傳送紀錄（[`docs/webhooks.md`](docs/webhooks.md)）。 |
| **組織** | 成員、邀請、角色（`admin`、`operator`、`viewer`、`custom`）、群組，以及每位成員可使用的 Agent 與 MCP 伺服器對應。 |
| **憑證金庫** | 每個租戶使用 ML-KEM-1024 與 AES-256-GCM，金鑰從 Cloud KMS 的 HMAC 金鑰衍生。秘密只能寫入，無法透過 API 讀回。 |
| **活動紀錄** | 記錄每個步驟的審計紀錄，可篩選並匯出為 JSON。工具參數與上游內容會加密給組織的 ML-KEM 酬載金鑰，以及已核准成員的金鑰。 |
| **帳號** | Email 與密碼、含備用碼的 TOTP、Email 驗證碼、passkey（WebAuthn）、重新驗證身分、重設密碼。 |
| **平台管理** | 建立組織，跨租戶檢視成員、Agent、連線、MCP 使用情況與審計紀錄，但看不到工具內容。 |

## 架構

```mermaid
flowchart LR
  C["MCP 用戶端<br/><sub>一個 Agent</sub>"] -- "OAuth bearer · /mcp" --> G
  F["主控台<br/><sub>dashboard.saturn-core.com</sub>"] -- "session token" --> API
  subgraph API["Saturn Backend · Cloud Run 上的 FastAPI"]
    G["Saturn MCP Gateway"] --> P["政策引擎"]
    P --> A["核准"]
    A --> E["執行器"]
    E --> L["審計紀錄"]
    V["憑證金庫"] --> E
  end
  E -- "HTTPS" --> U["上游 MCP 伺服器"]
  API --> DB[("Postgres")]
  API --> R[("Redis")]
  V -- "MAC 簽章" --> K["Cloud KMS"]
```

### 執行迴圈

**Run → Agent → Tool → Policy → Approval → Execute → Audit**

| 步驟 | 做什麼 | 程式碼 |
|---|---|---|
| **Run** | 一次 `tools/call` 會開啟一個 run 與一個 action。Agent 重新送出已核准的呼叫時，把 `approval_required` 錯誤中的 run id 填入 `saturnRunId`；每個對外提供的工具 schema 都帶有這個欄位。 | `features/mcp/saturn`、`features/execution/runs` |
| **Agent** | bearer token 對應到一位成員與一個 OAuth 用戶端，用戶端再對應到該成員擁有的 Agent。 | `features/identity/oauth`、`features/agent` |
| **Tool** | 只有 Agent 工具集中啟用的工具會被列出或可以呼叫，其他一律拒絕。 | `features/tooling` |
| **Policy** | 每個適用於該 Agent 的啟用中政策，都對這個工具與參數給出意見，最嚴格的意見勝出。 | `features/policy` |
| **Approval** | `approval_required` 會建立一筆待核准請求，綁定參數的金鑰化摘要、政策版本與核准策略版本。 | `features/execution/approvals` |
| **Execute** | 核准（或允許）後，呼叫以原子操作取得執行權，再帶著金庫中的憑證送到上游 MCP 伺服器。 | `features/mcp/servers`、`features/credentials` |
| **Audit** | 每個步驟（`tool_requested`、`policy_evaluated`、`approval_requested`、`approval_granted`、`execution_claimed`、`tool_executed`……）都寫入審計紀錄。 | `features/execution/activity` |

Agent 錢包與 x402 付款以前是這個迴圈的一部分。遷移 `039_drop_wallets_x402` 已將它們移除。

### 目錄結構

程式碼先依功能分組，再依職能分組。每個職能有自己的 `models/`、`services/`、`controllers/`，多數也有 `routes/`。

```
app/
  main.py          應用程式、middleware 與 router 掛載
  core/            設定、ID、列舉、安全標頭、來源驗證、速率限制
  db/              資料庫引擎與初始資料
  models/          ORM 註冊表（`from app.models import …`）
  schemas.py       共用的請求與回應模型
  shared/          跨功能的關聯表、分頁、執行環境檢查
  cli/             一次性的維護指令（`python -m app.cli.pq1`）
  features/
    identity/      auth（工作階段、MFA、passkey）、oauth（MCP 的授權伺服器）
    organization/  org：成員、邀請、群組、對應、訂閱
    platform/      admin
    agent/         agents
    mcp/           servers、oauth（上游登入）、saturn（Gateway）
    policy/        政策、政策圖、模型草擬的規則
    execution/     runs、approvals、activity（審計、酬載金鑰）
    tooling/       tools、tool sets
    credentials/   vault
    webhooks/      端點、傳送紀錄、背景 worker
    billing/       payments（保留位置）
```

`app/main.py` 掛載每個職能的 router。HTTP handler 放在 `controllers/`；`routes/` 是掛載點。Postgres 的 schema 變更是 `alembic/versions/` 中的 Alembic 遷移。

## 快速開始

這個 repo 是 API。主控台與管理後台是另外的 repository。

### 需求

- Docker 與 Compose，用來執行 Postgres 16、Redis 7 與 API。
- 一把 Cloud KMS HMAC 金鑰，以及可以用它簽章的 Google 憑證。API 啟動時會透過 KMS（`SATURN_KMS_KEY`）衍生租戶金鑰，無法衍生就停止。只有測試套件不需要它，測試使用固定的本機金鑰。

### 執行

```bash
cp .env.example .env
# 填入 POSTGRES_PASSWORD 與 REDIS_PASSWORD（例如 `openssl rand -hex 16`）、
# SEED_USER_EMAIL 與 SEED_USER_PASSWORD，並加上 SATURN_KMS_KEY。
docker compose up --build
```

第一次啟動前，先在 `.env` 設定 `SEED_USER_EMAIL` 與 `SEED_USER_PASSWORD`，這兩個值會建立平台管理員。不要 commit 它們。沒有設定 `POSTGRES_PASSWORD` 與 `REDIS_PASSWORD` 時，Compose 會拒絕啟動。

- API：http://localhost:8000
- 文件：http://localhost:8000/docs（在 Cloud Run 上，或任何設定 `EXPOSE_API_DOCS=false` 的環境中關閉）
- 健康檢查：`GET /health` 只要行程在服務就回 `{"status":"ok"}`，不檢查其他東西，所以探測不會因為某個依賴出問題而失敗。`GET /status` 回報每個服務（API、資料庫，以及有使用時的 Redis）；一律回 200，結果在內容裡，五秒內重複使用同一份。`GET /status/history` 回傳每個服務過去 90 天每天的可用率：worker 每分鐘檢查每個服務一次（API 是經由對外網址檢查），把結果累計到 `status_days` 當天那一列。主控台公開的 `/status` 頁面會把這兩者畫出來
- Postgres：127.0.0.1:5433（使用者 `saturn`，密碼為 `POSTGRES_PASSWORD`）
- Redis：127.0.0.1:6379（密碼為 `REDIS_PASSWORD`）

Postgres 與 Redis 只監聽 127.0.0.1。API 容器以非特權使用者（uid 10001）執行，掛載工作目錄並在變更時重新載入。啟動時會套用遷移，除非設定 `RUN_MIGRATIONS=false`。

## 驗證與 API

```bash
TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$SEED_USER_EMAIL\",\"password\":\"$SEED_USER_PASSWORD\"}" | python -c 'import sys,json; print(json.load(sys.stdin)["token"])')

curl -s localhost:8000/auth/me -H "Authorization: Bearer $TOKEN"
```

API 接受以 `Authorization: Bearer` 或主控台使用的 `saturn_session` cookie 帶入工作階段 token。`/auth/login` 在 10 分鐘內，每個來源位址最多 20 次、每個帳號最多 10 次嘗試。

**管理員必須先設定 passkey 或 TOTP。** 平台管理員或組織管理員（`team.write`）若 passkey 與驗證器 App 都沒有設定，除了 `/auth/me`、`/auth/logout`、`/auth/mfa…`、`/auth/totp…`、`/auth/passkeys…`、`/auth/reauth…` 與健康檢查之外，每個路由都會回傳 `403 MFA setup is required`。兩者擇一即可。passkey 需要瀏覽器，請在主控台（`/mfa`）新增。驗證器 App 可以用工作階段 token 設定：

```bash
curl -s -X POST localhost:8000/auth/totp/setup -H "Authorization: Bearer $TOKEN"
# 把回傳的 otpauth_url 加到驗證器 App，保存備用碼，然後：
curl -s -X POST localhost:8000/auth/totp/confirm \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

之後 `/auth/login` 會回傳 `mfa_required`，並附上 `challenge` 與 `methods`。`methods` 包含 `totp` 時，以 `POST /auth/login/totp` 與 `{"challenge": …, "code": …}` 完成登入。其他方式是 `email`（透過 Resend 寄出的驗證碼，`POST /auth/login/email`）與 `passkey`（先 `POST /auth/login/passkey/options`，再 `POST /auth/login/passkey`）。持有 passkey 的管理員以 `POST /auth/login/email` 送出驗證碼後不會完成登入：回應仍是 `mfa_required`，附上同一個 `challenge` 與還需要完成的方式。

代理人登入頁（`/oauth/authorize`）接受相同的驗證方式。passkey 綁定在主控台的來源，因此該頁會連到主控台的 `/connect-passkey`，由它要求 passkey，再把結果送到 `POST /oauth/login/passkey`。

其他帳號路由：以 Email 驗證碼自行註冊（`/auth/register/code`、`/auth/register`）、`/auth/forgot-password` 與 `/auth/reset-password`、`/auth/passkeys`、`/auth/reauth`，以及 `PATCH /auth/password`。

## 組織與角色

組織就是租戶。使用者以員工身分屬於一個組織，並擁有該組織內的存取權限：

- `agents` / `policies` / `approvals` / `team` → `none` | `read` | `write`
- 角色：`admin`、`operator`、`viewer` 或 `custom`

| 角色 | agents | policies | approvals | team |
|---|---|---|---|---|
| `admin` | write | write | write | write |
| `operator` | write | read | write | none |
| `viewer` | read | read | read | none |
| `custom` | 依成員個別設定 | | | |

```bash
curl -s localhost:8000/org -H "Authorization: Bearer $TOKEN"
curl -s localhost:8000/org/members -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:8000/org/invites \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"ops@saturn.ai","name":"Ops","role":"operator"}'
```

邀請連結會以 Email 寄給受邀者，需要設定 `RESEND_API_KEY` 與 `RESEND_FROM`；沒有設定時邀請會回傳 503。只有在本機開發（`IN_PROCESS_RUNTIME=true` 且沒有 `K_SERVICE`）時，回應才會包含一次性的 `token`。成員以 `POST /auth/accept-invite` 設定密碼。只有類型為 `organization` 的組織可以邀請成員，個人帳號不行。組織必須保留至少一位管理員（`team.write`）。

邀請以及 `PATCH /org/members/{employee_id}` 也可以把成員限定在指定的 Agent 與 MCP 伺服器。群組（`/org/groups`）用來為核准要求集合成員。

### 平台管理員

Bootstrap 建立的使用者是平台管理員（`is_platform_admin`）。管理後台用以下端點建立租戶並檢視整體狀況：

```bash
curl -s localhost:8000/admin/stats -H "Authorization: Bearer $TOKEN"
curl -s localhost:8000/admin/orgs -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:8000/admin/orgs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme","admin_email":"admin@acme.test","admin_name":"Acme Admin","admin_password":"password1"}'
curl -s localhost:8000/admin/users -H "Authorization: Bearer $TOKEN"
```

`admin_password` 只在本機開發與測試中使用；正式環境會寄一組驗證碼給新的管理員，由他自己設定密碼。建立組織時也會建立該組織的預設政策。平台管理的審計檢視（`/admin/audit`）不會包含工具參數或上游內容。

## MCP Gateway 與連接器

### 連接 Agent

把 API 的 `/mcp` URL 交給 MCP 用戶端。用戶端第一次請求會收到 `401`，`WWW-Authenticate` 標頭指向 protected-resource metadata；用戶端接著在 `/oauth/register` 註冊自己，並把成員導向 `/oauth/authorize`（登入與同意頁面由這個 API 提供）取得 token。metadata、連結與 callback URL 都取自 `PUBLIC_WS_URL`，不取自請求的 `Host` 標頭。

`initialize` 時，用戶端會成為該成員擁有的 Agent。使用相同 OAuth client ID 重新連線會沿用原本的 Agent；新的 client ID 會建立獨立 Agent，即使註冊名稱或回呼網域相同，也必須在主控台重新分配工具權限。`tools/list` 回傳 Agent 的工具集；`tools/call` 執行[執行迴圈](#執行迴圈)。

### 上游 MCP 伺服器

```bash
curl -s -X POST localhost:8000/mcp-servers \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Context7","endpoint":"https://mcp.context7.com/mcp"}'
```

連接、重新整理與移除伺服器需要 `team.write`。端點必須是 443 埠的 HTTPS、URL 中不含帳密、主機在 `ALLOWED_MCP_HOSTS`（`app/features/mcp/servers/services/mcp_endpoint.py`）之中，而且解析出的每個位址都必須是公開位址。要求 OAuth 的伺服器以 `POST /mcp-servers/oauth/start` 連接：Saturn 會探索它的授權伺服器，能註冊時就註冊用戶端，最後在 `${PUBLIC_WS_URL}/mcp-servers/oauth/callback` 完成。GitHub（`api.githubcopilot.com`）與 Google（`*.googleapis.com`）使用預設的 OAuth App，來自 `SATURN_GITHUB_OAUTH_CLIENT_ID` / `_SECRET` 與 `SATURN_GOOGLE_OAUTH_CLIENT_ID` / `_SECRET`。伺服器 metadata 指向的每個 URL，都要通過相同的 HTTPS 與公開位址檢查。token 過期或被伺服器拒絕時會自動更新。

探索到的工具會出現在 `/tools`。用 `/tool-sets` 把它們分組，再把工具集指派給各個 Agent。

## 政策與核准

### 政策

政策是一組規則。每條規則指定一個工具、可選的參數條件，以及一個決定：`allow`、`approval` 或 `deny`。條件以 `gt`、`gte`、`lt`、`lte`、`eq` 或 `ne`（也接受 `>`、`<=`、`==` 等寫法）比較參數，彼此以 AND 連接。政策狀態為 `active` 時，適用於組織中的每個 Agent，或它所指定的 Agent。

決定的方式：

1. 在清單式政策中，依位置第一條符合的規則決定。在圖形政策（有 `definition.nodes` 的政策）中，符合的規則裡最嚴格的那條決定。
2. 政策有這個工具的規則但沒有任何一條符合時，它的意見是 `deny`。
3. 跨政策時，最嚴格的意見勝出：`deny` 優先於 `approval_required`，`approval_required` 優先於 `allow`。不同政策之間從不比較位置。
4. 完全沒有適用的政策時，呼叫會被拒絕，除非設定 `POLICY_DEFAULT_DENY=false`。

工具集中標記為需要核准的項目，不論政策怎麼說都需要核准。建立組織時產生的預設政策，允許權限為唯讀的工具，`write`、`admin` 與 `mutate` 則需要核准；連接伺服器時會把新工具的規則加進去。既有組織不會被改寫。

`/policies/{id}/validate`、`/simulate` 與 `/activate` 用來在政策生效前檢查它。`/policies/generate` 與 `/policies/{id}/optimize`（各自也有 `/stream` 版本）會請 `POLICY_LLM_BASE_URL` 上的模型為每個工具提出一條規則。模型無法啟用政策，它沒有分類的工具維持拒絕，而且這些路由每小時每位成員限 20 次、每個組織限 60 次。

### 核准

核准策略（`/org/approval-policies`）設定一個請求需要幾份核准、由哪些群組提供（每一票最多填補一個群組席位）、申請人是否可以核准自己的請求，以及請求可以等待多久、核准後的呼叫可以在多久內重新送出。組織的預設值在 `/org/approval-window`：兩者都是 1,440 分鐘，範圍從 1 分鐘到 7 天。

程式碼強制執行的規則：

- **每位成員一票。** 只有所需群組中的在職成員可以投票。沒有核准策略時，只要還有其他核准人，申請人就不能核准自己的請求。
- **綁定在那一次呼叫上。** 執行前會比對參數與核准時的摘要，並重新評估政策。參數改變、政策版本改變或核准策略改變，都會讓核准失效（`409`）。政策若已改為拒絕，則直接駁回。
- **最多執行一次。** 核准以條件式更新離開待核准狀態，執行權在呼叫上游之前就已取得並 commit。上游執行後若發生錯誤，結果會記為不確定，不會自動重試。
- **到期。** API 行程中的 worker（`SATURN_EMBED_WORKER`）每 5 秒檢查一次，讓到期的核准失效並傳送 Webhook。

審核者使用 `GET /approvals` 與 `POST /approvals/{id}/approve`、`/reject` 或 `/cancel`。Agent 透過 Webhook，或以相同參數加上 `saturnRunId` 再次呼叫同一個工具，得知結果。

## 計費

Saturn 是免費的。每個方案（`free`、`pro`、`team`、`enterprise`）都有全部功能，方案目錄中的每個方案價格都是 0.00。保留方案名稱與檢查，是為了讓已儲存的方案仍能正確解析。`GET /org/subscription` 回報組織的方案。`GET /payments` 是保留給 Stripe 的路由，回傳空清單；它不會收費，也不會儲存任何資料。

Agent 錢包與 x402 付款已經移除（遷移 `039_drop_wallets_x402`）。

捐款透過 [GitHub Sponsors](https://github.com/sponsors/Saturn-Technology-Project)。

## 設定

設定來自環境變數（或 `.env`），參見 `.env.example`。應用程式設定，來自 `app/core/config.py`：

| 變數 | 預設值 | 作用 |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://saturn:saturn@localhost:5432/saturn` | 資料庫。Compose 以 `POSTGRES_PASSWORD` 組出它。 |
| `REDIS_URL` | `redis://localhost:6379/0` | 速率限制與 MCP 工作階段。Compose 以 `REDIS_PASSWORD` 組出它。 |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `5` / `10` | 每個行程保留的連線數，以及負載時可以多開幾條。instance 數 × 兩者總和必須低於資料庫的連線上限。 |
| `DB_POOL_TIMEOUT` | `10` | 請求等待空閒連線的秒數，超過即失敗 |
| `DB_POOL_RECYCLE` | `1800` | 連線池中的連線使用多少秒後換新 |
| `DB_COMMAND_TIMEOUT` | `60` | 單一 SQL 可以執行的秒數。`0` 表示不限制。 |
| `LOG_LEVEL` | `INFO` | 寫到 stdout 的最低等級 |
| `LOG_FORMAT` | Cloud Run 上為 `json`，其他為 `text` | 每行一個 JSON 物件，含 `severity`、`request_id` 與 Cloud Trace id，或純文字。每個請求記錄一行：方法、路徑、狀態碼、耗時；query string 一律不記錄。 |
| `DEFAULT_ORG_ID` | `org_saturn` | Bootstrap 組織的 ID |
| `DEFAULT_ACTOR_ID` | `user_operator` | Bootstrap 平台管理員的 ID |
| `SEED_USER_EMAIL` / `SEED_USER_PASSWORD` | 空 | 第一次啟動時建立平台管理員；留空則略過。在 Cloud Run 上密碼必須至少 16 個字元。 |
| `SEED_USER_NAME` | `Admin` | 它的顯示名稱 |
| `SKIP_DB_BOOTSTRAP` | `false` | `true` 會略過初始資料與啟動時的資料庫工作 |
| `SESSION_TTL_DAYS` | `7` | 工作階段的有效天數；24 小時沒有請求的工作階段也會結束 |
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:3001,https://dashboard.saturn-core.com` | 允許的瀏覽器來源，也是 cookie 請求與 passkey 信任的來源 |
| `IN_PROCESS_RUNTIME` | `false` | 只用於本機開發與測試：在行程內執行 run，速率限制與 MCP 工作階段存在記憶體中，回傳邀請 token |
| `POLICY_DEFAULT_DENY` | `true` | 沒有適用政策時拒絕呼叫 |
| `SATURN_EMBED_WORKER` | `true` | 在 API 行程中執行核准到期與 Webhook 的 worker |
| `SATURN_SECRET_PROJECT` | 空 | 用於 Secret Manager 的 Google Cloud 專案；留空則把密封的秘密存在資料庫 |
| `RESEND_API_KEY` / `RESEND_FROM` | 空 | 寄送邀請、驗證碼與通知的 Email 服務 |
| `POLICY_LLM_BASE_URL` / `POLICY_LLM_API_KEY` / `POLICY_LLM_MODEL` | 空 | 用於草擬政策規則、相容 OpenAI 的 `/chat/completions` 端點 |
| `LEGACY_PASSWORD_UNTIL` | 空 | ISO 日期，過了這天舊版（argon2 之前）密碼就不能再使用；留空表示沒有期限 |

直接從行程環境讀取：

| 變數 | 預設值 | 作用 |
|---|---|---|
| `SATURN_KMS_KEY` | 無，必填 | Cloud KMS MAC 金鑰的完整 `…/cryptoKeyVersions/N` 名稱，租戶金鑰由它衍生 |
| `PUBLIC_WS_URL` | 本機為請求的 base URL；Cloud Run 上必填 | OAuth metadata、連結與 callback 使用的公開來源（`wss://` 與 `ws://` 對應到 `https://` 與 `http://`） |
| `SATURN_GITHUB_OAUTH_CLIENT_ID` / `_SECRET` | 未設定 | GitHub MCP 伺服器使用的 OAuth App |
| `SATURN_GOOGLE_OAUTH_CLIENT_ID` / `_SECRET` | 未設定 | Google MCP 伺服器使用的 OAuth 用戶端 |
| `ORIGIN_AUTH_SECRET` | 未設定 | 除了 `/health` 之外，每個請求都必須帶上的共用秘密；Cloud Run 上必填 |
| `ORIGIN_AUTH_SECRET_PREVIOUS` | 未設定 | 輪替期間也接受的舊秘密 |
| `CONSOLE_PROXY_SECRET` | 未設定 | 與主控台共用；設定後，API 以主控台轉送的瀏覽器位址（`X-Saturn-Client-IP`）做速率限制 |
| `CONSOLE_PROXY_SECRET_PREVIOUS` | 未設定 | 輪替期間也接受的舊秘密 |
| `MCP_OAUTH_COOKIE_DOMAIN` | 自動推導 | 把 MCP 登入綁定到發起瀏覽器的 cookie 網域；預設為主控台與 API 共用的上層網域 |
| `SATURN_REQUIRE_BOUND_SECRETS` | 未設定 | 設為 `true` 時，拒絕尚未綁定到所屬項目的金庫值（`pq2.`）；請在重新封裝後再設定 |
| `ORIGIN_AUTH_HEADER` | `X-Saturn-Origin-Auth` | 攜帶它的標頭 |
| `EXPOSE_API_DOCS` | `true` | `false` 會關閉 `/docs`、`/redoc` 與 `/openapi.json`；在 Cloud Run 上一律關閉 |
| `K_SERVICE` | 由 Cloud Run 設定 | 標示正式環境：關閉文件、必須有來源驗證與 `PUBLIC_WS_URL`、cookie 一律為 `Secure`、回應中不含邀請 token |

容器另外讀取：

| 變數 | 預設值 | 作用 |
|---|---|---|
| `RUN_MIGRATIONS` | `true` | `false` 會在容器啟動時略過 `alembic upgrade head`（正式環境改在 Cloud Run Job 中執行） |
| `MIGRATION_LOCK_WAIT` | `300s` | 遷移等待另一個執行者的 advisory lock 的時間上限 |

## 安全

本節說明程式碼實際做了什麼。部署面的內容（身分、Redis TLS、Cloud SQL、ingress）見 [`infra/gcp/README.md`](infra/gcp/README.md)。

### 帳號與工作階段

- **密碼**以 Argon2id 雜湊儲存（time cost 2、19 MiB 記憶體、parallelism 1），長度至少 8 個字元。OAuth 登入頁面會在瀏覽器中，以內附的 Argon2 程式先雜湊密碼再送出。不存在的 Email 與錯誤密碼花費相同的時間。仍使用舊版（argon2 之前）PBKDF2 雜湊的帳號，在 `LEGACY_PASSWORD_UNTIL` 之前可以登入，之後必須重設密碼。
- **工作階段**是隨機 token，只以 SHA-256 雜湊儲存。超過 `SESSION_TTL_DAYS` 或閒置 24 小時就會失效。cookie 為 `HttpOnly`、`SameSite=Lax`，除了本機純 HTTP 執行之外一律 `Secure`。以 cookie 驗證的狀態變更必須來自受信任的來源。
- **MFA。** TOTP（RFC 6238，6 位數，每組驗證碼只接受一次，失敗 5 次後鎖定 15 分鐘），附 8 組以雜湊儲存的備用碼；TOTP 秘密密封在金庫中。Email 驗證碼，只在沒有啟用 TOTP 時提供。透過 WebAuthn 的 passkey。管理員必須設定 passkey 或 TOTP，而且持有其中之一的管理員無法只靠 Email 驗證碼登入。
- **重新驗證。** 變更帳號 Email、關閉 Email 驗證碼與刪除 passkey，都需要在最近 10 分鐘內登入過（`/auth/reauth`）。

### 憑證金庫

憑證與上游 OAuth token 以 ML-KEM-1024 與 AES-256-GCM 密封。每個組織，以及個人秘密所屬的每位使用者，都有自己的金鑰，由 Cloud KMS 對一段標記字串計算的 MAC 衍生。根金鑰從不離開 KMS，一個租戶的金鑰打不開另一個租戶的密文，資料庫或行程的副本中也沒有根金鑰。密封的秘密存在資料庫；設定 `SATURN_SECRET_PROJECT` 時，改以各租戶雜湊過的名稱存在 Secret Manager。`GET /org/credentials/secrets` 一律回傳 403：秘密只進不出。

### 審計內容

審計紀錄中的工具參數、原始請求與上游回應，會加密給組織的 ML-KEM-1024 酬載金鑰，以及已核准成員的金鑰。伺服器為每把公鑰封裝一把資料金鑰後就丟棄；它從不儲存或接受組織私鑰、成員私鑰或復原金鑰（`/org/payload-keys`）。沒有註冊任何金鑰時，這些內容不會被儲存。平台管理的回應永遠拿不到它們。組織沒有酬載金鑰時，待核准請求將要執行的參數改以從 KMS 衍生的組織金鑰密封；把核准綁定到參數的摘要，也是以 KMS 衍生金鑰計算的 HMAC，所以單憑資料庫副本無法用來驗證金額之類的猜測。已核准的呼叫為了重送而保留的結果，也以同樣方式密封；`python -m app.cli.seal_results --apply` 會把舊版以明文儲存的結果補上密封。

規則本身的變更也會記錄：建立、編輯、啟用、暫停或刪除政策，變更工具集或把它指派給 Agent，邀請成員或變更其角色、狀態與指派，以及移除 Agent 或 MCP 伺服器。有 team 權限的成員可以用 `GET /activity/changes` 查看。這些紀錄只包含 ID、名稱與變更前後的狀態，不含工具內容。

### 網路暴露面

- **對外。** MCP 端點，以及它的 OAuth metadata 指向的每個 URL，都必須是 443 埠的 HTTPS、不含帳密、不是 IP 字面值或 metadata 主機，而且只解析到公開位址。MCP 端點還必須在允許清單中。Webhook 目的地必須是標準埠的 HTTPS。
- **對內。** 在 Cloud Run 上，除了 `/health` 之外的每個請求都必須帶有 `ORIGIN_AUTH_SECRET`，所以只有邊緣代理能連到服務。`/health` 只說明行程是否在服務。（`/healthz` 是同一個路由的舊名稱；Cloud Run 保留了這個路徑，不會轉給服務。）
- **用戶端位址。** uvicorn 只信任來自 127.0.0.1 的 `X-Forwarded-*`。速率限制只有在來源驗證證明請求經過 Cloudflare 時才採用 `CF-Connecting-IP`，否則採用 `X-Forwarded-For` 最右邊的項目。
- **速率限制**計數在 Redis 中，失敗時拒絕：連不到 Redis 時，受限制的路由會拒絕請求。
- **請求大小。** 請求 body 超過 4 MiB 會被拒絕，登入與 OAuth 路由則是 64 KiB，在任何 handler 讀取之前就擋下。
- **標頭。** 每個回應都帶有嚴格的 Content-Security-Policy（API 為 `default-src 'none'`，OAuth 頁面使用每個請求各自的 nonce）、`X-Frame-Options: DENY`、`nosniff`、`Referrer-Policy: no-referrer` 與 Permissions-Policy；HTTPS 回應另加 HSTS。未處理的錯誤只回傳通用的 500。
- **本機。** Compose 把 Postgres 與 Redis 綁定在 127.0.0.1，兩者都必須設定密碼。

## 測試

Python 3.12。

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements-dev.txt
pytest
```

測試在記憶體中的 SQLite 上執行，使用 `IN_PROCESS_RUNTIME=true` 與固定的本機金庫金鑰，所以不需要 Postgres、Redis、KMS 或網路。Pytest 會載入本機的工具目錄 fixture（`tests/catalog.py`），讓執行迴圈的測試不依賴正式環境的初始資料。MCP 端點的 DNS 查詢會被替換成一個公開位址。

[Test workflow](.github/workflows/test.yml) 在每次推送到 `main` 與每個 pull request 時執行：先以 gitleaks 掃描目前的檔案與完整歷史（執行檔以固定的 SHA-256 核對），再以雜湊驗證安裝，接著執行 `ruff check`、對正式環境鎖檔執行 `pip-audit`，最後執行 `pytest`。另一個 job 會把所有遷移套用到 PostgreSQL 16，再把最新的一支復原後重新套用。第三個 job 會建置正式映像並在映像裡匯入應用程式，不會推送任何東西。遷移的寫法見 [`docs/migrations.md`](docs/migrations.md)。

## 相依套件與供應鏈

| 檔案 | 內容 |
|---|---|
| `requirements.in` | 正式環境的直接相依套件，以 `==` 鎖定 |
| `requirements-dev.in` | 只用於測試的額外套件（pytest、pytest-asyncio、aiosqlite） |
| `requirements.txt` | 含雜湊的完整正式環境 lock，安裝在映像檔中 |
| `requirements-dev.txt` | 正式環境 lock 加上測試工具，含雜湊，在 CI 中安裝 |

所有套件都以 `--require-hashes` 安裝，所以任何套件，不論直接或間接相依，都必須符合 lock 中的雜湊。映像檔只安裝 wheel（`--only-binary=:all:`），建置時不會有任何套件執行 `setup.py`，映像檔中也不含測試工具。新增或升級套件時，編輯 `.in` 檔，再以 `requirements.in` 開頭的 `uv pip compile` 指令重新產生兩份 lock；這些指令會排除約兩週內才發布的版本。`.in` 與 `.txt` 檔要一起 commit。

- 基礎映像檔 `python:3.12-slim` 以 digest 鎖定。每個 GitHub Action 都鎖定到 commit SHA。
- Dependabot 每週為 pip、GitHub Actions 與 Docker 基礎映像檔提出更新。
- 內附的第三方檔案連同版本與雜湊列在 [`docs/vendored-assets.md`](docs/vendored-assets.md)，任何一個檔案改變而表格沒有跟著改時，測試會失敗。

## 部署

Cloud Run + Cloud SQL + Memorystore，金庫使用 Cloud KMS。[部署 workflow](.github/workflows/deploy-cloud-run.yml) 在每次推送到 `main` 時執行：先跑 Test workflow，再透過 `production` environment 部署，一次只執行一個部署。

設定方式、所有部署變數與強化作業手冊（runtime service account、遷移 Job、Redis TLS、ingress）見 [`infra/gcp/README.md`](infra/gcp/README.md)。

## 授權

[FSL-1.1-ALv2](LICENSE.md)。著作權屬於 Rick Weng。你可以為任何目的閱讀、稽核、修改與自行架設這份程式碼，但不得用來提供與之競爭的商業服務。每個版本發布兩年後，也會以 Apache 2.0 授權提供。
