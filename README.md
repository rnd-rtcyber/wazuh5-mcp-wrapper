# Wazuh 5 MCP Server (Wrapper)

A minimal, deployable trim of [`gensecaihq/Wazuh-MCP-Server`](https://github.com/gensecaihq/Wazuh-MCP-Server): the same MCP (Model Context Protocol) remote server, stripped down to just the runtime code needed to serve both the original Wazuh 4.x tool set and the Wazuh 5 tool set built on top of it. No tests, installers, multi-cluster tooling, or audit docs — just the server.

It exposes Wazuh SIEM data and actions (agents, alerts, vulnerabilities, rules, decoders, active response, and — on Wazuh 5 — Sigma rules, Detectors, and content promotion) as MCP tools that an LLM client (Claude Desktop, Claude Code, or any other MCP client) can call over HTTP.

## Why this exists

Wazuh 5 is architecturally different enough from 4.x that "does the MCP server support Wazuh 5" isn't a yes/no question — see [How it works](#how-it-works) below. This wrapper is the trimmed set of files needed to actually run that support, split out of a larger fork used for day-to-day Wazuh 4→5 migration and rule-translation work, so it can be deployed on its own without dragging in everything else in that repo.

## What's included

```
src/wazuh_mcp_server/
  server.py           FastAPI app: MCP protocol handling, all tool schemas + dispatch
  config.py           .env loading / validation (WazuhConfig)
  auth.py             API key + JWT bearer auth
  oauth.py            OAuth 2.0 mode (optional alternative to bearer)
  security.py         Input validation, rate limiting, log sanitization
  session_store.py    In-memory or Redis-backed MCP session state
  monitoring.py       Structured logging, Prometheus metrics, health checks
  resilience.py       Circuit breaker / retry logic for upstream calls
  clusters.py         Multi-cluster registry (optional; single-cluster works without it)
  gcf_format.py       Optional compact response encoding (RESPONSE_FORMAT=gcf)
  api/
    wazuh_client.py    Wazuh 4.x manager REST client
    wazuh_indexer.py   Wazuh 4.x Indexer client (alerts/vulnerabilities, 4.8.0+)
    wazuh5_client.py   Wazuh 5 client (manager + Indexer + dashboard, see below)
pyproject.toml, requirements.txt   Python packaging / dependencies
Dockerfile, compose.yml            Container build + run
.env.example                       All configuration options, documented inline
start.bat, start.ps1               One-command start: server + public HTTPS tunnel + bearer token
```

Left out on purpose: `tests/`, `installers/`, `tools/` (release tooling), `docs/` (this README replaces it), multi-cluster docs, and anything not on the import path of `python -m wazuh_mcp_server`.

## How it works

### Wazuh 4.x (the original design)

One manager REST API (port 55000, `/agents`, `/rules`, `/decoders`, `/active-response`, ...), plus — for alerts/vulnerabilities on 4.8.0+ — the Wazuh Indexer (OpenSearch, port 9200). `api/wazuh_client.py` and `api/wazuh_indexer.py` talk to those two respectively. This part needed no adaptation for Wazuh 5; it's unchanged.

### Wazuh 5 (what had to be added)

Wazuh 5 moved rule/decoder content off the manager entirely, and split it across **three** separate backends that happen to share a host in a typical single-node lab:

| Subsystem | Where it actually lives | Port |
|---|---|---|
| Agents (`GET /agents`) | Manager's classic REST API — **unchanged from 4.x** | 55000 |
| Rules (Sigma), search | Indexer's Security Analytics plugin | 9200 |
| Rules (Sigma), create/update/delete | The **dashboard's own Node.js server** — not the Indexer | 443 |
| Detectors, search + create/update/delete | Indexer's Security Analytics plugin, directly | 9200 |
| Decoders, search + create/update/delete/promote | Indexer's `_content_manager` plugin | 9200 |
| Content lifecycle (draft → test → custom), `logtest` | Indexer's `_content_manager` plugin | 9200 |
| CDB lists | **No equivalent exists** — confirmed absent, not just unshipped | — |

The rule-write-goes-through-port-443 finding is not documented anywhere in Wazuh's own materials — it was found by running `ss -tlnp` on the manager to see what was actually listening on which port, then reading the dashboard server's own `WazuhRuleService.buildRuleResource()` source to get the exact request shape it expects (including a required `osd-xsrf` header the Indexer route doesn't need). `api/wazuh5_client.py` implements all three backends (manager, Indexer, dashboard) as one client, and `server.py` routes each Wazuh 5 tool to whichever of the three actually owns that operation.

Because of this split, Wazuh 5 support needed **no changes to the MCP protocol layer itself** — it's plain application code: a new client module plus 15 new tool schemas and dispatch branches in `server.py`, configured through their own `WAZUH5_*` environment variables, completely independent of the 4.x `WAZUH_*` settings. A single server instance can serve a 4.x manager and a 5.x manager at the same time.

### Log accessibility (agent vs. syslog)

The decode → rule-evaluation pipeline is source-agnostic: once a log reaches the manager, it doesn't matter whether it arrived from an installed Wazuh agent or as a raw syslog message from an unmanaged device (e.g. a FortiGate). Both are decoded and evaluated against the same rules/decoders. The practical differences are elsewhere:
- **Agent-centric tools** (`get_wazuh_agents`, FIM, syscollector, active response) only mean something for agent-collected sources — there's no "agent" for a syslog sender.
- **Unmatched logs are discarded by default** regardless of source, unless archiving (`logall`/`logall_json`) is enabled on the manager — so "can I see this log" is really "did something match it, or is archiving on," not "did it come from an agent."

## Requirements

- Python 3.11+ (3.13 recommended — matches the Docker image)
- A reachable Wazuh 4.x manager (`WAZUH_HOST`/`WAZUH_USER`/`WAZUH_PASS`) — **required at startup even if you only care about Wazuh 5**, see [Configuration](#configuration)
- Optionally, a Wazuh 5 manager/Indexer/dashboard to enable the 15 Wazuh 5 tools
- Optionally, Docker + Docker Compose

## Installation

### Option A — one command, exposed on the internet (Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
rem edit .env — see Configuration below
start.bat
```

`start.bat` starts the MCP server *and* puts a public HTTPS tunnel in front of it in one step — see [Exposing it publicly](#exposing-it-publicly-start-bat) below for exactly what it does and how to swap the tunnel provider.

### Option B — local Python only, no tunnel

```bash
python -m venv .venv
. .venv/Scripts/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
# edit .env — see Configuration below
python -m wazuh_mcp_server
```

`python -m wazuh_mcp_server` does **not** load `.env` itself (see `config.py` — only a separate `./config/wazuh.env` path is auto-loaded). Either export the file into your shell's environment yourself first (`start.bat` does this for you on Windows; on Linux/macOS: `set -a; source .env; set +a`), or use Docker Compose below, which loads `.env` natively.

The server listens on `MCP_HOST:MCP_PORT` (default `0.0.0.0:3000`) over plain HTTP. Put a TLS-terminating reverse proxy (nginx/Caddy/Traefik) or a tunnel in front of it for anything beyond local testing — there's no built-in HTTPS listener.

### Option C — Docker Compose

```bash
cp .env.example .env
# edit .env
docker compose up -d --build
```

`compose.yml` binds to `127.0.0.1` by default (`MCP_BIND` env var to change), runs as a non-root user, and drops all capabilities. `curl http://localhost:3000/health` to confirm it's up.

## Configuration

Copy `.env.example` to `.env` and fill in at least the Wazuh 4.x block — `WAZUH_HOST`, `WAZUH_USER`, `WAZUH_PASS` are validated at startup and the server refuses to boot without them, **even in a Wazuh-5-only deployment**. If your only manager is a Wazuh 5 box, point these three at it anyway (its classic `/agents`-style REST API is unchanged from 4.x, so this works cleanly) and set the `WAZUH5_*` block below to the same host.

```bash
# Required, always
WAZUH_HOST=https://your-wazuh-manager.example.com
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password
WAZUH_PORT=55000

# Optional — enables 4.x alert/vulnerability tools (Wazuh Indexer, 4.8.0+)
WAZUH_INDEXER_HOST=your-indexer-host
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=admin

# Enables the 15 Wazuh 5 tools. Leave unset to disable them cleanly (a clear
# config error on use, not a broken 4.x tool set).
WAZUH5_HOST=your-wazuh5-server.example.com
WAZUH5_PORT=55000
WAZUH5_USER=wazuh-wui
WAZUH5_PASS=wazuh-wui
# Indexer defaults to WAZUH5_HOST if unset; set separately only if it's a different host.
WAZUH5_INDEXER_HOST=your-wazuh5-server.example.com
WAZUH5_INDEXER_PORT=9200
WAZUH5_INDEXER_USER=admin
WAZUH5_INDEXER_PASS=admin
# Dashboard (owns rule writes) defaults to the Indexer values if unset.
WAZUH5_DASHBOARD_HOST=your-wazuh5-server.example.com
WAZUH5_DASHBOARD_PORT=443
WAZUH5_DASHBOARD_USER=admin
WAZUH5_DASHBOARD_PASS=admin

# Auth (see "Connecting a client" below)
AUTH_MODE=bearer
AUTH_SECRET_KEY=            # required in ENVIRONMENT=production; run: openssl rand -hex 32
MCP_API_KEY=                # optional fixed key; auto-generated and logged on startup if unset
```

`.env.example` documents every other option inline (rate limiting, CORS, OAuth mode, Redis session storage, active-response rollback commands, response format). Read it before deploying to production.

## Exposing it publicly (`start.bat`)

`start.bat` (→ `start.ps1`) is the fastest path from a fresh checkout to a working Claude Desktop / Claude Code connector: it starts the server, puts a public HTTPS tunnel in front of it, mints a bearer token, and prints both the connector URL and the `Authorization` header ready to paste in. Run it again later and it reuses the existing tunnel if it's still alive instead of starting a new one.

```bash
start.bat
```

```
==================================================================
 MCP connector URL   : https://random-words-here.trycloudflare.com/mcp
 Authorization header: Bearer eyJhbGciOi...
==================================================================
```

**Tunnel provider — cloudflared by default, substitutable.** On first run, if `cloudflared.exe` isn't already sitting next to the script, it's downloaded automatically (the official Windows amd64 build, straight from Cloudflare's own GitHub releases) and used to open a free, no-signup Cloudflare quick tunnel. To use a different tunnel tool instead — ngrok, localtunnel, an SSH reverse tunnel, your own reverse proxy, anything that can expose a local HTTP port over HTTPS — set two environment variables before running `start.bat` (in `.env`, or in the shell):

```bash
# {URL} is replaced with the server's local address (e.g. http://127.0.0.1:3000)
MCP_TUNNEL_CMD=ngrok http {URL}
# Only needed if the built-in patterns (trycloudflare.com, ngrok, loca.lt) don't match
# your provider's log output — a regex the script uses to find the public URL in it.
MCP_TUNNEL_URL_REGEX=https://[a-zA-Z0-9\-\.]+\.example\.com
```

When `MCP_TUNNEL_CMD` is set, `start.bat` never touches `cloudflared.exe` and runs your command instead — bring your own binary.

**Caveats:** a Cloudflare quick tunnel is ephemeral — the URL rotates every time the tunnel restarts, and it can silently die server-side after several hours even while `cloudflared` keeps retrying locally (re-run `start.bat` if a previously-working connector URL stops responding). For anything long-lived, use a named Cloudflare Tunnel, a real reverse proxy with a certificate, or point `MCP_TUNNEL_CMD` at whatever your infrastructure already provides.

To stop both processes, use the PIDs printed at the end of the run, or `Stop-Process` on whatever's listening on `MCP_PORT` and on `cloudflared.exe`.

## Connecting a client (Claude Desktop, Claude Code, etc.)

If you used `start.bat` above, you already have the connector URL and bearer header — skip to step 3.

1. Start the server. On first boot with `AUTH_MODE=bearer` and no `MCP_API_KEY` set, it auto-generates one and logs it once (`wazuh_...`) — save it, or set `MCP_API_KEY` yourself.
2. Exchange the API key for a bearer token:
   ```bash
   curl -sX POST http://localhost:3000/auth/token \
     -H "Content-Type: application/json" \
     -d '{"api_key":"wazuh_your-key-here"}'
   ```
   Returns `{"access_token": "...", "token_type": "bearer", "expires_in": 86400}`. Tokens are HS256-signed against `AUTH_SECRET_KEY`, so as long as that value stays fixed, a token survives server restarts.
3. In your MCP client, add a remote server pointing at `http://<host>:<port>/mcp` (or your tunnel/proxy URL), with an `Authorization` header of **`Bearer <access_token>`** — the full string including the `Bearer ` prefix, not just the raw token.

`GET /health` reports overall status; `GET /metrics` exposes Prometheus metrics.

## Tool reference

### Wazuh 4.x tools

Unchanged from upstream — agents, alerts, vulnerabilities, rules/decoders (manager-side XML), active response, cluster status, CDB lists, compliance reporting, and more. See `server.py`'s tool schemas for the full list; nothing about them changed for this wrapper.

### Wazuh 5 tools (15)

All require `WAZUH5_HOST` to be configured. Write tools require `wazuh:write` scope and, if `WAZUH_REQUIRE_ACTION_CONFIRMATION` is enabled, `confirm=true`.

| Tool | Backend | Notes |
|---|---|---|
| `get_wazuh5_agents` | Manager REST (55000) | Same response shape as 4.x `/agents` |
| `search_wazuh5_rules` | Indexer, Security Analytics (9200) | Sigma rules, not 4.x XML. See [gotcha](#gotchas--known-quirks) below on field-scoped search |
| `search_wazuh5_detectors` | Indexer, Security Analytics (9200) | Scheduled correlation layer; binds Rules to a data source |
| `search_wazuh5_integrations` | **Dashboard** (443) | Resolves an integration's real UUID (needed by rule tools) from its display name |
| `search_wazuh5_decoders` | Indexer, raw OpenSearch index (9200) | Not the `_content_manager` plugin — that route 405s on `_search` |
| `create_wazuh5_decoder` | Indexer, `_content_manager` (9200) | Lands in **draft** space only; promote separately |
| `update_wazuh5_decoder` | Indexer, `_content_manager` (9200) | Unlike rules, wants `integration_id` in the body |
| `delete_wazuh5_decoder` | Indexer, `_content_manager` (9200) | Only removes the draft copy |
| `get_wazuh5_promotion_diff` | Indexer, `_content_manager` (9200) | Always call before `promote_wazuh5_content` |
| `promote_wazuh5_content` | Indexer, `_content_manager` (9200) | Promotes **everything pending** in the space, not a subset — confirm the diff first |
| `update_wazuh5_policy` | Indexer, `_content_manager` (9200) | Broad/shared impact — one policy is likely shared across integrations; exact PUT body unconfirmed |
| `test_wazuh5_logtest` | Indexer, `_content_manager` (9200) | Needs a real integration id already loaded in the target space |
| `create_wazuh5_rule` | **Dashboard** (443) | Tags always submitted empty — a bare tag crashes the Sigma compiler |
| `update_wazuh5_rule` | **Dashboard** (443) | No `integration_id` param — immutable once the rule exists |
| `delete_wazuh5_rule` | **Dashboard** (443) | Route exists; not independently stress-tested |

## Gotchas / known quirks

These are load-bearing for correct tool use, carried over from live testing against a pre-GA Wazuh 5 build (beta5/RC1) — re-verify against your own build before assuming they're permanent:

- **Field-scoped search returns zero hits.** Queries like `category:sshd` or `space:draft` against the Security Analytics / `_content_manager` indices silently return nothing, even when matching content exists — confirmed both through the MCP tools and raw calls directly to the Indexer. Only unscoped free-text terms reliably match; filter on the returned fields client-side instead.
- **No consistent response envelope.** Wazuh 5 write tools return at least 5 different JSON shapes depending on which backend served them (raw OpenSearch hits, a `{ok,response}` dashboard wrapper, `{message,status}`, a hybrid of the two, or an empty `{ok,response:{}}`). Don't assume one shape across tools.
- **CDB lists have no Wazuh 5 equivalent.** Confirmed absent under any plausible name, not merely unshipped. `kvdbs` (a JSON key-value store) is the closest structural successor, not a 1:1 replacement.
- **Promotion is all-or-nothing (so far).** `promote_wazuh5_content` has only ever been tested with `get_wazuh5_promotion_diff`'s full, unmodified output, which promotes every pending change in that space. Passing a trimmed subset is untested — could be rejected, could silently promote everything anyway.
- **A rule's Sigma tags must stay empty for now.** A bare, non-dotted tag crashes the server's Sigma compiler with an opaque Java error; `create_wazuh5_rule`/`update_wazuh5_rule` always submit an empty tags array until a safe format is reconfirmed.

## License

This repository has its own [`LICENSE`](LICENSE) (MIT, Copyright (c) 2026 RT&Co. Cybersecurity Inc.) — separate from, but compatible with, the upstream project's own MIT license. It also retains upstream's original copyright notice, since this repo redistributes trimmed source from that project.

Upstream: [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server), Copyright (c) 2024 Wazuh MCP Server Contributors.
