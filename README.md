# MCP Sentinel

> ⚠️ **Active Development** — This project is under active construction.
> Milestones M0–M1 are complete (foundations + passthrough gateway).
> M2 (policy engine) is next. The API surface, config schema, and wire
> behaviour will change until v1.0. Do not run this in production yet.

**Security and governance gateway for AI agents using the
[Model Context Protocol](https://modelcontextprotocol.io/) (MCP).**

Sentinel sits between an AI agent and the MCP servers it talks to. Every
tool call, resource read, and prompt request passes through Sentinel,
where it is identified, evaluated against a Cedar policy bundle, risk-scored,
optionally held for human approval, and recorded in a tamper-evident audit
trail — before being forwarded to the upstream server.

```
┌─────────┐         ┌───────────────────────────────────────┐         ┌──────────┐
│  Agent   │ ──MCP─▸ │              Sentinel                 │ ──MCP─▸ │ Upstream │
│ (Claude, │         │  identify → policy → risk → approve → │         │  Server  │
│  GPT, …) │         │  audit → forward                      │         │ (fs, db, │
└─────────┘         └───────────────────────────────────────┘         │  git, …) │
                                                                      └──────────┘
```

## What Sentinel does

| Layer | What happens | Status |
|-------|-------------|--------|
| **Passthrough gateway** | Connects to upstream MCP servers, aggregates their tool catalogs under namespaced names (`server__tool`), forwards calls with header/body re-assertion | ✅ Done (M1) |
| **Policy engine** | Evaluates every request against a [Cedar](https://www.cedarpolicy.com/) policy bundle — allow, deny, review, or require approval | 🔜 Next (M2) |
| **Audit trail** | Hash-chained append-only log of every decision, tamper-detectable | Planned (M3) |
| **Risk scoring** | Heuristic + optional LLM-based risk assessment for escalation decisions | Planned (M4) |
| **Approval flow** | Suspend dangerous calls, notify via Discord, resume on human approval | Planned (M5) |
| **Server scanner** | Detect tool poisoning, invisible Unicode, definition drift, injection | Planned (M6) |
| **Governance tools** | MCP tools the agent can call: `explain_decision`, `query_audit_log`, `list_active_policies`, `verify_audit_chain`, `approve_request` | Planned (M7) |
| **Dashboard** | Server-rendered live view: decision feed, chain verification, pending approvals | Planned (M8) |

## Threat model

Sentinel treats upstream MCP servers as **untrusted**. The full threat model
is documented in [`docs/threat-model.md`](docs/threat-model.md) and covers:

- **T1** Tool poisoning (malicious descriptions that manipulate the agent)
- **T3** Definition drift / rug pulls (tool changes behaviour after approval)
- **T4/T5** Cross-server shadowing and confused-deputy attacks
- **T14** Invisible Unicode in tool names and arguments
- **T17** Denial-of-service via oversized payloads
- And 15+ more threat vectors with specific mitigations

## Architecture

Detailed architecture is in [`docs/architecture.md`](docs/architecture.md).

### Project structure

```
mcp-sentinel/
├── packages/
│   └── mcp-core/          # Shared domain types, error taxonomy, naming,
│                           # canonical JSON, headers, audit redaction, IDs
├── apps/
│   └── gateway/
│       └── src/
│           ├── config/     # Config loader with env: secret indirection
│           ├── upstream/   # Registry, client pool, health tracking, reconnect
│           ├── catalog/    # Tool catalog, namespacing, digest drift detection
│           ├── forward/    # Request routing, forwarding, discover aggregation
│           ├── server/     # SentinelServer, HTTP transport, sentinel tools
│           ├── observability/ # Structured NDJSON logger
│           └── main.ts     # Entry point
├── policies/               # Cedar policy bundle (42 policies, 7 files)
├── docs/                   # Architecture, threat model
└── scripts/                # Policy linter
```

### Protocol version

Sentinel enforces the **2026-07-28** MCP protocol exclusively
(`legacy: 'reject'`). Agents on older protocol versions receive a clear
error rather than a silently degraded session.

## What's built so far

### M0 — Foundations ✅

- **Monorepo scaffold** — npm workspaces, strict shared `tsconfig`, project
  references, vitest
- **`packages/mcp-core`** — Error taxonomy, MCP header framing, RFC 8785
  canonical JSON + hashing, tool namespacing (`server__tool`), audit-safe
  redaction, ULID identifiers
- **Design documents** — Architecture and threat model written before the
  engines they describe
- **Cedar policy bundle** — 42 policies across 7 files, strict-mode validated

### M1 — Passthrough gateway ✅

The gateway connects to configured upstream MCP servers and presents a
unified tool catalog to agents.

- **M1.1 Upstream registry & client pool** — Streamable HTTP and stdio
  transports, lazy single-flight connect, fail-fast circuit breaker,
  equal-jitter backoff, per-upstream era negotiation
- **M1.2 Tool catalog** — Aggregate `tools/list` across upstreams, namespace
  every tool, digest each definition for drift detection (TOFU model),
  DoS bounds on tools-per-server / total tools / definition bytes
- **M1.3 Request forwarding** — Route `tools/call`, `resources/read`,
  `prompts/get`, `server/discover` through the catalog to the correct
  upstream. Header/body consistency re-assertion, resource-URI alias
  rejection, `_meta` stripping, request/result byte bounds, output-schema
  validation
- **M1.4 Sentinel as a real MCP server** — `SentinelServer` with per-request
  `Server` factory via `createMcpHandler`. Hono HTTP transport with origin
  allowlist and body size cap. Five governance tool stubs. `tasks/*` methods
  return `-32601 MethodNotFound` (deferred to M5.5)

**Test coverage:** 393 tests across 17 test files. All pass.

### What's next

| Milestone | Summary | Notes |
|-----------|---------|-------|
| **M2** | Cedar policy engine | Security-critical — entity model, evaluation, hot reload |
| **M3** | Hash-chained audit trail | SQLite WAL, tamper localisation |
| **M4** | Risk scoring | Heuristic + optional LLM provider |
| **M5** | Approval flow | Discord webhook, HMAC-signed links, task bridging |
| **M6** | Server scanner | Tool poisoning, injection, drift detection, benchmark |
| **M7** | Sentinel's own MCP tools | Wire up the governance tool stubs |
| **M8** | Dashboard | Live SSE decision feed, chain verification |
| **M9** | Demo & packaging | Docker Compose, before/after scripts |

## Prerequisites

- **Node.js** ≥ 20.19.0
- **npm** ≥ 10

## Quick start

```bash
# Clone and install
git clone https://github.com/your-org/mcp-sentinel.git
cd mcp-sentinel
npm install

# Build
npm run build

# Run all checks (typecheck + policy lint + tests)
npm run check

# Start the gateway (after building)
npm run gateway

# Development mode (auto-reload)
npm run gateway:dev
```

## Configuration

The gateway reads its configuration from environment variables and a config
object. See [`apps/gateway/src/config/schema.ts`](apps/gateway/src/config/schema.ts)
for the full schema.

Key settings:

| Setting | Description | Default |
|---------|-------------|---------|
| `port` | HTTP listen port (0 = ephemeral) | `3100` |
| `instanceName` | Server name reported in `server/discover` | `mcp-sentinel` |
| `workspaceRoot` | Root directory for filesystem policy evaluation | Required |
| `upstream.connectTimeoutMs` | Upstream connection timeout | `10000` |
| `upstream.requestTimeoutMs` | Per-request timeout | `30000` |
| `http.maxBodyBytes` | Maximum request body size | `4194304` (4 MB) |

Secrets in config values can use `env:VAR_NAME` indirection to avoid
hardcoding tokens in config files.

## Scripts

| Command | What it does |
|---------|-------------|
| `npm run check` | Typecheck + policy lint + test suite |
| `npm run build` | TypeScript build (all workspaces) |
| `npm run test` | Run vitest |
| `npm run test:watch` | Run vitest in watch mode |
| `npm run typecheck` | TypeScript type checking only |
| `npm run policy:lint` | Validate Cedar policy bundle |
| `npm run gateway` | Start the gateway (production) |
| `npm run gateway:dev` | Start the gateway (dev, auto-reload) |

## License

Apache-2.0
