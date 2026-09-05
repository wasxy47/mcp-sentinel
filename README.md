# MCP Sentinel

> ⚠️ **Status: Active Development**
> Sentinel is currently under active development.
> We have completed M6 (Server & Result Scanner) and are beginning work on M7 (Sentinel's Governance Tools).
> See [PROGRESS.md](PROGRESS.md) for detailed milestone tracking.

**Security and governance gateway for AI agents using the
[Model Context Protocol](https://modelcontextprotocol.io/) (MCP).**

Sentinel sits between an AI agent and the MCP servers it talks to. Every
tool call, resource read, and prompt request passes through Sentinel,
where it is identified, evaluated against a Cedar policy bundle, risk-scored,
scanned for poisoning and injection, optionally held for human approval, and recorded in a tamper-evident audit
trail — before being forwarded to the upstream server.

```
┌──────────┐        ┌──────────────────────────────────────────────────┐        ┌──────────┐
│  Agent   │ ──MCP─▸│                    Sentinel                      │ ──MCP─▸│ Upstream │
│ (Claude, │        │  identify → scan → policy → risk → approve →     │        │  Server  │
│  GPT, …) │        │  audit → forward → scan result                   │        │ (fs, db, │
└──────────┘        └──────────────────────────────────────────────────┘        │  git, …) │
                                                                                └──────────┘
```

## What Sentinel does

| Layer | What happens | Status |
|-------|-------------|--------|
| **Passthrough gateway** | Connects to upstream MCP servers, aggregates their tool catalogs under namespaced names (`server__tool`), forwards calls with header/body re-assertion | ✅ Done (M1) |
| **Policy engine** | Evaluates a Cedar policy bundle against every action. Resources are extracted by deeply inspecting `tools/call` arguments (e.g., catching `../` directory traversal in a path parameter) | ✅ Done (M2) |
| **Audit trail** | Records an unalterable, cryptographically hash-chained log of every decision and its exact context (RFC 8785) into a tamper-evident SQLite store | ✅ Done (M3) |
| **Risk scoring** | Heuristic + optional LLM-based risk assessment for escalation decisions | ✅ Done (M4) |
| **Approval flow** | Suspend dangerous calls, notify via Discord, resume on human approval with task bridging | ✅ Done (M5) |
| **Server scanner** | Detect tool poisoning, invisible Unicode, shadowing, definition drift, result injection | ✅ Done (M6) |
| **Governance tools** | MCP tools the agent can call: `explain_decision`, `query_audit_log`, `list_active_policies`, `verify_audit_chain`, `approve_request` | Planned (M7) |
| **Dashboard** | Server-rendered live view: decision feed, chain verification, pending approvals | Planned (M8) |ible Unicode, definition drift, injection | Planned (M6) |
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
│   ├── mcp-core/          # Shared domain types, error taxonomy, naming,
│   │                      # canonical JSON, headers, audit redaction, IDs
│   ├── policy-engine/     # Cedar policy evaluation, entity extraction, WASM bindings
│   ├── audit-log/         # Tamper-evident hash-chained SQLite store, verification
│   ├── risk-engine/       # Deterministic heuristics + LLM risk evaluation & escalation
│   ├── approvals/         # Approval request lifecycle, HMAC tokens, Discord webhook
│   └── scanner/           # Static detectors (Unicode, poisoning, shadowing) & result scanner
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

### M2 — Cedar policy engine ✅

Evaluates every tool call and resource read against a Cedar policy bundle before forwarding.

- **M2.1 Entity model & deep extraction** — Maps MCP requests into Cedar entities (`Principal`, `Action`, `Resource`, `Context`). Deeply inspects arguments to extract underlying file paths, URIs, and database queries (e.g. detecting directory traversal `../`).
- **M2.2 Evaluation engine** — Cedar WASM evaluation with policy-id mapping and obligation enforcement (`review`, `redact`).
- **M2.3 Bundle loader & CI linting** — Strict-mode bundle validation, hot reload, and duplicate ID detection.

### M3 — Hash-chained audit trail ✅

Immutable, tamper-evident recording of every decision and action.

- **M3.1 Hash-chained SQLite store** — RFC 8785 canonical JSON serialization with SHA-256 hash chaining (`prevHash -> recordHash`) in SQLite WAL mode.
- **M3.2 Verifier & tamper localization** — Standalone chain verification capable of isolating exact points of modification or corruption.
- **M3.3 Query API** — Filtered reads supporting pagination and indexing by principal, action, decision, and timestamp.

### M4 — Risk scoring engine ✅

Multi-layer risk evaluation for dynamic policy escalation.

- **M4.1 Heuristic scorer** — Offline, deterministic scoring based on argument entropy, sensitive path references, command execution, and permission scope.
- **M4.2 LLM provider integration** — Optional OpenAI/Ollama/Groq integration with JSON-schema structured output for contextual risk assessment.
- **M4.3 Escalation policy** — Escalate-then-deny fail-closed posture when backends are unreachable or latency bounds are exceeded.

### M5 — Approval flow & task bridging ✅

Human-in-the-loop governance for high-risk and policy-obligated actions.

- **M5.1 Approval store & lifecycle** — State tracking for `pending`, `approved`, `denied`, and `expired` requests.
- **M5.2 HMAC loopback endpoints** — Cryptographically signed single-use URLs for one-click web browser approval/denial.
- **M5.3 Discord webhook notifier** — Real-time alerts with embedded request context, risk summary, and interactive links.
- **M5.4 MCP Task bridging** — Suspends dangerous tool calls awaiting approval and exposes them via MCP `tasks/*` methods for resumption without agent disconnection.

### M6 — Server & result scanner ✅

Comprehensive threat scanning on upstream tool definitions and tool results.

- **M6.1 Static detectors**:
  - **Unicode abuse (T2)**: Invisible zero-width formatting (ZWSP, ZWNJ, BOM, word joiner), bidirectional override controls (LTR/RTL overrides), and Unicode tag character channels (`U+E0000` steganography).
  - **Tool poisoning (T1, T5)**: Imperative instruction detection ("you must", "always send"), secrecy directives ("do not tell the user"), sensitive file references (`~/.ssh`, `/etc/shadow`, `.env`), exfiltration patterns (`send to https://...`, `curl`, `fetch`), and role override attempts (`[SYSTEM]`, mode switches).
  - **Tool shadowing & annotation lying (T4)**: Semantic capability analysis comparing tool names against actual capabilities declared in descriptions or hidden in schema parameters.
  - **Obfuscated payloads**: Base64 payload decoding and recursive content analysis.
- **M6.2 Result-side scanning (T18)**:
  - Scans untrusted upstream tool results (web pages, database rows, documents) for indirect prompt injections aimed at manipulating the agent.
  - Fail-closed enforcement: High/critical findings in tool results block the payload from reaching the agent and return a structured error with findings.
- **M6.3 Prompt-Guard classifier integration**:
  - Optional ML inference with `meta-llama/Prompt-Guard-86M` via HuggingFace API for neural prompt injection and jailbreak detection.
- **M6.4 Detection benchmark & empirical metrics**:
  - Evaluated against a synthetic corpus of 100 benchmark fixtures (50 malicious attack patterns, 50 real-world benign utilities).

#### M6.4 Benchmark Evaluation Evidence

| Corpus | Samples | Target Verdict | Actual Result | Detection / Pass Rate | False Positives |
|--------|---------|----------------|---------------|-----------------------|-----------------|
| **Malicious Attacks** | 50 | `malicious` / `suspicious` | 50 Caught, 0 Missed | **100.0% Detection Rate*** | N/A |
| **Benign Baseline** | 50 | `clean` | 50 Clean, 0 Flagged | **100.0% Pass Rate** | **0 (0.0% FP Rate)** |

> [!NOTE]
> *\*Measured against synthetic fixtures designed around the detectors' own patterns — real-world attack diversity may show different results.*

##### Threat Vector Breakdown

| Threat Vector | Description | Malicious Samples | Caught | Detection Rate |
|---------------|-------------|-------------------|--------|----------------|
| **T1: Imperative Poisoning** | Direct instructions coercing model behavior | 6 | 6 | 100.0% |
| **T1: Secrecy Directives** | Concealment commands ("hide from user", "silently send") | 5 | 5 | 100.0% |
| **T1: Sensitive Paths** | Targeting credentials, keys (`~/.ssh`, `/etc/shadow`, `.env`) | 5 | 5 | 100.0% |
| **T1: Exfiltration Channels** | Directives sending data via HTTP, `curl`, or `fetch` | 5 | 5 | 100.0% |
| **T1: Role Overrides** | System prompt overrides, jailbreaks, developer mode switches | 4 | 4 | 100.0% |
| **T1: Obfuscated Payloads** | Base64-encoded exfiltration and injection payloads | 3 | 3 | 100.0% |
| **T2: Invisible Unicode** | ZWSP, ZWNJ, BOM, tag steganography, bidi overrides | 5 | 5 | 100.0% |
| **T4: Tool Shadowing** | Benign name with hidden shell/filesystem/DB capabilities | 5 | 5 | 100.0% |
| **T5: Cross-Tool Manipulation** | Upstream instructions hijacking other registered tools | 2 | 2 | 100.0% |
| **T18: Result Injection** | Indirect prompt injections inside tool response data | 10 | 10 | 100.0% |
| **Total Malicious Corpus** | **All evaluated attack vectors** | **50** | **50** | **100.0% (50/50)** |

**Test coverage:** 581 tests across 30 test files. All pass. `npm run check` green.

### What's next

| Milestone | Summary | Notes |
|-----------|---------|-------|
| **M7** | Sentinel's own MCP tools | Wire up `explain_decision`, `query_audit_log`, `list_active_policies`, `verify_audit_chain`, `approve_request` |
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
