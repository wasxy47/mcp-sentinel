# Build progress

Milestone tracker for MCP Sentinel. Each milestone is only marked done once it
builds, typechecks and passes its own tests.

Status key: `[ ]` not started · `[~]` in progress · `[x]` done

## M0 — Foundations

- [x] **M0.1 Monorepo scaffold** — npm workspaces, strict shared `tsconfig`,
      project references, vitest, `.gitignore` with secret rules.
- [x] **M0.2 `packages/mcp-core`** — error taxonomy, MCP request-metadata header
      framing, RFC 8785 canonical JSON + hashing, tool namespacing, audit
      redaction, ULID identifiers, shared domain types.
      *100 unit tests. `npm run check` green.*
- [x] **M0.3 Design documents** — `docs/architecture.md`, `docs/threat-model.md`,
      Cedar schema + starter policy bundle. Written before the engines they
      describe, per the project brief.
      *42 policies across 7 files, strict-mode clean. `npm run policy:lint` green.*

## M1 — Passthrough gateway

- [x] **M1.1 Upstream registry & client pool** — connect to configured MCP
      servers over Streamable HTTP and stdio, health tracking, reconnection.
      *Config loader with `env:` secret indirection, NDJSON logger, lazy
      single-flight connect, fail-fast circuit breaker, equal-jitter backoff,
      per-upstream era negotiation. 122 unit tests against a real `McpServer`
      over `InMemoryTransport`. `npm run check` green.*
- [x] **M1.2 Tool catalog** — aggregate `tools/list` across upstreams, namespace
      every tool, digest each definition for drift detection.
      *Per-server `<serverId>__<toolName>` namespacing (T4/T5), TOFU digest drift
      with withhold/flag + baseline-survives-withhold revert recognition (T3),
      DoS bounds on tools-per-server / total tools / definition bytes (T17),
      allowlist, invalid-name and duplicate refusal, listing-failure retention,
      single-flight refresh. 44 unit tests against a real `McpServer` plus a
      low-level `Server` scripted to emit hostile `tools/list` payloads. `npm run
      check` green (266 tests total).*
- [x] **M1.3 Request forwarding** — `tools/call`, `resources/read`,
      `prompts/get`, `server/discover`; header/body consistency re-assertion;
      outbound header recomputation after name rewriting.
      *Split into pure resolution (`route.ts`) and execution (`forwarder.ts`) so
      every refusal is testable without a connection. Header/body agreement
      re-asserted on the rewritten body, catching a stale `Mcp-Name` inside
      Sentinel rather than at the upstream. Resource-URI alias rejection
      (byte-exact re-wrap), per-request dialability re-check so a mid-flight
      quarantine takes effect, reserved `_meta` stripping with a warning,
      request/result byte bounds (T17), and output-schema validation against the
      catalog's digested definition rather than a fresh upstream claim.
      `server/discover` advertises only capabilities Sentinel itself serves, no
      sub-flags, no upstream-authored prose, no topology. 66 unit tests, including
      a real in-process 2026-07-28 Streamable HTTP connection
      (`createMcpHandler` + a `fetch` override) to assert the outbound headers on
      the wire. `npm run check` green (349 tests total).*
- [x] **M1.4 Sentinel as a real MCP server** — `SentinelServer` per-request
      factory via `createMcpHandler` with `legacy: 'reject'` enforcing 2026-07-28
      only. Handlers: `server/discover`, `tools/list` (catalog + sentinel governance
      tools), `tools/call` (route → forward; sentinel own tools return isError stub
      deferred to M7), `resources/read` and `prompts/get` (conditional on upstream
      capability), `tasks/*` (get/cancel/list/update → -32601 MethodNotFound with
      M5.5 deferral message). `sentinel-tools.ts`: five governance tool definitions
      with full inputSchema. `http.ts`: Hono transport with origin allowlist, body
      size cap, `/health` endpoint. `main.ts`: entry point wiring. Config additions:
      `maxBodyBytes`, `port: 0` for ephemeral binding.
      *29 integration tests against a `MockModernClient` that constructs raw
      2026-07-28 JSON-RPC requests with correct `_meta` envelopes and header
      framing. 15 HTTP transport tests. `npm run check` green (393 tests total).*

## M2 — Policy engine

- [x] **M2.1 Cedar entity model** — principal/action/resource/context extraction
      from a request.
- [x] **M2.2 Evaluation** — `isAuthorized` hot path with static map (to avoid WASM OOB),
      policy-id → annotation map, obligation resolution.
- [x] **M2.3 Policy loading & linting** — bundle loader, `validate` in CI,
      hot reload.
      *Designed and implemented `policy-engine` package. Wired into `SentinelServer`
      (handlers: discover, list, call, read, prompts). Resolved Cedar WASM 4.12.0
      memory instability. Added regex/SQL injection safeguards and invisible Unicode filtering.
      126+ tests. `npm run check` green (518 tests total).*

## M3 — Audit trail

- [x] **M3.1 Hash-chained store** — SQLite schema, append path, WAL.
- [x] **M3.2 Verifier** — standalone chain verification, checkpoints,
      tamper localisation.
- [x] **M3.3 Query API** — filtered reads backing the dashboard and the
      `query_audit_log` tool.

## M4 — Risk engine

- [ ] **M4.1 Provider abstraction** — one OpenAI-compatible client covering
      Ollama and Groq; strict JSON-schema structured output.
- [ ] **M4.2 Heuristic scorer** — deterministic signals, always runs, works
      offline.
- [ ] **M4.3 Escalation policy** — timeouts, caching, and the
      *escalate-then-deny* posture when a backend is unreachable.

## M5 — Approval flow

- [ ] **M5.1 Approval store & lifecycle** — pending/approved/denied/expired.
- [ ] **M5.2 HMAC-signed loopback endpoint** — one-time approve/deny links.
- [ ] **M5.3 Discord webhook notifier** — request detail plus signed links.
- [ ] **M5.4 `approve_request` MCP tool** — same lifecycle, no browser needed.
- [ ] **M5.5 Task bridging** — suspended calls resume as MCP tasks.

## M6 — Server scanner

- [ ] **M6.1 Static detectors** — tool poisoning, invisible Unicode, shadowing,
      definition drift, annotation lying.
- [ ] **M6.2 Result-side injection scanning** — untrusted tool *output*.
- [ ] **M6.3 Optional classifier** — `llama-prompt-guard-2-86m` when a key is
      configured.
- [ ] **M6.4 Detection benchmark** — standalone test suite against known-benign
      and known-malicious fixtures; reports concrete detection rate/FP metrics.

## M7 — Sentinel's own tools

- [ ] `explain_decision`, `query_audit_log`, `list_active_policies`,
      `verify_audit_chain`, `scan_report`.

## M8 — Dashboard

- [ ] Server-rendered single page: live SSE decision feed, chain-verification
      badge, active policies, pending approvals. No build step.

## M9 — Demo & packaging

- [ ] **M9.1 Demo servers** — a benign filesystem-ish server and a malicious
      server attempting tool poisoning, shadowing and a rug pull.
- [ ] **M9.2 Before/after script** — the same agent transcript direct vs through
      Sentinel.
- [ ] **M9.3 Docker Compose** — one command to run the whole demo.
- [ ] **M9.4 README finalisation** — quickstart, screenshots, threat coverage
      table.
