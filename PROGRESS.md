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
- [ ] **M1.4 Sentinel as a real MCP server** — low-level `Server`, capability
      registration, `tasks/*` including the 2026-07-28 `tasks/update` extension
      method.

## M2 — Policy engine

- [ ] **M2.1 Cedar entity model** — principal/action/resource/context extraction
      from a request.
- [ ] **M2.2 Evaluation** — `preparseSchema` + `statefulIsAuthorized` hot path,
      policy-id → annotation map, obligation resolution.
- [ ] **M2.3 Policy loading & linting** — bundle loader, `validate` in CI,
      hot reload.

## M3 — Audit trail

- [ ] **M3.1 Hash-chained store** — SQLite schema, append path, WAL.
- [ ] **M3.2 Verifier** — standalone chain verification, checkpoints,
      tamper localisation.
- [ ] **M3.3 Query API** — filtered reads backing the dashboard and the
      `query_audit_log` tool.

## M4 — Risk engine

- [ ] **M4.1 Provider abstraction** — one OpenAI-compatible client covering
      Ollama, Groq and xAI; strict JSON-schema structured output.
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
