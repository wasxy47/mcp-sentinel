# MCP Sentinel — Architecture

> Status: living document. Written alongside the code, not after it.
> Companion documents: [threat-model.md](threat-model.md), [PROGRESS.md](../PROGRESS.md).

## 1. The problem

An AI agent with MCP tools is a program that decides at runtime which
privileged operations to perform, based on text it read a moment ago. That text
may come from a web page, a database row, a GitHub issue, or a tool description
written by whoever published the MCP server. There is no compile-time list of
what the agent will do.

Conventional access control assumes the caller's *intent* is fixed and only the
caller's *identity* needs checking. That assumption fails here. The agent's
identity is stable; its intent is attacker-influenceable. So the interesting
question is not "may this principal call `execute_sql`?" but "may this principal
call `execute_sql` **with this statement, right now, given what we know about the
server that suggested it**?"

Sentinel answers that question on every call, records the answer in a form that
cannot be quietly edited afterwards, and escalates to a human when it cannot
answer confidently on its own.

### Non-goals

- **Not a sandbox.** Sentinel governs the MCP boundary. An agent that can
  already run arbitrary code on the host does not need Sentinel's permission to
  do anything.
- **Not a model-alignment layer.** It constrains actions, not thoughts.
- **Not a replacement for upstream authorization.** The database should still
  have its own permissions. Sentinel is defence in depth, not the only defence.

## 2. Position in the system

```
┌────────────┐        MCP 2026-07-28          ┌──────────────────────────┐
│   Agent    │  ──────────────────────────▶   │      MCP Sentinel        │
│ (Claude,   │   Streamable HTTP, stateless   │                          │
│  IDE, …)   │  ◀──────────────────────────   │  policy → risk → approve │
└────────────┘                                └───────────┬──────────────┘
                                                          │
                          ┌───────────────────────────────┼─────────────────┐
                          │                               │                 │
                    ┌─────▼──────┐               ┌────────▼─────┐   ┌───────▼──────┐
                    │ filesystem │               │   database   │   │   github     │
                    │ MCP server │               │  MCP server  │   │  MCP server  │
                    └────────────┘               └──────────────┘   └──────────────┘
                       (untrusted)                  (untrusted)        (untrusted)
```

The agent sees **one** MCP server. Sentinel is a real, spec-compliant MCP server
in its own right — it answers `server/discover`, advertises capabilities,
implements the Tasks extension, and exposes its own tools
(`sentinel__explain_decision`, `sentinel__query_audit_log`,
`sentinel__list_active_policies`, `sentinel__approve_request`). It is not a
transparent proxy: it owns the conversation with the agent and decides, per
call, what to do with it.

Upstream servers are treated as **untrusted by default**, including their tool
descriptions. That is the single most important posture decision in the design;
[threat-model.md § Tool poisoning](threat-model.md#tool-poisoning) explains why.

## 3. Request lifecycle

Every inbound request walks the same pipeline. Stages are ordered cheapest-first
so that the common case — an allowed call matched by a static policy — pays
almost nothing.

```
  inbound HTTP request
        │
   ┌────▼─────────────────────────────────────────────────────┐
   │ 1. Transport gate                                        │  ~µs
   │    Origin check, method/route, body size cap             │
   └────┬─────────────────────────────────────────────────────┘
        │
   ┌────▼─────────────────────────────────────────────────────┐
   │ 2. Header framing            packages/mcp-core/headers   │  ~µs
   │    Read Mcp-Method / Mcp-Name / Mcp-Param-* — no body    │
   │    parse yet. These become the Cedar action & resource.  │
   └────┬─────────────────────────────────────────────────────┘
        │
   ┌────▼─────────────────────────────────────────────────────┐
   │ 3. Body parse + consistency re-assertion                 │  ~µs
   │    assertHeaderMatchesBody → -32020 on disagreement.     │
   │    Without this, stage 2 is a policy-bypass primitive.   │
   └────┬─────────────────────────────────────────────────────┘
        │
   ┌────▼─────────────────────────────────────────────────────┐
   │ 4. Catalog resolution        packages/mcp-core/naming    │  ~µs
   │    files__read_file → (server "files", tool "read_file") │
   │    Quarantined server or unknown tool → deny here.       │
   └────┬─────────────────────────────────────────────────────┘
        │
   ┌────▼─────────────────────────────────────────────────────┐
   │ 5. Policy evaluation         packages/policy-engine      │  ~100µs
   │    Cedar. forbid → DENY. permit → read obligation.       │
   │    No match → default deny.                              │
   └────┬─────────────────────────────────────────────────────┘
        │  obligation
        ├── allow ──────────────────────────────────────┐
        │                                               │
   ┌────▼──────────────────────────────┐                │
   │ 6. Risk assessment  (obligation   │  10ms–2s       │
   │    = review)     packages/risk-*  │                │
   │    Heuristics always; LLM when    │                │
   │    heuristics are inconclusive.   │                │
   └────┬──────────────────────────────┘                │
        │  band                                         │
        ├── low ────────────────────────────────────────┤
        ├── medium/high → treat as obligation=approve   │
        └── critical → DENY                             │
                       │                                │
   ┌───────────────────▼───────────────┐                │
   │ 7. Human approval (obligation     │  seconds–      │
   │    = approve)                     │  minutes       │
   │    Discord + signed loopback +    │                │
   │    approve_request MCP tool.      │                │
   │    Returns an MCP task handle.    │                │
   └────┬──────────────────────────────┘                │
        │ approved                                      │
        ├───────────────────────────────────────────────┤
        │                                               │
   ┌────▼───────────────────────────────────────────────▼─────┐
   │ 8. Forward upstream                                      │
   │    Rewrite params.name, RECOMPUTE Mcp-Name header,       │
   │    forward, scan the result for injection.               │
   └────┬─────────────────────────────────────────────────────┘
        │
   ┌────▼─────────────────────────────────────────────────────┐
   │ 9. Audit append              packages/audit              │  ~200µs
   │    Redact → canonicalise → hash-chain → durable insert.  │
   │    Happens for EVERY outcome, including denials.         │
   └──────────────────────────────────────────────────────────┘
```

Stage 9 runs on every path, including the error paths. A denial that leaves no
record is indistinguishable from an attack that was never attempted.

## 4. Key design decisions

Each subsection states the decision, the alternatives considered, and why the
alternative lost. These are the tradeoffs worth arguing about.

### 4.1 Cedar over OPA/Rego for the policy engine

**Decision: Cedar, via `@cedar-policy/cedar-wasm`.**

| | Cedar | OPA / Rego |
|---|---|---|
| Language power | Deliberately not Turing-complete | General-purpose logic language |
| Termination | Guaranteed; every query terminates | Not guaranteed in general |
| Analysis | Formally verified core; policies are *analysable* | Analysis is undecidable in general |
| Deployment | WASM, in-process, no sidecar | Sidecar or Go library; WASM build possible but heavier |
| Explainability | `diagnostics.reason` returns the *determining policy ids* | Must be built by hand into each rule |
| Expressiveness | Restricted: no loops, no arbitrary recursion | Anything |

Three properties decided it.

1. **Guaranteed termination on the hot path.** Every tool call blocks on policy
   evaluation. Rego's expressiveness means a badly written policy can be
   pathologically slow; Cedar's restricted language makes that structurally
   impossible. A policy engine that can hang is a denial-of-service vector
   pointed at your own agents.

2. **Free explainability.** Cedar returns the ids of the policies that
   determined the answer. The user asked for an `explain_decision` tool —
   with Cedar that is a lookup, not a reconstruction. With Rego I would have to
   thread justification data through every rule by hand and hope no rule forgets.

3. **In-process WASM, no sidecar.** Zero-budget constraint, and one fewer moving
   part in a security boundary.

**What we give up:** Rego handles data-heavy policies ("deny if this row appears
in that 50k-entry deny list") more naturally. Cedar's answer is entity
attributes, which must be materialised in advance. For Sentinel's decision shape
— a handful of attributes about principal, tool and arguments — that is not a
real constraint. If it becomes one, the `PolicyEngine` interface is narrow
enough to put a second implementation behind.

### 4.2 Modelling four outcomes on a two-valued engine

Cedar's `Decision` is binary: `allow` or `deny`. Sentinel needs four outcomes —
allow, deny, escalate-to-risk-engine, require-human-approval. Three options:

- **(a) Encode the outcome in the action name** (`callTool_reviewed`,
  `callTool_approved`). Rejected: it multiplies the action space, and a policy
  author must now know which variant to write rules against. The action should
  describe what the *agent* is doing, not what Sentinel decides to do about it.
- **(b) Run Cedar twice** — once against a "may this proceed at all" policy set,
  once against a "does this need review" set. Rejected: two evaluations, two
  policy sets to keep consistent, and no single artifact answering "what governs
  this call?"
- **(c) Annotation-driven obligations.** ✅ Chosen.

Cedar policies carry arbitrary `@annotation("value")` metadata. Sentinel reads a
`@sentinel_obligation` annotation off the policies that granted the permit:

```cedar
@id("allow_reads_from_workspace")
@sentinel_obligation("allow")
permit (
  principal,
  action == Action::"callTool",
  resource in ToolGroup::"read_only"
) when { context.path_within_workspace };

@id("writes_need_a_human")
@sentinel_obligation("approve")
permit (
  principal in AgentGroup::"standard",
  action == Action::"callTool",
  resource in ToolGroup::"mutating"
);
```

Cedar decides *permission*; the annotation decides *ceremony*. Because Cedar
reports which policies were determining, Sentinel reads their annotations and
takes the **strongest** obligation (`approve` > `review` > `allow`) — the same
conservative direction as Cedar's own forbid-overrides-permit rule. That
combination logic lives in `strongestObligation()` in
`packages/mcp-core/src/types.ts`.

Default-deny falls out for free: no matching permit means `deny`, with no
special-casing.

**One implementation detail that this design turns out to depend on.** The scheme
only works if Sentinel can map "which policies were determining" back to a policy
it can read annotations from — that is, if `diagnostics.reason` contains ids
Sentinel chose. Cedar's WASM API accepts a policy set as
`string | Policy[] | Record<PolicyId, Policy>`, and the three forms do not behave
the same way. Handing it one blob of text produces *positional* ids:

```
staticPolicies as Record  →  { decision: "allow", reason: ["fs_read_within_workspace"] }
staticPolicies as text     →  { decision: "allow", reason: ["policy16"] }
```

Positional ids are unusable here for two reasons: they carry no annotation to
look up, and they shift the moment a policy is inserted anywhere above — which
would silently re-point every already-recorded decision at a different rule.

So the loader in `packages/policy-engine` splits each file into individual
policies with `policySetTextToParts`, reads the `@id` annotation from each via
`policyToJson`, and hands Cedar a `Record<PolicyId, Policy>` keyed by those ids.
`npm run policy:lint` enforces the precondition that makes this safe: every policy
has an `@id`, and no two share one. See
[`../policies/README.md`](../policies/README.md).

### 4.3 Header-based policy input, with the check re-asserted

MCP 2026-07-28 mirrors `method` into the `Mcp-Method` header and
`params.name`/`params.uri` into `Mcp-Name`, precisely so intermediaries can
route and enforce policy without parsing the body. Sentinel uses that: the
header values *are* the Cedar action and resource.

This is only sound because the spec also requires any server that reads the body
to reject header/body disagreement with `-32020 HeaderMismatch`. Otherwise an
attacker sends `Mcp-Name: files__read_file` (which policy allows) with
`params.name: shell__exec` in the body, and the header fast path becomes a
policy-bypass primitive.

The SDK enforces this natively in its `standard-header-validation` stage.
Sentinel **re-asserts it anyway** (`assertHeaderMatchesBody`), because Sentinel
decides policy *before* the SDK sees the request. A version skew or bug that
relaxed the SDK's check would silently convert Sentinel's optimisation into a
vulnerability. One string comparison is a cheap price for not depending on
someone else's validation for a security invariant. See
[threat-model.md § Header/body desynchronisation](threat-model.md#headerbody-desynchronisation).

### 4.4 Audit storage: SQLite with a hash chain

**Decision: SQLite (`better-sqlite3@^12`), WAL mode, one row per decision,
`row_hash = SHA-256(canonical(payload) || prev_hash)`.**

Why SQLite rather than append-only files or Postgres: it is a single file with
no daemon (zero-budget, zero-ops), it gives real transactions so a row and its
chain-head update commit atomically, and it can be queried by the dashboard and
the `query_audit_log` tool without a second system. `better-sqlite3` is
synchronous, which is *desirable* here — the append is on the critical path and
must complete before the response is returned, so async buffers no benefit and
would introduce a window where a decision is served but unrecorded.

`better-sqlite3@^12` specifically: v13 requires Node ≥ 22, and the target
environment is Node 20. `node:sqlite` is not available on Node 20 either.

#### Schema shape: wide rows, not normalised

```sql
CREATE TABLE decisions (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,  -- chain position
    decision_id    TEXT    NOT NULL UNIQUE,            -- dec_<ULID>
    timestamp      TEXT    NOT NULL,                   -- ISO-8601 UTC
    agent_id       TEXT    NOT NULL,
    method         TEXT    NOT NULL,
    qualified_name TEXT,
    server_id      TEXT,
    verdict        TEXT    NOT NULL,
    obligation     TEXT    NOT NULL,
    payload        TEXT    NOT NULL,   -- full canonical JSON DecisionRecord
    payload_hash   TEXT    NOT NULL,   -- SHA-256 of payload
    prev_hash      TEXT    NOT NULL,
    row_hash       TEXT    NOT NULL
);
```

The indexed columns are duplicated *out of* the payload rather than joined *into*
it. Three reasons:

1. **The payload must be a single canonical blob.** Its hash has to be
   reproducible by an independent verifier that knows only RFC 8785 and SHA-256.
   Reconstructing a record from six joined tables and hoping the reconstruction
   is byte-identical is a verification scheme that will eventually fail on data
   nobody tampered with.
2. **An audit row is immutable.** The usual argument for normalisation —
   update anomalies — cannot arise. Nothing is ever updated.
3. **Query patterns are known and narrow:** by time, by agent, by tool, by
   verdict. Six indexed columns cover them.

The cost is storage duplication. For an append-only log of small JSON documents,
that is the right trade.

#### What the chain does and does not prove

The chain makes tampering **evident**, not **impossible**. Anyone who can write
to the file can rewrite a row *and* every subsequent row's hash. Two mitigations,
both planned in M3:

- **Checkpoints.** The chain head is periodically appended to
  `data/audit.checkpoints.jsonl` (a separate file, and optionally an external
  sink). Rewriting history now requires tampering with two artifacts.
- **Independent verification.** The verifier is a standalone entry point that
  reads the database without going through the writer, so a compromised writer
  cannot fake a passing verification.

Honest framing matters here: the property is *tamper-evidence under an attacker
who does not control every copy*, and that is what the README will claim.

### 4.5 Escalate, then deny

The failure posture, chosen by the operator brief:

| Situation | Outcome |
|---|---|
| Policy says `review`, risk engine reachable | Score it; band decides |
| Policy says `review`, risk engine **unreachable or timed out** | Escalate to human approval |
| Policy says `approve`, approval channel **unreachable or timed out** | **Deny** |
| Policy says `allow` | Allow (a static policy already decided) |

The invariant: **a risky call is never allowed unscored.** Degradation moves
toward more human involvement, and when humans cannot be reached, toward
refusal. Every degraded decision sets `degraded: true` on its audit record so an
operator can find and revisit them.

This is deliberately not "fail open". It also is not blanket fail-closed: an
`allow` obligation means a policy author already made an explicit judgement, and
a risk-engine outage should not revoke it.

### 4.6 One provider abstraction for Ollama and Groq

All two speak the OpenAI chat-completions wire format, so one
`OpenAICompatibleProvider` — parameterised by base URL, model and API key —
covers local Ollama and Groq with no code change, which the brief requires.
Selection is environment-driven:

```
SENTINEL_RISK_PROVIDER=ollama|groq|heuristic
SENTINEL_RISK_BASE_URL=...      # defaulted per provider
SENTINEL_RISK_MODEL=...
GROQ_API_KEY                    # read from the environment, never from a file
```

Two properties make the LLM safe to depend on:

- **Structured output is enforced by the decoder, not by prompting.** Groq
  supports `response_format: {type: "json_schema", strict: true}` with
  constrained decoding, so the response cannot be malformed. Ollama's `format`
  parameter gives the equivalent locally. Parsing failures are therefore a
  transport problem, not a modelling problem.
- **The heuristic scorer always runs.** It is deterministic, offline, and
  provides a floor. The LLM can raise a score but the heuristic's own critical
  signals cannot be argued away by a model. This matters because the LLM is
  being asked to reason about *attacker-controlled text* — it is inside the
  blast radius, and must not be the only thing standing in the way.

### 4.7 A gateway, not a `McpServer`

The SDK offers a high-level `McpServer` (register tools, get routing) and a
low-level `Server` (register raw method handlers). Sentinel uses the low-level
`Server`, which the SDK's own documentation recommends for gateways.

The reason: Sentinel's tool list is *dynamic and mostly not its own*. It
aggregates upstream catalogs, rewrites names, forwards calls to different
transports, and must handle methods the high-level API does not model —
including `tasks/update`, which the 2026-07-28 Tasks extension defines but SDK
v2.0.0 does not ship. `setRequestHandler` with an explicit schema handles that;
`registerTool` cannot.

### 4.8 Tool namespacing

Every proxied tool is advertised as `<serverId>__<toolName>`. Server ids are
`[a-z0-9][a-z0-9-]*` — **no underscores** — which makes splitting on the *first*
`__` unambiguous even when an upstream tool name contains `__` itself.

This is a security control, not just hygiene. Without it, a malicious server
declaring a tool named exactly like a trusted server's tool can shadow it and
harvest the calls. With it, the two are distinct resources with distinct Cedar
policies. The `sentinel` server id is reserved, so no upstream can impersonate
Sentinel's own tools. See
[threat-model.md § Tool shadowing](threat-model.md#tool-shadowing).

### 4.9 Redact before write, digest the original

The audit trail is a place credentials naturally accumulate — agents pass tokens
as tool arguments routinely. A faithful log turns "attacker read one file" into
"attacker has every credential the agent ever used".

So arguments are redacted before storage by two independent mechanisms: value
shape (14 credential patterns) and key name (token-based, so `apiKey` matches
but `keyword` does not). The **digest is computed over the original**, so an
investigator who can produce a candidate payload can still prove what a call
contained — without the database holding the secret.

Where placeholders carry a correlation id, it is a **keyed HMAC**, never a bare
digest: a bare digest of a low-entropy secret like a password is trivially
brute-forced, which would turn the redaction into a hash-cracking exercise.

## 5. Package layout

```
packages/
  mcp-core/       Protocol framing, canonical hashing, naming, redaction, ids,
                  shared types. Zero runtime deps beyond zod. Depends on nothing.
  policy-engine/  Cedar schema, policy loading/linting, entity extraction,
                  obligation resolution.
  audit/          Hash-chained SQLite store, verifier, query API.
  risk-engine/    Heuristic scorer + OpenAI-compatible LLM provider, caching,
                  escalation policy.
  scanner/        Tool-poisoning and prompt-injection detectors for server
                  definitions and tool results.
apps/
  gateway/        The MCP server: transport, pipeline, upstream pool, Sentinel's
                  own tools, approval endpoints, SSE feed.
  demo-servers/   A benign server and a deliberately malicious one.
  dashboard/      Server-rendered page + SSE. No build step, no framework.
```

Dependency direction is strictly downward: `mcp-core` ← everything else,
`gateway` ← all packages. No package imports a sibling that imports it back.
`mcp-core` in particular stays dependency-light so the audit verifier can run
standalone, without loading Cedar or the LLM client.

## 6. Protocol notes (2026-07-28)

The gateway targets the **stateless core**:

- No `initialize` handshake, no `Mcp-Session-Id`. Every request is
  self-contained and carries its own `_meta` with protocol version and client
  info. This suits a gateway well — there is no session state to lose.
- `server/discover` is implemented, as the spec requires.
- Request metadata headers (`Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`) with the
  `=?base64?…?=` sentinel for values that cannot travel literally. Implemented
  and tested in `packages/mcp-core/src/headers.ts`.
- GET and DELETE on the MCP endpoint return **405**; unknown methods return
  **404 + -32601**; failed Origin validation returns **403**.
- Error-code allocation is respected: `-32020..-32099` belongs to the spec, so
  Sentinel's own codes live in the implementation-defined `-32000..-32019` band.

### The Tasks discrepancy

The 2026-07-28 extension defines `tasks/update` and drops `tasks/result` and
`tasks/list`. SDK v2.0.0 ships the *pre-extension* shape: it has `tasks/get`,
`tasks/result`, `tasks/cancel`, `tasks/list` and `notifications/tasks/status`
as first-class types, and no `tasks/update`.

Resolution: build on the SDK's native task types where they exist, and register
`tasks/update` as a custom method via `setRequestHandler`. Both surfaces are
served, the gap is documented here rather than hidden, and when the SDK catches
up the custom registration is deleted.

## 7. Testing strategy

- **Unit tests per package**, colocated as `*.test.ts`. Every module ships with
  tests; `mcp-core` has 100.
- **Property-flavoured tests** where determinism is the actual requirement —
  canonical JSON must be construction-order independent, ULIDs must sort in
  creation order under a backwards clock.
- **Adversarial tests as first-class cases**, not an afterthought. The header
  name-smuggling attempt, the `__`-in-tool-name split, base64 non-canonicality,
  and regex `lastIndex` leakage across redaction calls are all tested because
  each is a real bypass if it regresses.
- **Integration tests** over `InMemoryTransport.createLinkedPair()` for
  gateway↔upstream flows, so no network is needed in CI.
- **The demo is a test.** The malicious-server scenario runs as an automated
  assertion that Sentinel blocks it, not just as a script for a screenshot.
