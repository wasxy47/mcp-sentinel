/**
 * Gateway configuration schema.
 *
 * Config is parsed with zod and every field is either required or has an
 * explicit default, so a running gateway never has an "undefined behaviour"
 * setting. Two rules govern what may appear here:
 *
 *  1. **No secrets.** Tokens, keys and HMAC material are read from the
 *     environment, never from the config file. The file is meant to be
 *     committed; a schema that accepts a bearer token invites one to be.
 *     `env` on an upstream server is the one hatch, and it names variables to
 *     forward rather than carrying values — see `UpstreamStdioSchema`.
 *
 *  2. **Defaults are the safe direction.** Trust defaults to `untrusted`,
 *     origin checks default to on, and the bind address defaults to loopback.
 *     An operator has to type something to widen the blast radius, which means
 *     the widening is visible in review.
 *
 * Sections land as their milestones do; `risk` and `approval` arrive with M4
 * and M5. Adding a section must not change the meaning of an existing config,
 * which is why every new block is `.prefault({})`-ed rather than required.
 */

import * as z from 'zod';

import { isValidServerId, SENTINEL_SERVER_ID } from '@mcp-sentinel/mcp-core';

/**
 * A server id becomes part of every qualified tool name (`files__read_file`),
 * so the naming rules from `mcp-core` apply here rather than being re-stated:
 * no separator characters, and not the reserved `sentinel` namespace.
 */
const ServerIdSchema = z
    .string()
    .min(1)
    .max(64)
    .refine(value => isValidServerId(value), {
        message: 'must be lowercase alphanumeric with dashes, and contain no "__" separator'
    })
    .refine(value => value !== SENTINEL_SERVER_ID, {
        message: `"${SENTINEL_SERVER_ID}" is reserved for the gateway's own tools`
    });

const UpstreamHttpSchema = z.object({
    kind: z.literal('http'),
    url: z.url(),
    /**
     * Extra headers on every outbound request. Values that start with `env:`
     * are resolved from the environment at connect time, so an operator can
     * write `{ "Authorization": "env:FILES_TOKEN" }` without the token itself
     * entering the file.
     */
    headers: z.record(z.string(), z.string()).default({})
});

const UpstreamStdioSchema = z.object({
    kind: z.literal('stdio'),
    command: z.string().min(1),
    args: z.array(z.string()).default([]),
    /**
     * Environment for the child process, on top of the SDK's safe inherited
     * subset (`HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM`, `USER`). Sentinel
     * never spreads its own `process.env` into an upstream: the gateway process
     * holds the Groq key, the approval HMAC secret and the audit database path,
     * and an upstream server is precisely the component not trusted with those.
     * As with headers, an `env:NAME` value forwards that one variable.
     */
    env: z.record(z.string(), z.string()).default({}),
    cwd: z.string().optional()
});

const UpstreamTransportSchema = z.discriminatedUnion('kind', [UpstreamHttpSchema, UpstreamStdioSchema]);

export const UpstreamServerSchema = z.object({
    id: ServerIdSchema,
    /** Human-facing name for the dashboard and approval prompts. */
    label: z.string().min(1).max(120).optional(),
    transport: UpstreamTransportSchema,
    /**
     * Defaults to `untrusted`. That is the whole posture of the project: a
     * server is scanned and its output treated as hostile input until an
     * operator says otherwise. `quarantined` is enforced at the connection
     * layer — the pool refuses to dial it at all — as well as by policy.
     */
    trust: z.enum(['trusted', 'untrusted', 'quarantined']).default('untrusted'),
    /**
     * When present, only these upstream tool names are catalogued. An
     * allowlist is a stronger control than a policy rule because a tool that
     * is never advertised is never described to the model, so a poisoned
     * description cannot reach it.
     */
    allowTools: z.array(z.string().min(1)).optional(),
    /** Set false to keep a server in the config but stop dialling it. */
    enabled: z.boolean().default(true)
});

export const UpstreamPoolSchema = z.object({
    /** Deadline for one connect attempt, including the era probe. */
    connectTimeoutMs: z.number().int().positive().max(120_000).default(10_000),
    /** Deadline for one forwarded request. */
    requestTimeoutMs: z.number().int().positive().max(600_000).default(30_000),
    /**
     * Reconnect backoff. Equal jitter, so a gateway restart does not
     * synchronise every upstream's retry into a thundering herd.
     *
     * `.prefault({})` rather than `.default({})`: in zod 4 a `default` is the
     * *output* value and would have to restate every field, so the block's own
     * per-field defaults would be bypassed — and a field added later would
     * silently arrive as `undefined` for anyone who omitted the block. A
     * `prefault` is parsed through the schema, so the inner defaults apply.
     */
    reconnect: z
        .object({
            initialDelayMs: z.number().int().positive().max(60_000).default(500),
            maxDelayMs: z.number().int().positive().max(3_600_000).default(30_000),
            factor: z.number().min(1).max(10).default(2),
            /**
             * Consecutive failures before the pool stops trying on demand and
             * fails fast until the next scheduled attempt. Without this, every
             * tool call against a dead upstream would pay the full connect
             * timeout, and a single dead server would degrade the whole gateway.
             */
            failFastAfter: z.number().int().positive().max(100).default(3)
        })
        .prefault({}),
    /**
     * `'auto'` probes each upstream with `server/discover` and falls back to
     * the 2025 `initialize` handshake. `'2026-07-28'` pins the modern era and
     * refuses anything else. See `docs/architecture.md` § 6 for why `auto` is
     * the default despite Sentinel itself speaking 2026-07-28 downstream.
     */
    upstreamProtocol: z.enum(['auto', '2026-07-28', 'legacy']).default('auto'),
    /**
     * Pages the SDK's aggregating `tools/list` walk may fetch before it throws.
     *
     * This is the *first* bound on a server that answers every `tools/list` with
     * another `nextCursor`. Sentinel's own `catalog.maxTools` cap cannot help
     * there: by the time the catalog counts tools the pages have already been
     * fetched and held in memory. Lower than the SDK's default of 64 because
     * Sentinel additionally caps tool counts, so a server needing more than 16
     * pages of tools is pathological rather than large.
     */
    listMaxPages: z.number().int().positive().max(1_000).default(16)
});

export const CatalogSchema = z.object({
    /**
     * Tools catalogued from one server. A server that advertises more has the
     * excess dropped, in the order it listed them, with a warning naming the
     * count — never silently.
     */
    maxToolsPerServer: z.number().int().positive().max(4_096).default(256),
    /**
     * Tools in the whole catalog. Applied in configuration order, so a server
     * an operator listed first is never crowded out by one listed later.
     */
    maxTools: z.number().int().positive().max(16_384).default(1_024),
    /**
     * Cap on one tool's canonical JSON. A tool definition is attacker-controlled
     * text that ends up in the agent's context window, in scanner input and in
     * risk-engine prompts, so an unbounded one is a cost amplifier (T17).
     */
    maxDefinitionBytes: z.number().int().positive().max(4_194_304).default(65_536),
    /**
     * What happens when a definition changes after Sentinel has already
     * catalogued it — the rug pull of threat-model T3.
     *
     * `withhold` (default) drops the tool from the advertised list until an
     * operator re-approves it; `flag` records the drift and keeps serving. The
     * default costs availability: an upstream that legitimately ships a new
     * description takes exactly the changed tools offline until someone looks.
     * That is the correct direction for a security gateway — the alternative is
     * that the one moment a definition changes under us is the one moment we
     * choose to trust it — and it is proportionate, because only the tools that
     * actually changed are withheld, not the server.
     */
    onDefinitionDrift: z.enum(['flag', 'withhold']).default('withhold')
});

/**
 * Bounds on what a *request* may carry through the gateway (T17).
 *
 * The catalog bounds what upstreams send us; this bounds what agents send them.
 * Both matter, and for the same reason: Sentinel does not merely relay bytes, it
 * canonicalises them, digests them, redacts them into an audit row and — from
 * M4 — puts them in front of a risk model. Every one of those costs scales with
 * the payload, so an unbounded argument object is a cost amplifier aimed at the
 * gateway rather than at any upstream.
 *
 * This is not the HTTP body cap. That one belongs at the transport gate (M1.4),
 * runs before any parsing, and is the cheaper of the two. This one runs on the
 * parsed params and is what a policy, an audit row and a risk prompt are sized
 * against.
 */
export const ForwardSchema = z.object({
    /**
     * Cap on the canonical JSON of one request's arguments.
     *
     * 256 KiB is generous for a tool call — well past any real argument object,
     * short of anything that would make canonicalisation or an LLM prompt
     * expensive. Raise it only having thought about the risk engine: this number
     * is an upper bound on what gets sent to a scorer per call.
     */
    maxArgumentBytes: z.number().int().positive().max(16_777_216).default(262_144),
    /**
     * Cap on one resource URI, in UTF-8 bytes, before wrapping.
     *
     * Separate from `maxArgumentBytes` because `resources/read` has no arguments
     * to bound — the URI *is* the payload, and it also becomes a Cedar resource
     * identifier and an audit-row column.
     */
    maxResourceUriBytes: z.number().int().positive().max(65_536).default(2_048),
    /**
     * Cap on the canonical JSON of one upstream result.
     *
     * The direction that matters most for injection: a tool result is text a
     * possibly-hostile server wrote that lands directly in the agent's context
     * window, and from M6 in a scanner's input. Not a wire-level bound — the
     * bytes have already arrived by the time this runs — but a bound on what
     * propagates onward, which is the part that costs.
     */
    maxResultBytes: z.number().int().positive().max(33_554_432).default(1_048_576)
});

export const HttpSchema = z.object({
    /**
     * Loopback by default. Sentinel sits between an agent and its tools, which
     * means it holds enough authority that exposing it on `0.0.0.0` should be
     * a deliberate, reviewable act.
     */
    host: z.string().min(1).default('127.0.0.1'),
    port: z.number().int().min(0).max(65_535).default(8787),
    /**
     * Origins permitted by the DNS-rebinding check the spec requires for local
     * servers. Empty means "loopback origins and requests with no Origin
     * header", which is the correct default for a locally-bound gateway.
     */
    allowedOrigins: z.array(z.string()).default([]),
    /**
     * Wire-level HTTP body size cap — the cheapest and earliest bound (T17).
     *
     * This runs before the body is parsed: the connection is rejected at the
     * transport gate, which is the right place for a resource-exhaustion
     * defence. The parsed-params cap (`forward.maxArgumentBytes`) runs later
     * and catches the specific case of oversized tool arguments; this one
     * catches anything that would cost too much to even parse.
     *
     * 4 MiB is the default. It is deliberately larger than `maxArgumentBytes`
     * (256 KiB) because the framing around the params is not zero-cost to
     * parse either, and because future capabilities (elicitation payloads,
     * embedded resources) may legitimately run larger. Raise it only having
     * thought about the parsing cost — this number is what an attacker can
     * push into the parser before being cut off.
     */
    maxBodyBytes: z.number().int().positive().max(67_108_864).default(4_194_304)
});

const ProviderConfigSchema = z.discriminatedUnion('kind', [
    z.object({
        kind: z.literal('groq'),
        /** The API key to use. Follows the `env:` prefix pattern. */
        apiKey: z.string().startsWith('env:'),
        model: z.string().default('llama-3.1-8b-instant')
    }),
    z.object({
        kind: z.literal('ollama'),
        url: z.url().default('http://localhost:11434'),
        model: z.string().default('llama3.1')
    })
]);

const RiskSchema = z.object({
    /** Disable LLM checks completely, relying only on heuristics. */
    heuristicOnly: z.boolean().default(false),
    
    /** 
     * Time to wait for the LLM before timing out. 
     * If it times out, the engine escalates-then-denies.
     */
    llmTimeoutMs: z.number().int().positive().default(5000),
    
    /** The risk score (0-100) at which the obligation is escalated. */
    escalationThreshold: z.number().int().min(0).max(100).default(80),
    
    /** The obligation to escalate to when the risk score exceeds the threshold. */
    escalateObligation: z.enum(['allow', 'review', 'approve']).default('approve'),
    
    /** Optional LLM provider configuration. If omitted, uses heuristics only. */
    provider: ProviderConfigSchema.optional()
});

export const GatewayConfigSchema = z
    .object({
        /** Identity Sentinel reports to upstreams, and to agents in discovery. */
        instanceName: z.string().min(1).max(120).default('mcp-sentinel'),
        http: HttpSchema.prefault({}),
        /** Directory holding `schema.cedarschema` and the `*.cedar` bundle. */
        policyDir: z.string().min(1).default('policies'),
        /** SQLite file for the hash-chained audit trail (M3). */
        auditDb: z.string().min(1).default('.sentinel/audit.db'),
        /**
         * Filesystem root that `pathsWithinWorkspace` is computed against. Policy
         * leans on this heavily, so it is required to be explicit rather than
         * silently defaulting to the process's cwd — which would move the security
         * boundary whenever someone changed directory before starting the gateway.
         */
        workspaceRoot: z.string().min(1),
        upstream: UpstreamPoolSchema.prefault({}),
        catalog: CatalogSchema.prefault({}),
        forward: ForwardSchema.prefault({}),
        risk: RiskSchema.prefault({}),
        servers: z.array(UpstreamServerSchema).default([]),
        /**
         * Group assignment for tools, used in policy evaluation.
         * Keys are group names (e.g. `read_only`), values are lists of fully
         * qualified tool names (e.g. `files__read_file`).
         */
        toolGroups: z.record(z.string(), z.array(z.string())).default({})
    })
    .superRefine((config, ctx) => {
        // A duplicate id would make `files__read_file` ambiguous, and the second
        // definition would silently shadow the first — the tool-shadowing threat
        // arriving through the config file rather than through a hostile server.
        // See docs/threat-model.md T4.
        const seen = new Set<string>();
        for (const [index, server] of config.servers.entries()) {
            if (seen.has(server.id)) {
                ctx.addIssue({
                    code: 'custom',
                    message: `duplicate server id "${server.id}"`,
                    path: ['servers', index, 'id']
                });
            }
            seen.add(server.id);
        }
    });

export type UpstreamServerSettings = z.output<typeof UpstreamServerSchema>;
export type UpstreamPoolSettings = z.output<typeof UpstreamPoolSchema>;
export type CatalogSettings = z.output<typeof CatalogSchema>;
export type ForwardSettings = z.output<typeof ForwardSchema>;
export type HttpSettings = z.output<typeof HttpSchema>;
export type RiskSettings = z.output<typeof RiskSchema>;
export type GatewayConfig = z.output<typeof GatewayConfigSchema>;
