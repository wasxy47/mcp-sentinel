/**
 * `SentinelServer` — the gateway as a spec-compliant MCP server.
 *
 * This is where the modules built in M1.1–M1.3 are wired into a live server.
 * The low-level SDK `Server` is used rather than `McpServer` for three reasons:
 *
 *  1. **Dynamic tool list.** Sentinel's tools are not known at construction time;
 *     they depend on which upstreams are dialable, and they change as upstreams
 *     connect and disconnect. `McpServer.registerTool` is for fixed tools.
 *
 *  2. **Custom methods.** `tasks/update` (the 2026-07-28 extension) has no
 *     `McpServer` equivalent. The SDK's 3-arg `setRequestHandler` handles it.
 *
 *  3. **No double routing.** The gateway's `tools/call` logic is "route through
 *     the catalog, then forward". That logic lives in `ForwardRouter`; `McpServer`
 *     would impose a second layer with no benefit.
 *
 * Architecture §4.7 documents this decision in full.
 *
 * ## setRequestHandler forms used
 *
 *  - **2-arg form** (method name + handler): for SDK-known methods where we want
 *    the fully-typed request parameter (`tools/list`, `tools/call`, `resources/read`,
 *    `prompts/get`, `server/discover`). The SDK validates the request against
 *    its own schema and the handler receives the typed result.
 *
 *  - **3-arg form** (method name + `{ params: Schema }` + handler): for custom
 *    methods where the SDK has no built-in schema (`tasks/*`). The handler
 *    receives the inferred Zod output.
 *
 * ## What this module does not do
 *
 *  - **Policy evaluation.** Calls are forwarded as-is; M2 adds the Cedar gate.
 *  - **Audit writes.** M3 adds the hash-chained append.
 *  - **Risk scoring.** M4.
 *  - **Approval suspension / task bridging.** M5.5.
 *
 * ## tasks/* stubs
 *
 * The 2026-07-28 Tasks extension is not implemented until M5.5.
 * Every task method returns `-32601 MethodNotFound` with a message that
 * explains the deferral. This is the correct JSON-RPC code: the method is
 * known to the spec but not implemented here.
 */

import { Server } from '@modelcontextprotocol/server';
import { createMcpHandler, ProtocolError, METHOD_NOT_FOUND } from '@modelcontextprotocol/server';
import * as z from 'zod';


import type { RequestMetadata } from '@mcp-sentinel/mcp-core';

import type { ToolCatalog } from '../catalog/catalog.js';
import type { GatewayConfig } from '../config/schema.js';
import type { Logger } from '../observability/logger.js';
import type { UpstreamRegistry } from '../upstream/registry.js';
import { buildDiscoverResult } from '../forward/discover.js';
import { Forwarder } from '../forward/forwarder.js';
import { ForwardRouter } from '../forward/route.js';
import { isSentinelOwnTool, sentinelToolDefinitions } from './sentinel-tools.js';

import type { PolicyEngine } from '@mcp-sentinel/policy-engine';
import {
    extractToolCallContext,
    extractResourceReadContext,
    extractBaseContext,
    agentPrincipalFromIdentity,
    toolResource,
} from '@mcp-sentinel/policy-engine';
import {
    PolicyDeniedError,
    newId,
    isoTimestamp,
    digestOf,
    type DecisionRecord
} from '@mcp-sentinel/mcp-core';
import type { AuditStore, AuditWriteError } from '@mcp-sentinel/audit';

/** The message every tasks/* stub returns. Searchable in logs and issues. */
export const TASKS_DEFERRED_MESSAGE =
    'tasks/* subsystem is deferred to M5.5 (approval bridging). ' +
    'No task state exists until Sentinel can suspend and resume calls awaiting human approval.';

/** Zod schema for any task method params — the 3-arg form requires `{ params }`. */
const AnyParamsSchema = z.object({}).passthrough();

/** Schema bundles for the 3-arg `setRequestHandler` overload. */
const TOOLS_CALL_SCHEMA = { params: z.object({ name: z.string(), arguments: z.record(z.string(), z.unknown()).optional() }).passthrough() } as const;
const RESOURCES_READ_SCHEMA = { params: z.object({ uri: z.string() }).passthrough() } as const;
const PROMPTS_GET_SCHEMA = { params: z.object({ name: z.string() }).passthrough() } as const;

/** Schema bundle expected by `setRequestHandler`'s 3-arg overload. */
const TASK_SCHEMA = { params: AnyParamsSchema } as const;

export interface SentinelServerDeps {
    readonly config: GatewayConfig;
    readonly registry: UpstreamRegistry;
    readonly catalog: ToolCatalog;
    readonly logger: Logger;
    /** Optional policy engine. If absent, evaluation is skipped (warns). */
    readonly policyEngine?: PolicyEngine | undefined;
    /** Optional audit store. If absent, audit logging is skipped (warns). */
    readonly auditStore?: AuditStore | undefined;
    /** Injectable clock. Tests must not depend on wall time. */
    readonly now?: () => number;
}

/**
 * Sentinel as a real MCP server.
 *
 * Construction registers all handlers. Call `.fetch(request)` to handle an
 * individual HTTP request (delegates to `createMcpHandler`). `createMcpHandler`
 * is invoked once and re-used, so the per-request `Server` instances the SDK
 * creates share none of the gateway's stateful deps; those are captured in
 * the factory closure.
 */
export class SentinelServer {
    private readonly config: GatewayConfig;
    private readonly registry: UpstreamRegistry;
    private readonly catalog: ToolCatalog;
    private readonly logger: Logger;
    private readonly policyEngine?: PolicyEngine;
    private readonly auditStore?: AuditStore;
    private readonly now?: () => number;
    private readonly router: ForwardRouter;
    private readonly forwarder: Forwarder;

    /**
     * The SDK handler produced by `createMcpHandler`.
     *
     * Stateless Streamable HTTP: each POST spawns a fresh `Server` instance
     * via the factory, handles the request, and tears down. The factory is the
     * closure that binds to the gateway's deps.
     */
    private readonly handler: ReturnType<typeof createMcpHandler>;

    public constructor(deps: SentinelServerDeps) {
        this.config = deps.config;
        this.registry = deps.registry;
        this.catalog = deps.catalog;
        this.logger = deps.logger;
        if (deps.policyEngine) {
            this.policyEngine = deps.policyEngine;
        }
        if (deps.auditStore) {
            this.auditStore = deps.auditStore;
        }
        if (deps.now) {
            this.now = deps.now;
        }

        if (!this.policyEngine) {
            this.logger.warn('SentinelServer starting without a PolicyEngine — all calls will bypass policy evaluation');
        }
        if (!this.auditStore) {
            this.logger.warn('SentinelServer starting without an AuditStore — all decisions will be unrecorded');
        }

        this.router = new ForwardRouter({
            catalog: this.catalog,
            registry: this.registry,
            settings: this.config.forward,
            logger: this.logger
        });

        this.forwarder = new Forwarder({
            registry: this.registry,
            settings: this.config.forward,
            logger: this.logger,
            ...(deps.now === undefined ? {} : { now: deps.now })
        });

        this.handler = createMcpHandler(() => this.buildServer(), {
            // Legacy 2025 traffic: reject it. The gateway speaks 2026-07-28 only.
            // An agent on an older client should get a clear protocol-version error
            // rather than a silently degraded session where capabilities differ.
            legacy: 'reject',
            onerror: (err) => this.logger.error('createMcpHandler onerror', { error: String(err), stack: (err as Error).stack })
        });
    }

    /**
     * Handle one HTTP request.
     *
     * Delegates entirely to the SDK handler. All Sentinel-specific logic is in
     * the handlers registered on the `Server` in `buildServer()`. This method
     * exists to give `http.ts` a clean seam that does not depend on SDK internals.
     */
    public fetch(request: Request): Promise<Response> {
        return this.handler.fetch(request);
    }

    /**
     * Close the handler (drains any in-flight SSE streams).
     */
    public async close(): Promise<void> {
        await this.handler.close();
    }

    /**
     * Build one per-request `Server` instance, wired to the gateway's deps.
     *
     * Called by `createMcpHandler` on every POST. The returned `Server` handles
     * exactly one request and is torn down by the SDK when the response is sent.
     * Gateway state (registry, catalog, etc.) is referenced through the closure —
     * never stored on the `Server` instance, which means there is nothing to clean
     * up and no shared mutable state between requests.
     *
     * Capabilities are computed from live upstream snapshots each time, so a
     * server that connects between two requests is reflected in the second
     * response without a restart.
     */
    private buildServer(): Server {
        const snapshots = this.registry.snapshots();
        const serverInfo = {
            name: this.config.instanceName,
            version: '0.1.0'
        };

        // Capabilities: what Sentinel itself can serve right now.
        // `aggregateCapabilities` reads the snapshots rather than a fixed config
        // value, so the answer changes as upstreams connect and disconnect.
        const capabilities: Record<string, object> = {
            // `tools` is unconditional: Sentinel always answers `tools/list`.
            tools: {},
            // `resources` and `prompts` only when a ready upstream has them.
            ...this.aggregateOptionalCapabilities(snapshots)
        };

        const server = new Server(serverInfo, { capabilities });

        // ── discovery ────────────────────────────────────────────────────────────
        // 2-arg form: SDK knows `server/discover` and types the response.
        server.setRequestHandler('server/discover', async _req => {
            this.enforcePolicy('discover', { kind: 'endpoint' }, extractBaseContext('2026-07-28'));
            return buildDiscoverResult({ serverInfo, snapshots: this.registry.snapshots() });
        });

        // ── tool listing ─────────────────────────────────────────────────────────
        // 2-arg form: SDK knows `tools/list`.
        server.setRequestHandler('tools/list', async _req => {
            this.enforcePolicy('listTools', { kind: 'endpoint' }, extractBaseContext('2026-07-28'));
            // Upstream tools come from the catalog, already in qualified form.
            // Sentinel's own tools are appended at the end, also in qualified form.
            return {
                tools: [...this.catalog.advertised(), ...sentinelToolDefinitions()]
            };
        });

        // ── tools/call ───────────────────────────────────────────────────────────
        // 3-arg form: handler return type is `unknown` (runtime-validated by the
        // SDK). The 2-arg form would require returning the exact `CallToolResult`
        // type, but `ForwardedResult` is a wider union — narrowing it here would
        // require a cast that trades compile-time safety for runtime safety we
        // already have from the SDK's own result validation.
        server.setRequestHandler('tools/call', TOOLS_CALL_SCHEMA, async (params) => {
            const name = params.name;

            // Sentinel's own tools: stub response until M7 implements them.
            if (isSentinelOwnTool(name)) {
                this.logger.debug('sentinel own tool called — stub response (M7)', { tool: name });
                return {
                    content: [
                        {
                            type: 'text' as const,
                            text:
                                `${name} is not yet implemented. ` +
                                `This tool will be available in a future milestone (M7). ` +
                                `If you need this capability now, access the gateway's ` +
                                `operator interface directly.`
                        }
                    ],
                    isError: true
                };
            }

            // Upstream tool: route and forward.
            const metadata = buildInlineMetadata('tools/call', name);
            const route = this.router.route(metadata, { method: 'tools/call', params });
            if (route.kind !== 'forward') {
                throw new Error('unexpected route kind for tools/call');
            }

            const start = this.now ? this.now() : Date.now();
            let decision;
            let context;
            
            // M2 policy evaluation
            if (this.policyEngine) {
                const entry = this.catalog.get(name);
                if (!entry) {
                    throw new ProtocolError(METHOD_NOT_FOUND, `tool ${name} not found`);
                }
                const snap = this.registry.snapshots().find(s => s.serverId === entry.serverId);
                const trust = snap?.trust ?? 'untrusted';
                
                const resource = toolResource(entry, this.config.toolGroups, trust);
                context = extractToolCallContext(params.arguments, {
                    workspaceRoot: this.config.workspaceRoot,
                    allowedHosts: this.config.http.allowedOrigins, // using allowedOrigins as allowedHosts for now
                    protocolVersion: '2026-07-28',
                    serverTrust: trust,
                    toolScanVerdict: entry.scan?.verdict ?? 'clean'
                });

                decision = this.enforcePolicy('callTool', resource, context);
                
                if (decision && decision.obligation !== 'allow') {
                    // Record deferred decision in audit
                    const record: DecisionRecord = {
                        decisionId: newId('decision'),
                        timestamp: isoTimestamp(start),
                        agent: agentPrincipalFromIdentity({ id: 'anonymous', name: 'unknown', trustTier: 'standard', authenticated: false }),
                        protocolVersion: '2026-07-28',
                        method: 'tools/call',
                        qualifiedName: name,
                        serverId: entry.serverId,
                        upstreamName: entry.toolName,
                        verdict: 'pending_approval',
                        obligation: decision.obligation,
                        policy: decision,
                        argsDigest: digestOf(params.arguments),
                        redactionFindings: [], // TODO: redact
                        latencyMs: (this.now ? this.now() : Date.now()) - start,
                        degraded: false
                    };
                    this.appendAudit(record);
                    
                    // M4/M5 stub
                    return {
                        content: [{ type: 'text', text: `Call deferred: requires ${decision.obligation}. (M4/M5 functionality not yet implemented)` }],
                        isError: true
                    };
                }
            }

            // M3: Upstream tool: route and forward, with audit wrap
            const serverId = this.catalog.get(name)?.serverId;
            const upstreamName = this.catalog.get(name)?.toolName;

            const recordBase = {
                decisionId: newId('decision'),
                timestamp: isoTimestamp(start),
                agent: agentPrincipalFromIdentity({ id: 'anonymous', name: 'unknown', trustTier: 'standard', authenticated: false }),
                protocolVersion: '2026-07-28',
                method: 'tools/call',
                qualifiedName: name,
                ...(serverId !== undefined ? { serverId } : {}),
                ...(upstreamName !== undefined ? { upstreamName } : {}),
                verdict: 'allow' as const,
                obligation: decision?.obligation ?? 'allow',
                policy: decision ?? { effect: 'permit' as const, obligation: 'allow' as const, reasons: [], errors: [], defaultDeny: false },
                argsDigest: digestOf(params.arguments),
                redactionFindings: [],
                degraded: false
            };

            this.appendAudit({
                ...recordBase,
                latencyMs: (this.now ? this.now() : Date.now()) - start,
            });
            
            try {
                const outcome = await this.forwarder.forward(route.target, undefined);
                // Ideally we'd append an audit update here with resultDigest, but AuditStore is append-only.
                return outcome.result;
            } catch (error) {
                // If upstream fails, we might want to log that too, but we already audited the allowance.
                throw error;
            }
        });

        // ── resources/read ───────────────────────────────────────────────────────
        // Only registered when at least one ready upstream advertises resources.
        if (capabilities.resources !== undefined) {
            server.setRequestHandler('resources/read', RESOURCES_READ_SCHEMA, async (params) => {
                const start = this.now ? this.now() : Date.now();
                const metadata = buildInlineMetadata('resources/read', params.uri);
                const route = this.router.route(metadata, { method: 'resources/read', params });
                if (route.kind !== 'forward') {
                    throw new Error('unexpected route kind for resources/read');
                }

                let decision;
                if (this.policyEngine) {
                    const snap = this.registry.snapshots().find(s => s.serverId === route.target.serverId);
                    const trust = snap?.trust ?? 'untrusted';
                    const context = extractResourceReadContext(route.target.upstreamName, {
                        workspaceRoot: this.config.workspaceRoot,
                        allowedHosts: this.config.http.allowedOrigins,
                        protocolVersion: '2026-07-28',
                        serverTrust: trust,
                        toolScanVerdict: 'clean'
                    });
                    const resource = {
                        kind: 'mcp-resource' as const,
                        qualifiedUri: params.uri,
                        rawUri: route.target.upstreamName,
                        serverId: route.target.serverId,
                        serverTrust: trust,
                        serverScanVerdict: snap?.health === 'ready' ? 'clean' : 'unknown',
                        scheme: new URL(route.target.upstreamName).protocol.slice(0, -1)
                    };
                    decision = this.enforcePolicy('readResource', resource, context);
                    if (decision && decision.obligation !== 'allow') {
                        // Record deferred decision in audit
                        const record: DecisionRecord = {
                            decisionId: newId('decision'),
                            timestamp: isoTimestamp(start),
                            agent: agentPrincipalFromIdentity({ id: 'anonymous', name: 'unknown', trustTier: 'standard', authenticated: false }),
                            protocolVersion: '2026-07-28',
                            method: 'resources/read',
                            qualifiedName: params.uri,
                            serverId: route.target.serverId,
                            upstreamName: route.target.upstreamName,
                            verdict: 'pending_approval',
                            obligation: decision.obligation,
                            policy: decision,
                            argsDigest: digestOf(params),
                            redactionFindings: [],
                            latencyMs: (this.now ? this.now() : Date.now()) - start,
                            degraded: false
                        };
                        this.appendAudit(record);
                        throw new PolicyDeniedError(`readResource requires ${decision.obligation}`, { obligation: decision.obligation });
                    }
                }

                const recordBase = {
                    decisionId: newId('decision'),
                    timestamp: isoTimestamp(start),
                    agent: agentPrincipalFromIdentity({ id: 'anonymous', name: 'unknown', trustTier: 'standard', authenticated: false }),
                    protocolVersion: '2026-07-28',
                    method: 'resources/read',
                    qualifiedName: params.uri,
                    serverId: route.target.serverId,
                    upstreamName: route.target.upstreamName,
                    verdict: 'allow' as const,
                    obligation: decision?.obligation ?? 'allow',
                    policy: decision ?? { effect: 'permit' as const, obligation: 'allow' as const, reasons: [], errors: [], defaultDeny: false },
                    argsDigest: digestOf(params),
                    redactionFindings: [],
                    degraded: false
                };
    
                this.appendAudit({
                    ...recordBase,
                    latencyMs: (this.now ? this.now() : Date.now()) - start,
                });

                try {
                    const outcome = await this.forwarder.forward(route.target, undefined);
                    return outcome.result;
                } catch (error) {
                    throw error;
                }
            });
        }

        // ── prompts/get ──────────────────────────────────────────────────────────
        // Only registered when at least one ready upstream advertises prompts.
        if (capabilities.prompts !== undefined) {
            server.setRequestHandler('prompts/get', PROMPTS_GET_SCHEMA, async (params) => {
                const start = this.now ? this.now() : Date.now();
                const metadata = buildInlineMetadata('prompts/get', params.name);
                const route = this.router.route(metadata, { method: 'prompts/get', params });
                if (route.kind !== 'forward') {
                    throw new Error('unexpected route kind for prompts/get');
                }

                let decision;
                if (this.policyEngine) {
                    const snap = this.registry.snapshots().find(s => s.serverId === route.target.serverId);
                    const trust = snap?.trust ?? 'untrusted';
                    const resource = {
                        kind: 'prompt' as const,
                        qualifiedName: params.name,
                        promptName: route.target.upstreamName,
                        serverId: route.target.serverId,
                        serverTrust: trust,
                        serverScanVerdict: snap?.health === 'ready' ? 'clean' : 'unknown',
                        promptScanVerdict: 'clean'
                    };
                    decision = this.enforcePolicy('getPrompt', resource, extractBaseContext('2026-07-28'));
                    if (decision && decision.obligation !== 'allow') {
                        // Record deferred decision in audit
                        const record: DecisionRecord = {
                            decisionId: newId('decision'),
                            timestamp: isoTimestamp(start),
                            agent: agentPrincipalFromIdentity({ id: 'anonymous', name: 'unknown', trustTier: 'standard', authenticated: false }),
                            protocolVersion: '2026-07-28',
                            method: 'prompts/get',
                            qualifiedName: params.name,
                            serverId: route.target.serverId,
                            upstreamName: route.target.upstreamName,
                            verdict: 'pending_approval',
                            obligation: decision.obligation,
                            policy: decision,
                            argsDigest: digestOf(params),
                            redactionFindings: [],
                            latencyMs: (this.now ? this.now() : Date.now()) - start,
                            degraded: false
                        };
                        this.appendAudit(record);
                        throw new PolicyDeniedError(`getPrompt requires ${decision.obligation}`, { obligation: decision.obligation });
                    }
                }

                const recordBase = {
                    decisionId: newId('decision'),
                    timestamp: isoTimestamp(start),
                    agent: agentPrincipalFromIdentity({ id: 'anonymous', name: 'unknown', trustTier: 'standard', authenticated: false }),
                    protocolVersion: '2026-07-28',
                    method: 'prompts/get',
                    qualifiedName: params.name,
                    serverId: route.target.serverId,
                    upstreamName: route.target.upstreamName,
                    verdict: 'allow' as const,
                    obligation: decision?.obligation ?? 'allow',
                    policy: decision ?? { effect: 'permit' as const, obligation: 'allow' as const, reasons: [], errors: [], defaultDeny: false },
                    argsDigest: digestOf(params),
                    redactionFindings: [],
                    degraded: false
                };
    
                this.appendAudit({
                    ...recordBase,
                    latencyMs: (this.now ? this.now() : Date.now()) - start,
                });

                try {
                    const outcome = await this.forwarder.forward(route.target, undefined);
                    return outcome.result;
                } catch (error) {
                    throw error;
                }
            });
        }

        // ── tasks/* stubs ────────────────────────────────────────────────────────
        //
        // The 2026-07-28 Tasks extension defines these methods. They are
        // registered so an agent sending them gets a clear, informative error
        // rather than a generic parse failure. Each returns -32601 (MethodNotFound).
        //
        // The 3-arg form is used because the SDK has no built-in schema for
        // `tasks/update` (the 2026-07-28 extension method). Using the same form
        // for all four keeps the pattern consistent and avoids mixing overloads.
        for (const taskMethod of ['tasks/get', 'tasks/cancel', 'tasks/list', 'tasks/update'] as const) {
            server.setRequestHandler(taskMethod, TASK_SCHEMA, async () => {
                this.logger.debug('tasks/* method called — deferred to M5.5', { method: taskMethod });
                throw new ProtocolError(METHOD_NOT_FOUND, TASKS_DEFERRED_MESSAGE);
            });
        }

        return server;
    }

    /**
     * Aggregate optional capabilities (resources, prompts) from live snapshots.
     *
     * `tools` is always present and handled at the call site. This returns only
     * the conditional capabilities so the caller can spread them in.
     */
    private aggregateOptionalCapabilities(
        snapshots: readonly ReturnType<UpstreamRegistry['snapshots']>[number][]
    ): Record<string, object> {
        let resources = false;
        let prompts = false;
        for (const snap of snapshots) {
            if (snap.health !== 'ready') continue;
            if (snap.capabilities?.resources !== undefined) resources = true;
            if (snap.capabilities?.prompts !== undefined) prompts = true;
        }
        return {
            ...(resources ? { resources: {} } : {}),
            ...(prompts ? { prompts: {} } : {})
        };
    }

    private enforcePolicy(
        action: import('@mcp-sentinel/policy-engine').McpAction,
        resource: import('@mcp-sentinel/policy-engine').PolicyResource,
        context: import('@mcp-sentinel/policy-engine').PolicyContext
    ) {
        if (!this.policyEngine) return null;

        // In M2, we use a fixed anonymous agent profile. Agent identity (JWT/mTLS)
        // is out of scope.
        const agent = agentPrincipalFromIdentity({
            id: 'anonymous',
            name: 'unknown',
            trustTier: 'standard',
            authenticated: false
        });

        const decision = this.policyEngine.evaluate({
            principal: agent,
            action,
            resource,
            context
        });

        if (decision.effect === 'forbid') {
            const firstReason = decision.reasons.length > 0 ? decision.reasons[0] : undefined;
            const reason = firstReason ? firstReason : 'Denied by policy';
            throw new PolicyDeniedError(reason, { reasons: decision.reasons });
        }

        return decision;
    }

    private appendAudit(record: DecisionRecord): void {
        if (!this.auditStore) return;
        try {
            this.auditStore.append(record);
        } catch (error) {
            // Fail-closed semantics for audit writes.
            throw {
                code: -32001,
                message: 'Audit write failed — request denied (fail-closed)',
                data: { error: error instanceof Error ? error.message : String(error) }
            };
        }
    }
}

/**
 * Build `RequestMetadata` from an already-agreed method and name.
 *
 * Inside the SDK's `Server` handler, the body has already been parsed and the
 * header/body agreement has already been verified by the SDK's inbound
 * validation ladder. The router's internal `assertHeaderMatchesBody` call
 * succeeds because both sides come from the same agreed value.
 */
function buildInlineMetadata(method: string, nameOrUri: string): RequestMetadata {
    return {
        protocolVersion: '2026-07-28',
        method,
        name: nameOrUri,
        params: new Map()
    };
}
