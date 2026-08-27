/**
 * Fixtures shared between the forward-path tests.
 *
 * Three kinds of upstream appear in these tests, and the split follows the one
 * `catalog.test.ts` established.
 *
 * `buildEchoServer` (from the upstream harness) is a genuine `McpServer` and
 * anchors fidelity: it proves the forward path works against a compliant server.
 *
 * `ScriptedUpstreams` here answers `tools/call`, `resources/read` and
 * `prompts/get` from a **low-level `Server`**, because most of what the forwarder
 * defends against is a server behaving badly — omitting a capability, throwing
 * from a handler, returning a result that does not match its own output schema,
 * returning a result too large to relay. `McpServer` correctly refuses to produce
 * several of those. It also records the params each handler *actually received*,
 * which is how the namespace-stripping claim gets verified from the far end
 * rather than from Sentinel's own bookkeeping.
 *
 * `modernUpstream` is the third and the interesting one. `InMemoryTransport`
 * negotiates era `legacy` / `2025-11-25` — it has no `setProtocolVersion` — so
 * nothing on it can exercise the 2026-07-28 wire at all. The headline claim of
 * this milestone, "the outbound `Mcp-Name` is recomputed after the name rewrite",
 * lives *on* that wire. So `modernUpstream` stands up a real modern connection
 * with no socket: `createMcpHandler` produces a web-standard
 * `fetch(Request) => Response`, and `StreamableHTTPClientTransport` accepts a
 * `fetch` override. Wiring one into the other gives a genuine
 * era-`modern` connection whose HTTP headers can be captured and asserted.
 */

import { InMemoryTransport, StreamableHTTPClientTransport, type Transport } from '@modelcontextprotocol/client';
import { Server, type ServerOptions } from '@modelcontextprotocol/server';
import { createMcpHandler } from '@modelcontextprotocol/server';

import {
    buildRequestMetadataHeaders,
    readRequestMetadata,
    type RequestMetadata
} from '@mcp-sentinel/mcp-core';

import { ToolCatalog } from '../catalog/catalog.js';
import type { GatewayConfig } from '../config/schema.js';
import { UpstreamRegistry } from '../upstream/registry.js';
import { TEST_CLIENT_INFO, gatewayConfig, testLogger } from '../upstream/harness.testkit.js';
import type { TransportFactory } from '../upstream/transport.js';
import { Forwarder } from './forwarder.js';
import { ForwardRouter } from './route.js';

/** An upstream server config entry, in the shape `gatewayConfig` wants. */
export function stdio(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return { id, transport: { kind: 'stdio', command: 'srv' }, ...overrides };
}

/**
 * The request metadata an honest client would send for this call.
 *
 * Deliberately built by *encoding* headers and then *decoding* them again rather
 * than by constructing a `RequestMetadata` literal. A literal would let a test
 * pass while `encodeHeaderValue`/`decodeHeaderValue` disagreed — which is exactly
 * the path a non-ASCII resource URI takes through the base64 sentinel.
 */
export function metadataFor(method: string, nameOrUri?: string): RequestMetadata {
    return readRequestMetadata(new Headers(buildRequestMetadataHeaders(method, nameOrUri)));
}

/** Metadata assembled from raw header values, for forging a mismatch. */
export function rawMetadata(headers: Record<string, string>): RequestMetadata {
    return readRequestMetadata(new Headers(headers));
}

/** What one scripted upstream does. Every field is optional; absent means absent. */
export interface UpstreamScript {
    /**
     * Capabilities the server declares. Omitting one is the whole point of the
     * capability-gate tests: the SDK's `Server` refuses to *register* a handler
     * for a method whose capability was not declared, so a server that lacks
     * `resources` cannot be faked by registering a handler that returns an error.
     */
    readonly capabilities?: ServerOptions['capabilities'];
    readonly tools?: readonly unknown[];
    readonly onCallTool?: (params: Record<string, unknown>) => unknown;
    readonly onReadResource?: (params: Record<string, unknown>) => unknown;
    readonly onGetPrompt?: (params: Record<string, unknown>) => unknown;
}

/** One request as the upstream's handler saw it — after the SDK's inbound lift. */
export interface ReceivedRequest {
    readonly serverId: string;
    readonly method: string;
    readonly params: Record<string, unknown>;
}

/**
 * Capabilities as `Server` wants them: present, not merely optional.
 *
 * `ServerOptions['capabilities']` includes `undefined`, which under
 * `exactOptionalPropertyTypes` cannot be handed back to `ServerOptions`. Narrowing
 * once here keeps the `?? ALL_CAPABILITIES` defaulting honest at the type level
 * instead of pushing a cast into both factories.
 */
type DeclaredCapabilities = NonNullable<ServerOptions['capabilities']>;

const ALL_CAPABILITIES: DeclaredCapabilities = { tools: {}, resources: {}, prompts: {} };

/**
 * Upstreams whose every handler is scripted per server id.
 *
 * The script is consulted at *request* time, so a test can change an upstream's
 * behaviour over a live connection.
 */
export class ScriptedUpstreams {
    private readonly scripts = new Map<string, UpstreamScript>();
    private readonly running: Server[] = [];

    /** Every request any upstream handler served, in order. */
    public readonly received: ReceivedRequest[] = [];

    public set(serverId: string, script: UpstreamScript): void {
        this.scripts.set(serverId, script);
    }

    /** Params the named server saw for this method, or `undefined`. */
    public paramsFor(serverId: string, method: string): Record<string, unknown> | undefined {
        return this.received.find(entry => entry.serverId === serverId && entry.method === method)?.params;
    }

    public readonly factory: TransportFactory = (settings): Transport => {
        // Capabilities are read at *connect* time, because they are negotiated
        // once and a server cannot change its mind mid-connection. Everything
        // else is read at *request* time, so a test can rewrite an upstream's
        // answers over a live connection — which is the only way to exercise
        // definition drift (T3) without tearing the connection down.
        const declared: DeclaredCapabilities = (this.scripts.get(settings.id) ?? {}).capabilities ?? ALL_CAPABILITIES;
        const server = new Server({ name: settings.id, version: '1.0.0' }, { capabilities: declared });
        const current = (): UpstreamScript => this.scripts.get(settings.id) ?? {};

        const record = (method: string, params: unknown): void => {
            this.received.push({
                serverId: settings.id,
                method,
                params: (params ?? {}) as Record<string, unknown>
            });
        };

        // Registration is guarded by the declared capabilities: `Server`'s own
        // `assertRequestHandlerCapability` throws for a method whose capability is
        // absent, which is what makes "the upstream simply has no resources"
        // expressible here rather than merely simulated.
        if (declared.tools !== undefined) {
            server.setRequestHandler('tools/list', async () => ({ tools: [...(current().tools ?? [])] }) as never);
            server.setRequestHandler('tools/call', async request => {
                record('tools/call', request.params);
                const answer = current().onCallTool?.(request.params as unknown as Record<string, unknown>);
                return (answer ?? { content: [{ type: 'text' as const, text: 'ok' }] }) as never;
            });
        }

        if (declared.resources !== undefined) {
            server.setRequestHandler('resources/read', async request => {
                record('resources/read', request.params);
                const answer = current().onReadResource?.(request.params as unknown as Record<string, unknown>);
                return (answer ?? { contents: [{ uri: request.params.uri, text: 'body' }] }) as never;
            });
        }

        if (declared.prompts !== undefined) {
            server.setRequestHandler('prompts/get', async request => {
                record('prompts/get', request.params);
                const answer = current().onGetPrompt?.(request.params as unknown as Record<string, unknown>);
                return (answer ??
                    {
                        messages: [{ role: 'user' as const, content: { type: 'text' as const, text: 'hi' } }]
                    }) as never;
            });
        }

        this.running.push(server);
        const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
        void server.connect(serverTransport);
        return clientTransport;
    };

    public async closeAll(): Promise<void> {
        await Promise.allSettled(this.running.map(async server => server.close()));
    }
}

/**
 * A modern-era upstream: a real 2026-07-28 Streamable HTTP connection with no
 * socket, and a record of every HTTP header the SDK put on the wire.
 *
 * The `fetch` handed to the transport captures the outbound headers and then
 * forwards the request into `createMcpHandler`'s own `fetch`. Both halves are the
 * SDK's real code — only the socket is missing, and the socket is the one part
 * that has no bearing on which headers get computed.
 */
export class ModernUpstream {
    /** Headers of every request the SDK sent, in order. */
    public readonly sentHeaders: Array<Record<string, string>> = [];
    public readonly received: ReceivedRequest[] = [];

    private readonly script: UpstreamScript;

    public constructor(script: UpstreamScript = {}) {
        this.script = script;
    }

    /** Headers of the first request carrying this `mcp-method`. */
    public headersFor(method: string): Record<string, string> | undefined {
        return this.sentHeaders.find(headers => headers['mcp-method'] === method);
    }

    public readonly factory: TransportFactory = (settings): Transport => {
        const script = this.script;
        const declared: DeclaredCapabilities = script.capabilities ?? ALL_CAPABILITIES;

        const handler = createMcpHandler(() => {
            const server = new Server({ name: settings.id, version: '1.0.0' }, { capabilities: declared });

            const record = (method: string, params: unknown): void => {
                this.received.push({
                    serverId: settings.id,
                    method,
                    params: (params ?? {}) as Record<string, unknown>
                });
            };

            if (declared.tools !== undefined) {
                server.setRequestHandler('tools/list', async () => ({ tools: [...(script.tools ?? [])] }) as never);
                server.setRequestHandler('tools/call', async request => {
                    record('tools/call', request.params);
                    const answer = script.onCallTool?.(request.params as unknown as Record<string, unknown>);
                    return (answer ?? { content: [{ type: 'text' as const, text: 'ok' }] }) as never;
                });
            }
            if (declared.resources !== undefined) {
                server.setRequestHandler('resources/read', async request => {
                    record('resources/read', request.params);
                    const answer = script.onReadResource?.(request.params as unknown as Record<string, unknown>);
                    return (answer ?? { contents: [{ uri: request.params.uri, text: 'body' }] }) as never;
                });
            }
            if (declared.prompts !== undefined) {
                server.setRequestHandler('prompts/get', async request => {
                    record('prompts/get', request.params);
                    const answer = script.onGetPrompt?.(request.params as unknown as Record<string, unknown>);
                    return (answer ??
                        {
                            messages: [{ role: 'user' as const, content: { type: 'text' as const, text: 'hi' } }]
                        }) as never;
                });
            }

            return server;
        });

        const capturing: typeof fetch = async (input, init) => {
            const request = new Request(input as Request, init);
            const headers: Record<string, string> = {};
            request.headers.forEach((value, key) => {
                headers[key.toLowerCase()] = value;
            });
            this.sentHeaders.push(headers);
            const body = await request.clone().text();
            return handler.fetch(
                new Request(request.url, {
                    method: request.method,
                    headers: request.headers,
                    body: body.length === 0 ? null : body
                })
            );
        };

        return new StreamableHTTPClientTransport(new URL('http://upstream.invalid/mcp'), {
            fetch: capturing as never,
            reconnectionOptions: { maxRetries: 0, initialReconnectionDelay: 1, maxReconnectionDelay: 1, reconnectionDelayGrowFactor: 1 }
        });
    };
}

export interface ForwardHarness {
    readonly router: ForwardRouter;
    readonly forwarder: Forwarder;
    readonly catalog: ToolCatalog;
    readonly registry: UpstreamRegistry;
    readonly config: GatewayConfig;
    readonly records: ReturnType<typeof testLogger>['records'];
}

export interface ForwardHarnessOptions {
    readonly servers: ReadonlyArray<Record<string, unknown>>;
    readonly factory: TransportFactory;
    /** Overrides for the `forward` config block. */
    readonly forward?: Record<string, unknown>;
    readonly catalogSettings?: Record<string, unknown>;
    readonly upstream?: Record<string, unknown>;
    /** Registered by the caller so the harness never leaks a live connection. */
    readonly cleanups: Array<() => Promise<void>>;
}

/** Wire a router and forwarder over a real registry and catalog. */
export function forwardHarness(options: ForwardHarnessOptions): ForwardHarness {
    const { logger, records } = testLogger();
    const config = gatewayConfig({
        servers: options.servers,
        ...(options.forward === undefined ? {} : { forward: options.forward }),
        ...(options.catalogSettings === undefined ? {} : { catalog: options.catalogSettings }),
        ...(options.upstream === undefined
            ? {}
            : {
                  upstream: {
                      connectTimeoutMs: 2_000,
                      requestTimeoutMs: 2_000,
                      reconnect: { initialDelayMs: 20, maxDelayMs: 200, factor: 2, failFastAfter: 2 },
                      ...options.upstream
                  }
              })
    });

    const registry = new UpstreamRegistry(config, {
        logger,
        clientInfo: TEST_CLIENT_INFO,
        transportFactory: options.factory,
        random: () => 1
    });
    options.cleanups.push(async () => registry.close());

    const catalog = new ToolCatalog({ registry, settings: config.catalog, logger });

    return {
        router: new ForwardRouter({ catalog, registry, settings: config.forward, logger }),
        forwarder: new Forwarder({ registry, settings: config.forward, logger, now: () => 0 }),
        catalog,
        registry,
        config,
        records
    };
}

/** A minimal but valid tool definition. */
export function toolDef(name: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
    return { name, description: 'A tool.', inputSchema: { type: 'object', properties: {} }, ...extra };
}
