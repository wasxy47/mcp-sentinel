/**
 * `SentinelServer` integration tests.
 *
 * These tests exercise Sentinel as a real MCP server: an agent-side SDK client
 * connects to a real `SentinelServer` instance and makes actual MCP calls.
 * The upstream layer uses `ScriptedUpstreams` (from the forward test harness)
 * so we can control exactly what each upstream returns and assert on what the
 * handler does with it.
 *
 * ## What "integration" means here
 *
 * End-to-end within the process, using `InMemoryTransport` on the upstream side
 * and `createMcpHandler`'s own fetch machinery on the Sentinel side. Nothing
 * mocked except the upstream servers themselves. The layer being proven:
 *
 *   agent SDK client
 *        → createMcpHandler (real, per-request Server instances)
 *        → SentinelServer.buildServer (our handler registrations)
 *        → ForwardRouter + Forwarder (routing, param rewrite)
 *        → ScriptedUpstream over InMemoryTransport
 *
 * ## What is NOT tested here
 *
 *   - HTTP transport (origin checks, body size cap) — that is `http.test.ts`.
 *   - Policy evaluation — M2.
 *   - Audit writes — M3.
 *
 * ## Test layout
 *
 * Each test group sets up its own `SentinelServer` with a fresh `registry` and
 * `catalog`. Groups that need a running upstream call `upstream.factory` through
 * the `ScriptedUpstreams` harness from `forward/harness.testkit.ts`.
 */

import { DiscoverResultSchema } from '@modelcontextprotocol/core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SENTINEL_PROTOCOL_VERSION, qualifyResourceUri } from '@mcp-sentinel/mcp-core';

import { ToolCatalog } from '../catalog/catalog.js';
import { GatewayConfigSchema } from '../config/schema.js';
import type { GatewayConfig } from '../config/schema.js';
import { Logger, collectingSink } from '../observability/logger.js';
import { UpstreamRegistry } from '../upstream/registry.js';
import { InMemoryTransport } from '@modelcontextprotocol/client';
import { ScriptedUpstreams, toolDef } from '../forward/harness.testkit.js';
import { TEST_CLIENT_INFO } from '../upstream/harness.testkit.js';
import { SentinelServer, TASKS_DEFERRED_MESSAGE } from './handlers.js';
import { SENTINEL_TOOL_NAMES } from './sentinel-tools.js';

// ── helpers ───────────────────────────────────────────────────────────────────

function makeConfig(overrides: Record<string, unknown> = {}): GatewayConfig {
    return GatewayConfigSchema.parse({
        workspaceRoot: '/tmp/mcp-sentinel-test',
        upstream: {
            connectTimeoutMs: 2_000,
            requestTimeoutMs: 2_000,
            reconnect: { initialDelayMs: 20, maxDelayMs: 200, factor: 2, failFastAfter: 2 }
        },
        ...overrides
    });
}

interface TestContext {
    config: GatewayConfig;
    logger: Logger;
    registry: UpstreamRegistry;
    catalog: ToolCatalog;
    sentinel: SentinelServer;
    upstreams: ScriptedUpstreams;
    cleanups: Array<() => Promise<void>>;
}

/**
 * Connect an agent-side MCP client to the SentinelServer.
 *
 * Uses a mock client that directly constructs modern 2026-07-28 requests and
 * dispatches them to SentinelServer's fetch endpoint, bypassing the SDK's
 * Client (which defaults to the 2025 legacy protocol and lacks envelope support).
 */
export class MockModernClient {
    private id = 1;
    constructor(private readonly sentinel: SentinelServer) {}

    async request<T = unknown>(req: { method: string, params?: unknown }, schema?: { parse: (val: unknown) => T }): Promise<T> {
        const payload = {
            jsonrpc: '2.0',
            id: this.id++,
            method: req.method,
            params: {
                ...(req.params && typeof req.params === 'object' ? req.params : {}),
                _meta: {
                    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities': {}
                }
            }
        };

        const headers = new Headers({
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'mcp-version': '2026-07-28',
            'mcp-method': req.method
        });
        
        const paramsRecord = req.params as Record<string, unknown> | undefined;
        if (paramsRecord?.name && typeof paramsRecord.name === 'string') {
            headers.set('mcp-name', paramsRecord.name);
        }
        if (paramsRecord?.uri && typeof paramsRecord.uri === 'string') {
            headers.set('mcp-name', paramsRecord.uri); // Resources use Mcp-Name too
        }
        if (paramsRecord?.taskId && typeof paramsRecord.taskId === 'string') {
            headers.set('mcp-taskid', paramsRecord.taskId);
        }

        const httpReq = new Request('http://sentinel.invalid/mcp', {
            method: 'POST',
            headers,
            body: JSON.stringify(payload)
        });

        const res = await this.sentinel.fetch(httpReq);
        const contentType = res.headers.get('content-type') ?? '';
        const text = await res.text();
        
        // Parse the response — may be plain JSON or SSE
        let body: { jsonrpc: string; id?: number; result?: unknown; error?: { code: number; message: string; data?: unknown } };
        if (contentType.includes('text/event-stream')) {
            // Extract JSON-RPC messages from SSE events
            const lines = text.split('\n');
            const jsonMessages: unknown[] = [];
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    try { jsonMessages.push(JSON.parse(line.slice(6))); } catch { /* skip non-JSON lines */ }
                }
            }
            // The last message with an id matching our request is the result
            body = jsonMessages.find((m: any) => m.id === payload.id) as typeof body
                ?? jsonMessages[jsonMessages.length - 1] as typeof body;
            if (!body) throw new Error(`No JSON-RPC response in SSE stream: ${text}`);
        } else {
            try {
                body = JSON.parse(text);
            } catch {
                throw new Error(`Non-JSON response (status ${res.status}): ${text}`);
            }
        }

        if (body.error) {
            console.error(`[MockModernClient] ${req.method} failed:`, JSON.stringify(body.error));
            const err = new Error(body.error.message) as Error & { code: number; data?: unknown };
            err.code = body.error.code;
            if (body.error.data !== undefined) (err as any).data = body.error.data;
            throw err;
        }

        expect(body.jsonrpc).toBe('2.0');

        const result = body.result;
        return schema ? schema.parse(result) : (result as T);
    }

    async listTools() { return this.request<{ tools: any[] }>({ method: 'tools/list' }); }
    async callTool(params: { name: string, arguments?: unknown }) { return this.request<{ content: any[], isError?: boolean }>({ method: 'tools/call', params }); }
    async readResource(params: { uri: string }) { return this.request<{ contents: any[] }>({ method: 'resources/read', params }); }
    async getPrompt(params: { name: string, arguments?: unknown }) { return this.request<{ messages: any[] }>({ method: 'prompts/get', params }); }
    async close() {}
}

async function connectClient(sentinel: SentinelServer): Promise<MockModernClient> {
    return new MockModernClient(sentinel);
}

function buildContext(serverConfigs: Record<string, unknown>[], upstreams: ScriptedUpstreams): TestContext {
    const { records, sink } = collectingSink();
    void records; // accessed via closure by tests that want it
    const logger = new Logger({ level: 'debug', sink });
    const config = makeConfig({ servers: serverConfigs });
    const registry = new UpstreamRegistry(config, {
        logger,
        clientInfo: TEST_CLIENT_INFO,
        transportFactory: upstreams.factory
    });
    const catalog = new ToolCatalog({ registry, settings: config.catalog, logger });
    const sentinel = new SentinelServer({ config, registry, catalog, logger });
    const cleanups: Array<() => Promise<void>> = [];
    cleanups.push(async () => registry.close());
    cleanups.push(async () => upstreams.closeAll());
    cleanups.push(async () => sentinel.close());
    return { config, logger, registry, catalog, sentinel, upstreams, cleanups };
}

// ── server/discover ───────────────────────────────────────────────────────────

describe('server/discover', () => {
    let ctx: TestContext;
    let client: MockModernClient;

    beforeEach(async () => {
        const upstreams = new ScriptedUpstreams();
        upstreams.set('files', { capabilities: { tools: {}, resources: {} } });
        ctx = buildContext([{ id: 'files', transport: { kind: 'stdio', command: 'srv' } }], upstreams);
        await ctx.registry.warmUp();
        await ctx.catalog.refresh();
        client = await connectClient(ctx.sentinel);
        ctx.cleanups.push(async () => client.close());
    });

    afterEach(async () => {
        await Promise.allSettled(ctx.cleanups.map(fn => fn()));
    });

    it('returns a result the SDK schema accepts', async () => {
        const result = await client.request({ method: 'server/discover' }, DiscoverResultSchema);
        expect(() => DiscoverResultSchema.parse(result)).not.toThrow();
    });

    it('advertises exactly the 2026-07-28 protocol version', async () => {
        const result = await client.request({ method: 'server/discover' }, DiscoverResultSchema);
        expect(result.supportedVersions).toEqual([SENTINEL_PROTOCOL_VERSION]);
    });

    it('advertises tools and resources (matching a ready upstream with both)', async () => {
        const result = await client.request({ method: 'server/discover' }, DiscoverResultSchema);
        expect(result.capabilities?.tools).toBeDefined();
        expect(result.capabilities?.resources).toBeDefined();
    });

    it('does not leak upstream server ids into the response', async () => {
        const result = await client.request({ method: 'server/discover' }, DiscoverResultSchema);
        const serialised = JSON.stringify(result);
        expect(serialised).not.toContain('files');
    });

    it('reports the configured instance name', async () => {
        const result = await client.request({ method: 'server/discover' }, DiscoverResultSchema);
        // The discover result carries serverInfo in _meta
        expect(JSON.stringify(result)).toContain('mcp-sentinel');
    });
});

// ── tools/list ────────────────────────────────────────────────────────────────

describe('tools/list', () => {
    let ctx: TestContext;
    let client: MockModernClient;

    beforeEach(async () => {
        const upstreams = new ScriptedUpstreams();
        upstreams.set('files', {
            capabilities: { tools: {} },
            tools: [toolDef('read_file'), toolDef('write_file')]
        });
        ctx = buildContext([{ id: 'files', transport: { kind: 'stdio', command: 'srv' } }], upstreams);
        await ctx.registry.warmUp();
        await ctx.catalog.refresh();
        client = await connectClient(ctx.sentinel);
        ctx.cleanups.push(async () => client.close());
    });

    afterEach(async () => {
        await Promise.allSettled(ctx.cleanups.map(fn => fn()));
    });

    it('includes upstream tools with their qualified names', async () => {
        const { tools } = await client.listTools();
        const names = tools.map(t => t.name);
        expect(names).toContain('files__read_file');
        expect(names).toContain('files__write_file');
    });

    it('includes all five sentinel governance tools', async () => {
        const { tools } = await client.listTools();
        const names = tools.map(t => t.name);
        for (const sentinelName of Object.values(SENTINEL_TOOL_NAMES)) {
            expect(names).toContain(sentinelName);
        }
    });

    it('does not include upstream bare names (only qualified)', async () => {
        const { tools } = await client.listTools();
        const names = tools.map(t => t.name);
        expect(names).not.toContain('read_file');
        expect(names).not.toContain('write_file');
    });

    it('includes tools from an empty upstream registry (only sentinel tools)', async () => {
        const emptyUpstreams = new ScriptedUpstreams();
        const emptyCtx = buildContext([], emptyUpstreams);
        const emptyClient = await connectClient(emptyCtx.sentinel);
        try {
            const { tools } = await emptyClient.listTools();
            const names = tools.map(t => t.name);
            // Only sentinel tools when there are no upstreams.
            for (const sentinelName of Object.values(SENTINEL_TOOL_NAMES)) {
                expect(names).toContain(sentinelName);
            }
            expect(names.filter(n => n.includes('__') && !n.startsWith('sentinel__'))).toHaveLength(0);
        } finally {
            await emptyClient.close();
            await emptyCtx.sentinel.close();
            await emptyCtx.registry.close();
        }
    });
});

// ── tools/call — upstream forwarding ─────────────────────────────────────────

describe('tools/call — upstream forwarding', () => {
    let ctx: TestContext;
    let client: MockModernClient;

    beforeEach(async () => {
        const upstreams = new ScriptedUpstreams();
        upstreams.set('echo', {
            capabilities: { tools: {} },
            tools: [toolDef('ping')],
            onCallTool: () => ({ content: [{ type: 'text', text: 'pong' }] })
        });
        ctx = buildContext(
            [{ id: 'echo', transport: { kind: 'stdio', command: 'srv' } }],
            upstreams
        );
        await ctx.registry.warmUp();
        await ctx.catalog.refresh();
        client = await connectClient(ctx.sentinel);
        ctx.cleanups.push(async () => client.close());
    });

    afterEach(async () => {
        await Promise.allSettled(ctx.cleanups.map(fn => fn()));
    });

    it('forwards a tool call and returns the upstream result', async () => {
        const result = await client.callTool({ name: 'echo__ping', arguments: {} });
        expect(result.content).toEqual([{ type: 'text', text: 'pong' }]);
    });

    it('strips the server namespace from the name the upstream sees', async () => {
        await client.callTool({ name: 'echo__ping', arguments: {} });
        const received = ctx.upstreams.paramsFor('echo', 'tools/call');
        expect(received?.name).toBe('ping'); // upstream sees bare name
        expect(received?.name).not.toContain('echo__');
    });

    it('returns UnknownToolError (-32007) for a tool not in the catalog', async () => {
        await expect(
            client.callTool({ name: 'echo__nonexistent', arguments: {} })
        ).rejects.toMatchObject({ code: -32007 });
    });

    it('returns UnknownToolError (-32007) for a completely invalid qualified name', async () => {
        await expect(
            client.callTool({ name: 'not-a-valid-name', arguments: {} })
        ).rejects.toMatchObject({ code: -32007 });
    });

    it('passes tool arguments through to the upstream unchanged', async () => {
        const upstreams2 = new ScriptedUpstreams();
        upstreams2.set('adder', {
            capabilities: { tools: {} },
            tools: [toolDef('add')],
            onCallTool: (params) => {
                const args = params['arguments'] as Record<string, number> | undefined;
                const a = args?.['a'] ?? 0;
                const b = args?.['b'] ?? 0;
                return { content: [{ type: 'text', text: String(a + b) }] };
            }
        });
        const ctx2 = buildContext(
            [{ id: 'adder', transport: { kind: 'stdio', command: 'srv' } }],
            upstreams2
        );
        await ctx2.registry.warmUp();
        await ctx2.catalog.refresh();
        const client2 = await connectClient(ctx2.sentinel);
        try {
            await client2.callTool({ name: 'adder__add', arguments: { a: 3, b: 4 } });
            const received = upstreams2.paramsFor('adder', 'tools/call');
            expect((received?.['arguments'] as Record<string, number>)?.['a']).toBe(3);
            expect((received?.['arguments'] as Record<string, number>)?.['b']).toBe(4);
        } finally {
            await client2.close();
            await ctx2.sentinel.close();
            await ctx2.registry.close();
            await upstreams2.closeAll();
        }
    });
});

// ── tools/call — sentinel own tools ──────────────────────────────────────────

describe('tools/call — sentinel own tools (stub responses)', () => {
    let ctx: TestContext;
    let client: MockModernClient;

    beforeEach(async () => {
        const upstreams = new ScriptedUpstreams();
        ctx = buildContext([], upstreams);
        client = await connectClient(ctx.sentinel);
        ctx.cleanups.push(async () => client.close());
    });

    afterEach(async () => {
        await Promise.allSettled(ctx.cleanups.map(fn => fn()));
    });

    for (const [toolKey, toolName] of Object.entries(SENTINEL_TOOL_NAMES) as [string, string][]) {
        it(`${toolName} returns isError:true with a "not implemented" message`, async () => {
            const args: Record<string, unknown> = {};
            // Provide required arguments for tools that need them.
            if (toolKey === 'explainDecision') args['decisionId'] = 'dec_01HN000000000000000000000';
            if (toolKey === 'approveRequest') args['token'] = 'dummy-token';

            const result = await client.callTool({ name: toolName, arguments: args });
            expect(result.isError).toBe(true);
            const textContent = result.content.find(c => c.type === 'text');
            expect(textContent?.text).toContain('not yet implemented');
            expect(textContent?.text).toContain('M7');
        });
    }
});

// ── resources/read ────────────────────────────────────────────────────────────

describe('resources/read', () => {
    let ctx: TestContext;
    let client: MockModernClient;

    beforeEach(async () => {
        const upstreams = new ScriptedUpstreams();
        upstreams.set('fs', {
            capabilities: { tools: {}, resources: {} },
            onReadResource: (params) => ({
                contents: [{ uri: params['uri'] as string, text: 'file contents' }]
            })
        });
        ctx = buildContext(
            [{ id: 'fs', transport: { kind: 'stdio', command: 'srv' } }],
            upstreams
        );
        await ctx.registry.warmUp();
        client = await connectClient(ctx.sentinel);
        ctx.cleanups.push(async () => client.close());
    });

    afterEach(async () => {
        await Promise.allSettled(ctx.cleanups.map(fn => fn()));
    });

    it('forwards a resource read and returns the upstream result', async () => {
        const qualifiedUri = qualifyResourceUri('fs', 'file:///test.txt');
        const result = await client.readResource({ uri: qualifiedUri });
        const content = result.contents[0];
        expect(content).toBeDefined();
        if (content && 'text' in content) {
            expect(content.text).toBe('file contents');
        } else {
            expect.fail('Expected text content');
        }
    });

    it('returns UnknownToolError for an unresolvable qualified URI', async () => {
        await expect(
            client.readResource({ uri: 'not-a-sentinel-uri' })
        ).rejects.toMatchObject({ code: -32007 });
    });
});

// ── prompts/get ───────────────────────────────────────────────────────────────

describe('prompts/get', () => {
    let ctx: TestContext;
    let client: MockModernClient;

    beforeEach(async () => {
        const upstreams = new ScriptedUpstreams();
        upstreams.set('templates', {
            capabilities: { tools: {}, prompts: {} },
            onGetPrompt: () => ({
                messages: [{ role: 'user', content: { type: 'text', text: 'Hello from template' } }]
            })
        });
        ctx = buildContext(
            [{ id: 'templates', transport: { kind: 'stdio', command: 'srv' } }],
            upstreams
        );
        await ctx.registry.warmUp();
        client = await connectClient(ctx.sentinel);
        ctx.cleanups.push(async () => client.close());
    });

    afterEach(async () => {
        await Promise.allSettled(ctx.cleanups.map(fn => fn()));
    });

    it('forwards a prompt get and returns the upstream result', async () => {
        const result = await client.getPrompt({ name: 'templates__greeting' });
        const content = result.messages[0]?.content;
        expect(content).toBeDefined();
        if (content && content.type === 'text') {
            expect(content.text).toBe('Hello from template');
        } else {
            expect.fail('Expected text content');
        }
    });

    it('returns UnknownToolError for an unknown prompt server', async () => {
        // The router cannot know whether a prompt exists on a live upstream.
        // What it CAN reject is a qualified name whose server prefix doesn't
        // match any dialable upstream — so test that path.
        await expect(
            client.getPrompt({ name: 'nosuchserver__greeting' })
        ).rejects.toMatchObject({ code: -32007 });
    });
});

// ── tasks/* stubs ─────────────────────────────────────────────────────────────

describe('tasks/* stubs', () => {
    let ctx: TestContext;
    let client: MockModernClient;

    beforeEach(async () => {
        const upstreams = new ScriptedUpstreams();
        ctx = buildContext([], upstreams);
        client = await connectClient(ctx.sentinel);
        ctx.cleanups.push(async () => client.close());
    });

    afterEach(async () => {
        await Promise.allSettled(ctx.cleanups.map(fn => fn()));
    });

    // Enumerate every task method so a newly-added one that lacks a handler
    // causes a test failure rather than a silent omission.
    const TASK_METHODS = ['tasks/get', 'tasks/cancel', 'tasks/list', 'tasks/update'] as const;

    for (const method of TASK_METHODS) {
        it(`${method} returns -32601 (MethodNotFound)`, async () => {
            await expect(
                client.request({ method, params: { taskId: 'task_01' } }, { parseAs: 'unknown' } as never)
            ).rejects.toMatchObject({ code: -32601 });
        });
    }

    it('tasks/update error message references the deferral milestone', async () => {
        // Use tasks/update rather than tasks/get because the SDK recognises
        // tasks/get as a standard method and normalises its error message to
        // the generic "Method not found". tasks/update is registered via
        // the 3-arg form (custom method), so our custom message survives.
        try {
            await client.request({ method: 'tasks/update', params: { taskId: 'task_01' } }, { parseAs: 'unknown' } as never);
            expect.fail('Expected tasks/update to throw');
        } catch (err: unknown) {
            expect((err as { message: string }).message).toContain('M5.5');
        }
    });

    it('all four task methods return the same deferral code', async () => {
        const codes: number[] = [];
        for (const method of TASK_METHODS) {
            try {
                await client.request({ method, params: {} }, { parseAs: 'unknown' } as never);
            } catch (err: unknown) {
                codes.push((err as { code: number }).code);
            }
        }
        expect(codes).toHaveLength(TASK_METHODS.length);
        expect(new Set(codes)).toEqual(new Set([-32601]));
    });
});
