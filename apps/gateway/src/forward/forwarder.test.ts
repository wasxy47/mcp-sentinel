/**
 * `Forwarder` tests.
 *
 * These are round trips, not mock assertions. A hand-rolled fake `Client` would
 * pass while the SDK's real verbs did something else — and the whole argument for
 * using `callTool`/`readResource`/`getPrompt` instead of a raw JSON-RPC
 * passthrough is that those verbs *do* something else: they validate results,
 * mirror `Mcp-Param-*`, and check the tool's output schema. Only a real client
 * against a real server can show that.
 *
 * Two claims need the modern-era fixture and cannot be made on `InMemoryTransport`
 * at all, because it negotiates era `legacy` / `2025-11-25`:
 *
 *  - the outbound `Mcp-Name` on the wire carries the *stripped* upstream name;
 *  - an upstream that asks Sentinel for input is refused, because Sentinel
 *    declares no client capabilities to answer with.
 */

import {
    MissingRequiredClientCapabilityError,
    ProtocolError,
    type CallToolResult,
    type GetPromptResult,
    type ReadResourceResult
} from '@modelcontextprotocol/client';
import { inputRequired } from '@modelcontextprotocol/server';
import { UnknownToolError, UpstreamUnavailableError, canonicalize, qualifyResourceUri, sha256Hex } from '@mcp-sentinel/mcp-core';
import { afterEach, describe, expect, it } from 'vitest';

import {
    ModernUpstream,
    ScriptedUpstreams,
    forwardHarness,
    metadataFor,
    stdio,
    toolDef,
    type ForwardHarness,
    type UpstreamScript
} from './harness.testkit.js';
import type { ForwardTarget } from './route.js';

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
    for (const cleanup of cleanups.reverse()) await cleanup();
    cleanups.length = 0;
});

interface Fixture extends ForwardHarness {
    readonly upstreams: ScriptedUpstreams;
}

async function fixture(
    script: UpstreamScript = { tools: [toolDef('read_file')] },
    options: { forward?: Record<string, unknown>; refresh?: boolean } = {}
): Promise<Fixture> {
    const upstreams = new ScriptedUpstreams();
    upstreams.set('files', script);

    const harness = forwardHarness({
        servers: [stdio('files')],
        factory: upstreams.factory,
        cleanups,
        ...(options.forward === undefined ? {} : { forward: options.forward })
    });
    cleanups.push(async () => upstreams.closeAll());

    if (options.refresh !== false) await harness.catalog.refresh();
    return { ...harness, upstreams };
}

function target(harness: ForwardHarness, method: string, nameOrUri: string, extra: Record<string, unknown> = {}): ForwardTarget {
    const field = method === 'resources/read' ? 'uri' : 'name';
    const route = harness.router.route(metadataFor(method, nameOrUri), {
        method,
        params: { [field]: nameOrUri, ...extra }
    });
    if (route.kind !== 'forward') expect.unreachable('expected a forward route');
    return route.target;
}

const OUTPUT_SCHEMA = {
    type: 'object',
    properties: { answer: { type: 'string' } },
    required: ['answer'],
    additionalProperties: false
} as const;

describe('Forwarder round trips', () => {
    it('calls a tool with the namespace stripped from the name the upstream sees', async () => {
        const harness = await fixture({
            tools: [toolDef('read_file')],
            onCallTool: params => ({ content: [{ type: 'text', text: `read ${String(params['name'])}` }] })
        });

        const outcome = await harness.forwarder.forward(
            target(harness, 'tools/call', 'files__read_file', { arguments: { path: '/tmp/x' } })
        );

        // Asserted from the far end: this is what the upstream's own handler saw.
        expect(harness.upstreams.paramsFor('files', 'tools/call')).toMatchObject({
            name: 'read_file',
            arguments: { path: '/tmp/x' }
        });
        expect((outcome.result as CallToolResult).content).toEqual([{ type: 'text', text: 'read read_file' }]);
        expect(outcome.inputRequired).toBe(false);
    });

    it('reads a resource with the wrapper removed from the uri', async () => {
        const harness = await fixture({ tools: [], capabilities: { tools: {}, resources: {} } });
        const uri = qualifyResourceUri('files', 'file:///etc/hosts');

        const outcome = await harness.forwarder.forward(target(harness, 'resources/read', uri));

        expect(harness.upstreams.paramsFor('files', 'resources/read')).toMatchObject({ uri: 'file:///etc/hosts' });
        expect((outcome.result as ReadResourceResult).contents[0]).toMatchObject({ uri: 'file:///etc/hosts' });
    });

    it('gets a prompt with the namespace stripped', async () => {
        const harness = await fixture({ tools: [] });

        const outcome = await harness.forwarder.forward(
            target(harness, 'prompts/get', 'files__summarise', { arguments: { style: 'terse' } })
        );

        expect(harness.upstreams.paramsFor('files', 'prompts/get')).toMatchObject({
            name: 'summarise',
            arguments: { style: 'terse' }
        });
        expect((outcome.result as GetPromptResult).messages).toHaveLength(1);
    });

    it('digests and measures the result it actually received', async () => {
        const harness = await fixture({
            tools: [toolDef('read_file')],
            onCallTool: () => ({ content: [{ type: 'text', text: 'body' }] })
        });

        const outcome = await harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'));

        const canonical = canonicalize(outcome.result);
        expect(outcome.resultDigest).toBe(sha256Hex(canonical));
        expect(outcome.resultBytes).toBe(Buffer.byteLength(canonical, 'utf8'));
        // The clock is injected and frozen, so this is 0 rather than "small".
        expect(outcome.latencyMs).toBe(0);
    });
});

describe('Forwarder relays what the upstream said', () => {
    it('relays an isError result as a result, not as a failure', async () => {
        const harness = await fixture({
            tools: [toolDef('read_file')],
            onCallTool: () => ({ isError: true, content: [{ type: 'text', text: 'no such file' }] })
        });

        const outcome = await harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'));

        // A tool that failed is an answer. Rewriting it would deny the agent the
        // information it needs to choose differently.
        expect(outcome.result as CallToolResult).toMatchObject({
            isError: true,
            content: [{ type: 'text', text: 'no such file' }]
        });
    });

    it('lets an upstream handler error reach the agent rather than becoming "unavailable"', async () => {
        const harness = await fixture({
            tools: [toolDef('read_file')],
            onCallTool: () => {
                throw new Error('upstream exploded');
            }
        });

        // `UpstreamClient.call` converts only connection loss and timeouts. A
        // handler error is the server answering, so it stays an answer — reported
        // with the JSON-RPC internal-error code rather than as an unreachable
        // server, which would be a lie the operator would then chase.
        await expect(harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'))).rejects.toThrow(
            ProtocolError
        );
        await expect(
            harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'))
        ).rejects.not.toBeInstanceOf(UpstreamUnavailableError);
    });

    it('validates structured output against the definition the catalog digested', async () => {
        const harness = await fixture({
            tools: [toolDef('read_file', { outputSchema: OUTPUT_SCHEMA })],
            onCallTool: () => ({ content: [{ type: 'text', text: 'ok' }], structuredContent: { wrong: true } })
        });

        const routed = target(harness, 'tools/call', 'files__read_file');
        expect(routed.entry?.definition.outputSchema).toBeDefined();

        await expect(harness.forwarder.forward(routed)).rejects.toThrow(
            /Structured content does not match the tool's output schema/u
        );
    });

    it('accepts structured output that conforms, so the check is not blanket', async () => {
        const harness = await fixture({
            tools: [toolDef('read_file', { outputSchema: OUTPUT_SCHEMA })],
            onCallTool: () => ({ content: [{ type: 'text', text: 'ok' }], structuredContent: { answer: 'yes' } })
        });

        const outcome = await harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'));
        expect((outcome.result as CallToolResult).structuredContent).toEqual({ answer: 'yes' });
    });

    it('validates against the definition it was handed, not the upstream\'s current claim', async () => {
        // The upstream advertises no output schema at all, so the SDK's own
        // `tools/list` cache holds none and would validate nothing. Verified by
        // probe: cache-bare plus `toolDefinition` throws, cache-bare alone does not.
        const harness = await fixture({
            tools: [toolDef('read_file')],
            onCallTool: () => ({ content: [{ type: 'text', text: 'ok' }], structuredContent: { wrong: true } })
        });

        const routed = target(harness, 'tools/call', 'files__read_file');
        expect(routed.entry?.definition.outputSchema).toBeUndefined();

        // Substituting a schema-bearing entry is the only way to make the two
        // sources disagree, and disagreement is the whole point: whatever is in the
        // entry is what gets enforced. When they agree — the normal case, and the
        // two tests above — the SDK would have validated from its cache anyway, so
        // those tests cannot show where the definition came from. This one can.
        const pinned = {
            ...routed,
            entry: {
                ...routed.entry,
                definition: { ...routed.entry?.definition, outputSchema: OUTPUT_SCHEMA }
            }
        } as unknown as ForwardTarget;

        // Which is what makes M6's rug-pull detection enforceable rather than
        // advisory: the catalog holds a digest of a definition an operator approved,
        // and that definition — not a fresh claim from the server — is the one the
        // result is checked against.
        await expect(harness.forwarder.forward(pinned)).rejects.toThrow(
            /Structured content does not match the tool's output schema/u
        );
    });
});

describe('Forwarder capability gate', () => {
    it('refuses a resource read against a server that never advertised resources', async () => {
        // The capability is *omitted*, not stubbed: `Server` refuses to register a
        // handler for a method whose capability was not declared, so this is a
        // server that genuinely has no resources rather than one pretending.
        const harness = await fixture({ tools: [], capabilities: { tools: {}, prompts: {} } });
        const uri = qualifyResourceUri('files', 'file:///etc/hosts');

        await expect(harness.forwarder.forward(target(harness, 'resources/read', uri))).rejects.toThrow(
            UnknownToolError
        );
    });

    it('refuses a prompt against a server that never advertised prompts', async () => {
        const harness = await fixture({ tools: [], capabilities: { tools: {}, resources: {} } });

        await expect(
            harness.forwarder.forward(target(harness, 'prompts/get', 'files__summarise'))
        ).rejects.toThrow(UnknownToolError);
    });

    it('reports the capability refusal as "unknown", giving away no topology', async () => {
        const harness = await fixture({ tools: [], capabilities: { tools: {}, prompts: {} } });
        const uri = qualifyResourceUri('files', 'file:///etc/hosts');

        try {
            await harness.forwarder.forward(target(harness, 'resources/read', uri));
            expect.unreachable('expected a refusal');
        } catch (error) {
            if (!(error instanceof UnknownToolError)) throw error;
            // Indistinguishable from "no such resource" and from "no such server".
            expect(error.data).toEqual({ qualifiedName: uri, kind: 'resource' });
            expect(error.message).not.toContain('capability');
        }
    });
});

describe('Forwarder result bounds (T17)', () => {
    it('refuses a result larger than maxResultBytes', async () => {
        const harness = await fixture(
            {
                tools: [toolDef('read_file')],
                onCallTool: () => ({ content: [{ type: 'text', text: 'x'.repeat(4_096) }] })
            },
            { forward: { maxResultBytes: 1_024 } }
        );

        // Not a wire-level bound and does not pretend to be one: the bytes have
        // arrived. What it stops is their propagation into the agent's context, an
        // audit row and a risk prompt.
        await expect(harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'))).rejects.toThrow(
            UpstreamUnavailableError
        );
    });

    it('names the reason without quoting the upstream', async () => {
        const harness = await fixture(
            {
                tools: [toolDef('read_file')],
                onCallTool: () => ({ content: [{ type: 'text', text: 'x'.repeat(4_096) }] })
            },
            { forward: { maxResultBytes: 1_024 } }
        );

        try {
            await harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'));
            expect.unreachable('expected a refusal');
        } catch (error) {
            if (!(error instanceof UpstreamUnavailableError)) throw error;
            expect(error.data).toEqual({ serverId: 'files', reason: 'response too large' });
        }
    });
});

/**
 * A real 2026-07-28 connection, in-process.
 *
 * `createMcpHandler` gives a web-standard `fetch`; `StreamableHTTPClientTransport`
 * accepts a `fetch` override. Both halves are the SDK's own code and the wire
 * format is real — only the socket is absent, and the socket has no bearing on
 * which headers get computed.
 */
describe('Forwarder on a modern connection', () => {
    async function modern(script: UpstreamScript): Promise<{ harness: ForwardHarness; upstream: ModernUpstream }> {
        const upstream = new ModernUpstream(script);
        const harness = forwardHarness({
            servers: [stdio('files')],
            factory: upstream.factory,
            upstream: { upstreamProtocol: '2026-07-28' },
            cleanups
        });
        await harness.catalog.refresh();
        return { harness, upstream };
    }

    it('puts the stripped upstream name in the Mcp-Name header on the wire', async () => {
        const { harness, upstream } = await modern({ tools: [toolDef('read_file')] });

        // The premise, stated rather than assumed: on a legacy connection there
        // would be no such headers to inspect at all.
        expect(harness.registry.snapshots()[0]).toMatchObject({ era: 'modern', protocolVersion: '2026-07-28' });

        await harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'));

        // The milestone's headline claim, checked where it actually matters. The SDK
        // derives both headers from the body it is about to send, so this is really
        // a check that the *body* was rewritten — but it is the upstream's view of
        // the request, and the upstream is what would reject a stale header.
        expect(upstream.headersFor('tools/call')).toMatchObject({
            'mcp-method': 'tools/call',
            'mcp-name': 'read_file',
            'mcp-protocol-version': '2026-07-28'
        });
    });

    it('base64-wraps a resource uri that cannot travel as a header value', async () => {
        const { harness, upstream } = await modern({ tools: [], capabilities: { tools: {}, resources: {} } });
        const upstreamUri = 'file:///notes/café.md';
        const routed = target(harness, 'resources/read', qualifyResourceUri('files', upstreamUri));

        await harness.forwarder.forward(routed);

        const expected = `=?base64?${Buffer.from(upstreamUri, 'utf8').toString('base64')}?=`;
        expect(upstream.headersFor('resources/read')?.['mcp-name']).toBe(expected);
        // And the router's prediction agreed with the wire, which is the whole
        // point of computing `expectedOutboundMetadata` at all.
        expect(routed.expectedOutboundMetadata['mcp-name']).toBe(expected);
    });

    it('refuses to answer an upstream that asks Sentinel for input', async () => {
        const { harness } = await modern({
            tools: [toolDef('read_file')],
            onCallTool: () =>
                inputRequired({
                    inputRequests: {
                        q1: {
                            method: 'elicitation/create',
                            params: {
                                mode: 'form',
                                message: 'which file did you mean?',
                                requestedSchema: { type: 'object', properties: {} }
                            }
                        }
                    },
                    requestState: 'opaque'
                })
        });

        // The posture, verified end to end. Sentinel's upstream client declares no
        // `elicitation`, `sampling` or `roots` capability, so the SDK's server seam
        // refuses to *emit* the input request — Sentinel, which holds the union of
        // every agent's authority, is never asked to answer a question on an agent's
        // behalf. `allowInputRequired: true` on the forwarder is the second line of
        // the same defence: if a capability is ever declared, the result surfaces to
        // the agent instead of being auto-fulfilled under Sentinel's identity.
        try {
            await harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'));
            expect.unreachable('expected a refusal');
        } catch (error) {
            if (!(error instanceof MissingRequiredClientCapabilityError)) throw error;
            // Pinned to the mechanism, because there are two in the SDK and only one
            // of them is live. The per-method table it checks first
            // (`requiredClientCapabilitiesForRequest`) is empty today, so a test that
            // merely matched the error class would not distinguish "refused the input
            // request" from "refused `tools/call` outright". This is the input-request
            // leg: the refusal names the request the upstream tried to ask.
            expect(error.message).toContain("Cannot request input 'q1'");
            expect(error.data).toMatchObject({ requiredCapabilities: { elicitation: expect.anything() } });
        }
    });

    it('completes a normal call on the same connection, so the refusal is specific', async () => {
        // Guards the test above against passing for the wrong reason: if the modern
        // fixture refused every `tools/call`, that test would still be green.
        const { harness } = await modern({ tools: [toolDef('read_file')] });
        const outcome = await harness.forwarder.forward(target(harness, 'tools/call', 'files__read_file'));
        expect((outcome.result as CallToolResult).content).toEqual([{ type: 'text', text: 'ok' }]);
    });
});
