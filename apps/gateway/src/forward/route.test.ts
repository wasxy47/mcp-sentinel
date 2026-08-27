/**
 * `ForwardRouter` tests.
 *
 * The router performs no I/O, so almost everything here is an assertion about a
 * refusal or about the exact shape of the `ForwardTarget` it produces. Two of
 * those assertions matter more than the rest and are worth naming up front:
 *
 *  - **Reserved `_meta` stripping is asserted on `target.params`, not on what an
 *    upstream received.** It has to be. The SDK lifts `io.modelcontextprotocol/*`
 *    keys out of *inbound* request params on the server side too, so a scripted
 *    upstream's handler never sees them — an upstream-side assertion would pass
 *    whether or not Sentinel stripped anything. The router's own output is the
 *    only place the claim is falsifiable.
 *
 *  - **`expectedOutboundMetadata` is checked here, and the *wire* is checked in
 *    `forwarder.test.ts`.** The router computes what the outbound headers must be;
 *    the SDK's transport derives what they actually are. Both halves need proving,
 *    and only one of them is testable without a connection.
 */

import { HeaderMismatchError, MethodNotFoundError, RequestTooLargeError, UnknownToolError, canonicalize, qualifyResourceUri, sha256Hex } from '@mcp-sentinel/mcp-core';
import { afterEach, describe, expect, it } from 'vitest';

import {
    ScriptedUpstreams,
    forwardHarness,
    metadataFor,
    rawMetadata,
    stdio,
    toolDef,
    type ForwardHarness
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

/**
 * A harness with `files` and `notes` upstreams and a refreshed catalog.
 *
 * The refresh is real: the tools reach the catalog by way of a genuine
 * `tools/list` over a live connection, so a routing test can never pass against a
 * catalog that the real path would not have produced.
 */
async function fixture(options: { forward?: Record<string, unknown> } = {}): Promise<Fixture> {
    const upstreams = new ScriptedUpstreams();
    upstreams.set('files', { tools: [toolDef('read_file'), toolDef('write_file')] });
    upstreams.set('notes', { tools: [toolDef('search')] });

    const harness = forwardHarness({
        servers: [stdio('files'), stdio('notes')],
        factory: upstreams.factory,
        cleanups,
        ...(options.forward === undefined ? {} : { forward: options.forward })
    });
    cleanups.push(async () => upstreams.closeAll());

    await harness.catalog.refresh();
    return { ...harness, upstreams };
}

/** Route a `tools/call`, with honest headers, and return the target. */
function routeCall(harness: ForwardHarness, name: string, params: Record<string, unknown> = {}): ForwardTarget {
    const route = harness.router.route(metadataFor('tools/call', name), {
        method: 'tools/call',
        params: { name, ...params }
    });
    if (route.kind !== 'forward') expect.unreachable('expected a forward route');
    return route.target;
}

describe('ForwardRouter resolution', () => {
    it('resolves a catalogued tool and strips the namespace for the upstream', async () => {
        const harness = await fixture();
        const target = routeCall(harness, 'files__read_file', { arguments: { path: '/tmp/x' } });

        expect(target).toMatchObject({
            method: 'tools/call',
            kind: 'tool',
            serverId: 'files',
            qualifiedName: 'files__read_file',
            upstreamName: 'read_file'
        });
        // The rewritten body is what goes upstream: the bare name, arguments intact.
        expect(target.params).toEqual({ name: 'read_file', arguments: { path: '/tmp/x' } });
        // And the entry travels with it, so the forwarder can validate the result
        // against the definition the catalog digested rather than a fresh claim.
        expect(target.entry?.definitionDigest).toMatch(/^[0-9a-f]{64}$/u);
    });

    it('resolves a wrapped resource uri to its owning server', async () => {
        const harness = await fixture();
        const uri = qualifyResourceUri('notes', 'file:///notes/todo.md');
        const route = harness.router.route(metadataFor('resources/read', uri), {
            method: 'resources/read',
            params: { uri }
        });
        if (route.kind !== 'forward') expect.unreachable('expected a forward route');

        expect(route.target).toMatchObject({
            kind: 'resource',
            serverId: 'notes',
            upstreamName: 'file:///notes/todo.md'
        });
        expect(route.target.params).toEqual({ uri: 'file:///notes/todo.md' });
        // No catalog entry: resources are not aggregated, so the upstream stays
        // authoritative for whether the URI exists.
        expect(route.target.entry).toBeUndefined();
    });

    it('resolves a qualified prompt name', async () => {
        const harness = await fixture();
        const route = harness.router.route(metadataFor('prompts/get', 'notes__summarise'), {
            method: 'prompts/get',
            params: { name: 'notes__summarise', arguments: { style: 'terse' } }
        });
        if (route.kind !== 'forward') expect.unreachable('expected a forward route');

        expect(route.target).toMatchObject({ kind: 'prompt', serverId: 'notes', upstreamName: 'summarise' });
        expect(route.target.params).toEqual({ name: 'summarise', arguments: { style: 'terse' } });
    });

    it('answers server/discover without resolving anything', async () => {
        const harness = await fixture();
        expect(harness.router.route(metadataFor('server/discover'), { method: 'server/discover' })).toEqual({
            kind: 'discover'
        });
    });

    it('refuses a method it does not forward', async () => {
        const harness = await fixture();
        // `tools/list` is M1.4's to serve, not this router's. Reaching here means
        // nothing upstream of it has a handler, which is a 404 rather than a bypass.
        expect(() => harness.router.route(metadataFor('tools/list'), { method: 'tools/list' })).toThrow(
            MethodNotFoundError
        );
    });
});

describe('ForwardRouter header/body consistency', () => {
    it('refuses a benign Mcp-Name hiding a different tool in the body', async () => {
        const harness = await fixture();
        // The bypass primitive this check exists for: policy reads the header, the
        // upstream would act on the body.
        expect(() =>
            harness.router.route(metadataFor('tools/call', 'files__read_file'), {
                method: 'tools/call',
                params: { name: 'files__write_file' }
            })
        ).toThrow(HeaderMismatchError);
    });

    it('refuses an Mcp-Method that disagrees with the body method', async () => {
        const harness = await fixture();
        expect(() =>
            harness.router.route(rawMetadata({ 'mcp-method': 'tools/call', 'mcp-name': 'files__read_file' }), {
                method: 'resources/read',
                params: { uri: 'files__read_file' }
            })
        ).toThrow(HeaderMismatchError);
    });

    it('refuses a forwardable method with no Mcp-Name header at all', async () => {
        const harness = await fixture();
        expect(() =>
            harness.router.route(rawMetadata({ 'mcp-method': 'tools/call' }), {
                method: 'tools/call',
                params: { name: 'files__read_file' }
            })
        ).toThrow(HeaderMismatchError);
    });

    it('refuses params that are not an object', async () => {
        const harness = await fixture();
        // Reported as a header mismatch, and correctly so: there is no
        // `params.name` for `Mcp-Name` to agree with.
        expect(() =>
            harness.router.route(metadataFor('tools/call', 'files__read_file'), {
                method: 'tools/call',
                params: 'files__read_file'
            })
        ).toThrow(HeaderMismatchError);
    });
});

describe('ForwardRouter unknown-name answers', () => {
    it('refuses a tool that is not in the catalog', async () => {
        const harness = await fixture();
        expect(() => routeCall(harness, 'files__delete_everything')).toThrow(UnknownToolError);
    });

    it('refuses a tool on a server that is not configured', async () => {
        const harness = await fixture();
        // Same error as above, deliberately: distinguishing them would let an agent
        // enumerate the operator's configuration by probing names.
        expect(() => routeCall(harness, 'secrets__read')).toThrow(UnknownToolError);
    });

    it('refuses a catalogued tool whose server was quarantined after the refresh', async () => {
        const harness = await fixture();
        expect(routeCall(harness, 'files__read_file').serverId).toBe('files');

        // Exactly what M6's scanner will do when it finds a poisoned tool: flip the
        // server's trust while its tools are still in the catalog. The catalog is
        // not consulted for dialability, so this must be re-checked per request.
        const files = harness.config.servers.find(server => server.id === 'files');
        if (files === undefined) expect.unreachable('files server missing from config');
        files.trust = 'quarantined';

        expect(() => routeCall(harness, 'files__read_file')).toThrow(UnknownToolError);
    });

    it('refuses a resource uri that is not wrapped in the sentinel scheme', async () => {
        const harness = await fixture();
        expect(() =>
            harness.router.route(metadataFor('resources/read', 'file:///etc/passwd'), {
                method: 'resources/read',
                params: { uri: 'file:///etc/passwd' }
            })
        ).toThrow(UnknownToolError);
    });

    it('refuses a non-canonical percent-encoding of a legitimate resource uri', async () => {
        const harness = await fixture();
        const canonical = qualifyResourceUri('notes', 'file:///notes/todo.md');
        // Lowercase hex digits decode to exactly the same URI as the canonical
        // uppercase spelling. If both resolved, a policy written against one would
        // silently not match the other — an alias is a policy bypass.
        const alias = canonical.toLowerCase();
        expect(alias).not.toBe(canonical);
        expect(decodeURIComponent(alias.slice('mcp-sentinel://notes/'.length))).toBe('file:///notes/todo.md');

        expect(() =>
            harness.router.route(metadataFor('resources/read', alias), {
                method: 'resources/read',
                params: { uri: alias }
            })
        ).toThrow(UnknownToolError);
    });

    it('round-trips a resource uri that is exactly ".."', async () => {
        const harness = await fixture();
        // The case that motivates parsing by hand: `new URL()` normalises dot
        // segments for this scheme and would erase it, forwarding a call for one
        // resource as a call for another.
        const uri = qualifyResourceUri('notes', '..');
        const route = harness.router.route(metadataFor('resources/read', uri), {
            method: 'resources/read',
            params: { uri }
        });
        if (route.kind !== 'forward') expect.unreachable('expected a forward route');
        expect(route.target.upstreamName).toBe('..');
    });

    it('refuses a prompt name with no namespace separator', async () => {
        const harness = await fixture();
        expect(() =>
            harness.router.route(metadataFor('prompts/get', 'summarise'), {
                method: 'prompts/get',
                params: { name: 'summarise' }
            })
        ).toThrow(UnknownToolError);
    });
});

describe('ForwardRouter size bounds (T17)', () => {
    it('refuses params whose canonical form exceeds maxArgumentBytes', async () => {
        const harness = await fixture({ forward: { maxArgumentBytes: 512 } });
        expect(() => routeCall(harness, 'files__read_file', { arguments: { blob: 'a'.repeat(1_024) } })).toThrow(
            RequestTooLargeError
        );
    });

    it('refuses an oversized resource uri before parsing it', async () => {
        const harness = await fixture({ forward: { maxResourceUriBytes: 64 } });
        const uri = qualifyResourceUri('notes', `file:///${'x'.repeat(256)}`);
        expect(() =>
            harness.router.route(metadataFor('resources/read', uri), {
                method: 'resources/read',
                params: { uri }
            })
        ).toThrow(RequestTooLargeError);
    });

    it('reports the bound and the measurement, both of which are Sentinel\'s own', async () => {
        const harness = await fixture({ forward: { maxArgumentBytes: 512 } });
        try {
            routeCall(harness, 'files__read_file', { arguments: { blob: 'a'.repeat(1_024) } });
            expect.unreachable('expected a refusal');
        } catch (error) {
            if (!(error instanceof RequestTooLargeError)) throw error;
            expect(error.data).toMatchObject({ limit: 512 });
            expect(error.httpStatus).toBe(413);
        }
    });

    it('measures the params it received, not the params it forwards', async () => {
        const harness = await fixture();
        const target = routeCall(harness, 'files__read_file', { arguments: { path: '/tmp/x' } });

        // The digest is evidence of the request, so it is taken over the inbound
        // params — qualified name and all — not over the rewritten body.
        const inbound = canonicalize({ name: 'files__read_file', arguments: { path: '/tmp/x' } });
        expect(target.argsDigest).toBe(sha256Hex(inbound));
        expect(target.paramsBytes).toBe(Buffer.byteLength(inbound, 'utf8'));
        // Which is emphatically not the digest of what gets forwarded.
        expect(target.argsDigest).not.toBe(sha256Hex(canonicalize(target.params)));
    });
});

describe('ForwardRouter _meta hygiene', () => {
    it('strips protocol-reserved keys and keeps everything else', async () => {
        const harness = await fixture();
        const target = routeCall(harness, 'files__read_file', {
            _meta: {
                'io.modelcontextprotocol/clientInfo': { name: 'not-sentinel', version: '9.9.9' },
                'io.modelcontextprotocol/protocolVersion': '2025-11-25',
                progressToken: 'tok-1',
                'com.example/tenant': 'acme'
            }
        });

        expect(target.strippedMetaKeys).toEqual([
            'io.modelcontextprotocol/clientInfo',
            'io.modelcontextprotocol/protocolVersion'
        ]);
        // Asserted on the router's output, because the SDK lifts reserved keys out
        // of inbound params on the server side too — an upstream-side assertion
        // would pass whether or not Sentinel had done its job.
        expect(target.params['_meta']).toEqual({ progressToken: 'tok-1', 'com.example/tenant': 'acme' });
    });

    it('warns when an agent tries to set a reserved key', async () => {
        const harness = await fixture();
        routeCall(harness, 'files__read_file', {
            _meta: { 'io.modelcontextprotocol/clientCapabilities': { elicitation: {} } }
        });

        const warning = harness.records.find(
            record => record.level === 'warn' && record.msg.includes('protocol-reserved _meta')
        );
        expect(warning?.fields).toMatchObject({
            serverId: 'files',
            method: 'tools/call',
            keys: ['io.modelcontextprotocol/clientCapabilities']
        });
    });

    it('drops _meta entirely when nothing survives the strip', async () => {
        const harness = await fixture();
        const target = routeCall(harness, 'files__read_file', {
            _meta: { 'io.modelcontextprotocol/logLevel': 'debug' }
        });
        // An empty `_meta: {}` is noise on the wire.
        expect('_meta' in target.params).toBe(false);
    });

    it('drops a _meta that is not an object without reporting it as an attempt', async () => {
        const harness = await fixture();
        const target = routeCall(harness, 'files__read_file', { _meta: 'nonsense' });
        expect('_meta' in target.params).toBe(false);
        expect(target.strippedMetaKeys).toEqual([]);
    });

    it('leaves a request with no _meta alone', async () => {
        const harness = await fixture();
        const target = routeCall(harness, 'files__read_file', { arguments: {} });
        expect('_meta' in target.params).toBe(false);
        expect(target.strippedMetaKeys).toEqual([]);
    });
});

describe('ForwardRouter outbound metadata', () => {
    it('recomputes Mcp-Name from the stripped upstream name', async () => {
        const harness = await fixture();
        const target = routeCall(harness, 'files__read_file');

        expect(target.expectedOutboundMetadata).toEqual({
            'mcp-protocol-version': '2026-07-28',
            'mcp-method': 'tools/call',
            'mcp-name': 'read_file'
        });
        // The qualified name must not survive into the header. An upstream that
        // received it would reject the call with -32020, correctly.
        expect(target.expectedOutboundMetadata['mcp-name']).not.toContain('__');
    });

    it('base64-wraps a resource uri that cannot travel as a header value', async () => {
        const harness = await fixture();
        // A non-ASCII upstream URI is not header-safe, so the spec's sentinel
        // applies. Round-tripping it through the real encode/decode path is the
        // point: `route` asserts its own computed headers against the rewritten
        // body, so a broken sentinel would fail there rather than here.
        const upstreamUri = 'file:///notes/café.md';
        const uri = qualifyResourceUri('notes', upstreamUri);
        const route = harness.router.route(metadataFor('resources/read', uri), {
            method: 'resources/read',
            params: { uri }
        });
        if (route.kind !== 'forward') expect.unreachable('expected a forward route');

        const encoded = route.target.expectedOutboundMetadata['mcp-name'];
        expect(encoded).toBe(`=?base64?${Buffer.from(upstreamUri, 'utf8').toString('base64')}?=`);
        expect(route.target.upstreamName).toBe(upstreamUri);
    });

    it('carries no Mcp-Name for a method that does not define one', async () => {
        const harness = await fixture();
        // Nothing to assert on the target — `server/discover` never reaches one —
        // but the same builder is what M1.4 will use, so the absence is worth
        // pinning: a stray `Mcp-Name` on a method that has no name field is itself
        // a header/body disagreement waiting to happen.
        expect(metadataFor('server/discover').name).toBeUndefined();
    });
});
