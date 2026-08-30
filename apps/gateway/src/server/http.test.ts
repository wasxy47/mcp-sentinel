/**
 * `http.ts` transport layer tests.
 *
 * Tests the Hono application that wraps the MCP handler. Covers:
 *  - Origin validation (DNS-rebinding defence)
 *  - Wire-level HTTP body size cap (T17)
 *  - Method routing (405 for GET/DELETE, 404 for unknown paths)
 *  - Health check endpoint
 *
 * Most tests use Hono's `app.request()` to test the routing and validation
 * logic without binding a real port. One test exercises `startHttpServer` to
 * prove the socket binding and graceful shutdown work.
 */

import { describe, expect, it } from 'vitest';
import { buildApp, startHttpServer, type HttpServerDeps } from './http.js';
import { SentinelServer } from './handlers.js';
import { Logger, collectingSink } from '../observability/logger.js';
import { GatewayConfigSchema, HttpSchema } from '../config/schema.js';
import { UpstreamRegistry } from '../upstream/registry.js';
import { ToolCatalog } from '../catalog/catalog.js';

// ── helpers ───────────────────────────────────────────────────────────────────

function mockSentinelServer(): SentinelServer {
    // A real SentinelServer needs config, registry, catalog.
    // For these tests, we just need its .fetch() method to return 200 OK.
    return {
        fetch: async () => new Response('OK', { status: 200 }),
        close: async () => {}
    } as unknown as SentinelServer;
}

function buildDeps(overrides: Record<string, unknown> = {}): HttpServerDeps {
    const { sink } = collectingSink();
    const logger = new Logger({ level: 'silent', sink }); // silent so we don't spam test output
    const settings = HttpSchema.parse({ host: '127.0.0.1', port: 0, ...overrides });
    return {
        sentinel: mockSentinelServer(),
        settings,
        logger
    };
}

// ── routing and healthz ───────────────────────────────────────────────────────

describe('HTTP routing', () => {
    it('GET /healthz returns 200 {"ok":true}', async () => {
        const app = buildApp(buildDeps());
        const res = await app.request('/healthz');
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ ok: true });
    });

    it('GET /mcp returns 405 Method Not Allowed', async () => {
        const app = buildApp(buildDeps());
        const res = await app.request('/mcp', { method: 'GET' });
        expect(res.status).toBe(405);
        expect(res.headers.get('Allow')).toBe('POST');
    });

    it('DELETE /mcp returns 405 Method Not Allowed', async () => {
        const app = buildApp(buildDeps());
        const res = await app.request('/mcp', { method: 'DELETE' });
        expect(res.status).toBe(405);
        expect(res.headers.get('Allow')).toBe('POST');
    });

    it('POST /unknown returns 404 Not Found', async () => {
        const app = buildApp(buildDeps());
        const res = await app.request('/unknown', { method: 'POST' });
        expect(res.status).toBe(404);
    });

    it('POST /mcp passes through to sentinel handler when valid', async () => {
        const app = buildApp(buildDeps());
        const res = await app.request('/mcp', { method: 'POST' });
        expect(res.status).toBe(200);
        expect(await res.text()).toBe('OK'); // from mockSentinelServer
    });
});

// ── origin validation (DNS rebinding defence) ─────────────────────────────────

describe('Origin validation', () => {
    it('accepts request with no Origin header (non-browser client)', async () => {
        const app = buildApp(buildDeps({ allowedOrigins: [] }));
        const res = await app.request('/mcp', { method: 'POST' });
        expect(res.status).toBe(200);
    });

    it('accepts loopback origins when allowedOrigins is empty (default)', async () => {
        const app = buildApp(buildDeps({ allowedOrigins: [] }));
        const origins = ['http://localhost', 'https://127.0.0.1', 'http://[::1]'];
        
        for (const origin of origins) {
            const res = await app.request('/mcp', {
                method: 'POST',
                headers: { origin }
            });
            expect(res.status).toBe(200);
        }
    });

    it('rejects non-loopback origin when allowedOrigins is empty', async () => {
        const app = buildApp(buildDeps({ allowedOrigins: [] }));
        const res = await app.request('/mcp', {
            method: 'POST',
            headers: { origin: 'http://evil.com' }
        });
        expect(res.status).toBe(403);
    });

    it('rejects loopback origin with a port (must be exact match)', async () => {
        const app = buildApp(buildDeps({ allowedOrigins: [] }));
        const res = await app.request('/mcp', {
            method: 'POST',
            // "http://localhost:3000" is cross-origin to "http://localhost"
            headers: { origin: 'http://localhost:3000' }
        });
        expect(res.status).toBe(403);
    });

    it('accepts explicitly allowed origin', async () => {
        const app = buildApp(buildDeps({ allowedOrigins: ['chrome-extension://my-extension-id'] }));
        const res = await app.request('/mcp', {
            method: 'POST',
            headers: { origin: 'chrome-extension://my-extension-id' }
        });
        expect(res.status).toBe(200);
    });

    it('rejects loopback origin when allowedOrigins is set (override)', async () => {
        const app = buildApp(buildDeps({ allowedOrigins: ['http://trusted.com'] }));
        const res = await app.request('/mcp', {
            method: 'POST',
            headers: { origin: 'http://localhost' }
        });
        expect(res.status).toBe(403);
    });
});

// ── wire-level body size cap (T17) ────────────────────────────────────────────

describe('Body size cap', () => {
    it('accepts body within maxBodyBytes', async () => {
        const app = buildApp(buildDeps({ maxBodyBytes: 100 }));
        const res = await app.request('/mcp', {
            method: 'POST',
            body: 'a'.repeat(100)
        });
        expect(res.status).toBe(200);
    });

    it('rejects request early if Content-Length exceeds maxBodyBytes', async () => {
        const app = buildApp(buildDeps({ maxBodyBytes: 100 }));
        const res = await app.request('/mcp', {
            method: 'POST',
            // We lie about the size to prove it checks the header without reading
            headers: { 'content-length': '101' },
            body: 'small body'
        });
        expect(res.status).toBe(413);
    });

    it('rejects request if actual read body exceeds maxBodyBytes (chunked/no content-length)', async () => {
        const app = buildApp(buildDeps({ maxBodyBytes: 100 }));
        
        // Hono's app.request doesn't easily simulate a chunked request without
        // content-length, so we'll pass a request object directly.
        const req = new Request('http://localhost/mcp', {
            method: 'POST',
            // Passing a ReadableStream omits Content-Length in the internal fetch polyfill
            body: new ReadableStream({
                start(controller) {
                    controller.enqueue(new TextEncoder().encode('a'.repeat(101)));
                    controller.close();
                }
            }),
            duplex: 'half'
        } as RequestInit);
        
        const res = await app.fetch(req);
        expect(res.status).toBe(413);
    });
});

// ── startHttpServer ───────────────────────────────────────────────────────────

describe('startHttpServer', () => {
    it('binds to a port and closes cleanly', async () => {
        // Port 0 asks the OS for an available ephemeral port
        const deps = buildDeps({ port: 0 });
        const server = await startHttpServer(deps);
        
        expect(server.port).toBeGreaterThan(0);
        expect(server.host).toBe('127.0.0.1');
        
        // Ensure it's listening
        const res = await fetch(`http://127.0.0.1:${server.port}/healthz`);
        expect(res.status).toBe(200);
        
        // Close it
        await server.close();
        
        // Ensure it's closed
        await expect(fetch(`http://127.0.0.1:${server.port}/healthz`)).rejects.toThrow();
    });
});
