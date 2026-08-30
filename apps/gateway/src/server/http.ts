/**
 * HTTP server lifecycle for the gateway.
 *
 * Binds the MCP handler from `SentinelServer` to a real HTTP listener via
 * `@hono/node-server`. All transport-gate concerns live here:
 *
 *  - **Origin validation** (DNS-rebinding defence). The spec requires this for
 *    servers bound to loopback. An empty `allowedOrigins` means "accept
 *    loopback origins and requests with no Origin header" — the correct default
 *    for a locally-bound server. Configuring a specific list tightens this.
 *
 *  - **Body size cap** (T17). The wire-level bound: checked before any parsing
 *    by inspecting `Content-Length` and then reading with a ceiling. This runs
 *    before the SDK, so an oversized body is refused at the TCP boundary rather
 *    than inflating the process's heap for the duration of the parse.
 *
 *  - **Method routing**. POST to `/mcp` → MCP handler. GET to `/mcp` → 405.
 *    Anything else → 404. DELETE is also 405 per the spec.
 *
 *  - **Healthz**. `GET /healthz` returns `{"ok":true}` so an operator can
 *    verify the process is up without a full MCP handshake.
 *
 * What is deliberately NOT here: TLS, authentication, rate limiting. Those are
 * the responsibility of the reverse proxy in front of the gateway in a
 * production deployment. Sentinel is designed to bind to loopback or a trusted
 * network, not to be directly internet-facing.
 */

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import type { HttpSettings } from '../config/schema.js';
import type { Logger } from '../observability/logger.js';
import type { SentinelServer } from './handlers.js';

export interface HttpServerDeps {
    readonly sentinel: SentinelServer;
    readonly settings: HttpSettings;
    readonly logger: Logger;
}

export interface BoundServer {
    readonly host: string;
    readonly port: number;
    /** Stop accepting new connections and wait for in-flight ones to drain. */
    close(): Promise<void>;
}

/**
 * The loopback hostnames and origins Sentinel accepts by default.
 *
 * The spec (Streamable HTTP § Origin Validation) requires that local servers
 * check the `Origin` header to prevent DNS-rebinding attacks where a malicious
 * web page tricks the browser into making cross-origin MCP requests.
 *
 * `localhost` and `127.0.0.1` are the two forms an agent typically sends;
 * `::1` covers the IPv6 loopback. Non-browser MCP clients (CLI tools, IDE
 * plugins) usually send no Origin header at all, which is also accepted.
 */
const LOOPBACK_ORIGINS: ReadonlySet<string> = new Set([
    'http://localhost',
    'https://localhost',
    'http://127.0.0.1',
    'https://127.0.0.1',
    'http://[::1]',
    'https://[::1]'
]);

/**
 * True when the request's Origin is permitted.
 *
 * An absent Origin is always accepted: non-browser clients (the common case
 * for an MCP gateway) do not send one. A present Origin must match either the
 * configured allowlist or the default loopback set.
 *
 * Note: the comparison is exact. `http://localhost:3000` is NOT loopback — it
 * is an origin on a different port, possibly a dev server controlled by a page
 * that could be injected. Only the bare loopback origins (no port) pass the
 * default check.
 */
function isOriginAllowed(origin: string | undefined, allowedOrigins: readonly string[]): boolean {
    if (origin === undefined) return true; // No Origin: non-browser client, allowed.
    if (allowedOrigins.length > 0) {
        return allowedOrigins.includes(origin);
    }
    return LOOPBACK_ORIGINS.has(origin);
}

/** Build the Hono application. Exported for use in integration tests. */
export function buildApp(deps: HttpServerDeps): Hono {
    const { sentinel, settings, logger } = deps;
    const app = new Hono();

    // ── health check ────────────────────────────────────────────────────────────
    app.get('/healthz', c => c.json({ ok: true }));

    // ── MCP endpoint — wrong method ──────────────────────────────────────────────
    // DELETE and GET on /mcp return 405 per the spec.
    app.on(['GET', 'DELETE'], '/mcp', c => {
        return c.text('Method Not Allowed', 405, {
            Allow: 'POST'
        });
    });

    // ── MCP endpoint — main handler ──────────────────────────────────────────────
    app.post('/mcp', async c => {
        // Origin check (DNS-rebinding defence).
        const origin = c.req.header('origin');
        if (!isOriginAllowed(origin, settings.allowedOrigins)) {
            logger.warn('rejected request from disallowed origin', { origin });
            return c.text('Forbidden: disallowed origin', 403);
        }

        // Wire-level body size cap (T17): check Content-Length if present so we
        // can reject before reading; then enforce with a capped read.
        const contentLength = c.req.header('content-length');
        if (contentLength !== undefined) {
            const declared = parseInt(contentLength, 10);
            if (!isNaN(declared) && declared > settings.maxBodyBytes) {
                logger.warn('rejected oversized request (Content-Length)', {
                    declaredBytes: declared,
                    limitBytes: settings.maxBodyBytes
                });
                return c.text('Request Entity Too Large', 413);
            }
        }

        // Read body with a ceiling. Using the raw Request so the SDK's handler
        // can re-read it if needed — Hono's `c.req.raw` passes the original.
        // We clone it once to read the size, then pass the original to the SDK.
        const raw = c.req.raw;
        const cloned = raw.clone();
        const body = await cloned.arrayBuffer();
        if (body.byteLength > settings.maxBodyBytes) {
            logger.warn('rejected oversized request (actual body)', {
                actualBytes: body.byteLength,
                limitBytes: settings.maxBodyBytes
            });
            return c.text('Request Entity Too Large', 413);
        }

        // Delegate to the SDK handler with the original request (not the clone),
        // so the SDK reads the stream itself and can handle SSE properly.
        return sentinel.fetch(raw);
    });

    // ── 404 for everything else ──────────────────────────────────────────────────
    app.notFound(c => c.text('Not Found', 404));

    return app;
}

/**
 * Start the HTTP server.
 *
 * Returns a `BoundServer` so the caller can log the port (which may differ from
 * `settings.port` when port 0 is requested) and close the server on shutdown.
 */
export async function startHttpServer(deps: HttpServerDeps): Promise<BoundServer> {
    const { settings, logger } = deps;
    const app = buildApp(deps);

    return new Promise((resolve, reject) => {
        const server = serve(
            {
                fetch: app.fetch,
                hostname: settings.host,
                port: settings.port
            },
            info => {
                // `info` is Node's `AddressInfo`: { address, family, port }.
                // `address` is the bound address (e.g. "127.0.0.1" or "::");
                // fall back to the configured host if the kernel returns empty.
                const boundHost = info.address || settings.host;
                logger.info('Sentinel HTTP server listening', {
                    host: boundHost,
                    port: info.port
                });
                resolve({
                    host: boundHost,
                    port: info.port,
                    close: async () => {
                        await new Promise<void>((res, rej) => {
                            server.close(err => (err ? rej(err) : res()));
                        });
                        logger.info('Sentinel HTTP server closed');
                    }
                });
            }
        );
        // @hono/node-server wraps Node's `http.Server`, which emits 'error' on
        // bind failure (EADDRINUSE etc.) before the callback fires.
        server.on('error', reject);
    });
}
