/**
 * Fixtures shared between the upstream tests.
 *
 * The point of this harness is that the upstream tests exercise a *real* MCP
 * server over a real SDK client — `InMemoryTransport.createLinkedPair()` rather
 * than a hand-rolled fake. A mock would pass while the negotiation, capability
 * exchange and error taxonomy the pool actually depends on were all wrong.
 */

import { InMemoryTransport, type Transport } from '@modelcontextprotocol/client';
import { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod';

import { GatewayConfigSchema, UpstreamPoolSchema, UpstreamServerSchema } from '../config/schema.js';
import type { GatewayConfig, UpstreamPoolSettings, UpstreamServerSettings } from '../config/schema.js';
import { Logger, collectingSink, type LogRecord } from '../observability/logger.js';
import type { TransportFactory } from './transport.js';

export const TEST_CLIENT_INFO = { name: 'mcp-sentinel-test', version: '0.0.0' } as const;

/** Build validated upstream settings, so tests exercise the real defaults. */
export function upstreamSettings(overrides: Record<string, unknown> = {}): UpstreamServerSettings {
    return UpstreamServerSchema.parse({
        id: 'demo',
        transport: { kind: 'stdio', command: 'node', args: ['--version'] },
        ...overrides
    });
}

/** Pool settings with fast timings, so a failure path test finishes promptly. */
export function poolSettings(overrides: Record<string, unknown> = {}): UpstreamPoolSettings {
    return UpstreamPoolSchema.parse({
        connectTimeoutMs: 2_000,
        requestTimeoutMs: 2_000,
        reconnect: { initialDelayMs: 20, maxDelayMs: 200, factor: 2, failFastAfter: 2 },
        ...overrides
    });
}

export function gatewayConfig(overrides: Record<string, unknown> = {}): GatewayConfig {
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

/** A logger that keeps its records, for asserting on transitions. */
export function testLogger(): { readonly logger: Logger; readonly records: LogRecord[] } {
    const { records, sink } = collectingSink();
    return { logger: new Logger({ level: 'debug', sink }), records };
}

export interface EchoServerOptions {
    readonly name?: string;
    readonly version?: string;
    /** Called on every `echo` invocation, so a test can make one fail. */
    readonly onEcho?: (message: string) => void;
}

/** A minimal but genuine MCP server with one tool. */
export function buildEchoServer(options: EchoServerOptions = {}): McpServer {
    const server = new McpServer({
        name: options.name ?? 'echo-server',
        version: options.version ?? '1.2.3'
    });

    server.registerTool(
        'echo',
        {
            description: 'Return the message it was given.',
            inputSchema: z.object({ message: z.string() })
        },
        ({ message }) => {
            options.onEcho?.(message);
            return { content: [{ type: 'text' as const, text: message }] };
        }
    );

    return server;
}

/**
 * A transport factory that spins up a fresh linked pair and a fresh server per
 * connect, counting attempts.
 *
 * `InMemoryTransport.send` queues messages until the peer attaches its
 * `onmessage`, and `start()` drains that queue — so kicking the server's connect
 * off without awaiting it is safe here, and lets the factory stay synchronous
 * the way the production one is.
 */
export class InMemoryUpstream {
    public connects = 0;
    public readonly servers: McpServer[] = [];

    private readonly build: () => McpServer;

    public constructor(build: () => McpServer = () => buildEchoServer()) {
        this.build = build;
    }

    public readonly factory: TransportFactory = (): Transport => {
        this.connects += 1;
        const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
        const server = this.build();
        this.servers.push(server);
        void server.connect(serverTransport);
        return clientTransport;
    };

    public async closeAll(): Promise<void> {
        await Promise.allSettled(this.servers.map(async server => server.close()));
    }
}

/** A factory whose transports never answer, for exercising the timeout path. */
export function deadTransportFactory(): TransportFactory {
    return (): Transport => {
        const [clientTransport] = InMemoryTransport.createLinkedPair();
        // The server half is dropped on the floor: nothing ever attaches an
        // `onmessage`, so every request the client sends sits in the queue.
        return clientTransport;
    };
}

/** A factory that throws, standing in for a command that cannot be spawned. */
export function throwingTransportFactory(error: Error): TransportFactory {
    return (): Transport => {
        throw error;
    };
}
