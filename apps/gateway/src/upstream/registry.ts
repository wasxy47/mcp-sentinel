/**
 * The set of upstream servers, keyed by id.
 *
 * Thin on purpose. It owns three things a per-connection object cannot:
 *
 *  - **Id resolution.** Every qualified tool name (`files__read_file`) resolves
 *    to exactly one upstream here. `get()` returning `undefined` for an unknown
 *    id is what stops a fabricated server prefix from reaching a real server.
 *
 *  - **Startup and shutdown as a whole.** Warm-up runs every upstream in
 *    parallel and never rejects; shutdown closes all of them even if some throw.
 *    A gateway that fails to start because one upstream is down cannot be used
 *    to diagnose that upstream being down, and a gateway that leaks a child
 *    process on shutdown is a gateway that fails its second restart.
 *
 *  - **Insertion order.** Config order is preserved so the catalog, the
 *    dashboard and `server/discover` all present servers the way the operator
 *    wrote them, rather than in whatever order a hash map iterates.
 *
 * Deliberately *not* here: policy, catalog, and anything that inspects a tool.
 * The registry knows which servers exist and how to reach them. What may be
 * called is M2's question.
 */

import type { Implementation } from '@modelcontextprotocol/client';

import { UpstreamUnavailableError } from '@mcp-sentinel/mcp-core';

import type { GatewayConfig, UpstreamServerSettings } from '../config/schema.js';
import { errorFields, type Logger } from '../observability/logger.js';
import { UpstreamClient, type UpstreamClientDeps, type UpstreamSnapshot } from './client.js';
import type { TransportFactory } from './transport.js';

export interface UpstreamRegistryDeps {
    readonly logger: Logger;
    readonly clientInfo: Implementation;
    readonly transportFactory?: TransportFactory;
    readonly now?: () => number;
    readonly random?: () => number;
}

export class UpstreamRegistry {
    private readonly clients: Map<string, UpstreamClient>;
    private readonly logger: Logger;
    private readonly now: () => number;
    private closed = false;

    public constructor(config: GatewayConfig, deps: UpstreamRegistryDeps) {
        this.logger = deps.logger;
        this.now = deps.now ?? Date.now;

        const clientDeps: UpstreamClientDeps = {
            pool: config.upstream,
            logger: deps.logger,
            clientInfo: deps.clientInfo,
            ...(deps.transportFactory === undefined ? {} : { transportFactory: deps.transportFactory }),
            ...(deps.now === undefined ? {} : { now: deps.now }),
            ...(deps.random === undefined ? {} : { random: deps.random })
        };

        // The config schema already rejects duplicate ids, so a Map built in
        // order is unambiguous. Building it here rather than trusting that
        // invariant silently would be belt-and-braces; the schema's error
        // message is the better place for the diagnosis, so it stays there.
        this.clients = new Map(
            config.servers.map(server => [server.id, new UpstreamClient(server, clientDeps)] as const)
        );

        this.logger.info('upstream registry built', {
            total: this.clients.size,
            dialable: this.dialable().length,
            quarantined: config.servers.filter(server => server.trust === 'quarantined').length
        });
    }

    /** Every upstream, in configuration order. */
    public all(): readonly UpstreamClient[] {
        return [...this.clients.values()];
    }

    /** Upstreams that may be dialled: enabled, not quarantined. */
    public dialable(): readonly UpstreamClient[] {
        return this.all().filter(client => client.dialable);
    }

    public has(serverId: string): boolean {
        return this.clients.has(serverId);
    }

    public get(serverId: string): UpstreamClient | undefined {
        return this.clients.get(serverId);
    }

    /**
     * Look up an upstream, or throw the same error type an unreachable one
     * produces.
     *
     * One error class and one JSON-RPC code for "no such server" and "server is
     * down", so callers need a single handling path — but the `reason` does
     * differ between them, and that is deliberate rather than an oversight.
     *
     * Hiding the difference here would be security theatre. `require` is an
     * internal invariant guard: its callers pass ids they already resolved
     * through the catalog, never a string an agent supplied. Enumeration is
     * prevented at that catalog layer instead (M1.2), where a qualified name
     * that does not resolve becomes `UnknownTool` whether or not the server
     * behind it exists — so an agent probing for `secrets__read` learns the same
     * thing either way. Making *this* message vague would only cost the operator
     * the diagnosis, while the oracle stayed open one layer up.
     */
    public require(serverId: string): UpstreamClient {
        const client = this.clients.get(serverId);
        if (client === undefined) {
            this.logger.warn('request referenced an unknown server id', { serverId });
            throw new UpstreamUnavailableError(serverId, 'no such server');
        }
        return client;
    }

    public settings(serverId: string): UpstreamServerSettings | undefined {
        return this.clients.get(serverId)?.server;
    }

    public snapshots(): readonly UpstreamSnapshot[] {
        return this.all().map(client => client.snapshot());
    }

    /**
     * Dial every dialable upstream once, in parallel.
     *
     * Never rejects — `warmUp` on each client already absorbs its own failure.
     * `allSettled` guards the remaining case: a bug in the client throwing
     * outside that handler should not take the gateway's startup with it.
     */
    public async warmUp(): Promise<readonly UpstreamSnapshot[]> {
        const targets = this.dialable();
        if (targets.length === 0) {
            this.logger.info('no upstreams to warm up');
            return this.snapshots();
        }

        const started = this.now();
        const settled = await Promise.allSettled(targets.map(async client => client.warmUp()));
        for (const [index, outcome] of settled.entries()) {
            if (outcome.status === 'rejected') {
                this.logger.error('unexpected error during warm-up', {
                    serverId: targets[index]?.id,
                    ...errorFields(outcome.reason)
                });
            }
        }

        const snapshots = this.snapshots();
        this.logger.info('upstream warm-up complete', {
            durationMs: this.now() - started,
            ready: snapshots.filter(snapshot => snapshot.health === 'ready').length,
            unavailable: snapshots.filter(snapshot => snapshot.health === 'unavailable').length,
            total: snapshots.length
        });
        return snapshots;
    }

    /** Close every connection. Safe to call more than once. */
    public async close(): Promise<void> {
        if (this.closed) return;
        this.closed = true;

        const settled = await Promise.allSettled(this.all().map(async client => client.close()));
        for (const [index, outcome] of settled.entries()) {
            if (outcome.status === 'rejected') {
                this.logger.warn('error closing upstream', {
                    serverId: this.all()[index]?.id,
                    ...errorFields(outcome.reason)
                });
            }
        }
        this.logger.info('upstream registry closed');
    }
}
