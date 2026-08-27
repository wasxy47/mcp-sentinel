import { SentinelErrorCode, UpstreamUnavailableError } from '@mcp-sentinel/mcp-core';
import { afterEach, describe, expect, it } from 'vitest';

import { UpstreamRegistry } from './registry.js';
import {
    InMemoryUpstream,
    TEST_CLIENT_INFO,
    gatewayConfig,
    testLogger,
    throwingTransportFactory
} from './harness.testkit.js';
import type { TransportFactory } from './transport.js';

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
    for (const cleanup of cleanups.reverse()) await cleanup();
    cleanups.length = 0;
});

function stdio(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return { id, transport: { kind: 'stdio', command: 'srv' }, ...overrides };
}

interface Harness {
    readonly registry: UpstreamRegistry;
    readonly upstream: InMemoryUpstream;
    readonly records: ReturnType<typeof testLogger>['records'];
}

function harness(
    servers: ReadonlyArray<Record<string, unknown>>,
    factory?: TransportFactory
): Harness {
    const upstream = new InMemoryUpstream();
    const { logger, records } = testLogger();
    const registry = new UpstreamRegistry(gatewayConfig({ servers }), {
        logger,
        clientInfo: TEST_CLIENT_INFO,
        transportFactory: factory ?? upstream.factory,
        random: () => 1
    });

    cleanups.push(async () => {
        await registry.close();
        await upstream.closeAll();
    });

    return { registry, upstream, records };
}

describe('UpstreamRegistry construction', () => {
    it('preserves configuration order', () => {
        // The catalog, the dashboard and `server/discover` all present servers
        // the way the operator wrote them, not in hash-map order.
        const { registry } = harness([stdio('zeta'), stdio('alpha'), stdio('mid')]);
        expect(registry.all().map(client => client.id)).toEqual(['zeta', 'alpha', 'mid']);
    });

    it('builds an empty registry from an empty server list', () => {
        const { registry } = harness([]);
        expect(registry.all()).toEqual([]);
        expect(registry.dialable()).toEqual([]);
        expect(registry.snapshots()).toEqual([]);
    });

    it('excludes quarantined and disabled servers from the dialable set', () => {
        const { registry } = harness([
            stdio('good'),
            stdio('evil', { trust: 'quarantined' }),
            stdio('parked', { enabled: false })
        ]);

        expect(registry.all()).toHaveLength(3);
        expect(registry.dialable().map(client => client.id)).toEqual(['good']);
    });

    it('logs the fleet composition at startup', () => {
        const { records } = harness([stdio('good'), stdio('evil', { trust: 'quarantined' })]);
        const built = records.find(record => record.msg === 'upstream registry built');

        expect(built?.fields).toMatchObject({ total: 2, dialable: 1, quarantined: 1 });
    });
});

describe('UpstreamRegistry lookup', () => {
    it('finds a configured server', () => {
        const { registry } = harness([stdio('files')]);

        expect(registry.has('files')).toBe(true);
        expect(registry.get('files')?.id).toBe('files');
        expect(registry.settings('files')?.transport.kind).toBe('stdio');
    });

    it('returns undefined for an id nobody configured', () => {
        // This is what stops a fabricated server prefix from reaching a real one.
        const { registry } = harness([stdio('files')]);

        expect(registry.has('fiIes')).toBe(false);
        expect(registry.get('fiIes')).toBeUndefined();
        expect(registry.settings('fiIes')).toBeUndefined();
    });

    it('require throws the same error type an unreachable server produces', () => {
        const { registry } = harness([stdio('files')]);

        expect(() => registry.require('files')).not.toThrow();
        expect(() => registry.require('secrets')).toThrow(UpstreamUnavailableError);
    });

    it('gives an unknown id the same error code as an unreachable one', () => {
        // Callers need one handling path. The `reason` differs, which is fine:
        // `require` only ever sees ids already resolved through the catalog, and
        // that is the layer where an agent-supplied name is refused.
        const { registry, records } = harness([stdio('files')]);

        try {
            registry.require('secrets');
            expect.unreachable('should have thrown');
        } catch (error) {
            expect(error).toBeInstanceOf(UpstreamUnavailableError);
            expect((error as UpstreamUnavailableError).code).toBe(SentinelErrorCode.UpstreamUnavailable);
            expect((error as UpstreamUnavailableError).data).toMatchObject({
                serverId: 'secrets',
                reason: 'no such server'
            });
        }

        const warned = records.find(record => record.msg === 'request referenced an unknown server id');
        expect(warned?.fields).toMatchObject({ serverId: 'secrets' });
    });

    it('reports a snapshot per server, in order', () => {
        const { registry } = harness([stdio('a'), stdio('b', { trust: 'quarantined' })]);
        const snapshots = registry.snapshots();

        expect(snapshots.map(snapshot => snapshot.serverId)).toEqual(['a', 'b']);
        expect(snapshots[0]?.health).toBe('idle');
        expect(snapshots[1]?.health).toBe('quarantined');
    });

    it('falls back to the id when no label was configured', () => {
        const { registry } = harness([stdio('a'), stdio('b', { label: 'Bravo' })]);
        expect(registry.snapshots().map(snapshot => snapshot.label)).toEqual(['a', 'Bravo']);
    });
});

describe('UpstreamRegistry warm-up', () => {
    it('dials every dialable upstream once', async () => {
        const { registry, upstream } = harness([stdio('a'), stdio('b'), stdio('c')]);
        const snapshots = await registry.warmUp();

        expect(upstream.connects).toBe(3);
        expect(snapshots.filter(snapshot => snapshot.health === 'ready')).toHaveLength(3);
    });

    it('skips quarantined and disabled upstreams', async () => {
        const { registry, upstream } = harness([
            stdio('a'),
            stdio('evil', { trust: 'quarantined' }),
            stdio('parked', { enabled: false })
        ]);
        await registry.warmUp();

        expect(upstream.connects).toBe(1);
        const health = Object.fromEntries(
            registry.snapshots().map(snapshot => [snapshot.serverId, snapshot.health])
        );
        expect(health).toEqual({ a: 'ready', evil: 'quarantined', parked: 'disabled' });
    });

    it('never rejects when an upstream is unreachable', async () => {
        // A gateway that refuses to start because one upstream is down cannot be
        // used to diagnose that upstream being down.
        const { registry } = harness([stdio('broken')], throwingTransportFactory(new Error('nope')));
        const snapshots = await registry.warmUp();

        expect(snapshots).toHaveLength(1);
        expect(snapshots[0]?.health).toBe('unavailable');
    });

    it('warms the healthy upstreams even when one is broken', async () => {
        const working = new InMemoryUpstream();
        const factory: TransportFactory = server => {
            if (server.id === 'broken') throw new Error('nope');
            return working.factory(server);
        };
        const { registry } = harness([stdio('a'), stdio('broken'), stdio('b')], factory);
        const snapshots = await registry.warmUp();

        const health = Object.fromEntries(
            snapshots.map(snapshot => [snapshot.serverId, snapshot.health])
        );
        expect(health).toEqual({ a: 'ready', broken: 'unavailable', b: 'ready' });
        await working.closeAll();
    });

    it('short-circuits with nothing to dial', async () => {
        const { registry, upstream, records } = harness([stdio('evil', { trust: 'quarantined' })]);
        await registry.warmUp();

        expect(upstream.connects).toBe(0);
        expect(records.some(record => record.msg === 'no upstreams to warm up')).toBe(true);
    });

    it('summarises the outcome for the operator', async () => {
        const working = new InMemoryUpstream();
        const factory: TransportFactory = server => {
            if (server.id === 'broken') throw new Error('nope');
            return working.factory(server);
        };
        const { registry, records } = harness([stdio('a'), stdio('broken')], factory);
        await registry.warmUp();

        const summary = records.find(record => record.msg === 'upstream warm-up complete');
        expect(summary?.fields).toMatchObject({ ready: 1, unavailable: 1, total: 2 });
        await working.closeAll();
    });
});

describe('UpstreamRegistry shutdown', () => {
    it('closes every upstream', async () => {
        const { registry } = harness([stdio('a'), stdio('b')]);
        await registry.warmUp();

        await registry.close();

        expect(registry.snapshots().every(snapshot => snapshot.health === 'closed')).toBe(true);
    });

    it('is idempotent', async () => {
        const { registry, records } = harness([stdio('a')]);
        await registry.warmUp();

        await registry.close();
        await registry.close();

        // A gateway that leaks a child process on shutdown fails its second
        // restart, so this path must not depend on being called exactly once.
        expect(records.filter(record => record.msg === 'upstream registry closed')).toHaveLength(1);
    });

    it('closes a registry that was never warmed up', async () => {
        const { registry } = harness([stdio('a'), stdio('evil', { trust: 'quarantined' })]);
        await expect(registry.close()).resolves.toBeUndefined();
    });

    it('refuses further use after close', async () => {
        const { registry } = harness([stdio('a')]);
        await registry.close();

        await expect(registry.require('a').ensureReady()).rejects.toThrow(/shutting down/u);
    });
});
