import { describe, expect, it } from 'vitest';

import { RESERVED_META_PREFIX, stripReservedMeta } from './meta.js';

describe('stripReservedMeta', () => {
    it('passes through vendor keys, trace context and progressToken', () => {
        const result = stripReservedMeta({
            traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
            tracestate: 'vendor=1',
            baggage: 'tenant=acme',
            progressToken: 7,
            'com.example/tenant': 'acme'
        });

        expect(result.stripped).toEqual([]);
        expect(result.meta).toEqual({
            traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
            tracestate: 'vendor=1',
            baggage: 'tenant=acme',
            progressToken: 7,
            'com.example/tenant': 'acme'
        });
    });

    it('strips every reserved key, not a hand-maintained list of them', () => {
        const result = stripReservedMeta({
            [`${RESERVED_META_PREFIX}clientInfo`]: { name: 'not-sentinel', version: '9.9.9' },
            [`${RESERVED_META_PREFIX}protocolVersion`]: '2025-06-18',
            [`${RESERVED_META_PREFIX}clientCapabilities`]: { roots: {} },
            [`${RESERVED_META_PREFIX}logLevel`]: 'debug',
            [`${RESERVED_META_PREFIX}related-task`]: { taskId: 'forged' },
            // Not yet reserved by any revision we know of — the prefix rule covers
            // it anyway, which is the whole point of matching on the prefix.
            [`${RESERVED_META_PREFIX}somethingFromTheFuture`]: 1,
            progressToken: 'keep-me'
        });

        expect(result.meta).toEqual({ progressToken: 'keep-me' });
        expect(result.stripped).toEqual([
            `${RESERVED_META_PREFIX}clientInfo`,
            `${RESERVED_META_PREFIX}protocolVersion`,
            `${RESERVED_META_PREFIX}clientCapabilities`,
            `${RESERVED_META_PREFIX}logLevel`,
            `${RESERVED_META_PREFIX}related-task`,
            `${RESERVED_META_PREFIX}somethingFromTheFuture`
        ]);
    });

    it('reports undefined rather than an empty object when nothing survives', () => {
        // An empty `_meta: {}` on the wire is noise; omitting the key is the same
        // thing said more cheaply.
        const result = stripReservedMeta({ [`${RESERVED_META_PREFIX}logLevel`]: 'debug' });
        expect(result.meta).toBeUndefined();
        expect(result.stripped).toHaveLength(1);
    });

    it('treats a missing or non-object _meta as nothing to forward', () => {
        for (const input of [undefined, null, 'string', 42, ['a'], true]) {
            expect(stripReservedMeta(input)).toEqual({ meta: undefined, stripped: [] });
        }
    });

    it('does not mutate its input', () => {
        const input = { [`${RESERVED_META_PREFIX}logLevel`]: 'debug', keep: 1 };
        stripReservedMeta(input);
        expect(Object.keys(input)).toHaveLength(2);
    });

    it('is case-sensitive on the prefix, matching the spec', () => {
        // `IO.ModelContextProtocol/` is not reserved, so it is a vendor key.
        const result = stripReservedMeta({ 'IO.ModelContextProtocol/clientInfo': {} });
        expect(result.stripped).toEqual([]);
        expect(result.meta).toEqual({ 'IO.ModelContextProtocol/clientInfo': {} });
    });
});
