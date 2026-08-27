import { describe, expect, it } from 'vitest';

import { ID_PREFIX, IdError, isId, isoTimestamp, newId, ULID_LENGTH, UlidFactory, ulid, ulidTime } from './ids.js';

describe('UlidFactory', () => {
    it('produces 26 Crockford base32 characters', () => {
        const id = new UlidFactory().next();
        expect(id).toHaveLength(ULID_LENGTH);
        expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    });

    it('excludes the ambiguous letters I, L, O and U', () => {
        const factory = new UlidFactory();
        const ids = Array.from({ length: 200 }, () => factory.next()).join('');
        expect(ids).not.toMatch(/[ILOU]/);
    });

    it('is unique across many calls pinned to one millisecond', () => {
        const factory = new UlidFactory();
        const at = Date.UTC(2024, 0, 1);
        const ids = new Set(Array.from({ length: 5000 }, () => factory.next(at)));
        expect(ids.size).toBe(5000);
    });

    it('sorts lexicographically in creation order within one millisecond', () => {
        const factory = new UlidFactory();
        const at = Date.UTC(2024, 0, 1);
        const ids = Array.from({ length: 1000 }, () => factory.next(at));
        expect(ids).toEqual([...ids].sort());
    });

    it('sorts lexicographically across milliseconds', () => {
        const factory = new UlidFactory();
        const ids = [
            factory.next(Date.UTC(2024, 0, 1)),
            factory.next(Date.UTC(2024, 0, 1) + 1),
            factory.next(Date.UTC(2025, 0, 1))
        ];
        expect(ids).toEqual([...ids].sort());
    });

    it('encodes the supplied timestamp', () => {
        const timestamp = Date.UTC(2024, 0, 1);
        expect(ulidTime(new UlidFactory().next(timestamp))).toBe(timestamp);
    });

    it('never regresses when the clock steps backwards', () => {
        const factory = new UlidFactory();
        const forward = factory.next(Date.UTC(2030, 0, 1));
        const afterStepBack = factory.next(Date.UTC(2020, 0, 1));
        // The wall-clock anomaly is recorded on the audit row, not smuggled into
        // the id — ids must stay monotonic for `ORDER BY id` pagination to hold.
        expect(afterStepBack > forward).toBe(true);
        expect(ulidTime(afterStepBack)).toBe(Date.UTC(2030, 0, 1));
    });

    it('rejects a timestamp outside the 48-bit range', () => {
        expect(() => new UlidFactory().next(-1)).toThrow(IdError);
        expect(() => new UlidFactory().next(2 ** 48)).toThrow(IdError);
        expect(() => new UlidFactory().next(Number.NaN)).toThrow(IdError);
    });

    it('stays usable after a rejected timestamp', () => {
        // Validation runs before any state mutation, so one bad call must not
        // poison the generator for the life of the process.
        const factory = new UlidFactory();
        expect(() => factory.next(2 ** 48)).toThrow(IdError);
        expect(factory.next(Date.UTC(2024, 0, 1))).toHaveLength(ULID_LENGTH);
    });
});

describe('ulid', () => {
    it('shares one monotonic generator process-wide', () => {
        const ids = Array.from({ length: 500 }, () => ulid());
        expect(new Set(ids).size).toBe(500);
        expect(ids).toEqual([...ids].sort());
    });
});

describe('ulidTime', () => {
    it('reads the timestamp back out of a prefixed id', () => {
        const before = Date.now();
        const id = newId('decision');
        const after = Date.now();
        const decoded = ulidTime(id)!;
        expect(decoded).toBeGreaterThanOrEqual(before);
        expect(decoded).toBeLessThanOrEqual(after);
    });

    it('returns undefined for malformed input', () => {
        expect(ulidTime('too-short')).toBeUndefined();
        expect(ulidTime('dec_too-short')).toBeUndefined();
        expect(ulidTime('I'.repeat(26))).toBeUndefined();
    });
});

describe('newId / isId', () => {
    it('prefixes each kind distinctly', () => {
        expect(newId('decision')).toMatch(/^dec_/);
        expect(newId('approval')).toMatch(/^apv_/);
        expect(newId('task')).toMatch(/^tsk_/);
        expect(newId('finding')).toMatch(/^fnd_/);
        expect(newId('trace')).toMatch(/^trc_/);
        expect(newId('checkpoint')).toMatch(/^ckp_/);
    });

    it('accepts its own output for every kind', () => {
        for (const kind of Object.keys(ID_PREFIX) as Array<keyof typeof ID_PREFIX>) {
            expect(isId(kind, newId(kind))).toBe(true);
        }
    });

    it('rejects an id of the wrong kind, so a mix-up fails loudly', () => {
        const approval = newId('approval');
        expect(isId('decision', approval)).toBe(false);
        expect(isId('approval', approval)).toBe(true);
    });

    it('rejects malformed ids', () => {
        expect(isId('decision', 'dec_')).toBe(false);
        expect(isId('decision', 'dec_short')).toBe(false);
        expect(isId('decision', `dec_${'I'.repeat(26)}`)).toBe(false);
        expect(isId('decision', 'x'.repeat(30))).toBe(false);
    });
});

describe('isoTimestamp', () => {
    it('is UTC with millisecond precision', () => {
        expect(isoTimestamp(Date.UTC(2024, 0, 2, 3, 4, 5, 678))).toBe('2024-01-02T03:04:05.678Z');
    });

    it('round-trips through Date.parse', () => {
        const now = Date.now();
        expect(Date.parse(isoTimestamp(now))).toBe(now);
    });
});
