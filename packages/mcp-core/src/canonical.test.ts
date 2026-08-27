import { describe, expect, it } from 'vitest';

import { CanonicalizationError, canonicalize, digestOf, GENESIS_HASH, hashesEqual, sha256Hex } from './canonical.js';

describe('canonicalize', () => {
    it('sorts object keys by UTF-16 code unit, not insertion order', () => {
        expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
        // Uppercase sorts before lowercase in code-unit order.
        expect(canonicalize({ a: 1, A: 2, B: 3, b: 4 })).toBe('{"A":2,"B":3,"a":1,"b":4}');
        // Surrogate pairs sort by code unit, which is what JCS specifies.
        expect(canonicalize({ '€': 1, z: 2 })).toBe('{"z":2,"€":1}');
    });

    it('produces identical output regardless of construction order', () => {
        const first: Record<string, unknown> = {};
        first.alpha = 1;
        first.beta = { y: 2, x: 3 };
        const second: Record<string, unknown> = {};
        second.beta = { x: 3, y: 2 };
        second.alpha = 1;

        expect(canonicalize(first)).toBe(canonicalize(second));
        expect(digestOf(first)).toBe(digestOf(second));
    });

    it('formats numbers the way RFC 8785 requires', () => {
        // These are the number vectors from RFC 8785 Appendix B. They hold
        // because JSON.stringify implements ECMAScript Number::toString, which
        // is exactly the serialisation JCS mandates.
        expect(canonicalize(333333333.33333329)).toBe('333333333.3333333');
        expect(canonicalize(1e30)).toBe('1e+30');
        expect(canonicalize(4.5)).toBe('4.5');
        expect(canonicalize(2e-3)).toBe('0.002');
        expect(canonicalize(1e-27)).toBe('1e-27');
    });

    it('normalises negative zero to 0 so equal values hash equally', () => {
        expect(canonicalize(-0)).toBe('0');
        expect(canonicalize({ v: -0 })).toBe(canonicalize({ v: 0 }));
        expect(canonicalize([-0])).toBe('[0]');
    });

    it('escapes strings with the shortest form and lowercase hex', () => {
        expect(canonicalize('\n')).toBe('"\\n"');
        expect(canonicalize('\t')).toBe('"\\t"');
        expect(canonicalize('\u000f')).toBe('"\\u000f"');
        expect(canonicalize('"')).toBe('"\\""');
        expect(canonicalize('\\')).toBe('"\\\\"');
        // Non-ASCII stays literal — no \u escaping.
        expect(canonicalize('€')).toBe('"€"');
        // Solidus is not escaped.
        expect(canonicalize('/')).toBe('"/"');
    });

    it('serialises literals and nesting', () => {
        expect(canonicalize([null, true, false])).toBe('[null,true,false]');
        expect(canonicalize({ a: [{ b: null }] })).toBe('{"a":[{"b":null}]}');
        expect(canonicalize({})).toBe('{}');
        expect(canonicalize([])).toBe('[]');
    });

    it('omits undefined properties and nulls undefined array elements', () => {
        expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
        // eslint-disable-next-line no-sparse-arrays
        expect(canonicalize([1, undefined, 3])).toBe('[1,null,3]');
    });

    it('ignores toJSON so a hash depends only on data', () => {
        const value = { a: 1, toJSON: () => ({ hijacked: true }) };
        expect(canonicalize(value)).toBe('{"a":1}');
    });

    it('rejects values that cannot be hashed deterministically', () => {
        expect(() => canonicalize(Number.NaN)).toThrow(CanonicalizationError);
        expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(CanonicalizationError);
        expect(() => canonicalize(1n)).toThrow(CanonicalizationError);
        expect(() => canonicalize(undefined)).toThrow(CanonicalizationError);

        const circular: Record<string, unknown> = { a: 1 };
        circular.self = circular;
        expect(() => canonicalize(circular)).toThrow(/circular/);
    });

    it('allows the same object to appear twice in one document', () => {
        // Repetition is not recursion; only a cycle is unhashable.
        const shared = { a: 1 };
        expect(canonicalize([shared, shared])).toBe('[{"a":1},{"a":1}]');
    });
});

describe('sha256Hex', () => {
    it('matches published SHA-256 vectors', () => {
        expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
        expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });

    it('hashes bytes and their UTF-8 string form identically', () => {
        expect(sha256Hex(new TextEncoder().encode('abc'))).toBe(sha256Hex('abc'));
    });
});

describe('digestOf', () => {
    it('is a 64-character lowercase hex digest', () => {
        expect(digestOf({ a: 1 })).toMatch(/^[0-9a-f]{64}$/);
    });

    it('distinguishes structurally different payloads', () => {
        expect(digestOf({ a: '1' })).not.toBe(digestOf({ a: 1 }));
        expect(digestOf({ a: { b: 1 } })).not.toBe(digestOf({ 'a.b': 1 }));
    });
});

describe('hashesEqual', () => {
    it('compares equal-length hex strings', () => {
        expect(hashesEqual(GENESIS_HASH, '0'.repeat(64))).toBe(true);
        expect(hashesEqual(GENESIS_HASH, `${'0'.repeat(63)}1`)).toBe(false);
    });

    it('returns false rather than throwing on a length mismatch', () => {
        expect(hashesEqual(GENESIS_HASH, 'abc')).toBe(false);
    });
});

describe('GENESIS_HASH', () => {
    it('is 64 zeroes, matching the digest width', () => {
        expect(GENESIS_HASH).toHaveLength(64);
        expect(GENESIS_HASH).toBe('0'.repeat(64));
    });
});
