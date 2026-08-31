/**
 * `strongestObligation` — exhaustive correctness tests.
 *
 * `approve > review > allow` is a security invariant: if the combinator
 * silently caps at a lower obligation, a call that should be held for
 * human approval gets waved through. Every permutation of the three values
 * is tested to make that regression visible immediately.
 */

import { describe, expect, it } from 'vitest';
import { strongestObligation } from '@mcp-sentinel/mcp-core';
import type { Obligation } from '@mcp-sentinel/mcp-core';

describe('strongestObligation', () => {
    it('returns allow for an empty list (safe default)', () => {
        expect(strongestObligation([])).toBe('allow');
    });

    it('returns the sole element when there is only one', () => {
        expect(strongestObligation(['allow'])).toBe('allow');
        expect(strongestObligation(['review'])).toBe('review');
        expect(strongestObligation(['approve'])).toBe('approve');
    });

    it('approve beats review', () => {
        expect(strongestObligation(['approve', 'review'])).toBe('approve');
        expect(strongestObligation(['review', 'approve'])).toBe('approve');
    });

    it('approve beats allow', () => {
        expect(strongestObligation(['approve', 'allow'])).toBe('approve');
        expect(strongestObligation(['allow', 'approve'])).toBe('approve');
    });

    it('review beats allow', () => {
        expect(strongestObligation(['review', 'allow'])).toBe('review');
        expect(strongestObligation(['allow', 'review'])).toBe('review');
    });

    it('handles all three — all 6 permutations return approve', () => {
        const perms: Obligation[][] = [
            ['allow', 'review', 'approve'],
            ['allow', 'approve', 'review'],
            ['review', 'allow', 'approve'],
            ['review', 'approve', 'allow'],
            ['approve', 'allow', 'review'],
            ['approve', 'review', 'allow'],
        ];
        for (const perm of perms) {
            expect(strongestObligation(perm), `perm: ${perm.join(',')}`).toBe('approve');
        }
    });

    it('handles duplicates correctly', () => {
        expect(strongestObligation(['allow', 'allow', 'allow'])).toBe('allow');
        expect(strongestObligation(['review', 'review'])).toBe('review');
        expect(strongestObligation(['approve', 'review', 'approve'])).toBe('approve');
    });
});
