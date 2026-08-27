import { describe, expect, it } from 'vitest';

import { backoffDelayMs, sleep, type BackoffPolicy } from './backoff.js';

const POLICY: BackoffPolicy = { initialDelayMs: 500, maxDelayMs: 30_000, factor: 2 };

describe('backoffDelayMs', () => {
    it('grows exponentially from the initial delay', () => {
        // random() === 1 gives the top of each band, which is the nominal target.
        expect(backoffDelayMs(1, POLICY, () => 1)).toBe(500);
        expect(backoffDelayMs(2, POLICY, () => 1)).toBe(1_000);
        expect(backoffDelayMs(3, POLICY, () => 1)).toBe(2_000);
        expect(backoffDelayMs(4, POLICY, () => 1)).toBe(4_000);
    });

    it('never exceeds the cap, however many attempts have failed', () => {
        for (const attempt of [10, 50, 200, 1_000]) {
            expect(backoffDelayMs(attempt, POLICY, () => 1)).toBeLessThanOrEqual(POLICY.maxDelayMs);
        }
    });

    it('survives an attempt count large enough to overflow the exponent', () => {
        // 2 ** 5000 is Infinity; the clamp must happen before rounding or this
        // returns NaN and the reconnect loop spins.
        const delay = backoffDelayMs(5_000, POLICY, () => 0.5);
        expect(Number.isFinite(delay)).toBe(true);
        expect(delay).toBeGreaterThan(0);
        expect(delay).toBeLessThanOrEqual(POLICY.maxDelayMs);
    });

    it('keeps a floor of half the target even when random() returns zero', () => {
        // This is the whole reason for equal jitter over full jitter: a zero
        // delay against a downed server is a hot retry loop, not a backoff.
        expect(backoffDelayMs(1, POLICY, () => 0)).toBe(250);
        expect(backoffDelayMs(3, POLICY, () => 0)).toBe(1_000);
    });

    it('stays within the [target/2, target] band for any random value', () => {
        for (const r of [0, 0.01, 0.25, 0.5, 0.75, 0.99]) {
            const delay = backoffDelayMs(2, POLICY, () => r);
            expect(delay).toBeGreaterThanOrEqual(500);
            expect(delay).toBeLessThanOrEqual(1_000);
        }
    });

    it('is monotonic in the attempt number until the cap is reached', () => {
        let previous = 0;
        for (let attempt = 1; attempt <= 6; attempt += 1) {
            const delay = backoffDelayMs(attempt, POLICY, () => 1);
            expect(delay).toBeGreaterThanOrEqual(previous);
            previous = delay;
        }
    });

    it('treats attempt numbers below 1 as the first attempt', () => {
        expect(backoffDelayMs(0, POLICY, () => 1)).toBe(500);
        expect(backoffDelayMs(-7, POLICY, () => 1)).toBe(500);
        expect(backoffDelayMs(1.9, POLICY, () => 1)).toBe(500);
    });

    it('handles factor 1 as a constant delay', () => {
        const flat: BackoffPolicy = { initialDelayMs: 100, maxDelayMs: 100, factor: 1 };
        expect(backoffDelayMs(1, flat, () => 1)).toBe(100);
        expect(backoffDelayMs(9, flat, () => 1)).toBe(100);
    });
});

describe('sleep', () => {
    it('resolves after the delay', async () => {
        const started = Date.now();
        await sleep(20);
        expect(Date.now() - started).toBeGreaterThanOrEqual(15);
    });

    it('rejects immediately when the signal is already aborted', async () => {
        const controller = new AbortController();
        controller.abort(new Error('already gone'));
        await expect(sleep(10_000, controller.signal)).rejects.toThrow('already gone');
    });

    it('rejects when the signal aborts mid-sleep', async () => {
        const controller = new AbortController();
        const pending = sleep(10_000, controller.signal);
        setTimeout(() => controller.abort(new Error('shutting down')), 5);
        await expect(pending).rejects.toThrow('shutting down');
    });

    it('removes its abort listener on the normal path', async () => {
        // A long-lived registry sleeps thousands of times against one signal;
        // leaked listeners would show up here as a growing count.
        const controller = new AbortController();
        for (let i = 0; i < 5; i += 1) await sleep(1, controller.signal);

        const target = controller.signal as unknown as {
            readonly listenerCount?: (type: string) => number;
        };
        if (typeof target.listenerCount === 'function') {
            expect(target.listenerCount('abort')).toBe(0);
        }
    });
});
