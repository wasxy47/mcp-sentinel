/**
 * Reconnect backoff.
 *
 * Kept as a pure function with an injectable random source because the property
 * that matters — the delay is bounded, monotonic in the attempt number, and
 * never zero — is only checkable if it can be tested without waiting.
 *
 * Jitter policy is **equal jitter**: half the target delay, plus a random amount
 * up to the other half. Full jitter (`random() * target`) is the more commonly
 * cited form, but it can return a near-zero delay, and a near-zero delay against
 * a server that is down is a hot retry loop wearing a backoff costume. Equal
 * jitter keeps a floor of half the target while still de-synchronising a fleet of
 * upstreams that all went down together.
 */

export interface BackoffPolicy {
    readonly initialDelayMs: number;
    readonly maxDelayMs: number;
    readonly factor: number;
}

/**
 * Delay before retry number `attempt`, where `attempt` is 1 for the first retry.
 *
 * @param attempt      1-based retry counter. Values below 1 are treated as 1.
 * @param policy       initial delay, cap, and growth factor.
 * @param random       source of randomness in `[0, 1)`; injected for tests.
 */
export function backoffDelayMs(attempt: number, policy: BackoffPolicy, random: () => number = Math.random): number {
    const step = Math.max(1, Math.floor(attempt));

    // Exponentiate in floating point but clamp before rounding: with a large
    // attempt count `initialDelayMs * factor ** step` overflows to Infinity, and
    // `Math.min` against the cap is what keeps that harmless.
    const uncapped = policy.initialDelayMs * policy.factor ** (step - 1);
    const target = Math.min(policy.maxDelayMs, Number.isFinite(uncapped) ? uncapped : policy.maxDelayMs);

    const half = target / 2;
    return Math.round(half + random() * half);
}

/**
 * Sleep that settles early — and rejects — when `signal` aborts.
 *
 * Shutdown must not have to wait out a 30-second reconnect delay, so the sleep
 * is cancellable rather than a bare `setTimeout`. The listener is removed on the
 * normal path too: a long-lived registry that reconnected a few thousand times
 * would otherwise accumulate abort listeners on one signal.
 */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted === true) return Promise.reject(signal.reason ?? new Error('aborted'));

    return new Promise<void>((resolvePromise, rejectPromise) => {
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort);
            resolvePromise();
        }, ms);

        function onAbort(): void {
            clearTimeout(timer);
            rejectPromise(signal?.reason ?? new Error('aborted'));
        }

        signal?.addEventListener('abort', onAbort, { once: true });
    });
}
