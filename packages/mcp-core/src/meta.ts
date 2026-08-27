/**
 * Per-request `_meta` hygiene on the way to an upstream server.
 *
 * MCP reserves the `io.modelcontextprotocol/` prefix in `_meta` for the
 * protocol's own use. On 2026-07-28 that is where the request envelope lives:
 * `…/protocolVersion`, `…/clientInfo`, `…/clientCapabilities`, `…/logLevel`.
 * The SDK's client attaches those itself on every outbound request — and it
 * attaches them by merging `{ ...envelope, ...params._meta }`, with the caller's
 * keys spread *last* so they win.
 *
 * That ordering is right for an application and wrong for a gateway. Relaying an
 * agent's `_meta` verbatim would let the agent overwrite the envelope Sentinel's
 * own client minted and present itself to the upstream as a different client,
 * with different declared capabilities, at a different protocol version — the
 * exact facts an upstream's own authorisation might key on. On a `legacy` era
 * connection there is no envelope to overwrite at all, so a forged key simply
 * travels as-is.
 *
 * So Sentinel strips the whole reserved prefix before forwarding. The rule is
 * deliberately the prefix rather than a list of known key names: a list has to
 * be kept in step with the spec, and the failure mode of falling behind is a
 * newly-reserved key becoming forgeable. Anything an upstream legitimately needs
 * to see under that prefix is minted by Sentinel, not relayed.
 *
 * Everything else passes through untouched — W3C trace context (`traceparent`,
 * `tracestate`, `baggage`), the bare `progressToken`, and vendor keys such as
 * `com.example/tenant`. Those are the agent's to send, and dropping them would
 * break distributed tracing across the gateway for no security gain.
 */

/** The prefix MCP reserves in `_meta` for protocol-owned keys. */
export const RESERVED_META_PREFIX = 'io.modelcontextprotocol/';

export interface StrippedMeta {
    /**
     * The `_meta` to forward, or `undefined` when nothing survived — an empty
     * `_meta: {}` is noise on the wire and is dropped rather than sent.
     */
    readonly meta: Record<string, unknown> | undefined;
    /**
     * Reserved keys that were removed, in the order they appeared. Non-empty
     * means the agent tried to write protocol-owned metadata; worth logging and,
     * from M3, worth recording on the decision.
     */
    readonly stripped: readonly string[];
}

/**
 * Remove reserved keys from an inbound `_meta`.
 *
 * A `_meta` that is not a JSON object is dropped whole rather than relayed: the
 * spec allows only an object there, the SDK's inbound validation on the far side
 * would reject it, and forwarding a shape the protocol does not permit serves
 * no one. That is not reported in `stripped`, which is specifically about
 * attempts to set reserved keys.
 */
export function stripReservedMeta(meta: unknown): StrippedMeta {
    if (typeof meta !== 'object' || meta === null || Array.isArray(meta)) {
        return { meta: undefined, stripped: [] };
    }

    const stripped: string[] = [];
    const kept: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(meta as Record<string, unknown>)) {
        if (key.startsWith(RESERVED_META_PREFIX)) {
            stripped.push(key);
            continue;
        }
        kept[key] = value;
    }

    return {
        meta: Object.keys(kept).length === 0 ? undefined : kept,
        stripped
    };
}
