/**
 * MCP 2026-07-28 Streamable HTTP request-metadata headers.
 *
 * The transport mirrors selected JSON-RPC body fields into HTTP headers so that
 * intermediaries can route and enforce policy *without parsing the body*. That
 * is precisely what Sentinel does: `Mcp-Method` becomes the Cedar action and
 * `Mcp-Name` becomes the Cedar resource, both read straight off the request.
 *
 * Reading policy inputs from headers is only sound because the spec also
 * requires any server that processes the body to reject header/body
 * disagreements with `-32020`. Sentinel both relies on the SDK's enforcement of
 * that rule and re-asserts it itself (`assertHeaderMatchesBody`) so that the
 * header fast path can never be used to smuggle a different tool name past
 * policy. See docs/threat-model.md § Header/body desynchronisation.
 *
 * Spec: specification/2026-07-28/basic/transports/streamable-http § Request Metadata
 */

import { HeaderMismatchError } from './errors.js';

/** Canonical lowercase header names. HTTP field names are case-insensitive. */
export const HEADER_PROTOCOL_VERSION = 'mcp-protocol-version';
export const HEADER_MCP_METHOD = 'mcp-method';
export const HEADER_MCP_NAME = 'mcp-name';
/** Prefix for parameters mirrored via a tool's `x-mcp-header` annotation. */
export const HEADER_MCP_PARAM_PREFIX = 'mcp-param-';

/** The protocol revision this gateway speaks. */
export const SENTINEL_PROTOCOL_VERSION = '2026-07-28';

/**
 * Methods for which `Mcp-Name` is REQUIRED, mapped to the body field the header
 * mirrors. Every other method MUST NOT be expected to carry the header.
 */
export const MCP_NAME_SOURCE_FIELD: Readonly<Record<string, 'name' | 'uri'>> = Object.freeze({
    'tools/call': 'name',
    'resources/read': 'uri',
    'prompts/get': 'name'
});

const SENTINEL_PREFIX = '=?base64?';
const SENTINEL_SUFFIX = '?=';

/** Strict base64: canonical alphabet, correct padding, whole quantums only. */
const STRICT_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * True when `value` matches the Base64 sentinel wrapper exactly. The markers
 * are case-sensitive and MUST appear lowercase, so we compare literally.
 */
export function looksBase64Encoded(value: string): boolean {
    return (
        value.length >= SENTINEL_PREFIX.length + SENTINEL_SUFFIX.length &&
        value.startsWith(SENTINEL_PREFIX) &&
        value.endsWith(SENTINEL_SUFFIX)
    );
}

/**
 * True when `value` can travel as a plain HTTP field value.
 *
 * RFC 9110 permits visible ASCII (0x21–0x7E), space (0x20) and htab (0x09).
 * Leading or trailing whitespace is excluded because it is not preserved
 * reliably across intermediaries — the spec calls it out as a case that MUST be
 * Base64-encoded instead.
 */
export function isHeaderSafe(value: string): boolean {
    for (const char of value) {
        const code = char.codePointAt(0)!;
        const visible = code >= 0x21 && code <= 0x7e;
        if (!visible && code !== 0x20 && code !== 0x09) return false;
    }
    if (value.length > 0) {
        const first = value.charCodeAt(0);
        const last = value.charCodeAt(value.length - 1);
        if (first === 0x20 || first === 0x09 || last === 0x20 || last === 0x09) return false;
    }
    return true;
}

/**
 * Encode a body value for transport in `Mcp-Name` or `Mcp-Param-*`.
 *
 * Values that are already header-safe pass through unchanged, *except* one that
 * would itself look like the sentinel — encoding that is mandatory, otherwise a
 * literal `=?base64?x?=` tool name would be silently decoded by the peer.
 */
export function encodeHeaderValue(value: string): string {
    if (isHeaderSafe(value) && !looksBase64Encoded(value)) return value;
    const base64 = Buffer.from(value, 'utf8').toString('base64');
    return `${SENTINEL_PREFIX}${base64}${SENTINEL_SUFFIX}`;
}

/**
 * Decode an `Mcp-Name` / `Mcp-Param-*` value, unwrapping the sentinel when
 * present. Servers MUST decode before comparing against the body.
 *
 * @throws {HeaderMismatchError} when the wrapper is present but its payload is
 *   not strict base64 of valid UTF-8. A malformed encoding is a validation
 *   failure, not something to silently pass through as a literal.
 */
export function decodeHeaderValue(value: string, headerName = 'header'): string {
    if (!looksBase64Encoded(value)) return value;

    const payload = value.slice(SENTINEL_PREFIX.length, value.length - SENTINEL_SUFFIX.length);
    if (payload.length % 4 !== 0 || !STRICT_BASE64.test(payload)) {
        throw new HeaderMismatchError(`${headerName} is not valid base64`, { header: headerName });
    }

    const bytes = Buffer.from(payload, 'base64');
    // Buffer.from is lenient; re-encoding proves the input was canonical.
    if (bytes.toString('base64') !== payload) {
        throw new HeaderMismatchError(`${headerName} is not canonical base64`, { header: headerName });
    }

    try {
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
        throw new HeaderMismatchError(`${headerName} is not valid UTF-8`, { header: headerName });
    }
}

/**
 * The protocol metadata Sentinel extracts from a request before it looks at the
 * body. This is the input to the header fast-path policy gate.
 */
export interface RequestMetadata {
    /** Raw `MCP-Protocol-Version`, or undefined when absent. */
    readonly protocolVersion: string | undefined;
    /** Raw `Mcp-Method` — the JSON-RPC method, used as the Cedar action. */
    readonly method: string | undefined;
    /** Decoded `Mcp-Name` — the tool name or resource URI, the Cedar resource. */
    readonly name: string | undefined;
    /** Decoded `Mcp-Param-*` values, keyed by the lowercased name portion. */
    readonly params: ReadonlyMap<string, string>;
}

/** Minimal shape we need from a headers container — `Headers` satisfies it. */
export interface HeaderReader {
    get(name: string): string | null;
    forEach(callback: (value: string, key: string) => void): void;
}

/**
 * Pull the request-metadata headers off an inbound request.
 *
 * Decoding happens here so that every downstream consumer — policy, audit,
 * scanner — sees the same plain values, and a malformed encoding fails once, at
 * the edge, with the spec-mandated error.
 */
export function readRequestMetadata(headers: HeaderReader): RequestMetadata {
    const rawName = headers.get(HEADER_MCP_NAME);
    const params = new Map<string, string>();

    headers.forEach((value, key) => {
        const lower = key.toLowerCase();
        if (!lower.startsWith(HEADER_MCP_PARAM_PREFIX)) return;
        const paramName = lower.slice(HEADER_MCP_PARAM_PREFIX.length);
        if (paramName.length === 0) return;
        params.set(paramName, decodeHeaderValue(value, key));
    });

    return {
        protocolVersion: headers.get(HEADER_PROTOCOL_VERSION) ?? undefined,
        method: headers.get(HEADER_MCP_METHOD) ?? undefined,
        name: rawName === null ? undefined : decodeHeaderValue(rawName, HEADER_MCP_NAME),
        params
    };
}

/**
 * Re-assert the spec's header/body consistency rule.
 *
 * The SDK's inbound validation ladder already enforces this for requests it
 * serves. Sentinel checks it independently because Sentinel decides policy from
 * the headers *before* the SDK sees the request: a bug or version skew that
 * relaxed the SDK's check would silently turn Sentinel's fast path into a
 * bypass. Defence in depth on a security boundary is worth one string compare.
 *
 * Returns the agreed method, so a caller that has just proved the header and
 * body match does not have to re-narrow `body.method` from `unknown` or assert
 * its way past the type system.
 *
 * @throws {HeaderMismatchError} on any missing, extra, or disagreeing header.
 */
export function assertHeaderMatchesBody(
    metadata: RequestMetadata,
    body: { method?: unknown; params?: Record<string, unknown> | undefined }
): string {
    const bodyMethod = typeof body.method === 'string' ? body.method : undefined;

    if (metadata.method === undefined) {
        throw new HeaderMismatchError('Mcp-Method header is required on all requests');
    }
    if (bodyMethod === undefined) {
        throw new HeaderMismatchError('request body has no method to validate Mcp-Method against');
    }
    if (metadata.method !== bodyMethod) {
        throw new HeaderMismatchError(
            `Mcp-Method header value '${metadata.method}' does not match body value '${bodyMethod}'`,
            { header: HEADER_MCP_METHOD }
        );
    }

    const sourceField = MCP_NAME_SOURCE_FIELD[bodyMethod];
    if (sourceField === undefined) {
        // Mcp-Name is not defined for this method. A stray value is not an error
        // (intermediaries may add headers), so there is nothing to compare.
        return bodyMethod;
    }

    const bodyValue = body.params?.[sourceField];
    if (typeof bodyValue !== 'string') {
        throw new HeaderMismatchError(
            `${bodyMethod} requires a string params.${sourceField} to validate Mcp-Name against`,
            { header: HEADER_MCP_NAME }
        );
    }
    if (metadata.name === undefined) {
        throw new HeaderMismatchError(`Mcp-Name header is required for ${bodyMethod}`, {
            header: HEADER_MCP_NAME
        });
    }
    if (metadata.name !== bodyValue) {
        throw new HeaderMismatchError(
            `Mcp-Name header value '${metadata.name}' does not match body params.${sourceField} value '${bodyValue}'`,
            { header: HEADER_MCP_NAME }
        );
    }

    return bodyMethod;
}

/**
 * Build the outbound request-metadata headers for a call Sentinel forwards.
 *
 * Sentinel rewrites `params.name` when it strips its namespace prefix (an agent
 * calls `files__read_file`; the upstream server only knows `read_file`). The
 * mirrored header MUST be recomputed to match, or the upstream server will
 * correctly reject the forwarded request with -32020.
 */
export function buildRequestMetadataHeaders(
    method: string,
    nameOrUri?: string
): Record<string, string> {
    const headers: Record<string, string> = {
        [HEADER_PROTOCOL_VERSION]: SENTINEL_PROTOCOL_VERSION,
        [HEADER_MCP_METHOD]: method
    };
    if (MCP_NAME_SOURCE_FIELD[method] !== undefined && nameOrUri !== undefined) {
        headers[HEADER_MCP_NAME] = encodeHeaderValue(nameOrUri);
    }
    return headers;
}
