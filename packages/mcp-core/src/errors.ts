/**
 * JSON-RPC error codes and the Sentinel error hierarchy.
 *
 * The MCP 2026-07-28 revision partitions the JSON-RPC server-error range
 * (see spec `basic/index#error-codes`):
 *
 *   -32000 .. -32019   implementation-defined  (Sentinel allocates from here)
 *   -32020 .. -32099   reserved for the MCP specification
 *
 * We therefore keep every Sentinel-specific code inside -32000..-32019 and
 * never invent codes in the reserved band.
 */

/** Codes defined by JSON-RPC 2.0 itself. */
export const JsonRpcErrorCode = {
    ParseError: -32700,
    InvalidRequest: -32600,
    MethodNotFound: -32601,
    InvalidParams: -32602,
    InternalError: -32603
} as const;

/**
 * Codes defined by the MCP specification in its reserved sub-range. Sentinel
 * emits these — it never defines new ones here.
 */
export const McpErrorCode = {
    /** HTTP headers disagree with the request body, or a required one is missing. */
    HeaderMismatch: -32020,
    /** The request omitted a client capability the server requires. */
    MissingRequiredClientCapability: -32021,
    /** The server does not implement the requested protocol revision. */
    UnsupportedProtocolVersion: -32022
} as const;

/**
 * Sentinel's own codes, allocated from the implementation-defined range.
 * These are the codes an agent sees when the gateway refuses to forward.
 */
export const SentinelErrorCode = {
    /** A Cedar `forbid` matched, or no `permit` did (default-deny). */
    PolicyDenied: -32000,
    /** Human approval is required but the caller cannot carry a task handle. */
    ApprovalRequired: -32001,
    /** A human explicitly denied the call, or the approval window expired. */
    ApprovalDenied: -32002,
    /** The risk engine scored the call above the configured deny threshold. */
    RiskThresholdExceeded: -32003,
    /** The upstream MCP server is unreachable, or its handshake failed. */
    UpstreamUnavailable: -32004,
    /** The scanner quarantined the tool or server (e.g. tool poisoning). */
    ScannerQuarantine: -32005,
    /** Policy said "review" but no risk verdict could be obtained (fail-closed). */
    RiskEngineUnavailable: -32006,
    /** The requested tool is not present in the gateway's catalog. */
    UnknownTool: -32007,
    /** The request body exceeded a configured size bound (T17). */
    RequestTooLarge: -32008
} as const;

export type SentinelErrorCodeValue = (typeof SentinelErrorCode)[keyof typeof SentinelErrorCode];

/**
 * Base class for every error Sentinel converts into a JSON-RPC error response.
 *
 * `httpStatus` matters because the spec pins particular statuses to particular
 * failures: header validation MUST be `400`, an unknown method MUST be `404`.
 * `data` is surfaced to the caller, so it must never contain raw arguments —
 * only already-redacted, non-secret detail.
 */
export class SentinelError extends Error {
    public readonly code: number;
    public readonly httpStatus: number;
    public readonly data: Record<string, unknown> | undefined;

    public constructor(
        code: number,
        message: string,
        options: { httpStatus?: number; data?: Record<string, unknown>; cause?: unknown } = {}
    ) {
        super(message, options.cause === undefined ? undefined : { cause: options.cause });
        this.name = new.target.name;
        this.code = code;
        this.httpStatus = options.httpStatus ?? 200;
        this.data = options.data;
    }

    /** Render as a JSON-RPC error object (the `error` member of a response). */
    public toJsonRpcError(): { code: number; message: string; data?: Record<string, unknown> } {
        return this.data === undefined
            ? { code: this.code, message: this.message }
            : { code: this.code, message: this.message, data: this.data };
    }
}

/**
 * A header/body disagreement, or a missing/malformed required header.
 *
 * The spec requires HTTP 400 plus code -32020. This is a security control, not
 * a nicety: Sentinel makes policy decisions from `Mcp-Method`/`Mcp-Name`
 * without parsing the body, so if a header could disagree with the body that
 * would be a policy-bypass primitive. See docs/threat-model.md.
 */
export class HeaderMismatchError extends SentinelError {
    public constructor(message: string, data?: Record<string, unknown>) {
        super(McpErrorCode.HeaderMismatch, `Header mismatch: ${message}`, {
            httpStatus: 400,
            ...(data === undefined ? {} : { data })
        });
    }
}

/** The gateway does not implement the requested JSON-RPC method (HTTP 404). */
export class MethodNotFoundError extends SentinelError {
    public constructor(method: string) {
        super(JsonRpcErrorCode.MethodNotFound, `Method not found: ${method}`, {
            httpStatus: 404,
            data: { method }
        });
    }
}

/** A policy decision refused the call. Carries the deciding policy IDs. */
export class PolicyDeniedError extends SentinelError {
    public constructor(message: string, data: Record<string, unknown>) {
        super(SentinelErrorCode.PolicyDenied, message, { data });
    }
}

/**
 * An upstream MCP server could not be reached, or its handshake failed.
 *
 * Deliberately vague to the caller. `reason` is a short, operator-facing phrase
 * ("connect timed out", "process exited"), never the upstream's raw error text:
 * a hostile upstream that controls its own error strings would otherwise get a
 * channel straight into the agent's context. The full detail goes to the audit
 * record and the log, both of which are read by humans.
 */
export class UpstreamUnavailableError extends SentinelError {
    public constructor(serverId: string, reason: string, options: { cause?: unknown } = {}) {
        super(SentinelErrorCode.UpstreamUnavailable, `Upstream "${serverId}" is unavailable: ${reason}`, {
            data: { serverId, reason },
            ...(options.cause === undefined ? {} : { cause: options.cause })
        });
    }
}

/**
 * The requested tool, resource or prompt is not in the gateway's catalog.
 *
 * Deliberately the single answer to several distinct situations: the name does
 * not parse, the server behind it does not exist, the server exists but is
 * quarantined or disabled, the tool was withheld because its definition drifted,
 * or the server never advertised the capability the request needs. Telling those
 * apart would give an agent an enumeration oracle over the operator's
 * configuration — probing `secrets__read` would reveal whether a `secrets`
 * server is configured at all. The operator gets the real reason in the log;
 * the agent gets "unknown".
 */
export class UnknownToolError extends SentinelError {
    public constructor(qualifiedName: string, kind: 'tool' | 'resource' | 'prompt' = 'tool') {
        super(SentinelErrorCode.UnknownTool, `Unknown ${kind}: ${qualifiedName}`, {
            data: { qualifiedName, kind }
        });
    }
}

/**
 * A request exceeded a configured size bound.
 *
 * Tool arguments are attacker-influenced bulk that Sentinel must canonicalise,
 * digest, log, and — from M4 — feed to a risk model. Every one of those costs
 * scales with the payload, so the bound is checked once at the gateway edge
 * rather than being discovered downstream. See docs/threat-model.md § T17.
 *
 * `limit` and `bytes` are safe to return: both are Sentinel's own measurements,
 * and knowing the configured cap tells an agent nothing it could not learn by
 * bisecting anyway.
 */
export class RequestTooLargeError extends SentinelError {
    public constructor(what: string, bytes: number, limit: number) {
        super(SentinelErrorCode.RequestTooLarge, `${what} is too large: ${bytes} bytes exceeds the ${limit}-byte limit`, {
            httpStatus: 413,
            data: { bytes, limit }
        });
    }
}

/**
 * The request's params are structurally unusable — not merely wrong, but
 * something Sentinel cannot process at all.
 *
 * Distinct from a policy denial: nothing was decided, because there was nothing
 * coherent to decide about. `detail` is Sentinel's own description of the defect,
 * never a value copied out of the request.
 */
export class MalformedParamsError extends SentinelError {
    public constructor(detail: string) {
        super(JsonRpcErrorCode.InvalidParams, `Invalid params: ${detail}`, { httpStatus: 400 });
    }
}
