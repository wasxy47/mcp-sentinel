/**
 * `@mcp-sentinel/mcp-core` — protocol plumbing and shared vocabulary.
 *
 * Everything here is dependency-light and side-effect free so that it can be
 * used from the gateway's hot path, from the audit verifier (which must run
 * standalone), and from tests.
 */

export {
    JsonRpcErrorCode,
    McpErrorCode,
    SentinelErrorCode,
    SentinelError,
    HeaderMismatchError,
    MethodNotFoundError,
    PolicyDeniedError,
    UpstreamUnavailableError,
    UnknownToolError,
    RequestTooLargeError,
    MalformedParamsError
} from './errors.js';
export type { SentinelErrorCodeValue } from './errors.js';

export {
    HEADER_PROTOCOL_VERSION,
    HEADER_MCP_METHOD,
    HEADER_MCP_NAME,
    HEADER_MCP_PARAM_PREFIX,
    SENTINEL_PROTOCOL_VERSION,
    MCP_NAME_SOURCE_FIELD,
    looksBase64Encoded,
    isHeaderSafe,
    encodeHeaderValue,
    decodeHeaderValue,
    readRequestMetadata,
    assertHeaderMatchesBody,
    buildRequestMetadataHeaders
} from './headers.js';
export type { RequestMetadata, HeaderReader } from './headers.js';

export {
    CanonicalizationError,
    canonicalize,
    sha256Hex,
    digestOf,
    GENESIS_HASH,
    hashesEqual
} from './canonical.js';

export {
    NAMESPACE_SEPARATOR,
    SENTINEL_SERVER_ID,
    RESOURCE_URI_SCHEME,
    NamingError,
    isValidServerId,
    isValidToolName,
    assertValidServerId,
    qualifyToolName,
    parseQualifiedToolName,
    isSentinelToolName,
    qualifyPromptName,
    parseQualifiedPromptName,
    qualifyResourceUri,
    parseQualifiedResourceUri,
    isQualifiedResourceUri
} from './naming.js';
export type { QualifiedToolName, QualifiedPromptName, QualifiedResourceUri } from './naming.js';

export { RESERVED_META_PREFIX, stripReservedMeta } from './meta.js';
export type { StrippedMeta } from './meta.js';

export { redact, redactText, isSensitiveKey } from './redact.js';
export type { RedactionFinding, RedactionResult, RedactOptions } from './redact.js';

export {
    ULID_LENGTH,
    IdError,
    UlidFactory,
    ulid,
    ulidTime,
    ID_PREFIX,
    newId,
    isId,
    isoTimestamp
} from './ids.js';
export type { IdKind } from './ids.js';

export { OBLIGATION_RANK, strongestObligation } from './types.js';
export type {
    ToolDefinition,
    Obligation,
    Verdict,
    AgentIdentity,
    UpstreamTransport,
    ServerTrust,
    UpstreamServerConfig,
    CatalogEntry,
    Severity,
    ScanFinding,
    ScanSummary,
    PolicyDecision,
    RiskAssessment,
    ApprovalState,
    ApprovalSummary,
    DecisionRecord
} from './types.js';
