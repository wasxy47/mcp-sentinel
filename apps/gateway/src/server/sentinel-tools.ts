/**
 * Sentinel's own tool definitions.
 *
 * These are the tools the gateway exposes under the reserved `sentinel`
 * namespace (see `SENTINEL_SERVER_ID` in `mcp-core/naming.ts`). They are
 * advertised in `tools/list` from M1.4 onward, so agents can discover and
 * call them. Handlers in `handlers.ts` return a clear "not implemented" until
 * the implementing milestone arrives.
 *
 * Having the definitions live here rather than inline in `handlers.ts` lets
 * the catalog build-out (M7) add real handlers without touching the discovery
 * surface, and keeps the definition shapes available to tests.
 *
 * Naming convention: `sentinel__<toolName>` — the `SENTINEL_SERVER_ID` prefix
 * (`sentinel`) followed by the double-underscore separator, then the tool name
 * in `snake_case`. The `sentinel` server id is reserved and cannot be claimed
 * by an upstream (see `config/schema.ts` `ServerIdSchema`).
 *
 * Why these five?
 *   - `explain_decision`    — the primary human-facing debug tool; lets an
 *     operator (or the agent itself) understand why a call was allowed or
 *     denied. Required for accountability.
 *   - `query_audit_log`     — time-bounded query into the hash-chained store.
 *   - `list_active_policies`— surfaces which Cedar policies are loaded and what
 *     each one does; makes the policy bundle observable without a file read.
 *   - `verify_audit_chain`  — runs the standalone verifier over a range and
 *     returns the result; lets an agent surface tamper-evidence findings.
 *   - `approve_request`     — the in-band approval path for the offline case
 *     (M5.4). Requires the HMAC-signed token delivered to the human out-of-band
 *     so the agent cannot self-approve; the token never appears in any response
 *     to the agent.
 */

import type { ToolDefinition } from '@mcp-sentinel/mcp-core';

/** Qualified names of Sentinel's own tools, as constants for use in handlers. */
export const SENTINEL_TOOL_NAMES = Object.freeze({
    explainDecision: 'sentinel__explain_decision',
    queryAuditLog: 'sentinel__query_audit_log',
    listActivePolicies: 'sentinel__list_active_policies',
    verifyAuditChain: 'sentinel__verify_audit_chain',
    approveRequest: 'sentinel__approve_request'
} as const);

export type SentinelToolName = (typeof SENTINEL_TOOL_NAMES)[keyof typeof SENTINEL_TOOL_NAMES];

const SENTINEL_TOOL_NAME_SET: ReadonlySet<string> = new Set(Object.values(SENTINEL_TOOL_NAMES));

/** True when `name` is one of Sentinel's own qualified tool names. */
export function isSentinelOwnTool(name: string): name is SentinelToolName {
    return SENTINEL_TOOL_NAME_SET.has(name);
}

/**
 * The tool definitions Sentinel advertises under its own namespace.
 *
 * These are in the advertised form — `name` is the qualified name the agent
 * sees (`sentinel__explain_decision`), not the bare tool name. The catalog's
 * `advertised()` method applies the same transform to upstream tools; keeping
 * the same shape here means `handlers.ts` can concatenate both arrays directly.
 *
 * Input schemas use `type: 'object'` with explicit properties rather than bare
 * empty objects, so Cedar context extraction (M2) has something to validate
 * against, and agents can understand what each tool expects.
 */
export function sentinelToolDefinitions(): readonly ToolDefinition[] {
    return [
        {
            name: SENTINEL_TOOL_NAMES.explainDecision,
            description:
                'Explain why a past gateway decision was made. Returns the Cedar policies ' +
                'that determined the outcome, the obligation they carried, the risk score if ' +
                'one was computed, and whether human approval was involved. Use this when a ' +
                'call was denied or held and you need to understand why.',
            inputSchema: {
                type: 'object',
                properties: {
                    decisionId: {
                        type: 'string',
                        description: 'The dec_<ULID> identifier from the JSON-RPC error data, or from query_audit_log.'
                    }
                },
                required: ['decisionId'],
                additionalProperties: false
            }
        },
        {
            name: SENTINEL_TOOL_NAMES.queryAuditLog,
            description:
                'Query the hash-chained audit trail. Returns decision records matching ' +
                'the given filters, ordered newest-first. Arguments are present in redacted ' +
                'form only — values are replaced with a keyed HMAC placeholder. Use ' +
                'explain_decision for the full story of a single decision.',
            inputSchema: {
                type: 'object',
                properties: {
                    agentId: {
                        type: 'string',
                        description: 'Filter to decisions made for this agent id.'
                    },
                    serverId: {
                        type: 'string',
                        description: 'Filter to decisions involving this upstream server id.'
                    },
                    verdict: {
                        type: 'string',
                        enum: ['allow', 'deny', 'pending_approval'],
                        description: 'Filter to decisions with this verdict.'
                    },
                    since: {
                        type: 'string',
                        description: 'ISO-8601 timestamp; only decisions at or after this time.'
                    },
                    until: {
                        type: 'string',
                        description: 'ISO-8601 timestamp; only decisions before this time.'
                    },
                    limit: {
                        type: 'integer',
                        minimum: 1,
                        maximum: 200,
                        default: 50,
                        description: 'Maximum number of records to return.'
                    }
                },
                required: [],
                additionalProperties: false
            }
        },
        {
            name: SENTINEL_TOOL_NAMES.listActivePolicies,
            description:
                'List the Cedar policies currently loaded by the gateway, with their ids, ' +
                'obligations and a human-readable summary. Use this to understand what rules ' +
                'govern a call before making it, or to explain an unexpected denial.',
            inputSchema: {
                type: 'object',
                properties: {
                    file: {
                        type: 'string',
                        description: 'If provided, show only policies from this policy file (e.g. "20-filesystem.cedar").'
                    }
                },
                required: [],
                additionalProperties: false
            }
        },
        {
            name: SENTINEL_TOOL_NAMES.verifyAuditChain,
            description:
                'Run the standalone audit-chain verifier over a range of the log and return ' +
                'the result. A passing result means no row in the range has been tampered with ' +
                'since it was written. A failing result names the first broken link. ' +
                'Remember: the property is tamper-evidence, not tamper-proofing — an attacker ' +
                'who can write every copy can forge a consistent chain.',
            inputSchema: {
                type: 'object',
                properties: {
                    fromSeq: {
                        type: 'integer',
                        minimum: 1,
                        description: 'First sequence number to verify (inclusive). Defaults to the beginning.'
                    },
                    toSeq: {
                        type: 'integer',
                        minimum: 1,
                        description: 'Last sequence number to verify (inclusive). Defaults to the latest.'
                    }
                },
                required: [],
                additionalProperties: false
            }
        },
        {
            name: SENTINEL_TOOL_NAMES.approveRequest,
            description:
                'Approve or deny a pending approval request using a one-time signed token. ' +
                'The token is delivered to the human operator through the notification channel ' +
                'and is never returned to the agent — this is intentional. An agent that calls ' +
                'this tool without a valid token will receive an error; prompt injection cannot ' +
                'self-authorise through here because the token is not in any response the agent ' +
                'has ever seen.',
            inputSchema: {
                type: 'object',
                properties: {
                    token: {
                        type: 'string',
                        description:
                            'The HMAC-signed one-time token from the approval notification. ' +
                            'Encodes the approval id, outcome and expiry; verified server-side ' +
                            'with a constant-time compare.'
                    }
                },
                required: ['token'],
                additionalProperties: false
            }
        }
    ] as ToolDefinition[];
}
