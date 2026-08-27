/**
 * Domain types shared across every Sentinel package.
 *
 * These live in `mcp-core` so that `policy-engine`, `risk-engine`, `scanner`,
 * `audit` and the gateway all agree on the vocabulary without depending on each
 * other. The decision pipeline is:
 *
 *   Cedar policy  ──forbid──────────────────────────────────────▶ deny
 *        │
 *        └─permit─▶ obligation?
 *                    ├─ allow   ─────────────────────────────────▶ allow
 *                    ├─ review  ─▶ risk engine ─▶ score bands ─┬─▶ allow
 *                    │                                          ├─▶ approval
 *                    │                                          └─▶ deny
 *                    └─ approve ─▶ approval (human) ────────────┬─▶ allow
 *                                                               └─▶ deny
 *
 * Cedar's own answer is binary (`allow` / `deny`), so the middle two states are
 * carried as *obligations* annotated on the policies that granted the permit.
 * See docs/architecture.md § Modelling four outcomes on a two-valued engine.
 */

import type * as z from 'zod';
import type { ToolSchema } from '@modelcontextprotocol/core';
import type { RedactionFinding } from './redact.js';

/** An MCP tool definition, as it appears on the wire. */
export type ToolDefinition = z.infer<typeof ToolSchema>;

/**
 * What a matched policy requires beyond a bare permit. Ordered by strictness:
 * when several policies grant a permit, the strongest obligation wins.
 */
export type Obligation = 'allow' | 'review' | 'approve';

/** Strictness ranking used to combine obligations. Higher wins. */
export const OBLIGATION_RANK: Readonly<Record<Obligation, number>> = Object.freeze({
    allow: 0,
    review: 1,
    approve: 2
});

/** Combine obligations from several matched policies, strictest first. */
export function strongestObligation(obligations: readonly Obligation[]): Obligation {
    let winner: Obligation = 'allow';
    for (const candidate of obligations) {
        if (OBLIGATION_RANK[candidate] > OBLIGATION_RANK[winner]) winner = candidate;
    }
    return winner;
}

/** The gateway's final answer for a request. */
export type Verdict =
    /** Forward to the upstream server. */
    | 'allow'
    /** Refuse; the agent receives a JSON-RPC error. */
    | 'deny'
    /** Suspended pending a human; the agent receives a task handle. */
    | 'pending_approval';

/** Who is calling. Derived from client info plus any authenticated identity. */
export interface AgentIdentity {
    /** Stable id used as the Cedar principal, e.g. `claude-code` or an OAuth sub. */
    readonly id: string;
    /** Self-reported client name from `io.modelcontextprotocol/clientInfo`. */
    readonly name?: string;
    readonly version?: string;
    /**
     * Trust tier assigned by configuration, not by the client. Self-reported
     * identity is an assertion, never a credential — policies that care about
     * trust must key on this, which an operator sets.
     */
    readonly trustTier: 'trusted' | 'standard' | 'untrusted';
    /** True when `id` came from a verified token rather than self-report. */
    readonly authenticated: boolean;
}

/** How to reach an upstream MCP server. */
export type UpstreamTransport =
    | { readonly kind: 'http'; readonly url: string; readonly headers?: Readonly<Record<string, string>> }
    | {
          readonly kind: 'stdio';
          readonly command: string;
          readonly args?: readonly string[];
          readonly env?: Readonly<Record<string, string>>;
          readonly cwd?: string;
      };

/** Operator-declared trust posture for an upstream server. */
export type ServerTrust =
    /** Vetted; its tool descriptions are treated as benign-by-default. */
    | 'trusted'
    /** Default. Descriptions are scanned and treated as untrusted input. */
    | 'untrusted'
    /** Blocked outright: the scanner or an operator quarantined it. */
    | 'quarantined';

export interface UpstreamServerConfig {
    readonly id: string;
    readonly label: string;
    readonly transport: UpstreamTransport;
    readonly trust: ServerTrust;
    /** Optional per-server tool allowlist; when present, other tools are hidden. */
    readonly allowTools?: readonly string[];
}

/** A tool in the gateway's catalog, as advertised to agents. */
export interface CatalogEntry {
    /** Name agents see, e.g. `files__read_file`. */
    readonly qualifiedName: string;
    readonly serverId: string;
    /** Name the upstream server knows, e.g. `read_file`. */
    readonly toolName: string;
    readonly definition: ToolDefinition;
    /**
     * Digest of the upstream definition. Comparing this across refreshes is how
     * a "rug pull" — a server that serves a benign description first and a
     * malicious one later — is detected.
     */
    readonly definitionDigest: string;
    readonly scan?: ScanSummary;
}

/** Severity of a scanner finding. */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** One thing the scanner found wrong with a tool or server. */
export interface ScanFinding {
    readonly id: string;
    readonly detector: string;
    readonly severity: Severity;
    readonly title: string;
    readonly detail: string;
    /** Where in the definition, e.g. `description` or `inputSchema.properties.path`. */
    readonly location: string;
    /** The offending excerpt, redacted and length-capped. */
    readonly evidence?: string;
}

/** Aggregate scanner outcome for one tool. */
export interface ScanSummary {
    readonly verdict: 'clean' | 'suspicious' | 'malicious';
    readonly highestSeverity: Severity | undefined;
    readonly findings: readonly ScanFinding[];
    readonly scannedAt: string;
}

/** Cedar's answer, plus the obligations carried by the deciding policies. */
export interface PolicyDecision {
    readonly effect: 'permit' | 'forbid';
    readonly obligation: Obligation;
    /** Ids of the policies that determined the answer (Cedar `diagnostics.reason`). */
    readonly reasons: readonly string[];
    /** Non-fatal evaluation errors, e.g. a policy referencing a missing attribute. */
    readonly errors: readonly string[];
    /** True when no policy matched at all and default-deny applied. */
    readonly defaultDeny: boolean;
}

/** The risk engine's structured verdict for an ambiguous call. */
export interface RiskAssessment {
    /** 0 = certainly benign, 100 = certainly malicious. */
    readonly score: number;
    readonly band: 'low' | 'medium' | 'high' | 'critical';
    /** Short human-readable justification, redacted before storage. */
    readonly rationale: string;
    /** Machine-readable signals the model claims to have seen. */
    readonly signals: readonly string[];
    readonly provider: string;
    readonly model: string;
    /** True when served from the decision cache rather than a fresh inference. */
    readonly cached: boolean;
    readonly latencyMs: number;
}

/** State of a human approval request. */
export type ApprovalState = 'pending' | 'approved' | 'denied' | 'expired';

export interface ApprovalSummary {
    readonly approvalId: string;
    readonly state: ApprovalState;
    readonly requestedAt: string;
    readonly decidedAt?: string;
    /** Free-form approver label; never a credential. */
    readonly approver?: string;
    readonly reason?: string;
}

/**
 * One row of the audit trail — the complete, self-contained story of a single
 * gateway decision. Everything here is safe to persist: arguments appear only
 * as a digest plus a redacted copy.
 */
export interface DecisionRecord {
    readonly decisionId: string;
    readonly timestamp: string;
    readonly agent: AgentIdentity;
    readonly protocolVersion: string;
    readonly method: string;
    readonly qualifiedName?: string;
    readonly serverId?: string;
    readonly upstreamName?: string;
    readonly verdict: Verdict;
    readonly obligation: Obligation;
    readonly policy: PolicyDecision;
    readonly risk?: RiskAssessment;
    readonly approval?: ApprovalSummary;
    readonly scan?: ScanSummary;
    /** SHA-256 over the canonical form of the original, unredacted arguments. */
    readonly argsDigest: string;
    /** Arguments with secrets removed. Safe to display. */
    readonly argsRedacted?: unknown;
    readonly redactionFindings: readonly RedactionFinding[];
    /** Digest of the upstream result, when the call was forwarded. */
    readonly resultDigest?: string;
    /** Task handle minted for an approval-suspended call. */
    readonly taskId?: string;
    readonly latencyMs: number;
    /**
     * True when the decision was reached with a degraded pipeline (e.g. the risk
     * engine was unreachable). Lets an auditor find decisions to revisit.
     */
    readonly degraded: boolean;
    readonly error?: { readonly code: number; readonly message: string };
}
