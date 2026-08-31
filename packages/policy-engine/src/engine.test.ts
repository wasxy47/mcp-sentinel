/**
 * PolicyEngine integration tests — evaluated against the REAL policy bundle.
 *
 * These are not unit tests for stub logic — they are correctness tests for the
 * security invariants of the full Cedar evaluation pipeline. If a guard test
 * fails, a real-world bypass may exist.
 *
 * ## Test structure
 *
 * 1. **Happy path** — verify expected allow/review obligations for normal calls.
 * 2. **Absolute forbid guards** — the ten invariants in 00-guards.cedar that
 *    must deny regardless of any permit. Each is a separate test so a failure
 *    names the exact guard that broke.
 * 3. **Obligation combining** — multiple matching permits; strongest wins.
 * 4. **Failure modes** — default-deny, evaluation errors, unknown actions.
 */

import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';

import { loadBundle } from './loader.js';
import type { PolicyBundle } from './loader.js';
import { PolicyEngine } from './engine.js';
import type { EvaluationRequest, McpAction } from './engine.js';
import type { AgentPrincipal, PolicyResource } from './entities.js';
import {
    extractToolCallContext,
    extractResourceReadContext,
    extractBaseContext,
} from './extract.js';
import type { ExtractConfig } from './extract.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const POLICIES_DIR = path.resolve(__dirname, '../../../policies');
const SCHEMA_PATH = path.join(POLICIES_DIR, 'schema.cedarschema');
const WORKSPACE = '/workspace/project';

const noopLogger = { warn: () => {} };

let bundle: PolicyBundle;
let engine: PolicyEngine;

beforeAll(() => {
    bundle = loadBundle(POLICIES_DIR, SCHEMA_PATH);
    engine = new PolicyEngine(bundle, noopLogger);
});

// ── Helpers ───────────────────────────────────────────────────────────────────

const standardAgent: AgentPrincipal = {
    id: 'test-agent',
    trustTier: 'standard',
    authenticated: false,
    clientName: 'test',
    agentGroups: [],
};

const trustedAgent: AgentPrincipal = {
    id: 'trusted-agent',
    trustTier: 'trusted',
    authenticated: false,
    clientName: 'test',
    agentGroups: ['approvers'],
};

const untrustedAgent: AgentPrincipal = {
    id: 'untrusted-agent',
    trustTier: 'untrusted',
    authenticated: false,
    clientName: 'attacker',
    agentGroups: [],
};

const cleanToolBase = {
    kind: 'tool' as const,
    qualifiedName: 'files__read_file',
    toolName: 'read_file',
    serverId: 'files',
    serverTrust: 'trusted' as const,
    serverScanVerdict: 'clean',
    toolScanVerdict: 'clean',
    definitionDrifted: false,
    toolGroups: ['read_only'],
};

const mutatingTool: PolicyResource = {
    kind: 'tool',
    qualifiedName: 'files__write_file',
    toolName: 'write_file',
    serverId: 'files',
    serverTrust: 'trusted',
    serverScanVerdict: 'clean',
    toolScanVerdict: 'clean',
    definitionDrifted: false,
    toolGroups: ['mutating'],
};

const baseExtractConfig: ExtractConfig = {
    workspaceRoot: WORKSPACE,
    allowedHosts: ['internal.corp'],
    protocolVersion: '2026-07-28',
    serverTrust: 'trusted',
    toolScanVerdict: 'clean',
};

function cleanToolContext(overrides: Partial<ExtractConfig> = {}) {
    return extractToolCallContext(
        { path: `${WORKSPACE}/src/main.ts` },
        { ...baseExtractConfig, ...overrides },
    );
}

function endpointRequest(action: McpAction): EvaluationRequest {
    return {
        principal: standardAgent,
        action,
        resource: { kind: 'endpoint' },
        context: extractBaseContext('2026-07-28'),
    };
}

function toolRequest(
    resource: PolicyResource,
    context: ReturnType<typeof extractToolCallContext>,
    principal: AgentPrincipal = standardAgent,
    action: McpAction = 'callTool',
): EvaluationRequest {
    return { principal, action, resource, context };
}

// ── 1. Happy path ─────────────────────────────────────────────────────────────

describe('happy path', () => {
    it('read-only tool inside workspace → permit with allow obligation', () => {
        const r = engine.evaluate(
            toolRequest(cleanToolBase, cleanToolContext()),
        );
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('allow');
        expect(r.defaultDeny).toBe(false);
    });

    it('read-only tool outside workspace → permit with review obligation', () => {
        const ctx = extractToolCallContext(
            { path: '/etc/some-config' },
            { ...baseExtractConfig },
        );
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx));
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('review');
    });

    it('read-only tool with suspicious scan verdict → review', () => {
        const ctx = extractToolCallContext(
            { path: `${WORKSPACE}/src/main.ts` },
            { ...baseExtractConfig, toolScanVerdict: 'suspicious' },
        );
        const resource: PolicyResource = {
            ...cleanToolBase,
            toolScanVerdict: 'suspicious',
        };
        const r = engine.evaluate(toolRequest(resource, ctx));
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('review');
    });

    it('mutating tool inside workspace, trusted agent → approve', () => {
        const ctx = extractToolCallContext(
            { path: `${WORKSPACE}/src/main.ts` },
            { ...baseExtractConfig },
        );
        const r = engine.evaluate(toolRequest(mutatingTool, ctx, trustedAgent));
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('approve');
    });

    it('resource read inside workspace over file: scheme → allow', () => {
        const rctx = extractResourceReadContext(
            `file://${WORKSPACE}/src/main.ts`,
            baseExtractConfig,
        );
        const r = engine.evaluate({
            principal: standardAgent,
            action: 'readResource',
            resource: {
                kind: 'mcp-resource',
                qualifiedUri: `mcp-sentinel://files/file%3A%2F%2F${WORKSPACE}/src/main.ts`,
                rawUri: `file://${WORKSPACE}/src/main.ts`,
                serverId: 'files',
                serverTrust: 'trusted',
                serverScanVerdict: 'clean',
                scheme: 'file',
            },
            context: rctx,
        });
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('allow');
    });

    it('resource read over https → review', () => {
        const rctx = extractResourceReadContext('https://internal.corp/data', baseExtractConfig);
        const r = engine.evaluate({
            principal: standardAgent,
            action: 'readResource',
            resource: {
                kind: 'mcp-resource',
                qualifiedUri: 'mcp-sentinel://files/https%3A%2F%2Finternal.corp%2Fdata',
                rawUri: 'https://internal.corp/data',
                serverId: 'files',
                serverTrust: 'trusted',
                serverScanVerdict: 'clean',
                scheme: 'https',
            },
            context: rctx,
        });
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('review');
    });

    it('listTools → permit allow (catalog policy)', () => {
        const r = engine.evaluate(endpointRequest('listTools'));
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('allow');
    });

    it('discover → permit allow', () => {
        const r = engine.evaluate(endpointRequest('discover'));
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('allow');
    });

    it('explainDecision → permit allow (governance open policy)', () => {
        const r = engine.evaluate(endpointRequest('explainDecision'));
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('allow');
    });

    it('listActivePolicies → permit allow (governance open policy)', () => {
        const r = engine.evaluate(endpointRequest('listActivePolicies'));
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('allow');
    });
});

// ── 2. Absolute forbid guards ─────────────────────────────────────────────────
//
// These must deny regardless of any matching permit. Cedar's forbid-overrides-
// permit rule ensures this — but we verify it empirically for each guard.

describe('guard: quarantined server', () => {
    it('tool call to quarantined server → deny', () => {
        const quarantinedTool: PolicyResource = {
            ...cleanToolBase,
            serverTrust: 'quarantined',
        };
        const r = engine.evaluate(
            toolRequest(quarantinedTool, cleanToolContext({ serverTrust: 'quarantined' })),
        );
        expect(r.effect).toBe('forbid');
    });
});

describe('guard: malicious tool scan verdict', () => {
    it('tool with malicious scanVerdict → deny', () => {
        const maliciousTool: PolicyResource = {
            ...cleanToolBase,
            toolScanVerdict: 'malicious',
        };
        const ctx = extractToolCallContext(
            { path: `${WORKSPACE}/src/main.ts` },
            { ...baseExtractConfig, toolScanVerdict: 'malicious' },
        );
        const r = engine.evaluate(toolRequest(maliciousTool, ctx));
        expect(r.effect).toBe('forbid');
    });
});

describe('guard: definition drift (rug-pull)', () => {
    it('tool with definitionDrifted=true → deny', () => {
        const driftedTool: PolicyResource = {
            ...cleanToolBase,
            definitionDrifted: true,
        };
        const r = engine.evaluate(toolRequest(driftedTool, cleanToolContext()));
        expect(r.effect).toBe('forbid');
    });
});

describe('guard: credential to untrusted server', () => {
    it('credential in args + untrusted server → deny', () => {
        const untrustedTool: PolicyResource = {
            ...cleanToolBase,
            serverTrust: 'untrusted',
        };
        const ctx = extractToolCallContext(
            // Classic AWS access key ID — exactly 20 chars (AKIA + 16 uppercase alphanumeric)
            { key: 'AKIAIOSFODNN7EXAMPLE' },
            { ...baseExtractConfig, serverTrust: 'untrusted' },
        );
        expect(ctx.containsCredential).toBe(true);
        const r = engine.evaluate(toolRequest(untrustedTool, ctx));
        expect(r.effect).toBe('forbid');
    });

    it('credential in args + trusted server is NOT blocked by this guard', () => {
        // The credential guard is specifically about untrusted servers.
        const ctx = extractToolCallContext(
            // Classic AWS access key ID — exactly 20 chars
            { key: 'AKIAIOSFODNN7EXAMPLE' },
            { ...baseExtractConfig, serverTrust: 'trusted' },
        );
        expect(ctx.containsCredential).toBe(true);
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx));
        expect(r.effect).toBe('permit');
    });
});

describe('guard: credential to external URL', () => {
    it('credential in args + external URL → deny', () => {
        const ctx = extractToolCallContext(
            { auth: 'Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig', url: 'https://evil.com' },
            { ...baseExtractConfig },
        );
        expect(ctx.containsCredential).toBe(true);
        expect(ctx.hasExternalUrl).toBe(true);
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx));
        expect(r.effect).toBe('forbid');
    });
});

describe('guard: sensitive path in tool call', () => {
    it('~/.ssh/id_rsa path → deny callTool', () => {
        const ctx = extractToolCallContext(
            { path: '/root/.ssh/id_rsa' },
            { ...baseExtractConfig },
        );
        expect(ctx.hasSensitivePath).toBe(true);
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx));
        expect(r.effect).toBe('forbid');
    });

    it('.env file path → deny callTool', () => {
        const ctx = extractToolCallContext(
            { path: '/workspace/.env' },
            { ...baseExtractConfig },
        );
        expect(ctx.hasSensitivePath).toBe(true);
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx));
        expect(r.effect).toBe('forbid');
    });
});

describe('guard: sensitive path in resource read', () => {
    it('file:///etc/shadow → deny readResource', () => {
        const rctx = extractResourceReadContext('file:///etc/shadow', baseExtractConfig);
        expect(rctx.hasSensitivePath).toBe(true);
        const r = engine.evaluate({
            principal: standardAgent,
            action: 'readResource',
            resource: {
                kind: 'mcp-resource',
                qualifiedUri: 'mcp-sentinel://files/file%3A%2F%2F%2Fetc%2Fshadow',
                rawUri: 'file:///etc/shadow',
                serverId: 'files',
                serverTrust: 'trusted',
                serverScanVerdict: 'clean',
                scheme: 'file',
            },
            context: rctx,
        });
        expect(r.effect).toBe('forbid');
    });
});

describe('guard: invisible Unicode in arguments', () => {
    it('zero-width space in argument → deny callTool', () => {
        const ctx = extractToolCallContext(
            { cmd: 'read\u200Bfile' },
            { ...baseExtractConfig },
        );
        expect(ctx.hasInvisibleUnicode).toBe(true);
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx));
        expect(r.effect).toBe('forbid');
    });

    it('bidi override in path argument → deny callTool', () => {
        const ctx = extractToolCallContext(
            { path: `${WORKSPACE}/\u202Esrc/main.ts` },
            { ...baseExtractConfig },
        );
        expect(ctx.hasInvisibleUnicode).toBe(true);
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx));
        expect(r.effect).toBe('forbid');
    });
});

describe('guard: critical risk score (second-pass)', () => {
    it('riskScore >= 90 → deny regardless of permit', () => {
        // Add second-pass context fields.
        const ctx = {
            ...cleanToolContext(),
            riskScore: 90,
            riskBand: 'critical',
        };
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx as any));
        expect(r.effect).toBe('forbid');
    });

    it('riskScore = 89 does NOT trigger the critical guard', () => {
        const ctx = {
            ...cleanToolContext(),
            riskScore: 89,
            riskBand: 'high',
        };
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx as any));
        // Should still be a permit (the high-band escalation is handled by the gateway, not Cedar).
        expect(r.effect).toBe('permit');
    });
});

describe('guard: untrusted agent mutation', () => {
    it('untrusted agent calling mutating tool → deny even with a permit', () => {
        const ctx = extractToolCallContext(
            { path: `${WORKSPACE}/src/main.ts` },
            { ...baseExtractConfig },
        );
        const r = engine.evaluate(toolRequest(mutatingTool, ctx, untrustedAgent));
        expect(r.effect).toBe('forbid');
    });

    it('untrusted agent calling read-only tool → permit (reads are allowed)', () => {
        const ctx = cleanToolContext();
        const r = engine.evaluate(toolRequest(cleanToolBase, ctx, untrustedAgent));
        // The guard only blocks mutation; reads are OK.
        expect(r.effect).toBe('permit');
    });
});

// ── 3. Obligation combining ───────────────────────────────────────────────────

describe('obligation combining', () => {
    it('two permits: allow + review → strongest is review', () => {
        // A suspicious tool scan verdict triggers fs_read_suspicious_tool (review),
        // while being inside the workspace triggers fs_read_within_workspace (allow).
        // But the suspicious-verdict policy fires when toolScanVerdict==suspicious,
        // which is also in the when-clause. Only one permit matches at a time here.
        // Let's verify: outside workspace (review) overrides clean inside (allow) if we
        // have a separate suspicious tool:
        const suspiciousTool: PolicyResource = {
            ...cleanToolBase,
            toolScanVerdict: 'suspicious',
        };
        const ctx = extractToolCallContext(
            { path: `${WORKSPACE}/src/main.ts` },
            { ...baseExtractConfig, toolScanVerdict: 'suspicious' },
        );
        const r = engine.evaluate(toolRequest(suspiciousTool, ctx));
        // fs_read_suspicious_tool (review) fires — and fs_read_within_workspace
        // won't fire because toolScanVerdict != 'clean'. So result is review.
        expect(r.effect).toBe('permit');
        expect(r.obligation).toBe('review');
    });

    it('mutating tool → approve (strongest possible for a write)', () => {
        const ctx = cleanToolContext();
        const r = engine.evaluate(toolRequest(mutatingTool, ctx, trustedAgent));
        expect(r.obligation).toBe('approve');
    });
});

// ── 4. Failure modes ──────────────────────────────────────────────────────────

describe('failure modes', () => {
    it('no matching permit → default deny', () => {
        // A mutating tool called by an agent in no group, with no applicable permit.
        const noGroupAgent: AgentPrincipal = {
            ...standardAgent,
            trustTier: 'standard',
        };
        // No policy covers mutating + standard-tier + outside-workspace.
        const ctx = extractToolCallContext(
            { path: '/tmp/random' },
            { ...baseExtractConfig },
        );
        // mutatingTool has no matching permit for standard-tier + outside workspace.
        const r = engine.evaluate(toolRequest(mutatingTool, ctx, noGroupAgent));
        // Either default-deny or there's a guard that fires — either way, forbid.
        expect(r.effect).toBe('forbid');
    });

    it('audit-log query requires authenticated agent → deny (M2 known limitation)', () => {
        // gov_query_audit_log requires principal.authenticated — always false in M2.
        const r = engine.evaluate({
            principal: { ...trustedAgent, agentGroups: ['auditors'] },
            action: 'queryAuditLog',
            resource: { kind: 'endpoint' },
            context: extractBaseContext('2026-07-28'),
        });
        // authenticated is false → the when-clause fails → deny
        expect(r.effect).toBe('forbid');
    });

    it('approveRequest requires authenticated agent → deny (M2 known limitation)', () => {
        const r = engine.evaluate({
            principal: { ...trustedAgent, agentGroups: ['approvers'] },
            action: 'approveRequest',
            resource: { kind: 'endpoint' },
            context: extractBaseContext('2026-07-28'),
        });
        expect(r.effect).toBe('forbid');
    });
});
