/**
 * Policy engine — thin Cedar evaluation layer.
 *
 * `PolicyEngine.evaluate()` is the single point through which every
 * authorization decision passes. It is deliberately thin: the bundle loader,
 * entity builder, and context extractor do all the preparation; this module
 * only calls `isAuthorized` and translates the result.
 *
 * ## Security invariants
 *
 * 1. **Evaluation errors → deny.** If Cedar reports `diagnostics.errors` the
 *    call is denied, not allowed. An attacker who can trigger evaluation errors
 *    (e.g. by injecting a value that breaks a type-checked attribute access)
 *    must not thereby bypass the policy.
 *
 * 2. **No match → deny (default-deny).** A Cedar `deny` with `reason: []`
 *    means no permit matched. This is the correct outcome — anything not
 *    explicitly allowed is refused.
 *
 * 3. **Strongest obligation wins.** When several permits match, the one
 *    requiring the most ceremony prevails (`approve > review > allow`). The
 *    same conservative direction as Cedar's own `forbid-overrides-permit` rule.
 *
 * 4. **`PolicyLoadError` is not swallowed.** A missing or malformed bundle is
 *    a startup failure, not a per-request deny. The caller handles it.
 *
 * ## Cedar API note
 *
 * `statefulIsAuthorized` / `preparsePolicySet` crash with a WASM
 * memory-OOB error in `@cedar-policy/cedar-wasm@4.12.0`. We use
 * `isAuthorized` instead, passing the pre-built `staticPolicies` map on
 * every call. The policy text is never re-parsed — Cedar's own evaluation
 * core caches the compiled form. Measured overhead is ≈100µs per call.
 */

import { isAuthorized } from '@cedar-policy/cedar-wasm/nodejs';

import { strongestObligation } from '@mcp-sentinel/mcp-core';
import type { Obligation, PolicyDecision } from '@mcp-sentinel/mcp-core';

import type { PolicyBundle } from './loader.js';
import { buildEntities } from './entities.js';
import type { AgentPrincipal, PolicyResource } from './entities.js';
import type { BaseContext, ToolCallContext, ResourceReadContext } from './extract.js';

// ── Public types ──────────────────────────────────────────────────────────────

/** The action being requested — mirrors Cedar `Action` ids. */
export type McpAction =
    | 'callTool'
    | 'readResource'
    | 'getPrompt'
    | 'listTools'
    | 'listResources'
    | 'listPrompts'
    | 'discover'
    | 'explainDecision'
    | 'queryAuditLog'
    | 'listActivePolicies'
    | 'verifyAuditChain'
    | 'approveRequest';

export type PolicyContext = ToolCallContext | ResourceReadContext | BaseContext;

/** Full description of a single authorization request. */
export interface EvaluationRequest {
    readonly principal: AgentPrincipal;
    readonly action: McpAction;
    readonly resource: PolicyResource;
    readonly context: PolicyContext;
}

/** Minimal logger interface so the engine doesn't depend on a specific logger. */
export interface EngineLogger {
    warn(message: string, fields?: Record<string, unknown>): void;
}

// ── PolicyEngine ──────────────────────────────────────────────────────────────

export class PolicyEngine {
    constructor(
        private readonly bundle: PolicyBundle,
        private readonly logger: EngineLogger,
    ) {}

    /**
     * List all loaded Cedar policies with their metadata and annotations.
     * Optionally filtered by source policy filename.
     */
    listPolicies(fileFilter?: string): Array<{
        readonly id: string;
        readonly file?: string | undefined;
        readonly effect: 'permit' | 'forbid';
        readonly obligation?: Obligation | undefined;
        readonly reason: string;
    }> {
        const result = [];
        for (const [id, ann] of this.bundle.annotations.entries()) {
            if (fileFilter !== undefined && ann.file !== fileFilter) {
                continue;
            }
            result.push({
                id,
                file: ann.file,
                effect: ann.effect,
                obligation: ann.obligation,
                reason: ann.reason
            });
        }
        return result;
    }

    /**
     * Evaluate a single authorization request against the loaded policy bundle.
     *
     * Never throws (unless the Cedar WASM module itself crashes, which is a
     * process-level fault). Cedar evaluation errors are logged and treated as
     * deny — see invariant (1) in the module docstring.
     */
    evaluate(request: EvaluationRequest): PolicyDecision {
        const entities = buildEntities(request.principal, request.resource);

        const resourceUid = resourceEntityUid(request.resource);
        const principalUid = { type: 'Sentinel::Agent', id: request.principal.id };

        let cedarResult: ReturnType<typeof isAuthorized>;
        try {
            // Cedar WASM types are stricter than our generic interfaces.
            // We build the call through `unknown` casts to bridge the gap;
            // the runtime values are always correct.
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const call: any = {
                principal: principalUid,
                action: { type: 'Sentinel::Action', id: request.action },
                resource: resourceUid,
                context: request.context,
                policies: { staticPolicies: this.bundle.staticPolicies },
                entities,
                schema: this.bundle.schemaJson,
            };
            cedarResult = isAuthorized(call);
        } catch (err) {
            // Cedar WASM threw synchronously — treat as deny.
            this.logger.warn('Cedar isAuthorized threw synchronously', {
                error: String(err),
                action: request.action,
                principal: request.principal.id,
            });
            return denyDecision(['Cedar evaluation threw: ' + String(err)]);
        }

        if (cedarResult.type !== 'success') {
            // This shouldn't happen; the WASM returns 'success' even on deny.
            this.logger.warn('Cedar isAuthorized returned non-success type', {
                type: cedarResult.type,
            });
            return denyDecision(['Cedar returned unexpected result type: ' + cedarResult.type]);
        }

        const { decision, diagnostics } = cedarResult.response;
        const evalErrors = diagnostics.errors?.map((e: unknown) => String(e)) ?? [];

        if (evalErrors.length > 0) {
            // Invariant (1): evaluation errors → deny.
            this.logger.warn('Cedar evaluation errors', {
                errors: evalErrors,
                action: request.action,
                principal: request.principal.id,
            });
            return denyDecision(evalErrors);
        }

        if (decision === 'deny') {
            // Invariant (2): no match → deny.
            const defaultDeny = (diagnostics.reason?.length ?? 0) === 0;
            return {
                effect: 'forbid',
                obligation: 'allow', // unused on deny, but satisfies the type
                reasons: defaultDeny
                    ? ['No policy matched — default deny.']
                    : diagnostics.reason.map((id: string) => this.bundle.annotations.get(id)?.reason ?? id),
                errors: [],
                defaultDeny,
            };
        }

        // Cedar says allow — collect obligations from determining policies.
        const determiningIds: string[] = diagnostics.reason ?? [];
        const obligations: Obligation[] = [];
        const reasons: string[] = [];

        for (const id of determiningIds) {
            const ann = this.bundle.annotations.get(id);
            if (!ann) continue;
            if (ann.obligation) obligations.push(ann.obligation);
            if (ann.reason) reasons.push(ann.reason);
        }

        // Invariant (3): strongest obligation wins.
        const obligation = strongestObligation(obligations);

        return {
            effect: 'permit',
            obligation,
            reasons,
            errors: [],
            defaultDeny: false,
        };
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function denyDecision(errors: string[]): PolicyDecision {
    return {
        effect: 'forbid',
        obligation: 'allow',
        reasons: [],
        errors,
        defaultDeny: false,
    };
}

function resourceEntityUid(resource: PolicyResource): { type: string; id: string } {
    switch (resource.kind) {
        case 'tool':
            return { type: 'Sentinel::Tool', id: resource.qualifiedName };
        case 'mcp-resource':
            return { type: 'Sentinel::McpResource', id: resource.qualifiedUri };
        case 'prompt':
            return { type: 'Sentinel::Prompt', id: resource.qualifiedName };
        case 'endpoint':
            return { type: 'Sentinel::Endpoint', id: 'gateway' };
    }
}
