/**
 * `@mcp-sentinel/policy-engine` — Cedar policy evaluation for MCP Sentinel.
 *
 * Public API surface:
 *
 * ```ts
 * import { loadBundle, PolicyEngine } from '@mcp-sentinel/policy-engine';
 *
 * const bundle = loadBundle(policyDir, schemaPath);
 * const engine = new PolicyEngine(bundle, logger);
 * const decision = engine.evaluate({ principal, action, resource, context });
 * ```
 */

export { loadBundle, reloadBundle, PolicyLoadError } from './loader.js';
export type { PolicyBundle, PolicyAnnotations } from './loader.js';

export {
    extractToolCallContext,
    extractResourceReadContext,
    extractBaseContext,
    hasInvisibleUnicode,
} from './extract.js';
export type {
    BaseContext,
    ToolCallContext,
    ResourceReadContext,
    SqlKind,
    ExtractConfig,
} from './extract.js';

export {
    buildEntities,
    agentPrincipalFromIdentity,
    toolResource,
} from './entities.js';
export type {
    AgentPrincipal,
    PolicyResource,
    ResourceKind,
} from './entities.js';

export { PolicyEngine } from './engine.js';
export type { McpAction, PolicyContext, EvaluationRequest, EngineLogger } from './engine.js';
