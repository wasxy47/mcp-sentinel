/**
 * Cedar entity builder.
 *
 * Translates Sentinel's internal request model into the flat array of Cedar
 * entity records that `isAuthorized()` needs. Every Cedar entity is a JSON
 * object with `uid`, `attrs`, and `parents`.
 *
 * ## Entity model (mirrors schema.cedarschema)
 *
 * ```
 * Principal   Sentinel::Agent          (in AgentGroup)
 * Resource    Sentinel::Tool           (in ToolGroup)
 *             Sentinel::McpResource
 *             Sentinel::Prompt
 *             Sentinel::Endpoint       (singleton)
 * Related     Sentinel::Server         (referenced by Tool, McpResource, Prompt)
 *             Sentinel::ToolGroup      (for group-level policies)
 *             Sentinel::AgentGroup     (for group-level policies)
 * ```
 *
 * ## M2 note on `authenticated`
 *
 * Every `Agent` is built with `authenticated: false` in M2. Agent
 * authentication (JWT/mTLS) is out of scope; the schema field exists for when
 * it arrives. Policies that require `principal.authenticated` (e.g.
 * `gov_query_audit_log`) will deny all callers until a real auth layer is
 * added — this is the correct safe default. See PROGRESS.md for the known
 * limitation note.
 */

import type { AgentIdentity, CatalogEntry, ServerTrust } from '@mcp-sentinel/mcp-core';

// ── Public API types ──────────────────────────────────────────────────────────

/** What kind of MCP resource the request targets. */
export type ResourceKind = 'tool' | 'mcp-resource' | 'prompt' | 'endpoint';

/** Describes the principal making the request. */
export interface AgentPrincipal {
    readonly id: string;
    readonly trustTier: 'trusted' | 'standard' | 'untrusted';
    readonly authenticated: boolean;
    readonly clientName: string;
    readonly agentGroups: readonly string[];
}

/** Describes the resource being accessed. */
export type PolicyResource =
    | {
          readonly kind: 'tool';
          readonly qualifiedName: string;
          readonly toolName: string;
          readonly serverId: string;
          readonly serverTrust: ServerTrust;
          readonly serverScanVerdict: string;
          readonly toolScanVerdict: string;
          readonly definitionDrifted: boolean;
          readonly toolGroups: readonly string[];
      }
    | {
          readonly kind: 'mcp-resource';
          readonly qualifiedUri: string;
          readonly rawUri: string;
          readonly serverId: string;
          readonly serverTrust: ServerTrust;
          readonly serverScanVerdict: string;
          readonly scheme: string;
      }
    | {
          readonly kind: 'prompt';
          readonly qualifiedName: string;
          readonly promptName: string;
          readonly serverId: string;
          readonly serverTrust: ServerTrust;
          readonly serverScanVerdict: string;
          readonly promptScanVerdict: string;
      }
    | {
          readonly kind: 'endpoint';
      };

// Cedar entity wire type (what isAuthorized() expects).
interface CedarEntity {
    uid: { type: string; id: string };
    attrs: Record<string, unknown>;
    parents: Array<{ type: string; id: string }>;
}

/**
 * Build the Cedar entity array for a single authorization request.
 *
 * @param principal  The agent making the request.
 * @param resource   The resource being accessed.
 */
export function buildEntities(
    principal: AgentPrincipal,
    resource: PolicyResource,
): CedarEntity[] {
    const entities: CedarEntity[] = [];

    // ── Agent ─────────────────────────────────────────────────────────────────
    const agentGroupParents = principal.agentGroups.map(g => ({
        type: 'Sentinel::AgentGroup',
        id: g,
    }));

    entities.push({
        uid: { type: 'Sentinel::Agent', id: principal.id },
        attrs: {
            trustTier: principal.trustTier,
            authenticated: principal.authenticated,
            clientName: principal.clientName,
        },
        parents: agentGroupParents,
    });

    // Agent groups (Cedar requires referenced entities to exist).
    for (const g of principal.agentGroups) {
        entities.push({
            uid: { type: 'Sentinel::AgentGroup', id: g },
            attrs: {},
            parents: [],
        });
    }

    // ── Resource ──────────────────────────────────────────────────────────────
    switch (resource.kind) {
        case 'tool': {
            // Server entity
            entities.push(makeServer(resource.serverId, resource.serverTrust, resource.serverScanVerdict));

            // ToolGroup entities + Tool parents
            const toolGroupParents = resource.toolGroups.map(g => ({
                type: 'Sentinel::ToolGroup',
                id: g,
            }));
            for (const g of resource.toolGroups) {
                entities.push({
                    uid: { type: 'Sentinel::ToolGroup', id: g },
                    attrs: {},
                    parents: [],
                });
            }

            entities.push({
                uid: { type: 'Sentinel::Tool', id: resource.qualifiedName },
                attrs: {
                    qualifiedName: resource.qualifiedName,
                    toolName: resource.toolName,
                    server: { __entity: { type: 'Sentinel::Server', id: resource.serverId } },
                    scanVerdict: resource.toolScanVerdict,
                    definitionDrifted: resource.definitionDrifted,
                },
                parents: toolGroupParents,
            });
            break;
        }

        case 'mcp-resource': {
            entities.push(makeServer(resource.serverId, resource.serverTrust, resource.serverScanVerdict));

            entities.push({
                uid: { type: 'Sentinel::McpResource', id: resource.qualifiedUri },
                attrs: {
                    uri: resource.rawUri,
                    server: { __entity: { type: 'Sentinel::Server', id: resource.serverId } },
                    scheme: resource.scheme,
                },
                parents: [],
            });
            break;
        }

        case 'prompt': {
            entities.push(makeServer(resource.serverId, resource.serverTrust, resource.serverScanVerdict));

            entities.push({
                uid: { type: 'Sentinel::Prompt', id: resource.qualifiedName },
                attrs: {
                    qualifiedName: resource.qualifiedName,
                    server: { __entity: { type: 'Sentinel::Server', id: resource.serverId } },
                    scanVerdict: resource.promptScanVerdict,
                },
                parents: [],
            });
            break;
        }

        case 'endpoint': {
            entities.push({
                uid: { type: 'Sentinel::Endpoint', id: 'gateway' },
                attrs: {},
                parents: [],
            });
            break;
        }
    }

    return entities;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeServer(
    serverId: string,
    trust: ServerTrust,
    scanVerdict: string,
): CedarEntity {
    return {
        uid: { type: 'Sentinel::Server', id: serverId },
        attrs: {
            serverId,
            trust,
            scanVerdict,
        },
        parents: [],
    };
}

/**
 * Derive an `AgentPrincipal` from a gateway `AgentIdentity`.
 * In M2, `authenticated` is always overridden to `false`.
 */
export function agentPrincipalFromIdentity(
    identity: AgentIdentity,
    agentGroups: readonly string[] = [],
): AgentPrincipal {
    return {
        id: identity.id,
        trustTier: identity.trustTier,
        authenticated: identity.authenticated,
        clientName: identity.name ?? 'unknown',
        agentGroups,
    };
}

/**
 * Derive a `PolicyResource` for a tool call from the catalog entry.
 *
 * @param entry         The catalog entry for the qualified tool name.
 * @param toolGroups    Map of group name → list of qualified tool names.
 * @param serverTrust   Operator-declared trust for the upstream server.
 */
export function toolResource(
    entry: CatalogEntry,
    toolGroups: Record<string, string[]>,
    serverTrust: ServerTrust,
): Extract<PolicyResource, { kind: 'tool' }> {
    // Find which groups this tool belongs to.
    const groups = Object.entries(toolGroups)
        .filter(([, members]) => members.includes(entry.qualifiedName))
        .map(([g]) => g);

    return {
        kind: 'tool',
        qualifiedName: entry.qualifiedName,
        toolName: entry.toolName,
        serverId: entry.serverId,
        serverTrust,
        serverScanVerdict: entry.scan?.verdict ?? 'clean',
        toolScanVerdict: entry.scan?.verdict ?? 'clean',
        definitionDrifted: false, // TODO: wire from catalog digest comparison (M6)
        toolGroups: groups,
    };
}
