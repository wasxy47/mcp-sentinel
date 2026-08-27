/**
 * `server/discover`: what the gateway tells an agent it is.
 *
 * On 2026-07-28 there is no `initialize` handshake, so this is the only place an
 * agent learns what it is talking to. It is also the smallest surface in the
 * gateway with the most room to lie by accident, so the rules here are narrow:
 *
 *  - **Advertise what *Sentinel* can serve, not what upstreams support.** The two
 *    differ. A capability is a promise about the gateway's own handlers, and a
 *    promise Sentinel cannot keep is worse than a missing capability: the agent
 *    stops probing and starts depending. So `resources` and `prompts` appear only
 *    when some dialable upstream actually has them, and sub-flags — `subscribe`,
 *    `listChanged` — stay off until Sentinel implements the machinery behind
 *    them, whatever the upstreams say.
 *
 *  - **No upstream-authored text.** An upstream's `instructions` field is prose a
 *    possibly-hostile server wrote, and `server/discover` is the one response an
 *    agent reads *before* it has any reason to be suspicious — the ideal
 *    placement for a prompt injection. Sentinel's `instructions` is a fixed
 *    string written here. Upstream instructions are not aggregated, now or later.
 *
 *  - **No topology.** Which servers are configured, how many, whether one is
 *    unhealthy: all useful to an operator, all a map of the deployment to
 *    anything else. That belongs to the dashboard (M8) and the audit trail, both
 *    of which the operator reaches directly. The one thing the agent does learn is
 *    the namespacing convention, because it needs it to form a request at all.
 */

import { SENTINEL_PROTOCOL_VERSION, NAMESPACE_SEPARATOR, RESOURCE_URI_SCHEME } from '@mcp-sentinel/mcp-core';
import type { DiscoverResult, Implementation, ServerCapabilities } from '@modelcontextprotocol/client';

import type { UpstreamSnapshot } from '../upstream/client.js';

export interface DiscoverDeps {
    /** Identity the gateway reports downstream. Same shape it reports upstream. */
    readonly serverInfo: Implementation;
    /** Snapshots of every configured upstream, from `UpstreamRegistry.snapshots()`. */
    readonly snapshots: readonly UpstreamSnapshot[];
}

/**
 * Aggregate upstream capabilities into the gateway's own.
 *
 * Read from `UpstreamSnapshot.capabilities` rather than from the SDK's
 * `getDiscoverResult()`, which is only populated on a modern Streamable HTTP
 * connection — a stdio upstream, or a legacy one, has capabilities but no
 * discover result, and reading the wrong one would make every such server look
 * capability-less.
 *
 * Only *dialable, connected* upstreams count. A quarantined server's tools are
 * not in the catalog, so advertising a capability on its behalf would promise a
 * surface with nothing behind it. A server that has not connected yet has not
 * told us anything, and guessing is how you end up promising `resources` to an
 * agent that will only ever get "unknown resource" back.
 *
 * `tools` is unconditional: the gateway has its own toolset (M7) and answers
 * `tools/list` whether or not any upstream is reachable. An empty list is a
 * truthful answer; a missing `tools` capability would not be.
 */
export function aggregateCapabilities(snapshots: readonly UpstreamSnapshot[]): ServerCapabilities {
    let resources = false;
    let prompts = false;

    for (const snapshot of snapshots) {
        if (snapshot.health !== 'ready') continue;
        const capabilities = snapshot.capabilities;
        if (capabilities === undefined) continue;
        if (capabilities.resources !== undefined) resources = true;
        if (capabilities.prompts !== undefined) prompts = true;
    }

    // Empty objects, not `{ listChanged: true }`. Sentinel does not yet emit
    // `notifications/*/list_changed`, and a capability flag is a commitment to
    // behaviour, not a description of an upstream's.
    return {
        tools: {},
        ...(resources ? { resources: {} } : {}),
        ...(prompts ? { prompts: {} } : {})
    };
}

/**
 * The instructions Sentinel sends to agents.
 *
 * Two things worth an agent's context budget: how to address a namespaced
 * tool or resource — without which it cannot form a valid request — and that
 * calls are mediated, so a denial is a decision rather than a malfunction.
 * Everything else an agent can discover by asking.
 */
export function gatewayInstructions(instanceName: string): string {
    return (
        `${instanceName} is a security gateway in front of one or more MCP servers. ` +
        `Tools and prompts are namespaced as "<serverId>${NAMESPACE_SEPARATOR}<name>"; ` +
        `resources as "${RESOURCE_URI_SCHEME}://<serverId>/<percent-encoded upstream uri>". ` +
        'Every call is evaluated against policy before it reaches an upstream server, so a ' +
        'call may be denied or held for human approval. A denial is a decision, not an error ' +
        'to retry: read it and choose a different action.'
    );
}

/** Build the gateway's `server/discover` response. */
export function buildDiscoverResult(deps: DiscoverDeps): DiscoverResult {
    return {
        // One entry. Sentinel implements exactly one revision downstream; listing
        // a version it does not serve would be an invitation to a request it must
        // then reject. Upstream era negotiation is a separate, per-server matter —
        // an agent talking to the gateway is talking 2026-07-28 regardless of what
        // sits behind it.
        supportedVersions: [SENTINEL_PROTOCOL_VERSION],
        capabilities: aggregateCapabilities(deps.snapshots),
        instructions: gatewayInstructions(deps.serverInfo.name),
        _meta: {
            'io.modelcontextprotocol/serverInfo': deps.serverInfo
        }
    };
}
