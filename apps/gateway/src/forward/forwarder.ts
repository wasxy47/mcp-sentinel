/**
 * Execution: send a routed request to its upstream and hand the answer back.
 *
 * Everything about *whether* the call may happen has already been decided by the
 * router (and, from M2, by policy). What is left is doing it faithfully, and the
 * interesting decisions are all about faithfulness:
 *
 *  - **The SDK's typed verbs, not a raw `request`.** `callTool`, `readResource`
 *    and `getPrompt` carry behaviour a raw JSON-RPC passthrough would forfeit:
 *    result-schema validation, SEP-2243 `Mcp-Param-*` header mirroring on a
 *    2026-07-28 Streamable HTTP connection, and — for `callTool` given a
 *    `toolDefinition` — output-schema validation against the same definition the
 *    catalog digested. A gateway that skipped those would be a weaker link than
 *    the client it replaced.
 *
 *  - **Upstream errors belong to the agent.** A tool that failed, a resource that
 *    does not exist: those are answers, and they are relayed. `UpstreamClient`
 *    converts only transport failures. Nothing here rewrites an upstream's
 *    result — the redaction and injection scanning that will happen to it are
 *    M6's, and they are additive to this path, not a replacement for it.
 *
 *  - **An upstream's questions are never answered by Sentinel.** See `forward`.
 *
 *  - **The result is bounded and digested (T17).** One canonicalisation, two
 *    uses.
 */

import {
    isInputRequiredResult,
    type CallToolRequestOptions,
    type CallToolRequestParams,
    type CallToolResult,
    type Client,
    type GetPromptRequestParams,
    type GetPromptResult,
    type InputRequiredResult,
    type ReadResourceRequestParams,
    type ReadResourceResult,
    type RequestOptions
} from '@modelcontextprotocol/client';

import {
    canonicalize,
    CanonicalizationError,
    sha256Hex,
    UnknownToolError,
    UpstreamUnavailableError
} from '@mcp-sentinel/mcp-core';

import type { ForwardSettings } from '../config/schema.js';
import { type Logger } from '../observability/logger.js';
import type { UpstreamRegistry } from '../upstream/registry.js';
import type { ForwardMethod, ForwardTarget } from './route.js';

/**
 * What an upstream can answer with.
 *
 * `InputRequiredResult` is in the union because Sentinel asks for it — see
 * `forward` — so callers must handle it rather than assume a finished result.
 */
export type ForwardedResult = CallToolResult | ReadResourceResult | GetPromptResult | InputRequiredResult;

export interface ForwardOutcome {
    readonly target: ForwardTarget;
    readonly result: ForwardedResult;
    /**
     * True when the upstream answered `input_required` rather than with a result.
     * The call is not finished; see `forward` for what the agent must do next and
     * for the leg Sentinel cannot yet carry.
     */
    readonly inputRequired: boolean;
    /** SHA-256 over the canonical form of the result, for the audit trail (M3). */
    readonly resultDigest: string;
    readonly resultBytes: number;
    /** Time spent in the upstream call, measured at this boundary. */
    readonly latencyMs: number;
}

export interface ForwarderDeps {
    readonly registry: UpstreamRegistry;
    readonly settings: ForwardSettings;
    readonly logger: Logger;
    /** Injectable clock. Tests must not depend on wall time. */
    readonly now?: () => number;
}

/** Capability an upstream must declare before a method may be sent to it. */
const REQUIRED_CAPABILITY: Readonly<Record<ForwardMethod, 'tools' | 'resources' | 'prompts'>> = Object.freeze({
    'tools/call': 'tools',
    'resources/read': 'resources',
    'prompts/get': 'prompts'
});

export class Forwarder {
    private readonly registry: UpstreamRegistry;
    private readonly settings: ForwardSettings;
    private readonly logger: Logger;
    private readonly now: () => number;

    public constructor(deps: ForwarderDeps) {
        this.registry = deps.registry;
        this.settings = deps.settings;
        this.logger = deps.logger;
        this.now = deps.now ?? (() => Date.now());
    }

    /**
     * Send a routed request upstream.
     *
     * `allowInputRequired: true` on every verb is a deliberate posture. Without
     * it, an upstream that needs elicitation or sampling mid-call would have the
     * SDK's client try to satisfy it — and the only authority that client holds is
     * *Sentinel's*, which is to say the union of every agent's. A gateway that
     * answers an upstream's questions on the agent's behalf has silently become
     * the principal. With the flag set, the `input_required` result is handed back
     * instead, for the agent's own client to fulfil under the agent's (and its
     * human's) authority.
     *
     * What actually happens today is narrower and stricter than that, and worth
     * recording because it is easy to misread the flag as the thing doing the work.
     * Sentinel's upstream `Client` declares **no** client capabilities at all — no
     * `elicitation`, `sampling` or `roots`. The SDK's server seam checks an
     * outbound input request against the requester's declared capabilities and
     * refuses to emit one it cannot answer, so an upstream that tries gets
     * `MissingRequiredClientCapabilityError` and the question never reaches
     * Sentinel. `allowInputRequired: true` is therefore defence in depth: it is
     * what makes the posture hold if a capability is ever declared.
     *
     * Which it should not be, without the retry relay. The spec reserves
     * `inputResponses` and `requestState` on client-initiated requests, and the SDK
     * lifts both out of request params before any handler sees them — verified in
     * both directions: re-sending them on an outbound `callTool` delivers only
     * `{ name, arguments }` to the upstream. So declaring a capability without also
     * threading the retry leg through would not degrade gracefully; the upstream
     * would re-ask the identical question forever. A livelock is worse than a
     * refusal, and the refusal is what happens now.
     *
     * The relay itself waits on M1.4, where the low-level `Server` exposes the
     * lifted values on `ctx.mcpReq` and there is somewhere to put them.
     *
     * @throws {UnknownToolError} the upstream never advertised the capability.
     * @throws {UpstreamUnavailableError} transport failure, or an unusable result.
     */
    public async forward(target: ForwardTarget, signal?: AbortSignal): Promise<ForwardOutcome> {
        const client = this.registry.require(target.serverId);
        const started = this.now();

        const raw: unknown = await client.call(
            target.method,
            async (sdk, options) => this.invoke(sdk, options, target),
            signal
        );

        const latencyMs = this.now() - started;
        const inputRequired = isInputRequiredResult(raw);
        const measured = this.measureResult(target, raw);

        this.logger.debug('forwarded request completed', {
            serverId: target.serverId,
            method: target.method,
            qualifiedName: target.qualifiedName,
            latencyMs,
            resultBytes: measured.bytes,
            inputRequired
        });

        return {
            target,
            result: raw as ForwardedResult,
            inputRequired,
            resultDigest: measured.digest,
            resultBytes: measured.bytes,
            latencyMs
        };
    }

    /**
     * Dispatch to the typed verb for this method.
     *
     * Runs inside `UpstreamClient.call`, so the `Client` it receives is already
     * connected — which is what makes the capability gate possible here rather
     * than as a pre-check: `getServerCapabilities()` only has an answer after the
     * handshake.
     *
     * The params casts are structural. Sentinel forwards the agent's params
     * largely as it received them, which may include the spec-reserved
     * `inputResponses`/`requestState` fields; those are legal on the wire and the
     * SDK relays them, but they are typed on the inbound side, not on these
     * request-params types.
     */
    private async invoke(sdk: Client, options: RequestOptions, target: ForwardTarget): Promise<unknown> {
        this.requireCapability(sdk, target);
        const params = target.params as Record<string, unknown>;

        switch (target.method) {
            case 'tools/call': {
                const callOptions: CallToolRequestOptions = {
                    ...options,
                    allowInputRequired: true,
                    // The catalog's own definition, so the output-schema validation
                    // the SDK performs is against the bytes Sentinel digested — not
                    // against whatever the server would claim if asked again mid-call.
                    ...(target.entry === undefined ? {} : { toolDefinition: target.entry.definition })
                };
                return sdk.callTool(params as unknown as CallToolRequestParams, callOptions);
            }
            case 'resources/read':
                return sdk.readResource(params as unknown as ReadResourceRequestParams, {
                    ...options,
                    allowInputRequired: true,
                    // Never serve a resource read from the SDK's response cache. A
                    // cached body would make the audit row a lie — "we asked the
                    // upstream at this time" when we did not — and would keep
                    // serving content the upstream has since changed or withdrawn,
                    // which is precisely what a rug pull looks like from here.
                    //
                    // Not covered by a behavioural test, and deliberately not faked
                    // into one: no response-cache store is configured on these
                    // clients today, so a read with and without this flag are
                    // observably identical. A test asserting a difference would be
                    // asserting its own mock. It is here so that configuring a cache
                    // later — for `tools/list`, say — cannot silently start serving
                    // stale resource bodies through the audit trail.
                    cacheMode: 'bypass'
                });
            case 'prompts/get':
                return sdk.getPrompt(params as unknown as GetPromptRequestParams, {
                    ...options,
                    allowInputRequired: true
                });
        }
    }

    /**
     * Refuse a method the upstream never advertised support for.
     *
     * The SDK's client checks this too, and throws a raw
     * `SdkError(CapabilityNotSupported)` — which is neither a transport failure
     * nor a timeout, so `UpstreamClient.call` rethrows it untouched and it would
     * reach the agent as an opaque SDK error with an SDK error code. Checking here
     * first turns it into Sentinel's own vocabulary.
     *
     * Reported as `UnknownToolError`, not as a distinct "capability" error, for the
     * same reason every other absence is: a server with no `resources` capability
     * has no resources, so "unknown resource" is both true and uninformative to
     * someone mapping the deployment.
     *
     * `tools/call` is checked for symmetry but is effectively already guaranteed:
     * a tool only reaches the catalog by way of a successful `tools/list`.
     */
    private requireCapability(sdk: Client, target: ForwardTarget): void {
        const needed = REQUIRED_CAPABILITY[target.method];
        const capabilities = sdk.getServerCapabilities();
        if (capabilities?.[needed] !== undefined) return;

        this.logger.debug('upstream does not advertise the capability this request needs', {
            serverId: target.serverId,
            method: target.method,
            capability: needed
        });
        throw new UnknownToolError(target.qualifiedName, target.kind);
    }

    /**
     * Bound and digest the result — one canonicalisation, both uses.
     *
     * This is not a wire-level bound and does not pretend to be one: the bytes
     * have already arrived and been parsed by the time we can measure them. What
     * it stops is an oversized result propagating *onward* — into the agent's
     * context window, into an audit row, and into a risk-engine prompt. The
     * wire-level cap belongs to the transport (M1.4).
     */
    private measureResult(target: ForwardTarget, result: unknown): { digest: string; bytes: number } {
        let canonical: string;
        try {
            canonical = canonicalize(result);
        } catch (cause) {
            // Unreachable for a result that came off the wire as JSON. Treated as an
            // unusable response rather than passed on: a result Sentinel cannot
            // digest is a result it cannot record, and 'malformed response' is
            // already in `describeFailure`'s vocabulary for exactly this shape of
            // problem.
            this.logger.warn('upstream result could not be digested', {
                serverId: target.serverId,
                method: target.method,
                detail: cause instanceof CanonicalizationError ? cause.message : 'not canonicalisable'
            });
            throw new UpstreamUnavailableError(target.serverId, 'malformed response', { cause });
        }

        const bytes = Buffer.byteLength(canonical, 'utf8');
        if (bytes > this.settings.maxResultBytes) {
            this.logger.warn('refusing an oversized upstream result', {
                serverId: target.serverId,
                method: target.method,
                qualifiedName: target.qualifiedName,
                bytes,
                limit: this.settings.maxResultBytes
            });
            throw new UpstreamUnavailableError(target.serverId, 'response too large');
        }

        return { digest: sha256Hex(canonical), bytes };
    }
}
