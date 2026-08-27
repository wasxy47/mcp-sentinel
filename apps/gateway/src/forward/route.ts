/**
 * Routing: turn an inbound request into a concrete upstream target, or refuse.
 *
 * This is the stage that decides *what* a request is addressed to. It performs no
 * I/O, so every refusal here is one Sentinel can make before touching an
 * upstream, and every one of them is a security decision:
 *
 *  - **Header/body re-assertion.** Sentinel reads `Mcp-Method` and `Mcp-Name` to
 *    route and (from M2) to decide policy without parsing the body. If a header
 *    could disagree with the body, that fast path would be a bypass primitive:
 *    show the gateway a benign `Mcp-Name`, send the body you actually want. So
 *    the invariant is re-asserted here, independently of the SDK's own inbound
 *    ladder. It costs one string compare.
 *
 *  - **A single "unknown" answer.** A name that does not parse, a server that is
 *    not configured, a server that is quarantined, a tool withheld for definition
 *    drift — all become the same `UnknownToolError`. Distinguishing them would
 *    hand an agent an enumeration oracle over the operator's configuration.
 *
 *  - **`tools/call` resolves only through the catalog.** Not by parsing the name
 *    and trusting the parts. The catalog is where drift-withholding, the
 *    allowlist, the DoS caps and duplicate refusal live; resolving around it
 *    would quietly undo all four. `resources/read` and `prompts/get` have no
 *    catalog behind them yet, so they resolve structurally — see `resolveTarget`.
 *
 *  - **Reserved `_meta` stripping.** `io.modelcontextprotocol/*` keys are the
 *    protocol's, not the agent's. See `stripReservedMeta`.
 *
 *  - **A size bound (T17).** Measured once, and the same canonical bytes become
 *    the digest the audit trail records.
 *
 * The outbound `Mcp-Method`/`Mcp-Name` are computed here too, and then *asserted*
 * against the rewritten body rather than merely attached — see
 * `expectedOutboundMetadata`.
 */

import {
    canonicalize,
    CanonicalizationError,
    MalformedParamsError,
    MCP_NAME_SOURCE_FIELD,
    MethodNotFoundError,
    RequestTooLargeError,
    UnknownToolError,
    assertHeaderMatchesBody,
    buildRequestMetadataHeaders,
    parseQualifiedPromptName,
    parseQualifiedResourceUri,
    readRequestMetadata,
    sha256Hex,
    stripReservedMeta,
    type CatalogEntry,
    type RequestMetadata
} from '@mcp-sentinel/mcp-core';

import type { ToolCatalog } from '../catalog/catalog.js';
import type { ForwardSettings } from '../config/schema.js';
import type { Logger } from '../observability/logger.js';
import type { UpstreamRegistry } from '../upstream/registry.js';

/** The methods this router forwards. Exactly the ones that carry an `Mcp-Name`. */
export const FORWARD_METHODS = Object.freeze(['tools/call', 'resources/read', 'prompts/get'] as const);

export type ForwardMethod = (typeof FORWARD_METHODS)[number];

/** The gateway answers this one itself, from aggregated upstream state. */
export const DISCOVER_METHOD = 'server/discover';

const FORWARD_METHOD_SET: ReadonlySet<string> = new Set<string>(FORWARD_METHODS);

export function isForwardMethod(method: string): method is ForwardMethod {
    return FORWARD_METHOD_SET.has(method);
}

/** Which of tool/resource/prompt a method addresses, for error text and logs. */
const TARGET_KIND: Readonly<Record<ForwardMethod, 'tool' | 'resource' | 'prompt'>> = Object.freeze({
    'tools/call': 'tool',
    'resources/read': 'resource',
    'prompts/get': 'prompt'
});

/** A request resolved to one upstream, ready to execute. */
export interface ForwardTarget {
    readonly method: ForwardMethod;
    readonly kind: 'tool' | 'resource' | 'prompt';
    readonly serverId: string;
    /** The name or URI the agent used, namespace and all. */
    readonly qualifiedName: string;
    /** The name or URI the upstream knows, prefix stripped. */
    readonly upstreamName: string;
    /** Params to send upstream: name rewritten, reserved `_meta` removed. */
    readonly params: Readonly<Record<string, unknown>>;
    /** Present for `tools/call` only; carries the digested definition. */
    readonly entry: CatalogEntry | undefined;
    /**
     * SHA-256 over the canonical form of the inbound params, exactly as the agent
     * sent them — before the name was rewritten and before anything was
     * stripped. That is what makes it evidence: the audit trail records what was
     * asked for, not what Sentinel decided to forward.
     *
     * `_meta` is included, deliberately. It is part of what the agent sent, and
     * faithfulness is the point. A consumer that needs a digest stable across
     * repeated identical calls — a risk-score cache key, say — must derive its
     * own over the semantic payload, because `_meta` carries per-call values like
     * `progressToken`.
     */
    readonly argsDigest: string;
    /** Byte length of those same canonical bytes, measured once. */
    readonly paramsBytes: number;
    /** Reserved `_meta` keys the agent tried to set. Empty in the normal case. */
    readonly strippedMetaKeys: readonly string[];
    /**
     * The `Mcp-Method`/`Mcp-Name` this request must present upstream.
     *
     * Not attached to the outbound request, and that is not an oversight. The
     * SDK's Streamable HTTP transport derives both headers from the message body
     * it is about to send, and refuses a per-request override of either. So the
     * recomputation the spec requires after a name rewrite happens by
     * construction — there is no code path in which Sentinel rewrites
     * `params.name` and forgets the header.
     *
     * What is left worth doing is checking it. These are computed from the
     * rewritten name and then asserted against the rewritten body with the same
     * `assertHeaderMatchesBody` used on the inbound edge. A rewrite that broke
     * the invariant is caught here, at Sentinel's own boundary, instead of
     * arriving as a -32020 from the upstream. They are exposed rather than
     * discarded because the audit trail should be able to record exactly what was
     * asserted, and because a stdio upstream has no headers to inspect after the
     * fact.
     */
    readonly expectedOutboundMetadata: Readonly<Record<string, string>>;
}

export type Route =
    | { readonly kind: 'forward'; readonly target: ForwardTarget }
    | { readonly kind: 'discover' };

/** The parsed JSON-RPC request, before Sentinel trusts any of it. */
export interface InboundRequest {
    readonly method?: unknown;
    readonly params?: unknown;
}

export interface ForwardRouterDeps {
    readonly catalog: ToolCatalog;
    readonly registry: UpstreamRegistry;
    readonly settings: ForwardSettings;
    readonly logger: Logger;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export class ForwardRouter {
    private readonly catalog: ToolCatalog;
    private readonly registry: UpstreamRegistry;
    private readonly settings: ForwardSettings;
    private readonly logger: Logger;

    public constructor(deps: ForwardRouterDeps) {
        this.catalog = deps.catalog;
        this.registry = deps.registry;
        this.settings = deps.settings;
        this.logger = deps.logger;
    }

    /**
     * Resolve one request.
     *
     * @throws {HeaderMismatchError} headers disagree with the body (HTTP 400).
     * @throws {MethodNotFoundError} not a method this router handles (HTTP 404).
     * @throws {RequestTooLargeError} params exceed the configured bound.
     * @throws {UnknownToolError} nothing this gateway serves answers to that name.
     */
    public route(metadata: RequestMetadata, request: InboundRequest): Route {
        // Params first, because the consistency check needs to read a field out of
        // them. A non-object `params` is passed along as `undefined` rather than
        // rejected here: for the methods that require a name, the check below fails
        // with the precise reason, and for `server/discover` there is nothing to
        // require.
        const params = isPlainObject(request.params) ? request.params : undefined;
        const method = assertHeaderMatchesBody(metadata, { method: request.method, params });

        if (method === DISCOVER_METHOD) return { kind: 'discover' };
        if (!isForwardMethod(method)) {
            // Not a bug and not an attack: M1.4's `Server` serves `tools/list`,
            // `tasks/*` and the rest itself and only routes the forwardable methods
            // here. Anything else reaching this point genuinely has no handler.
            throw new MethodNotFoundError(method);
        }

        const sourceField = MCP_NAME_SOURCE_FIELD[method];
        if (params === undefined || sourceField === undefined) {
            // Unreachable. Every forwardable method defines an `Mcp-Name` source
            // field and requires a string there, both of which the assertion above
            // has already demanded — this is the type system catching up.
            throw new MalformedParamsError(`${method} requires a name`);
        }

        const measured = this.measure(method, params);
        const kind = TARGET_KIND[method];
        const qualifiedName = params[sourceField] as string;

        const resolved = this.resolveTarget(method, kind, qualifiedName);
        const stripped = stripReservedMeta(params['_meta']);

        if (stripped.stripped.length > 0) {
            // Worth a warning rather than a debug line: a well-behaved agent has no
            // reason to set a protocol-reserved key, so this is either a broken
            // client or an attempt to impersonate one.
            this.logger.warn('stripped protocol-reserved _meta keys from a forwarded request', {
                serverId: resolved.serverId,
                method,
                keys: [...stripped.stripped]
            });
        }

        const forwardedParams: Record<string, unknown> = { ...params };
        forwardedParams[sourceField] = resolved.upstreamName;
        if (stripped.meta === undefined) delete forwardedParams['_meta'];
        else forwardedParams['_meta'] = stripped.meta;

        const expectedOutboundMetadata = buildRequestMetadataHeaders(method, resolved.upstreamName);
        // The invariant, checked rather than assumed. `new Headers` then
        // `readRequestMetadata` deliberately goes the long way round: it exercises
        // the real encode/decode path, including the base64 sentinel that a resource
        // URI with non-header-safe bytes takes. A throw here means Sentinel built a
        // request it knows the upstream must reject — refusing is the right
        // direction for that kind of bug.
        assertHeaderMatchesBody(readRequestMetadata(new Headers(expectedOutboundMetadata)), {
            method,
            params: forwardedParams
        });

        return {
            kind: 'forward',
            target: {
                method,
                kind,
                serverId: resolved.serverId,
                qualifiedName,
                upstreamName: resolved.upstreamName,
                params: forwardedParams,
                entry: resolved.entry,
                argsDigest: measured.digest,
                paramsBytes: measured.bytes,
                strippedMetaKeys: stripped.stripped,
                expectedOutboundMetadata
            }
        };
    }

    /**
     * Canonicalise the inbound params once, then derive the bound check and the
     * digest from the same bytes — the trick the catalog uses on tool definitions,
     * for the same reason: `digestOf` would serialise a second time for no gain.
     *
     * Measured before resolution so an oversized payload is refused without a
     * catalog lookup, and measured over the params as received so the digest is
     * evidence of the request rather than of Sentinel's rewrite of it.
     */
    private measure(method: ForwardMethod, params: Record<string, unknown>): { digest: string; bytes: number } {
        let canonical: string;
        try {
            canonical = canonicalize(params);
        } catch (cause) {
            // Unreachable for a body that arrived as JSON — JSON cannot express the
            // values canonicalisation rejects. Handled anyway, because a request
            // that cannot be digested cannot be audited, and forwarding a call that
            // will leave no evidence is the thing to avoid.
            const detail = cause instanceof CanonicalizationError ? cause.message : 'not canonicalisable';
            this.logger.warn('refusing a request whose params cannot be digested', { method, detail });
            throw new MalformedParamsError('params could not be canonicalised for auditing');
        }

        const bytes = Buffer.byteLength(canonical, 'utf8');
        if (bytes > this.settings.maxArgumentBytes) {
            this.logger.warn('refusing oversized request params', {
                method,
                bytes,
                limit: this.settings.maxArgumentBytes
            });
            throw new RequestTooLargeError('request params', bytes, this.settings.maxArgumentBytes);
        }

        return { digest: sha256Hex(canonical), bytes };
    }

    /**
     * Map a qualified name onto a server and the name that server knows.
     *
     * `tools/call` goes through the catalog and nothing else. `resources/read` and
     * `prompts/get` are resolved structurally — parse the qualified form, require
     * the owning server to be configured and dialable — because there is no
     * catalog of resources or prompts to consult: Sentinel does not aggregate
     * their listings until M1.4, and even then the upstream stays authoritative
     * for whether a given URI exists. Making up a local answer would mean
     * refusing resources that do exist. The upstream's own "not found" is the
     * honest answer, and it arrives through the forward path.
     */
    private resolveTarget(
        method: ForwardMethod,
        kind: 'tool' | 'resource' | 'prompt',
        qualifiedName: string
    ): { serverId: string; upstreamName: string; entry: CatalogEntry | undefined } {
        if (method === 'tools/call') {
            const entry = this.catalog.get(qualifiedName);
            if (entry === undefined) {
                this.logger.debug('rejecting a call for a tool not in the catalog', { qualifiedName });
                throw new UnknownToolError(qualifiedName, kind);
            }
            this.requireDialable(entry.serverId, qualifiedName, kind);
            return { serverId: entry.serverId, upstreamName: entry.toolName, entry };
        }

        if (method === 'resources/read') {
            const uriBytes = Buffer.byteLength(qualifiedName, 'utf8');
            if (uriBytes > this.settings.maxResourceUriBytes) {
                throw new RequestTooLargeError('resource uri', uriBytes, this.settings.maxResourceUriBytes);
            }
            const parsed = parseQualifiedResourceUri(qualifiedName);
            if (parsed === undefined) throw new UnknownToolError(qualifiedName, kind);
            this.requireDialable(parsed.serverId, qualifiedName, kind);
            return { serverId: parsed.serverId, upstreamName: parsed.uri, entry: undefined };
        }

        const parsed = parseQualifiedPromptName(qualifiedName);
        if (parsed === undefined) throw new UnknownToolError(qualifiedName, kind);
        this.requireDialable(parsed.serverId, qualifiedName, kind);
        return { serverId: parsed.serverId, upstreamName: parsed.promptName, entry: undefined };
    }

    /**
     * Refuse anything addressed to a server that is absent, disabled or
     * quarantined — as "unknown", not as "unavailable".
     *
     * The distinction is deliberate. Absence by *configuration* is
     * indistinguishable, to an agent, from a server that was never configured;
     * saying so would let it map the operator's setup. Absence by *runtime
     * failure* is a fact about the world and is reported honestly, but that
     * happens later, from the forward attempt itself.
     *
     * Checked for `tools/call` too, even though the catalog only lists dialable
     * servers: a server quarantined *after* the last refresh is still in the
     * catalog, and the connection layer would otherwise refuse it as
     * `UpstreamUnavailable` — leaking the same distinction one layer down.
     */
    private requireDialable(serverId: string, qualifiedName: string, kind: 'tool' | 'resource' | 'prompt'): void {
        const client = this.registry.get(serverId);
        if (client !== undefined && client.dialable) return;
        this.logger.debug('rejecting a request for a server that is not dialable', {
            serverId,
            configured: client !== undefined
        });
        throw new UnknownToolError(qualifiedName, kind);
    }
}
