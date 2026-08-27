/**
 * Namespacing for everything the gateway exposes: tools, prompts, resources.
 *
 * Sentinel fronts several upstream MCP servers at one endpoint, so two servers
 * may legitimately both offer `read_file`. Presenting both under that bare name
 * would be ambiguous and — worse — is an attack: a malicious server that
 * declares a tool named identically to a trusted one can shadow it and harvest
 * the calls intended for the trusted server. See docs/threat-model.md § Tool
 * shadowing.
 *
 * Every proxied tool is therefore advertised as `<serverId>__<toolName>`.
 * Because a server id may not contain an underscore, splitting on the *first*
 * `__` is unambiguous even when the upstream tool name itself contains `__`.
 * Prompts use the same rule.
 *
 * Resource URIs cannot: `__` is not a legal prefix for a URI, and a bare
 * `resources/read` carries nothing but a `uri`. Two upstreams exposing
 * `file:///etc/hosts` would be indistinguishable, and the agent would have had
 * no way to say which one it meant. They are wrapped instead, as
 * `mcp-sentinel://<serverId>/<percent-encoded upstream URI>` — see
 * `qualifyResourceUri`. That is a disambiguation requirement first and a
 * shadowing defence second; both point the same way.
 */

/**
 * Separator between server id and tool name. Two underscores rather than `/`,
 * `:` or `.` because those are rejected by clients that constrain tool names to
 * `[a-zA-Z0-9_-]`, which many do.
 */
export const NAMESPACE_SEPARATOR = '__';

/**
 * Server id reserved for the gateway's own tools, so `sentinel__query_audit_log`
 * can never be claimed by an upstream server.
 */
export const SENTINEL_SERVER_ID = 'sentinel';

/**
 * Server ids are lowercase alphanumeric with dashes. Underscores are excluded
 * on purpose — that is what makes the first-`__` split unambiguous.
 */
const SERVER_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** MCP tool names in practice; also what most clients will accept. */
const TOOL_NAME_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

export class NamingError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'NamingError';
    }
}

/** True when `id` is a well-formed server id. */
export function isValidServerId(id: string): boolean {
    return SERVER_ID_PATTERN.test(id);
}

/** True when `name` is a plausible upstream tool name. */
export function isValidToolName(name: string): boolean {
    return TOOL_NAME_PATTERN.test(name);
}

/** Assert a server id is well-formed, with a message that says why it is not. */
export function assertValidServerId(id: string): void {
    if (!isValidServerId(id)) {
        throw new NamingError(
            `invalid server id '${id}': expected lowercase alphanumeric with dashes, ` +
                'no underscores (underscores are reserved for the namespace separator)'
        );
    }
}

/** Shared implementation for the tool and prompt joiners. */
function qualify(kind: 'tool' | 'prompt', serverId: string, name: string): string {
    assertValidServerId(serverId);
    if (!isValidToolName(name)) {
        throw new NamingError(`invalid ${kind} name '${name}' on server '${serverId}'`);
    }
    return `${serverId}${NAMESPACE_SEPARATOR}${name}`;
}

/** Combine a server id and an upstream tool name into the advertised name. */
export function qualifyToolName(serverId: string, toolName: string): string {
    return qualify('tool', serverId, toolName);
}

/** A parsed qualified tool name. */
export interface QualifiedToolName {
    readonly serverId: string;
    readonly toolName: string;
}

/**
 * Split an advertised name back into server id and upstream tool name.
 *
 * Returns `undefined` rather than throwing: an unparseable name is an ordinary
 * "unknown tool" condition driven by client input, not a programming error, and
 * the caller turns it into a JSON-RPC error with the right code.
 */
export function parseQualifiedToolName(qualified: string): QualifiedToolName | undefined {
    const index = qualified.indexOf(NAMESPACE_SEPARATOR);
    if (index <= 0) return undefined;

    const serverId = qualified.slice(0, index);
    const toolName = qualified.slice(index + NAMESPACE_SEPARATOR.length);
    if (!isValidServerId(serverId) || !isValidToolName(toolName)) return undefined;

    return { serverId, toolName };
}

/** True when the qualified name belongs to the gateway's own toolset. */
export function isSentinelToolName(qualified: string): boolean {
    return qualified.startsWith(`${SENTINEL_SERVER_ID}${NAMESPACE_SEPARATOR}`);
}

/**
 * Prompt names use the tool rule verbatim: `prompts/get` carries a `name`, the
 * same shape `tools/call` does, so the same `<serverId>__<name>` form and the
 * same first-`__` split apply. Kept as separate functions rather than aliases
 * because the error text should say which of the two the caller was building,
 * and because the two namespaces are free to diverge later.
 */
export function qualifyPromptName(serverId: string, promptName: string): string {
    return qualify('prompt', serverId, promptName);
}

/** A parsed qualified prompt name. */
export interface QualifiedPromptName {
    readonly serverId: string;
    readonly promptName: string;
}

/** Split an advertised prompt name back into server id and upstream name. */
export function parseQualifiedPromptName(qualified: string): QualifiedPromptName | undefined {
    const parsed = parseQualifiedToolName(qualified);
    if (parsed === undefined) return undefined;
    return { serverId: parsed.serverId, promptName: parsed.toolName };
}

/**
 * Scheme for wrapped resource URIs. Distinct from anything an upstream can
 * legitimately serve, so a wrapped URI is recognisable on sight — and so an
 * upstream that maliciously exposes a `mcp-sentinel://` URI of its own is
 * simply wrapped a second time rather than being confused for a Sentinel one.
 */
export const RESOURCE_URI_SCHEME = 'mcp-sentinel';

const RESOURCE_URI_PREFIX = `${RESOURCE_URI_SCHEME}://`;

/**
 * Wrap an upstream resource URI so the owning server travels with it.
 *
 * The upstream URI is percent-encoded whole, as a single opaque path segment.
 * That is what makes the wrapping total: `encodeURIComponent` escapes `/`, `?`,
 * `#` and `%`, so no part of the upstream URI can be mistaken for structure of
 * the wrapper, and the reversal is byte-exact for any input — including URIs
 * that are not hierarchical at all (`urn:isbn:…`), that carry spaces, or that
 * already use this scheme.
 */
export function qualifyResourceUri(serverId: string, uri: string): string {
    assertValidServerId(serverId);
    if (uri.length === 0) {
        throw new NamingError(`empty resource uri on server '${serverId}'`);
    }
    return `${RESOURCE_URI_PREFIX}${serverId}/${encodeURIComponent(uri)}`;
}

/** A parsed qualified resource URI. */
export interface QualifiedResourceUri {
    readonly serverId: string;
    readonly uri: string;
}

/**
 * Unwrap a `mcp-sentinel://` URI back into server id and upstream URI.
 *
 * Parsed by hand rather than with `new URL()`, which would be the obvious
 * choice and is wrong here. WHATWG URL parsing normalises dot segments for this
 * scheme: `mcp-sentinel://files/..` yields an empty pathname, `…/a/../b` yields
 * `/b`, and `…/%2E%2E` percent-decodes *before* normalising, so escaping does
 * not save it. An upstream resource whose URI is exactly `..` — legal, and
 * exactly the sort of thing a hostile server would pick — would be erased on
 * the way back, and a call meant for one resource would be forwarded for
 * another. Splitting the string literally has no such failure mode.
 *
 * Returns `undefined` for anything unparseable, on the same reasoning as
 * `parseQualifiedToolName`: it is client input, not a programming error.
 *
 * Only the canonical spelling is accepted. `file:///x` can be percent-encoded
 * many ways (`file%3A%2F%2F%2Fx`, `file:%2F%2F%2Fx`, …), all decoding to the
 * same upstream URI, and a policy written against one spelling would not match
 * the others — an alias is a policy bypass. So the decoded URI is re-wrapped and
 * required to equal the input byte for byte; every non-canonical alias becomes
 * an unknown resource instead. Agents do not invent these URIs, they echo back
 * what `resources/list` gave them, so nothing legitimate is lost.
 */
export function parseQualifiedResourceUri(qualified: string): QualifiedResourceUri | undefined {
    if (!qualified.startsWith(RESOURCE_URI_PREFIX)) return undefined;

    const rest = qualified.slice(RESOURCE_URI_PREFIX.length);
    const slash = rest.indexOf('/');
    if (slash <= 0) return undefined;

    const serverId = rest.slice(0, slash);
    if (!isValidServerId(serverId)) return undefined;

    const encoded = rest.slice(slash + 1);
    if (encoded.length === 0) return undefined;

    let uri: string;
    try {
        uri = decodeURIComponent(encoded);
    } catch {
        // decodeURIComponent throws URIError on a malformed escape ('%zz') or a
        // lone surrogate. Both mean the caller did not send something this
        // function produced, which is an unknown-resource condition.
        return undefined;
    }
    if (uri.length === 0) return undefined;
    if (`${RESOURCE_URI_PREFIX}${serverId}/${encodeURIComponent(uri)}` !== qualified) return undefined;

    return { serverId, uri };
}

/** True when the URI is wrapped in Sentinel's resource scheme. */
export function isQualifiedResourceUri(uri: string): boolean {
    return uri.startsWith(RESOURCE_URI_PREFIX);
}
