/**
 * The tool catalog: the single answer to "what tools exist, and which upstream
 * owns each one".
 *
 * Everything downstream of it — the `tools/list` Sentinel advertises to agents,
 * the resolution of a `tools/call` back to a concrete upstream, the Cedar
 * resource a policy is written against — reads from here. That makes the catalog
 * a security control in three distinct ways, and each one is why a plain
 * "fan out `tools/list` and concatenate" is not enough:
 *
 *  - **Namespacing (T4/T5, tool shadowing).** Every upstream tool is advertised
 *    as `<serverId>__<toolName>`. Two servers may both offer `read_file`; here
 *    they become `files__read_file` and `evil__read_file`, distinct resources
 *    with distinct policies. A tool name that cannot be namespaced — a server
 *    that sends a control character or an overlong name — is dropped, never
 *    coerced into something that parses.
 *
 *  - **Drift detection (T3, the rug pull).** Each definition is digested. A
 *    definition that *changes* after Sentinel first catalogued it is the rug
 *    pull: benign while the operator watches, malicious later. On drift the
 *    changed tool is withheld (the default) or flagged, per config. First
 *    sightings are trust-on-first-use by construction — T3 is specifically about
 *    the change, and vetting a first sighting is the scanner's job (M6).
 *
 *  - **Bounding attacker-controlled bulk (T17, DoS).** A tool definition is text
 *    an untrusted server wrote that will land in the agent's context window, in
 *    scanner input and in risk-engine prompts. So tools per server, tools in
 *    total, and the size of any single definition are all capped — and when a cap
 *    bites the drop is logged with a count, never silently. A silent truncation
 *    reads as "we catalogued everything" when we did not.
 *
 * The catalog does not connect, retry, or interpret transport errors — that is
 * `UpstreamClient`'s job, reached through the registry. If a server's listing
 * fails, the catalog keeps that server's previously-known tools rather than
 * blanking them on a transient blip; a later `tools/call` surfaces the real
 * unreachability honestly through the forward path.
 */

import {
    CanonicalizationError,
    canonicalize,
    isValidToolName,
    qualifyToolName,
    sha256Hex,
    UpstreamUnavailableError,
    type CatalogEntry,
    type ToolDefinition
} from '@mcp-sentinel/mcp-core';

import type { CatalogSettings } from '../config/schema.js';
import { errorFields, type Logger } from '../observability/logger.js';
import type { UpstreamClient } from '../upstream/client.js';
import type { UpstreamRegistry } from '../upstream/registry.js';
import type { Scanner } from '@mcp-sentinel/scanner';

export interface ToolCatalogDeps {
    readonly registry: UpstreamRegistry;
    readonly settings: CatalogSettings;
    readonly logger: Logger;
    readonly scanner?: Scanner;
}

/** Why a listed tool did not make it into the catalog. */
export type DropReason =
    /** The name is not something `<serverId>__<toolName>` can safely carry. */
    | 'invalid-name'
    /** Excluded by the server's `allowTools`. */
    | 'not-allowed'
    /** Canonical definition exceeded `maxDefinitionBytes`. */
    | 'oversized'
    /** The definition could not be canonicalised, so it cannot be digested. */
    | 'unhashable'
    /** The server advertised more tools than `maxToolsPerServer`. */
    | 'server-cap'
    /** The server listed the same tool name twice. */
    | 'duplicate';

/**
 * A definition changed after it was first catalogued — a candidate rug pull.
 * Surfaced so the dashboard and the audit trail can record it; `action` says
 * what the catalog did about it.
 */
export interface DriftEvent {
    readonly qualifiedName: string;
    readonly serverId: string;
    readonly toolName: string;
    readonly previousDigest: string;
    readonly currentDigest: string;
    /** `withhold` dropped the tool from the catalog; `flag` kept serving it. */
    readonly action: 'flag' | 'withhold';
}

/** What one server's refresh did, for the operator and the dashboard. */
export interface ServerRefreshOutcome {
    readonly serverId: string;
    /** True when the listing returned; false when it failed (entries retained). */
    readonly ok: boolean;
    /** Tools the upstream advertised, before any filtering. */
    readonly listed: number;
    /** Tools now advertised for this server. */
    readonly catalogued: number;
    /** Tools withheld this refresh because their definition drifted. */
    readonly withheld: number;
    /** Non-drift drops, by reason. Present even when zero, so a reader can tell. */
    readonly dropped: Readonly<Record<DropReason, number>>;
    /** Short operator-facing phrase. Never raw upstream error text. */
    readonly reason?: string;
}

export interface CatalogRefreshResult {
    readonly outcomes: readonly ServerRefreshOutcome[];
    readonly drift: readonly DriftEvent[];
    readonly entries: readonly CatalogEntry[];
    readonly totalTools: number;
}

/** Per-server catalog state, retained across refreshes so drift can be seen. */
interface ServerState {
    /** Advertised entries, keyed by upstream tool name, in listed order. */
    entries: Map<string, CatalogEntry>;
    /**
     * The digest currently accepted for each tool name — the drift baseline.
     *
     * Deliberately not derived from `entries`: a tool withheld for drift is
     * absent from `entries` but keeps its last known-good digest here, so a
     * server that reverts to the benign definition is recognised as a revert
     * rather than as another fresh change.
     */
    readonly baseline: Map<string, string>;
}

/** One tool measured once — the canonical form serves both size check and digest. */
interface MeasuredTool {
    readonly definition: ToolDefinition;
    readonly digest: string;
}

/** A listed tool, as the SDK hands it over. */
type ListedTool = ToolDefinition;

function zeroDrops(): Record<DropReason, number> {
    return {
        'invalid-name': 0,
        'not-allowed': 0,
        oversized: 0,
        unhashable: 0,
        'server-cap': 0,
        duplicate: 0
    };
}

/**
 * Reduce a listing failure to a phrase that is safe to store and display.
 *
 * `UpstreamClient.call` has already converted transport failures into
 * `UpstreamUnavailableError`, whose `reason` is drawn from a fixed vocabulary.
 * Anything else is an error the *upstream* produced, and its text is
 * attacker-controlled — so it is replaced wholesale rather than trimmed. Full
 * detail still reaches the log through `errorFields`.
 */
function listingFailureReason(cause: unknown): string {
    if (cause instanceof UpstreamUnavailableError) {
        const reason = cause.data === undefined ? undefined : cause.data['reason'];
        if (typeof reason === 'string') return reason;
    }
    return 'tool listing failed';
}

export class ToolCatalog {
    private readonly registry: UpstreamRegistry;
    private readonly settings: CatalogSettings;
    private readonly logger: Logger;
    private readonly scanner?: Scanner;

    private readonly servers = new Map<string, ServerState>();
    /** Flattened lookup for resolution, rebuilt from scratch every refresh. */
    private index = new Map<string, CatalogEntry>();
    private refreshInFlight: Promise<CatalogRefreshResult> | undefined;

    public constructor(deps: ToolCatalogDeps) {
        this.registry = deps.registry;
        this.settings = deps.settings;
        this.logger = deps.logger;
        if (deps.scanner) {
            this.scanner = deps.scanner;
        }
    }

    /** Every advertised tool, in configuration order then listed order. */
    public all(): readonly CatalogEntry[] {
        return [...this.index.values()];
    }

    /**
     * The tool definitions to advertise to agents.
     *
     * The stored `definition` keeps the upstream's own `name`, because that is
     * what was digested and what drift is measured against. The name is swapped
     * for the qualified one only on the way out.
     */
    public advertised(): readonly ToolDefinition[] {
        return this.all().map(entry => ({ ...entry.definition, name: entry.qualifiedName }));
    }

    /** Resolve a qualified name (`files__read_file`) to its catalog entry. */
    public get(qualifiedName: string): CatalogEntry | undefined {
        return this.index.get(qualifiedName);
    }

    public has(qualifiedName: string): boolean {
        return this.index.has(qualifiedName);
    }

    /** Advertised entries for one server, in listed order. */
    public forServer(serverId: string): readonly CatalogEntry[] {
        return [...(this.servers.get(serverId)?.entries.values() ?? [])];
    }

    public get size(): number {
        return this.index.size;
    }

    /**
     * Re-list every dialable upstream and rebuild the advertised catalog.
     *
     * Never rejects: a server whose listing throws keeps its previous entries and
     * is reported with `ok: false`. Quarantined and disabled servers are never
     * listed — their tools must not reach the catalog at all, so the refusal
     * lives at the connection layer *and* here, by only iterating `dialable()`.
     *
     * Single-flight, like the connect path: `tools/list` from an agent and a
     * `list_changed` notification can arrive together, and two refreshes
     * interleaving over the same baseline would let a drift check read a digest
     * the other had already overwritten. A concurrent caller joins the running
     * refresh, which means it inherits the first caller's `signal`.
     */
    public async refresh(signal?: AbortSignal): Promise<CatalogRefreshResult> {
        const inFlight = this.refreshInFlight;
        if (inFlight !== undefined) return inFlight;

        const attempt = this.refreshOnce(signal).finally(() => {
            this.refreshInFlight = undefined;
        });
        this.refreshInFlight = attempt;
        return attempt;
    }

    private async refreshOnce(signal: AbortSignal | undefined): Promise<CatalogRefreshResult> {
        const targets = this.registry.dialable();
        const drift: DriftEvent[] = [];

        const outcomes = await Promise.all(
            targets.map(async client => this.refreshServer(client, drift, signal))
        );

        // Forget servers that left the configuration, so their tools stop being
        // advertised. Copy the key list first: mutating a Map mid-iteration is
        // legal but reads worse than this.
        const live = new Set(targets.map(client => client.id));
        for (const serverId of [...this.servers.keys()]) {
            if (!live.has(serverId)) this.servers.delete(serverId);
        }

        // Rebuilt from `targets`, not from `this.servers`: the refreshes above ran
        // concurrently, so Map insertion order reflects whichever upstream
        // answered first. Configuration order is a property operators rely on —
        // it decides which server survives the global cap — so it has to come
        // from the config-ordered list rather than from scheduling.
        this.rebuildIndex(targets);

        const failed = outcomes.filter(outcome => !outcome.ok).length;
        this.logger.info('tool catalog refreshed', {
            servers: outcomes.length,
            tools: this.index.size,
            drift: drift.length,
            failed
        });

        return { outcomes, drift, entries: this.all(), totalTools: this.index.size };
    }

    private async refreshServer(
        client: UpstreamClient,
        drift: DriftEvent[],
        signal: AbortSignal | undefined
    ): Promise<ServerRefreshOutcome> {
        const serverId = client.id;
        const state = this.stateFor(serverId);
        const dropped = zeroDrops();

        let listed: readonly ListedTool[];
        try {
            listed = await client.listTools(signal);
        } catch (cause) {
            const reason = listingFailureReason(cause);
            // Entries are retained deliberately: one failed listing must not empty
            // a server's catalog. If the server really is gone, the forward path
            // says so when a call is actually attempted.
            this.logger.warn('tool listing failed; keeping the previous catalog', {
                serverId,
                reason,
                retained: state.entries.size,
                ...errorFields(cause)
            });
            return {
                serverId,
                ok: false,
                listed: 0,
                catalogued: state.entries.size,
                withheld: 0,
                dropped,
                reason
            };
        }

        const allowTools = client.server.allowTools;
        const allowed = allowTools === undefined ? undefined : new Set(allowTools);
        const next = new Map<string, CatalogEntry>();
        let withheld = 0;

        for (const tool of listed) {
            const toolName = tool.name;

            if (!isValidToolName(toolName)) {
                dropped['invalid-name'] += 1;
                this.logger.warn('dropping tool with an unusable name', {
                    serverId,
                    // Length only. The name is attacker-controlled and may carry
                    // control characters or homoglyphs aimed at a log reader.
                    nameLength: toolName.length
                });
                continue;
            }
            if (allowed !== undefined && !allowed.has(toolName)) {
                dropped['not-allowed'] += 1;
                continue;
            }
            if (next.has(toolName)) {
                // Two tools under one name on one server: the second can only
                // shadow the first, so it is refused rather than allowed to win.
                dropped.duplicate += 1;
                this.logger.warn('dropping duplicate tool name', { serverId, toolName });
                continue;
            }
            if (next.size >= this.settings.maxToolsPerServer) {
                dropped['server-cap'] += 1;
                continue;
            }

            const measured = this.measure(serverId, toolName, tool, dropped);
            if (measured === undefined) continue;

            const qualifiedName = qualifyToolName(serverId, toolName);
            const priorDigest = state.baseline.get(toolName);

            if (priorDigest !== undefined && priorDigest !== measured.digest) {
                const action = this.settings.onDefinitionDrift;
                drift.push({
                    qualifiedName,
                    serverId,
                    toolName,
                    previousDigest: priorDigest,
                    currentDigest: measured.digest,
                    action
                });
                this.logger.warn('tool definition changed since it was first catalogued', {
                    serverId,
                    toolName,
                    previousDigest: priorDigest,
                    currentDigest: measured.digest,
                    action
                });
                if (action === 'withhold') {
                    // The baseline keeps pointing at the known-good digest, so a
                    // revert is recognised. The tool is simply not advertised.
                    withheld += 1;
                    continue;
                }
            }

            // Accepted: a first sighting, an unchanged digest, or a drift the
            // operator chose only to flag. The baseline records what is being
            // served, so the *next* change is measured against it.
            let scan;
            if (this.scanner) {
                scan = await this.scanner.scanTool(measured.definition);
            }

            state.baseline.set(toolName, measured.digest);
            next.set(toolName, {
                qualifiedName,
                serverId,
                toolName,
                definition: measured.definition,
                definitionDigest: measured.digest,
                ...(scan ? { scan } : {})
            });
        }

        const totalDropped = Object.values(dropped).reduce((sum, count) => sum + count, 0);
        if (totalDropped > 0) {
            this.logger.info('tools dropped while building the catalog', {
                serverId,
                listed: listed.length,
                catalogued: next.size,
                ...dropped
            });
        }

        state.entries = next;
        return { serverId, ok: true, listed: listed.length, catalogued: next.size, withheld, dropped };
    }

    /**
     * Canonicalise once, then derive the size check and the digest from the same
     * bytes — `digestOf` would serialise a second time for no gain. Returns
     * `undefined`, dropping the tool, when it is too large or cannot be hashed.
     */
    private measure(
        serverId: string,
        toolName: string,
        tool: ListedTool,
        dropped: Record<DropReason, number>
    ): MeasuredTool | undefined {
        let canonical: string;
        try {
            canonical = canonicalize(tool);
        } catch (cause) {
            // Unreachable for a definition that came off the wire as JSON, since
            // JSON cannot express the values that fail canonicalisation. Handled
            // anyway: a tool that cannot be digested cannot be checked for drift,
            // and serving an uncheckable definition is the thing to avoid.
            dropped.unhashable += 1;
            const detail = cause instanceof CanonicalizationError ? cause.message : 'not canonicalisable';
            this.logger.warn('dropping tool whose definition cannot be digested', {
                serverId,
                toolName,
                detail
            });
            return undefined;
        }

        const bytes = Buffer.byteLength(canonical, 'utf8');
        if (bytes > this.settings.maxDefinitionBytes) {
            dropped.oversized += 1;
            this.logger.warn('dropping oversized tool definition', {
                serverId,
                toolName,
                bytes,
                limit: this.settings.maxDefinitionBytes
            });
            return undefined;
        }

        return { definition: tool, digest: sha256Hex(canonical) };
    }

    private stateFor(serverId: string): ServerState {
        const existing = this.servers.get(serverId);
        if (existing !== undefined) return existing;
        const created: ServerState = { entries: new Map(), baseline: new Map() };
        this.servers.set(serverId, created);
        return created;
    }

    /**
     * Flatten per-server entries into the lookup index, applying the global cap.
     *
     * The cap is applied here rather than per server so that a server the
     * operator listed first is never crowded out of the catalog by one listed
     * later — the alternative would let a hostile upstream displace a trusted
     * one's tools just by advertising enough of its own.
     */
    private rebuildIndex(order: readonly UpstreamClient[]): void {
        const index = new Map<string, CatalogEntry>();
        let capped = 0;

        for (const client of order) {
            const state = this.servers.get(client.id);
            if (state === undefined) continue;
            for (const entry of state.entries.values()) {
                if (index.size >= this.settings.maxTools) {
                    capped += 1;
                    continue;
                }
                index.set(entry.qualifiedName, entry);
            }
        }

        if (capped > 0) {
            this.logger.warn('global tool cap reached; tools left out of the catalog', {
                limit: this.settings.maxTools,
                dropped: capped
            });
        }
        this.index = index;
    }
}
