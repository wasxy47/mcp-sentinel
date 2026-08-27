/**
 * One connection to one upstream MCP server.
 *
 * This is the layer that decides *when* Sentinel talks to a server it does not
 * trust, so the policy choices are as important as the plumbing:
 *
 *  - **Lazy connect with a fail-fast window.** Dialling happens on first use, not
 *    at startup, and after `failFastAfter` consecutive failures the client
 *    refuses to dial again until its backoff window expires. Without that window
 *    a single dead upstream would add a full connect timeout to *every* request,
 *    and one broken server would degrade the whole gateway.
 *
 *  - **Single-flight connects.** Ten tool calls arriving against a disconnected
 *    stdio upstream must share one attempt. The naive version spawns ten child
 *    processes, nine of which are orphaned.
 *
 *  - **Quarantined servers are never dialled.** Quarantine is enforced here as
 *    well as in Cedar. A policy bug should not be sufficient to reach a server
 *    an operator has marked malicious; two independent controls should be.
 *
 *  - **`inputRequired.autoFulfill` is off.** On 2026-07-28 a server obtains
 *    client input by answering with an `input_required` result. If Sentinel let
 *    the SDK fulfil those automatically, Sentinel — holding the gateway's
 *    authority — would be answering elicitation and sampling requests *on the
 *    agent's behalf*, which is precisely the confused-deputy the project exists
 *    to prevent. The result is surfaced instead, for M1.3 to relay to the agent.
 *
 *  - **Generation counters guard against stale callbacks.** A `close` event from
 *    a connection that was already replaced must not mark the *new* connection
 *    unhealthy. Every connect takes a generation number and every callback
 *    checks it before mutating state.
 *
 * Nothing here consults policy. Deciding whether a call is permitted is M2's
 * job; this module's contract is "reach the server, or fail in a way the audit
 * trail can explain".
 */

import {
    Client,
    SdkError,
    SdkErrorCode,
    UnsupportedProtocolVersionError,
    type Implementation,
    type ProtocolEra,
    type RequestOptions,
    type ServerCapabilities,
    type Tool,
    type Transport,
    type VersionNegotiationOptions
} from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

import { isoTimestamp, SENTINEL_PROTOCOL_VERSION, UpstreamUnavailableError } from '@mcp-sentinel/mcp-core';
import type { ServerTrust } from '@mcp-sentinel/mcp-core';

import type { UpstreamPoolSettings, UpstreamServerSettings } from '../config/schema.js';
import { errorFields, type Logger } from '../observability/logger.js';
import { backoffDelayMs, type BackoffPolicy } from './backoff.js';
import { buildUpstreamTransport, type TransportFactory } from './transport.js';

/**
 * Longest a captured stderr fragment may grow without a newline before it is
 * flushed anyway. A child that writes a megabyte with no line break should not
 * be able to grow the gateway's heap.
 */
const MAX_STDERR_FRAGMENT = 8 * 1024;

/** Cap on self-reported identity strings copied out of an upstream's handshake. */
const MAX_SERVER_INFO_LENGTH = 200;

/** Floor for the era probe, so a tiny connect timeout still leaves it a chance. */
const MIN_PROBE_TIMEOUT_MS = 1_000;

export type UpstreamHealth =
    /** Configured and dialable, not yet dialled. */
    | 'idle'
    /** A connect attempt is in flight. */
    | 'connecting'
    /** Connected and usable. */
    | 'ready'
    /** Reachable in principle; the last attempt or connection failed. */
    | 'unavailable'
    /** `trust: "quarantined"` — never dialled. */
    | 'quarantined'
    /** `enabled: false` — present in config, deliberately not dialled. */
    | 'disabled'
    /** The gateway is shutting down. */
    | 'closed';

/** Upstream identity, copied field-by-field and length-capped. */
export interface UpstreamServerInfo {
    readonly name: string;
    readonly version: string;
    readonly title: string | undefined;
}

/** Point-in-time view of one upstream, for the dashboard and `server/discover`. */
export interface UpstreamSnapshot {
    readonly serverId: string;
    readonly label: string;
    readonly trust: ServerTrust;
    readonly transportKind: 'http' | 'stdio';
    readonly health: UpstreamHealth;
    readonly era: ProtocolEra | undefined;
    readonly protocolVersion: string | undefined;
    readonly serverInfo: UpstreamServerInfo | undefined;
    readonly capabilities: ServerCapabilities | undefined;
    readonly connectedAt: string | undefined;
    /** Short operator-facing phrase. Never raw upstream error text. */
    readonly lastError: string | undefined;
    readonly consecutiveFailures: number;
    readonly attempts: number;
    /** Epoch ms before which a failed upstream will not be re-dialled. */
    readonly retryNotBefore: number;
}

export interface UpstreamClientDeps {
    readonly pool: UpstreamPoolSettings;
    readonly logger: Logger;
    /** Identity Sentinel presents to the upstream. */
    readonly clientInfo: Implementation;
    /** Overridable so tests can substitute `InMemoryTransport.createLinkedPair()`. */
    readonly transportFactory?: TransportFactory;
    /** Injectable clock. Tests must not depend on wall time. */
    readonly now?: () => number;
    /** Injectable randomness, for deterministic backoff assertions. */
    readonly random?: () => number;
}

/**
 * Map the operator's `upstreamProtocol` setting onto the SDK's negotiation
 * options.
 *
 * The default is `auto` even though Sentinel speaks 2026-07-28 downstream to
 * agents. Pinning upstream would be the purer choice and would also make the
 * gateway useless: essentially every MCP server deployed today is 2025-era, and
 * a security gateway nobody can put in front of their servers protects nothing.
 * The era is recorded per upstream in the audit trail instead, so "this call
 * went to a legacy server" is a queryable fact rather than a hidden one.
 *
 * The probe gets half the connect budget. It shares the deadline with the
 * legacy `initialize` fallback that may follow it, and a probe allowed to
 * consume the whole budget turns "this is a 2025 server" into "this server
 * timed out".
 */
export function negotiationOptions(
    mode: UpstreamPoolSettings['upstreamProtocol'],
    connectTimeoutMs: number
): VersionNegotiationOptions {
    switch (mode) {
        case 'legacy':
            return { mode: 'legacy' };
        case '2026-07-28':
            return { mode: { pin: SENTINEL_PROTOCOL_VERSION } };
        case 'auto':
            return {
                mode: 'auto',
                probe: { timeoutMs: Math.max(MIN_PROBE_TIMEOUT_MS, Math.floor(connectTimeoutMs / 2)) }
            };
    }
}

/**
 * Reduce a thrown value to one of a fixed set of operator-facing phrases.
 *
 * The upstream's own message is never returned. It is *inspected* — a substring
 * test against our own vocabulary — but every value this function can return is
 * a literal written here, so a server cannot inject text into the agent's
 * context or into a log message through its error strings. Full detail still
 * reaches the log through `errorFields`, which nests it under `error`.
 */
export function describeFailure(cause: unknown): string {
    if (UnsupportedProtocolVersionError.isInstance(cause)) return 'protocol version not supported';

    if (SdkError.isInstance(cause)) {
        switch (cause.code) {
            case SdkErrorCode.RequestTimeout:
                return 'request timed out';
            case SdkErrorCode.EraNegotiationFailed:
                return 'protocol negotiation failed';
            case SdkErrorCode.ConnectionClosed:
                return 'connection closed';
            case SdkErrorCode.NotConnected:
                return 'not connected';
            case SdkErrorCode.SendFailed:
                return 'send failed';
            case SdkErrorCode.ClientHttpAuthentication:
                return 'authentication required';
            case SdkErrorCode.ClientHttpForbidden:
                return 'access forbidden';
            case SdkErrorCode.InvalidResult:
                return 'malformed response';
            default:
                break;
        }
    }

    if (cause instanceof Error) {
        const code = 'code' in cause ? String((cause as { readonly code?: unknown }).code) : '';
        switch (code) {
            case 'ECONNREFUSED':
                return 'connection refused';
            case 'ENOTFOUND':
            case 'EAI_AGAIN':
                return 'host not found';
            case 'ENOENT':
                return 'command not found';
            case 'EACCES':
            case 'EPERM':
                return 'permission denied';
            case 'ETIMEDOUT':
                return 'connect timed out';
            case 'ECONNRESET':
                return 'connection reset';
            default:
                break;
        }
        if (cause.name === 'AbortError' || cause.name === 'TimeoutError') return 'connect timed out';
    }

    return 'handshake failed';
}

/** True when the failure means the connection itself is gone, not just this call. */
function isConnectionLoss(cause: unknown): boolean {
    if (!SdkError.isInstance(cause)) {
        return cause instanceof Error && 'code' in cause && cause.code === 'ECONNRESET';
    }
    return (
        cause.code === SdkErrorCode.ConnectionClosed ||
        cause.code === SdkErrorCode.NotConnected ||
        cause.code === SdkErrorCode.SendFailed
    );
}

/** Close without letting a failure during teardown mask the original error. */
async function safeClose(client: Client, logger: Logger): Promise<void> {
    try {
        await client.close();
    } catch (cause) {
        logger.debug('error while closing upstream connection', errorFields(cause));
    }
}

function truncate(value: string): string {
    return value.length > MAX_SERVER_INFO_LENGTH ? `${value.slice(0, MAX_SERVER_INFO_LENGTH)}…` : value;
}

/**
 * Copy the fields Sentinel uses out of a self-reported handshake.
 *
 * Field-by-field rather than a spread: the upstream chose this object's shape,
 * and anything it added would otherwise flow into the dashboard and the audit
 * trail unexamined.
 */
function sanitizeServerInfo(info: Implementation | undefined): UpstreamServerInfo | undefined {
    if (info === undefined) return undefined;
    const title = typeof info.title === 'string' ? truncate(info.title) : undefined;
    return {
        name: truncate(info.name),
        version: truncate(info.version),
        title
    };
}

export class UpstreamClient {
    public readonly server: UpstreamServerSettings;

    private readonly pool: UpstreamPoolSettings;
    private readonly logger: Logger;
    private readonly clientInfo: Implementation;
    private readonly transportFactory: TransportFactory;
    private readonly now: () => number;
    private readonly random: () => number;
    private readonly backoff: BackoffPolicy;

    private health: UpstreamHealth;
    private client: Client | undefined;
    private connectInFlight: Promise<Client> | undefined;

    /**
     * Incremented on every connect and on every deliberate teardown. Callbacks
     * captured for generation N ignore themselves once the counter has moved on.
     */
    private generation = 0;

    private attempts = 0;
    private consecutiveFailures = 0;
    private retryNotBefore = 0;
    private connectedAt: string | undefined;
    private lastError: string | undefined;
    private era: ProtocolEra | undefined;
    private protocolVersion: string | undefined;
    private serverInfo: UpstreamServerInfo | undefined;
    private capabilities: ServerCapabilities | undefined;
    private shuttingDown = false;

    public constructor(server: UpstreamServerSettings, deps: UpstreamClientDeps) {
        this.server = server;
        this.pool = deps.pool;
        this.logger = deps.logger.child({ serverId: server.id });
        this.clientInfo = deps.clientInfo;
        this.transportFactory = deps.transportFactory ?? buildUpstreamTransport;
        this.now = deps.now ?? Date.now;
        this.random = deps.random ?? Math.random;
        this.backoff = {
            initialDelayMs: deps.pool.reconnect.initialDelayMs,
            maxDelayMs: deps.pool.reconnect.maxDelayMs,
            factor: deps.pool.reconnect.factor
        };

        this.health =
            server.trust === 'quarantined' ? 'quarantined' : server.enabled ? 'idle' : 'disabled';
    }

    public get id(): string {
        return this.server.id;
    }

    public get trust(): ServerTrust {
        return this.server.trust;
    }

    /** True when this upstream may ever be dialled. */
    public get dialable(): boolean {
        return this.server.enabled && this.server.trust !== 'quarantined' && !this.shuttingDown;
    }

    public snapshot(): UpstreamSnapshot {
        return {
            serverId: this.server.id,
            label: this.server.label ?? this.server.id,
            trust: this.server.trust,
            transportKind: this.server.transport.kind,
            health: this.health,
            era: this.era,
            protocolVersion: this.protocolVersion,
            serverInfo: this.serverInfo,
            capabilities: this.capabilities,
            connectedAt: this.connectedAt,
            lastError: this.lastError,
            consecutiveFailures: this.consecutiveFailures,
            attempts: this.attempts,
            retryNotBefore: this.retryNotBefore
        };
    }

    /**
     * Return a connected client, dialling if necessary.
     *
     * Throws `UpstreamUnavailableError` rather than a transport error, so every
     * caller upstack sees one error type with a code the audit trail understands.
     */
    public async ensureReady(): Promise<Client> {
        if (this.shuttingDown) {
            throw new UpstreamUnavailableError(this.server.id, 'gateway is shutting down');
        }
        if (!this.server.enabled) {
            throw new UpstreamUnavailableError(this.server.id, 'server is disabled in configuration');
        }
        if (this.server.trust === 'quarantined') {
            // Refused before any I/O: quarantine must not depend on the policy
            // engine having been loaded, or on it being correct.
            throw new UpstreamUnavailableError(this.server.id, 'server is quarantined');
        }

        const existing = this.client;
        if (existing !== undefined && this.health === 'ready') return existing;

        const inFlight = this.connectInFlight;
        if (inFlight !== undefined) return inFlight;

        const waitMs = this.retryNotBefore - this.now();
        if (this.consecutiveFailures >= this.pool.reconnect.failFastAfter && waitMs > 0) {
            throw new UpstreamUnavailableError(
                this.server.id,
                `unreachable after ${this.consecutiveFailures} attempts; next retry in ${waitMs}ms`
            );
        }

        const attempt = this.connectOnce().finally(() => {
            this.connectInFlight = undefined;
        });
        this.connectInFlight = attempt;
        return attempt;
    }

    /**
     * Dial once at startup so the dashboard and catalog have real status.
     *
     * Failures are swallowed: a gateway that refuses to start because one
     * upstream is down is a gateway that cannot be used to *diagnose* that
     * upstream being down. The failure is logged and visible in the snapshot.
     */
    public async warmUp(): Promise<UpstreamSnapshot> {
        if (!this.dialable) {
            this.logger.info('skipping warm-up', { health: this.health });
            return this.snapshot();
        }
        try {
            await this.ensureReady();
        } catch (cause) {
            this.logger.warn('warm-up failed; will retry on first use', errorFields(cause));
        }
        return this.snapshot();
    }

    /**
     * Run one request against the upstream.
     *
     * The callback receives the request options — timeout, and the caller's abort
     * signal — rather than building them itself, so no call site can accidentally
     * inherit the SDK's 60-second default in place of the configured deadline.
     *
     * Errors the *upstream* produced (a tool that failed, a resource that does
     * not exist) are rethrown untouched: they belong to the agent. Only
     * transport-level failures are converted, and only those mark the connection
     * unhealthy.
     */
    public async call<T>(
        operation: string,
        fn: (client: Client, options: RequestOptions) => Promise<T>,
        signal?: AbortSignal
    ): Promise<T> {
        const client = await this.ensureReady();
        const generation = this.generation;
        const started = this.now();

        const options: RequestOptions = {
            timeout: this.pool.requestTimeoutMs,
            ...(signal === undefined ? {} : { signal })
        };

        try {
            const result = await fn(client, options);
            this.logger.debug('upstream request completed', {
                operation,
                durationMs: this.now() - started
            });
            return result;
        } catch (cause) {
            const reason = describeFailure(cause);
            this.logger.warn('upstream request failed', {
                operation,
                reason,
                durationMs: this.now() - started,
                ...errorFields(cause)
            });

            if (isConnectionLoss(cause)) {
                this.handleDisconnect(generation, reason);
                throw new UpstreamUnavailableError(this.server.id, reason, { cause });
            }
            if (SdkError.isInstance(cause) && cause.code === SdkErrorCode.RequestTimeout) {
                // The connection may well be fine — a slow tool is not a dead
                // server — so the client is left in place. But from the agent's
                // point of view the upstream did not answer, and saying so with
                // the upstream error code is more honest than a generic failure.
                throw new UpstreamUnavailableError(this.server.id, reason, { cause });
            }
            throw cause;
        }
    }

    /** Liveness check. Cheap enough to run from the dashboard. */
    public async ping(signal?: AbortSignal): Promise<void> {
        await this.call('ping', async (client, options) => client.ping(options), signal);
    }

    /**
     * List the upstream's tools, aggregated across pages by the SDK.
     *
     * The no-`cursor` call is deliberate: it makes the SDK walk every page,
     * apply the `listMaxPages` cap this client was built with, and — on a
     * Streamable HTTP modern connection — drop tools whose `x-mcp-header`
     * declarations violate SEP-2243 before Sentinel ever sees them. Driving
     * pagination by hand here would forfeit all three. `cacheMode: 'refresh'`
     * so a catalog refresh sees the server's current tools rather than a copy
     * the SDK cached on connect — drift detection depends on it.
     */
    public async listTools(signal?: AbortSignal): Promise<readonly Tool[]> {
        const result = await this.call(
            'tools/list',
            async (client, options) => client.listTools(undefined, { ...options, cacheMode: 'refresh' }),
            signal
        );
        return result.tools;
    }

    /**
     * Drop the current connection without counting a failure.
     *
     * Used when configuration changes or the scanner quarantines a server
     * mid-flight. The next `ensureReady` dials again immediately, because the
     * reset was Sentinel's decision, not evidence the server is broken.
     */
    public async reset(reason: string): Promise<void> {
        const client = this.client;
        this.generation += 1;
        this.client = undefined;
        this.clearNegotiatedState();
        this.consecutiveFailures = 0;
        this.retryNotBefore = 0;
        if (this.dialable) this.setHealth('idle');
        this.logger.info('upstream connection reset', { reason });
        if (client !== undefined) await safeClose(client, this.logger);
    }

    public async close(): Promise<void> {
        this.shuttingDown = true;
        this.generation += 1;

        // Let an in-flight connect settle first; `connectOnce` sees the shutdown
        // flag and closes whatever it built, so nothing is left orphaned.
        await this.connectInFlight?.catch(() => undefined);

        const client = this.client;
        this.client = undefined;
        this.clearNegotiatedState();
        this.setHealth('closed');
        if (client !== undefined) await safeClose(client, this.logger);
    }

    private async connectOnce(): Promise<Client> {
        const generation = ++this.generation;
        this.attempts += 1;
        this.setHealth('connecting');
        this.logger.debug('connecting to upstream', {
            attempt: this.attempts,
            transport: this.server.transport.kind,
            negotiation: this.pool.upstreamProtocol
        });

        // Building the transport can fail on its own — a malformed URL, a stdio
        // spawn that throws synchronously. That is a connect failure like any
        // other and must count towards the fail-fast window, so it is inside
        // the same accounting as the handshake rather than escaping raw.
        let transport: Transport;
        try {
            transport = this.transportFactory(this.server);
            this.attachStderr(transport);
        } catch (cause) {
            const reason = describeFailure(cause);
            this.recordConnectFailure(generation, reason, cause);
            throw new UpstreamUnavailableError(this.server.id, reason, { cause });
        }

        const client = new Client(this.clientInfo, {
            versionNegotiation: negotiationOptions(this.pool.upstreamProtocol, this.pool.connectTimeoutMs),
            // See the header note: Sentinel must never answer an upstream's
            // elicitation or sampling request on the agent's behalf.
            inputRequired: { autoFulfill: false },
            // Bounds the SDK's aggregating `tools/list` walk. A server whose
            // `nextCursor` never converges is a memory-exhaustion primitive, and
            // this is the only layer that can stop it before the pages are read.
            listMaxPages: this.pool.listMaxPages
        });

        client.onerror = (error: Error): void => {
            this.logger.warn('upstream transport error', errorFields(error));
        };

        try {
            await client.connect(transport, { timeout: this.pool.connectTimeoutMs });
        } catch (cause) {
            await safeClose(client, this.logger);
            const reason = describeFailure(cause);
            this.recordConnectFailure(generation, reason, cause);
            throw new UpstreamUnavailableError(this.server.id, reason, { cause });
        }

        if (this.shuttingDown || generation !== this.generation) {
            // Shut down or reset while we were dialling. Release the connection
            // rather than storing one nobody asked for.
            await safeClose(client, this.logger);
            throw new UpstreamUnavailableError(this.server.id, 'connection superseded during handshake');
        }

        this.client = client;

        /**
         * Attached only now, deliberately.
         *
         * The SDK tears down the connection as part of *failing* a handshake:
         * `_legacyHandshake` calls `close()` and then rethrows, so `onclose`
         * fires before `connect()` rejects. Arming this earlier meant
         * `handleDisconnect` ran first, bumped the generation, and left
         * `recordConnectFailure` looking at a stale one — so it returned without
         * counting anything. A server that accepted connections and then never
         * answered `initialize` would never have tripped the fail-fast window,
         * which is precisely the case the window exists for.
         *
         * Until the connection is adopted, the dial owns its own failures. There
         * is no gap: nothing awaits between `connect()` resolving and here.
         */
        client.onclose = (): void => this.handleDisconnect(generation, 'connection closed');

        this.era = client.getProtocolEra();
        this.protocolVersion = client.getNegotiatedProtocolVersion();
        this.serverInfo = sanitizeServerInfo(client.getServerVersion());
        this.capabilities = client.getServerCapabilities();
        this.connectedAt = isoTimestamp(this.now());
        this.consecutiveFailures = 0;
        this.retryNotBefore = 0;
        this.lastError = undefined;
        this.setHealth('ready');

        this.logger.info('upstream connected', {
            attempt: this.attempts,
            era: this.era,
            protocolVersion: this.protocolVersion,
            serverName: this.serverInfo?.name,
            serverVersion: this.serverInfo?.version,
            trust: this.server.trust
        });

        return client;
    }

    private recordConnectFailure(generation: number, reason: string, cause: unknown): void {
        if (generation !== this.generation) return;

        this.consecutiveFailures += 1;
        this.lastError = reason;
        this.client = undefined;
        this.clearNegotiatedState();

        const delayMs = backoffDelayMs(this.consecutiveFailures, this.backoff, this.random);
        this.retryNotBefore = this.now() + delayMs;
        this.setHealth('unavailable');

        this.logger.warn('upstream connect failed', {
            attempt: this.attempts,
            consecutiveFailures: this.consecutiveFailures,
            reason,
            retryInMs: delayMs,
            ...errorFields(cause)
        });
    }

    /**
     * Handle a connection that dropped after having been established.
     *
     * This deliberately does *not* increment `consecutiveFailures`. That counter
     * gates the fail-fast window and exists to describe "this server will not
     * accept connections"; a connection that worked and then dropped has earned
     * one immediate retry.
     */
    private handleDisconnect(generation: number, reason: string): void {
        if (generation !== this.generation || this.shuttingDown) return;

        this.generation += 1;
        this.client = undefined;
        this.clearNegotiatedState();
        this.lastError = reason;
        this.setHealth('unavailable');
        this.logger.warn('upstream disconnected', { reason });
    }

    private clearNegotiatedState(): void {
        this.era = undefined;
        this.protocolVersion = undefined;
        this.serverInfo = undefined;
        this.capabilities = undefined;
        this.connectedAt = undefined;
    }

    private setHealth(health: UpstreamHealth): void {
        if (this.health === health) return;
        this.logger.debug('upstream health changed', { from: this.health, to: health });
        this.health = health;
    }

    /**
     * Forward a stdio child's stderr into Sentinel's log, line by line.
     *
     * `transport.ts` asks for `stderr: 'pipe'` precisely so that this can happen:
     * with the SDK default of `'inherit'` an upstream writes straight into the
     * gateway's own stderr, where its text is indistinguishable from Sentinel's.
     */
    private attachStderr(transport: Transport): void {
        if (!(transport instanceof StdioClientTransport)) return;
        const stream = transport.stderr;
        if (stream === null) return;

        let fragment = '';
        stream.on('data', (chunk: Buffer | string) => {
            fragment += typeof chunk === 'string' ? chunk : chunk.toString('utf8');

            if (fragment.length > MAX_STDERR_FRAGMENT) {
                this.logger.fromUpstream(this.server.id, 'stderr', fragment);
                fragment = '';
                return;
            }

            const lines = fragment.split('\n');
            fragment = lines.pop() ?? '';
            for (const line of lines) {
                this.logger.fromUpstream(this.server.id, 'stderr', line);
            }
        });
        stream.on('error', (error: Error) => {
            this.logger.debug('error reading upstream stderr', errorFields(error));
        });
    }
}
