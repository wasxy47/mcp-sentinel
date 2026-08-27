/**
 * Structured logging.
 *
 * Three decisions worth stating, because each is a security property rather
 * than a style preference:
 *
 *  1. **Everything goes to stderr, never stdout.** The gateway may itself be
 *     launched over stdio by a host, in which case stdout *is* the JSON-RPC
 *     framing. A stray log line on stdout would corrupt the protocol stream.
 *
 *  2. **Fields are redacted on the way out.** Sentinel's whole job is standing
 *     between an agent and tools it passes credentials to, so a log line is the
 *     single most likely place for a token to escape into a file with weaker
 *     permissions than the audit database. Running `redact()` over every payload
 *     means a future `logger.info('forwarding', { args })` cannot leak, rather
 *     than relying on every author to remember.
 *
 *  3. **Text originating upstream is attributed and truncated.** `logger.fromUpstream`
 *     tags lines a server produced so that a human reading the log can never
 *     mistake an upstream's own output for Sentinel's. A server that logs
 *     `"level":"error","msg":"policy engine disabled"` should not be able to
 *     forge a Sentinel log record — a nested, labelled field cannot.
 *
 * Deliberately dependency-free: pino or winston would be better at volume, but
 * the audit trail is the durable record here and this is only the operator's
 * console. One file with no dependencies is easier to reason about than a
 * transport pipeline.
 */

import { isoTimestamp, redact } from '@mcp-sentinel/mcp-core';

export const LOG_LEVELS = ['debug', 'info', 'warn', 'error', 'silent'] as const;

export type LogLevel = (typeof LOG_LEVELS)[number];

const LEVEL_RANK: Readonly<Record<LogLevel, number>> = Object.freeze({
    debug: 10,
    info: 20,
    warn: 30,
    error: 40,
    silent: 100
});

/** Fields attached to a log record. Values are redacted before emission. */
export type LogFields = Readonly<Record<string, unknown>>;

/** Cap on any single string in a log record. Keeps one call from filling a disk. */
const MAX_LOG_STRING = 512;

/** Cap on a line of captured upstream output. */
const MAX_UPSTREAM_LINE = 2_000;

export interface LogRecord {
    readonly time: string;
    readonly level: Exclude<LogLevel, 'silent'>;
    readonly msg: string;
    readonly fields: LogFields;
}

/** Where records go. Injected so tests can assert on them without parsing stderr. */
export type LogSink = (record: LogRecord) => void;

export interface LoggerOptions {
    readonly level?: LogLevel;
    readonly sink?: LogSink;
    /** Fields merged into every record from this logger. */
    readonly base?: LogFields;
}

/** Serialize a record as one NDJSON line on stderr. */
export const stderrSink: LogSink = record => {
    const line = JSON.stringify({
        time: record.time,
        level: record.level,
        msg: record.msg,
        ...record.fields
    });
    process.stderr.write(`${line}\n`);
};

/** A sink that keeps records in memory. Returned array is live; read it after. */
export function collectingSink(): { readonly records: LogRecord[]; readonly sink: LogSink } {
    const records: LogRecord[] = [];
    return { records, sink: record => void records.push(record) };
}

/**
 * Turn an unknown thrown value into loggable fields.
 *
 * `cause` is followed one level deep because the SDK and Node both wrap — a
 * transport failure arrives as `Error: connect failed` with the `ECONNREFUSED`
 * in the cause, and losing that makes the log useless for diagnosis.
 */
export function errorFields(error: unknown): LogFields {
    if (!(error instanceof Error)) return { error: String(error) };

    const cause = error.cause;
    const causeText = cause instanceof Error ? `${cause.name}: ${cause.message}` : undefined;

    return {
        error: `${error.name}: ${error.message}`,
        ...(causeText === undefined ? {} : { cause: causeText }),
        ...('code' in error && typeof error.code === 'number' ? { errorCode: error.code } : {})
    };
}

export class Logger {
    private readonly level: LogLevel;
    private readonly sink: LogSink;
    private readonly base: LogFields;

    public constructor(options: LoggerOptions = {}) {
        this.level = options.level ?? 'info';
        this.sink = options.sink ?? stderrSink;
        this.base = options.base ?? {};
    }

    /** A logger that merges `fields` into every record, e.g. `{ serverId }`. */
    public child(fields: LogFields): Logger {
        return new Logger({
            level: this.level,
            sink: this.sink,
            base: { ...this.base, ...fields }
        });
    }

    public enabled(level: Exclude<LogLevel, 'silent'>): boolean {
        return LEVEL_RANK[level] >= LEVEL_RANK[this.level];
    }

    public debug(msg: string, fields: LogFields = {}): void {
        this.emit('debug', msg, fields);
    }

    public info(msg: string, fields: LogFields = {}): void {
        this.emit('info', msg, fields);
    }

    public warn(msg: string, fields: LogFields = {}): void {
        this.emit('warn', msg, fields);
    }

    public error(msg: string, fields: LogFields = {}): void {
        this.emit('error', msg, fields);
    }

    /**
     * Log a line of text produced by an upstream server.
     *
     * The text lands in a single `upstreamOutput` field rather than being
     * interpolated into `msg`, so it cannot impersonate a Sentinel record no
     * matter what it contains. It is truncated first, because an upstream
     * controls its own volume.
     */
    public fromUpstream(serverId: string, stream: 'stderr' | 'stdout', text: string): void {
        const trimmed = text.trimEnd();
        if (trimmed.length === 0) return;

        this.emit('warn', 'upstream wrote to its own log stream', {
            serverId,
            source: `upstream-${stream}`,
            upstreamOutput: trimmed.length > MAX_UPSTREAM_LINE ? `${trimmed.slice(0, MAX_UPSTREAM_LINE)}…` : trimmed
        });
    }

    private emit(level: Exclude<LogLevel, 'silent'>, msg: string, fields: LogFields): void {
        if (!this.enabled(level)) return;

        const merged = { ...this.base, ...fields };
        // `redact` returns `unknown`; it preserves plain objects, so the cast
        // holds for the object we just built. Findings are dropped: a log line
        // is not the audit trail, and reporting "we redacted 3 things" in the
        // operator's console is noise.
        const { value } = redact(merged, { maxStringLength: MAX_LOG_STRING });

        this.sink({
            time: isoTimestamp(),
            level,
            msg,
            fields: (value ?? {}) as LogFields
        });
    }
}

/** Parse a `SENTINEL_LOG_LEVEL`-style value, falling back to `info`. */
export function parseLogLevel(value: string | undefined, fallback: LogLevel = 'info'): LogLevel {
    if (value === undefined) return fallback;
    const normalized = value.trim().toLowerCase();
    return (LOG_LEVELS as readonly string[]).includes(normalized) ? (normalized as LogLevel) : fallback;
}
