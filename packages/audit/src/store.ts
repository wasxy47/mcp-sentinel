/**
 * Hash-chained audit store backed by SQLite.
 *
 * ## Design invariants
 *
 * 1. **Append-only.** There is no `UPDATE` or `DELETE` path. The chain is
 *    evidence; rewriting evidence defeats the purpose.
 *
 * 2. **Hash-chained.** Every row includes the SHA-256 of the previous row's
 *    hash concatenated with its own canonical JSON, so tampering with a
 *    single row breaks the chain from that point forward. The genesis hash
 *    (row 0's `prevHash`) is the all-zero sentinel defined in `mcp-core`.
 *
 * 3. **Fail-closed.** If `append()` throws, the caller MUST NOT proceed
 *    with the action. An unaudited action defeats the audit trail's purpose.
 *    The gateway enforces this: `tools/call`, `resources/read`, and
 *    `prompts/get` are denied when the audit write fails. Discovery and
 *    listing operations are best-effort — they log a warning and proceed.
 *
 * 4. **WAL mode.** Readers never block writers and vice versa. The `NORMAL`
 *    synchronous mode trades crash safety of the WAL index for throughput;
 *    a crash can lose at most the last committed transaction, and the chain
 *    verifier will detect the truncation.
 *
 * 5. **Serialised writes.** `better-sqlite3` is synchronous, so there is no
 *    concurrent-write issue. The `INSERT` is wrapped in a prepared statement
 *    for performance, and the chain head is cached in-process to avoid a
 *    `SELECT MAX(sequence)` on every append.
 */

import Database from 'better-sqlite3';
import type { Database as DatabaseType, Statement } from 'better-sqlite3';

import {
    canonicalize,
    sha256Hex,
    GENESIS_HASH,
    type DecisionRecord,
} from '@mcp-sentinel/mcp-core';

// ── Schema ──────────────────────────────────────────────────────────────────

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS audit_log (
    sequence    INTEGER PRIMARY KEY AUTOINCREMENT,
    decisionId  TEXT    UNIQUE NOT NULL,
    timestamp   TEXT    NOT NULL,
    agentId     TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    verdict     TEXT    NOT NULL,
    obligation  TEXT    NOT NULL,
    serverId    TEXT,
    qualifiedName TEXT,
    recordJson  TEXT    NOT NULL,
    prevHash    TEXT    NOT NULL,
    hash        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agentId   ON audit_log(agentId);
CREATE INDEX IF NOT EXISTS idx_audit_method    ON audit_log(method);
CREATE INDEX IF NOT EXISTS idx_audit_verdict   ON audit_log(verdict);
`;

// ── Types ───────────────────────────────────────────────────────────────────

/** A row as stored in SQLite, with chain metadata. */
export interface AuditRow {
    readonly sequence: number;
    readonly decisionId: string;
    readonly timestamp: string;
    readonly agentId: string;
    readonly method: string;
    readonly verdict: string;
    readonly obligation: string;
    readonly serverId: string | null;
    readonly qualifiedName: string | null;
    readonly recordJson: string;
    readonly prevHash: string;
    readonly hash: string;
}

/** Thrown when an audit store operation fails in a way the caller must handle. */
export class AuditWriteError extends Error {
    constructor(message: string, cause?: unknown) {
        super(message, cause ? { cause } : undefined);
        this.name = 'AuditWriteError';
    }
}

/** Minimal logger so the store does not depend on a specific logger. */
export interface AuditLogger {
    warn(message: string, fields?: Record<string, unknown>): void;
    debug(message: string, fields?: Record<string, unknown>): void;
}

// ── Store ───────────────────────────────────────────────────────────────────

export class AuditStore {
    private readonly db: DatabaseType;
    private readonly insertStmt: Statement;
    private readonly selectTailStmt: Statement;
    private chainHead: string;

    constructor(
        dbPath: string,
        private readonly logger: AuditLogger,
    ) {
        this.db = new Database(dbPath);

        // SQLite pragmas for reliability and throughput
        this.db.pragma('journal_mode = WAL');
        this.db.pragma('synchronous = NORMAL');
        this.db.pragma('foreign_keys = ON');

        // Create tables
        this.db.exec(SCHEMA_SQL);

        // Prepare statements
        this.insertStmt = this.db.prepare(`
            INSERT INTO audit_log
                (decisionId, timestamp, agentId, method, verdict, obligation,
                 serverId, qualifiedName, recordJson, prevHash, hash)
            VALUES
                (@decisionId, @timestamp, @agentId, @method, @verdict, @obligation,
                 @serverId, @qualifiedName, @recordJson, @prevHash, @hash)
        `);

        this.selectTailStmt = this.db.prepare(
            'SELECT hash FROM audit_log ORDER BY sequence DESC LIMIT 1'
        );

        // Initialise the chain head from the database
        const tail = this.selectTailStmt.get() as { hash: string } | undefined;
        this.chainHead = tail?.hash ?? GENESIS_HASH;

        this.logger.debug('audit store opened', {
            path: dbPath,
            chainHead: this.chainHead,
            isGenesis: this.chainHead === GENESIS_HASH,
        });
    }

    /**
     * Append a decision record to the audit chain.
     *
     * The record is serialised with RFC 8785 canonical JSON, chained to the
     * previous hash, and inserted in a single synchronous SQLite statement.
     *
     * @throws {AuditWriteError} if the insert fails for any reason. The
     *   caller MUST treat this as a hard failure and deny the request.
     */
    append(record: DecisionRecord): void {
        const prevHash = this.chainHead;
        const recordJson = canonicalize(record);
        const hash = sha256Hex(prevHash + recordJson);

        try {
            this.insertStmt.run({
                decisionId: record.decisionId,
                timestamp: record.timestamp,
                agentId: record.agent.id,
                method: record.method,
                verdict: record.verdict,
                obligation: record.obligation,
                serverId: record.serverId ?? null,
                qualifiedName: record.qualifiedName ?? null,
                recordJson,
                prevHash,
                hash,
            });
        } catch (cause) {
            // Do NOT update chainHead — the row was not written.
            throw new AuditWriteError(
                `Audit write failed for ${record.decisionId}: ${cause instanceof Error ? cause.message : String(cause)}`,
                cause,
            );
        }

        // Only update the in-process chain head after a successful insert.
        this.chainHead = hash;
    }

    /** Current chain head hash. Exposed for testing and the verifier. */
    get head(): string {
        return this.chainHead;
    }

    /** Total number of rows in the audit log. */
    get length(): number {
        const row = this.db.prepare('SELECT COUNT(*) AS cnt FROM audit_log').get() as { cnt: number };
        return row.cnt;
    }

    /** Close the database connection. Idempotent. */
    close(): void {
        this.db.close();
    }

    /**
     * Read all rows in chain order. Used by the verifier.
     * For large databases, callers should use `readPage()` instead.
     */
    readAll(): AuditRow[] {
        return this.db.prepare(
            'SELECT * FROM audit_log ORDER BY sequence ASC'
        ).all() as AuditRow[];
    }

    /**
     * Read a page of rows in chain order, for paginated verification.
     */
    readPage(offset: number, limit: number): AuditRow[] {
        return this.db.prepare(
            'SELECT * FROM audit_log ORDER BY sequence ASC LIMIT ? OFFSET ?'
        ).all(limit, offset) as AuditRow[];
    }

    /**
     * Get the raw database handle. Exposed for testing only — production
     * code should use the public API exclusively.
     * @internal
     */
    get _db(): DatabaseType {
        return this.db;
    }
}
