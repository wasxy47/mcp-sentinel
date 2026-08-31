/**
 * Query API for the audit trail.
 *
 * Filters are combined with AND — every provided field narrows the result set.
 * Results are always in chain order (sequence ASC) so that a consumer can
 * verify the sub-chain if needed.
 *
 * ## Pagination
 *
 * `limit` and `afterSequence` provide cursor-based pagination. The sequence
 * number is monotonically increasing and unique, so there is no ambiguity.
 * Callers should pass `afterSequence = lastRow.sequence` from the previous
 * page.
 */

import type { AuditRow } from './store.js';
import type { Database as DatabaseType } from 'better-sqlite3';

// ── Types ───────────────────────────────────────────────────────────────────

/** Filters for querying the audit log. All fields are optional AND-combined. */
export interface AuditQueryFilter {
    /** Filter by agent id (exact match). */
    readonly agentId?: string;
    /** Filter by MCP method (exact match, e.g. 'tools/call'). */
    readonly method?: string;
    /** Filter by verdict (exact match). */
    readonly verdict?: string;
    /** Filter by obligation (exact match). */
    readonly obligation?: string;
    /** Filter by server id (exact match). */
    readonly serverId?: string;
    /** ISO timestamp lower bound (inclusive). */
    readonly since?: string;
    /** ISO timestamp upper bound (inclusive). */
    readonly until?: string;
    /** Cursor: only return rows after this sequence number. */
    readonly afterSequence?: number;
    /** Maximum number of rows to return. Defaults to 100. */
    readonly limit?: number;
}

/** A query result with pagination metadata. */
export interface AuditQueryResult {
    readonly rows: readonly AuditRow[];
    readonly total: number;
    readonly hasMore: boolean;
}

// ── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;

// ── Query builder ───────────────────────────────────────────────────────────

/**
 * Query the audit log with the given filters.
 *
 * This is a pure function over a database handle so it can be tested
 * independently from the `AuditStore` lifecycle.
 */
export function queryAuditLog(
    db: DatabaseType,
    filter: AuditQueryFilter = {},
): AuditQueryResult {
    const conditions: string[] = [];
    const params: Record<string, unknown> = {};

    if (filter.agentId !== undefined) {
        conditions.push('agentId = @agentId');
        params.agentId = filter.agentId;
    }
    if (filter.method !== undefined) {
        conditions.push('method = @method');
        params.method = filter.method;
    }
    if (filter.verdict !== undefined) {
        conditions.push('verdict = @verdict');
        params.verdict = filter.verdict;
    }
    if (filter.obligation !== undefined) {
        conditions.push('obligation = @obligation');
        params.obligation = filter.obligation;
    }
    if (filter.serverId !== undefined) {
        conditions.push('serverId = @serverId');
        params.serverId = filter.serverId;
    }
    if (filter.since !== undefined) {
        conditions.push('timestamp >= @since');
        params.since = filter.since;
    }
    if (filter.until !== undefined) {
        conditions.push('timestamp <= @until');
        params.until = filter.until;
    }
    if (filter.afterSequence !== undefined) {
        conditions.push('sequence > @afterSequence');
        params.afterSequence = filter.afterSequence;
    }

    const where = conditions.length > 0
        ? `WHERE ${conditions.join(' AND ')}`
        : '';

    const limit = Math.min(filter.limit ?? DEFAULT_LIMIT, MAX_LIMIT);

    // Count total matching rows (without limit)
    const countRow = db.prepare(`SELECT COUNT(*) AS cnt FROM audit_log ${where}`).get(params) as { cnt: number };
    const total = countRow.cnt;

    // Fetch the page
    const rows = db.prepare(
        `SELECT * FROM audit_log ${where} ORDER BY sequence ASC LIMIT @_limit`
    ).all({ ...params, _limit: limit + 1 }) as AuditRow[];

    const hasMore = rows.length > limit;
    if (hasMore) rows.pop();

    return { rows, total, hasMore };
}
