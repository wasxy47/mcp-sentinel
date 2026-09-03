import Database from 'better-sqlite3';
import { join } from 'path';
import { mkdirSync } from 'fs';

export type ApprovalState = 'pending' | 'approved' | 'denied' | 'expired';

export interface ApprovalRequest {
    readonly approvalId: string;
    readonly agentId: string;
    readonly method: string;
    readonly qualifiedName: string;
    readonly params: string; // JSON string of the original params
    readonly state: ApprovalState;
    readonly requestedAt: string;
    readonly decidedAt?: string;
    readonly approver?: string;
    readonly reason?: string;
}

export class ApprovalStore {
    private db: Database.Database;

    constructor(dbPath: string) {
        mkdirSync(join(dbPath, '..'), { recursive: true });
        this.db = new Database(dbPath);
        this.init();
    }

    private init() {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS approvals (
                approvalId TEXT PRIMARY KEY,
                agentId TEXT NOT NULL,
                method TEXT NOT NULL,
                qualifiedName TEXT NOT NULL,
                params TEXT NOT NULL,
                state TEXT NOT NULL,
                requestedAt TEXT NOT NULL,
                decidedAt TEXT,
                approver TEXT,
                reason TEXT
            )
        `);
    }

    public create(request: ApprovalRequest): void {
        const stmt = this.db.prepare(`
            INSERT INTO approvals (
                approvalId, agentId, method, qualifiedName, params, state, requestedAt
            ) VALUES (
                @approvalId, @agentId, @method, @qualifiedName, @params, @state, @requestedAt
            )
        `);
        stmt.run(request);
    }

    public get(approvalId: string): ApprovalRequest | undefined {
        const stmt = this.db.prepare(`SELECT * FROM approvals WHERE approvalId = ?`);
        const row = stmt.get(approvalId) as ApprovalRequest | undefined;
        return row;
    }

    public updateState(approvalId: string, state: ApprovalState, approver?: string, reason?: string): void {
        const decidedAt = new Date().toISOString();
        const stmt = this.db.prepare(`
            UPDATE approvals
            SET state = @state, decidedAt = @decidedAt, approver = @approver, reason = @reason
            WHERE approvalId = @approvalId AND state = 'pending'
        `);
        const result = stmt.run({ approvalId, state, decidedAt, approver, reason });
        if (result.changes === 0) {
            throw new Error(`Approval ${approvalId} is not in pending state or does not exist`);
        }
    }
}
