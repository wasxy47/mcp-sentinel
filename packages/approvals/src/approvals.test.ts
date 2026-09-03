import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Signer } from './signer.js';
import { ApprovalStore } from './store.js';
import { randomBytes } from 'crypto';
import { mkdirSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

// ── Signer tests ────────────────────────────────────────────────────────────

describe('Signer', () => {
    const secret = randomBytes(32).toString('hex');

    it('signs and verifies a valid token', () => {
        const signer = new Signer(secret);
        const token = signer.sign('apv_01', 'approve');
        const result = signer.verify(token);
        expect(result.approvalId).toBe('apv_01');
        expect(result.action).toBe('approve');
    });

    it('signs and verifies a deny token', () => {
        const signer = new Signer(secret);
        const token = signer.sign('apv_02', 'deny');
        const result = signer.verify(token);
        expect(result.approvalId).toBe('apv_02');
        expect(result.action).toBe('deny');
    });

    it('rejects a tampered token', () => {
        const signer = new Signer(secret);
        const token = signer.sign('apv_03', 'approve');
        // Tamper: change the last character of the HMAC
        const parts = token.split(':');
        parts[3] = parts[3]!.slice(0, -1) + (parts[3]!.endsWith('0') ? '1' : '0');
        const tampered = parts.join(':');
        expect(() => signer.verify(tampered)).toThrow('Invalid signature');
    });

    it('rejects an expired token', async () => {
        // Use a very short expiration (1 ms) and wait for it
        const signer = new Signer(secret, 1);
        const token = signer.sign('apv_04', 'approve');
        // Force expiration by modifying the expiry in the token
        const parts = token.split(':');
        parts[2] = String(Date.now() - 1000); // 1 second in the past
        // Re-sign with correct HMAC for the tampered payload
        // This won't work since we can't re-sign, so use a different approach:
        // Create a signer with 0ms expiry
        const expiredSigner = new Signer(secret, 0);
        const expiredToken = expiredSigner.sign('apv_05', 'approve');
        // Wait a tick to ensure expiry
        await new Promise(r => setTimeout(r, 10));
        expect(() => expiredSigner.verify(expiredToken)).toThrow('Token has expired');
    });

    it('rejects a malformed token', () => {
        const signer = new Signer(secret);
        expect(() => signer.verify('not-a-valid-token')).toThrow('Invalid token format');
    });

    it('rejects a token with an invalid action', () => {
        const signer = new Signer(secret);
        expect(() => signer.verify('id:invalid:12345:abcd')).toThrow('Invalid action in token');
    });

    it('tokens signed with different secrets do not verify', () => {
        const signer1 = new Signer(randomBytes(32).toString('hex'));
        const signer2 = new Signer(randomBytes(32).toString('hex'));
        const token = signer1.sign('apv_06', 'approve');
        expect(() => signer2.verify(token)).toThrow('Invalid signature');
    });
});

// ── ApprovalStore tests ─────────────────────────────────────────────────────

describe('ApprovalStore', () => {
    let dbPath: string;
    let store: ApprovalStore;
    let tmpDir: string;

    beforeEach(() => {
        tmpDir = join(tmpdir(), `sentinel-test-${randomBytes(4).toString('hex')}`);
        mkdirSync(tmpDir, { recursive: true });
        dbPath = join(tmpDir, 'approvals.db');
        store = new ApprovalStore(dbPath);
    });

    afterEach(() => {
        if (existsSync(tmpDir)) {
            rmSync(tmpDir, { recursive: true, force: true });
        }
    });

    it('creates and retrieves an approval request', () => {
        store.create({
            approvalId: 'apv_01',
            agentId: 'agent-a',
            method: 'tools/call',
            qualifiedName: 'files__write_file',
            params: '{"path":"/etc/passwd"}',
            state: 'pending',
            requestedAt: new Date().toISOString()
        });

        const result = store.get('apv_01');
        expect(result).toBeDefined();
        expect(result!.approvalId).toBe('apv_01');
        expect(result!.agentId).toBe('agent-a');
        expect(result!.state).toBe('pending');
    });

    it('returns undefined for a non-existent approval', () => {
        expect(store.get('nonexistent')).toBeUndefined();
    });

    it('transitions from pending to approved', () => {
        store.create({
            approvalId: 'apv_02',
            agentId: 'agent-b',
            method: 'tools/call',
            qualifiedName: 'db__drop_table',
            params: '{}',
            state: 'pending',
            requestedAt: new Date().toISOString()
        });

        store.updateState('apv_02', 'approved', 'admin-user', 'Looks safe');
        const result = store.get('apv_02');
        expect(result!.state).toBe('approved');
        expect(result!.approver).toBe('admin-user');
        expect(result!.reason).toBe('Looks safe');
        expect(result!.decidedAt).toBeDefined();
    });

    it('transitions from pending to denied', () => {
        store.create({
            approvalId: 'apv_03',
            agentId: 'agent-c',
            method: 'tools/call',
            qualifiedName: 'files__delete_file',
            params: '{}',
            state: 'pending',
            requestedAt: new Date().toISOString()
        });

        store.updateState('apv_03', 'denied', 'admin-user', 'Too risky');
        const result = store.get('apv_03');
        expect(result!.state).toBe('denied');
    });

    it('rejects a state transition on a non-pending approval (replay prevention)', () => {
        store.create({
            approvalId: 'apv_04',
            agentId: 'agent-d',
            method: 'tools/call',
            qualifiedName: 'files__write_file',
            params: '{}',
            state: 'pending',
            requestedAt: new Date().toISOString()
        });

        store.updateState('apv_04', 'approved', 'admin');
        // Second attempt to transition — should fail (single-use)
        expect(() => store.updateState('apv_04', 'denied', 'admin')).toThrow('not in pending state');
    });

    it('rejects approve-then-deny (single-use tokens)', () => {
        store.create({
            approvalId: 'apv_05',
            agentId: 'agent-e',
            method: 'tools/call',
            qualifiedName: 'files__write_file',
            params: '{}',
            state: 'pending',
            requestedAt: new Date().toISOString()
        });

        store.updateState('apv_05', 'approved', 'admin');
        // Try to deny after already approved
        expect(() => store.updateState('apv_05', 'denied', 'admin')).toThrow('not in pending state');
    });

    it('rejects transition for non-existent approval', () => {
        expect(() => store.updateState('nonexistent', 'approved', 'admin')).toThrow('not in pending state');
    });
});
