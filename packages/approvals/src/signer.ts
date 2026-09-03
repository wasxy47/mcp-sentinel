import { createHmac, timingSafeEqual } from 'crypto';

export class Signer {
    private secret: Buffer;
    private expirationMs: number;

    constructor(secretHex: string, expirationMs: number = 24 * 60 * 60 * 1000) {
        this.secret = Buffer.from(secretHex, 'hex');
        this.expirationMs = expirationMs;
    }

    public sign(approvalId: string, action: 'approve' | 'deny'): string {
        const expiresAt = Date.now() + this.expirationMs;
        const payload = `${approvalId}:${action}:${expiresAt}`;
        const hmac = createHmac('sha256', this.secret).update(payload).digest('hex');
        return `${payload}:${hmac}`;
    }

    public verify(token: string): { approvalId: string; action: 'approve' | 'deny' } {
        const parts = token.split(':');
        if (parts.length !== 4) {
            throw new Error('Invalid token format');
        }

        const [approvalId, action, expiresAtStr, providedHmac] = parts as [string, string, string, string];

        if (action !== 'approve' && action !== 'deny') {
            throw new Error('Invalid action in token');
        }

        const expiresAt = parseInt(expiresAtStr, 10);
        if (isNaN(expiresAt) || Date.now() > expiresAt) {
            throw new Error('Token has expired');
        }

        const payload = `${approvalId}:${action}:${expiresAt}`;
        const expectedHmac = createHmac('sha256', this.secret).update(payload).digest('hex');

        const providedBuffer = Buffer.from(providedHmac, 'hex');
        const expectedBuffer = Buffer.from(expectedHmac, 'hex');

        if (providedBuffer.length !== expectedBuffer.length || !timingSafeEqual(providedBuffer, expectedBuffer)) {
            throw new Error('Invalid signature');
        }

        return { approvalId, action };
    }
}
