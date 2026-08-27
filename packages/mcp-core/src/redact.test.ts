import { describe, expect, it } from 'vitest';

import { isSensitiveKey, redact, redactText } from './redact.js';

describe('isSensitiveKey', () => {
    it('matches separator-delimited and camelCase forms alike', () => {
        for (const key of [
            'password',
            'Password',
            'PASSWORD',
            'db_password',
            'db-password',
            'db.password',
            'apiKey',
            'api_key',
            'API_KEY',
            'x-api-key',
            'APIKey',
            'myToken',
            'access_token',
            'refreshToken',
            'privateKey',
            'Authorization',
            'clientSecret',
            'sessionId',
            'Cookie'
        ]) {
            expect(isSensitiveKey(key), key).toBe(true);
        }
    });

    it('does not fire on words that merely contain a sensitive substring', () => {
        // The failure mode of naive substring matching, in both directions.
        for (const key of ['compass', 'spinner', 'keyword', 'tokenizer', 'author', 'passenger', 'keys']) {
            expect(isSensitiveKey(key), key).toBe(false);
        }
    });

    it('leaves ordinary field names alone', () => {
        for (const key of ['path', 'query', 'limit', 'userId', 'file_name']) {
            expect(isSensitiveKey(key), key).toBe(false);
        }
    });
});

describe('redact — value shapes', () => {
    it('redacts credentials with recognisable shapes', () => {
        const cases: ReadonlyArray<[string, string]> = [
            ['ghp_' + 'a'.repeat(36), 'github-token'],
            ['AKIAIOSFODNN7EXAMPLE', 'aws-access-key-id'],
            ['gsk_' + 'b'.repeat(52), 'groq-api-key'],
            ['xai-' + 'c'.repeat(40), 'xai-api-key'],
            ['npm_' + 'd'.repeat(36), 'npm-token'],
            ['AIza' + 'e'.repeat(35), 'google-api-key'],
            ['xoxb-1234567890-abcdef', 'slack-token'],
            ['sk_live_' + 'f'.repeat(24), 'stripe-key']
        ];

        for (const [secret, kind] of cases) {
            const result = redact({ note: `the value is ${secret} ok` });
            expect(result.redacted, kind).toBe(true);
            expect(result.findings.map(finding => finding.kind), kind).toContain(kind);
            expect(JSON.stringify(result.value), kind).not.toContain(secret);
        }
    });

    it('redacts a JWT while leaving surrounding text readable', () => {
        const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        const result = redact({ note: `token=${jwt} end` });
        expect(result.findings[0]?.kind).toBe('jwt');
        expect(String((result.value as { note: string }).note)).toMatch(/^token=\[REDACTED:jwt:len=\d+\] end$/);
    });

    it('redacts credentials embedded in a connection URL', () => {
        const result = redact({ dsn: 'postgres://admin:hunter2@db.internal:5432/app' });
        expect(result.redacted).toBe(true);
        expect(JSON.stringify(result.value)).not.toContain('hunter2');
        // The host and database survive, which is what makes the log useful.
        expect(JSON.stringify(result.value)).toContain('db.internal:5432/app');
    });

    it('redacts a PEM private key block', () => {
        const pem = ['-----BEGIN RSA PRIVATE KEY-----', 'MIIEow', 'IBAAKCAQ', '-----END RSA PRIVATE KEY-----'].join('\n');
        const result = redact({ key: pem });
        expect(JSON.stringify(result.value)).not.toContain('MIIEow');
    });

    it('leaves benign values untouched', () => {
        const input = { path: '/tmp/report.csv', limit: 10, nested: { ok: true, list: [1, 2, 3] } };
        const result = redact(input);
        expect(result.redacted).toBe(false);
        expect(result.findings).toHaveLength(0);
        expect(result.value).toEqual(input);
    });
});

describe('redact — key names', () => {
    it('redacts by key name when the value has no recognisable shape', () => {
        const result = redact({ password: 'hunter2', user: 'alice' });
        expect(result.redacted).toBe(true);
        expect(result.findings).toEqual([{ path: 'password', kind: 'key-name:password' }]);
        expect(result.value).toEqual({
            password: '[REDACTED:by-key-name:len=7]',
            user: 'alice'
        });
    });

    it('redacts non-string values under a sensitive key wholesale', () => {
        const result = redact({ credentials: { user: 'alice', pass: 'hunter2' } });
        expect(JSON.stringify(result.value)).not.toContain('hunter2');
        expect(JSON.stringify(result.value)).not.toContain('alice');
    });

    it('records the full path of each finding', () => {
        const result = redact({ request: { headers: { Authorization: 'Basic abc' } } });
        expect(result.findings[0]?.path).toBe('request.headers.Authorization');
    });

    it('walks arrays and indexes their paths', () => {
        const result = redact({ steps: [{ ok: true }, { apiKey: 'x' }] });
        expect(result.findings[0]?.path).toBe('steps[1].apiKey');
    });

    it('leaves null and undefined alone rather than inventing a placeholder', () => {
        const result = redact({ password: null, token: undefined });
        expect(result.redacted).toBe(false);
        expect(result.value).toEqual({ password: null });
    });
});

describe('redact — limits', () => {
    it('truncates oversized strings so one call cannot write an unbounded row', () => {
        const result = redact({ blob: 'x'.repeat(5000) }, { maxStringLength: 100 });
        const blob = (result.value as { blob: string }).blob;
        expect(blob.startsWith('x'.repeat(100))).toBe(true);
        expect(blob).toContain('[truncated 4900 chars]');
        expect(blob.length).toBeLessThan(200);
    });

    it('stops at the depth limit', () => {
        let deep: unknown = 'bottom';
        for (let index = 0; index < 20; index += 1) deep = { nested: deep };
        const rendered = JSON.stringify(redact(deep, { maxDepth: 5 }).value);
        expect(rendered).toContain('[REDACTED:max-depth-exceeded]');
        expect(rendered).not.toContain('bottom');
    });
});

describe('redact — correlation ids', () => {
    const secret = 'ghp_' + 'a'.repeat(36);

    it('omits the correlation id unless a key is supplied', () => {
        expect(redactText(secret)).toMatch(/^\[REDACTED:github-token:len=40\]$/);
    });

    it('gives the same secret the same id under the same key', () => {
        const options = { correlationKey: 'k1' };
        expect(redactText(secret, options)).toBe(redactText(secret, options));
    });

    it('gives different ids under different keys, so ids are not a global oracle', () => {
        expect(redactText(secret, { correlationKey: 'k1' })).not.toBe(
            redactText(secret, { correlationKey: 'k2' })
        );
    });

    it('gives different secrets different ids under one key', () => {
        const other = 'ghp_' + 'b'.repeat(36);
        expect(redactText(secret, { correlationKey: 'k1' })).not.toBe(
            redactText(other, { correlationKey: 'k1' })
        );
    });

    it('emits a 12-hex-character id', () => {
        expect(redactText(secret, { correlationKey: 'k1' })).toMatch(
            /^\[REDACTED:github-token:len=40:id=[0-9a-f]{12}\]$/
        );
    });
});

describe('redact — statelessness', () => {
    it('is not affected by regex lastIndex carrying across calls', () => {
        // The value patterns are module-level and global; a leaked lastIndex
        // would make the second call miss the secret entirely.
        const secret = 'AKIAIOSFODNN7EXAMPLE';
        const first = redact({ a: secret, b: secret });
        expect(first.findings.filter(finding => finding.kind === 'aws-access-key-id')).toHaveLength(2);
        const second = redact({ a: secret });
        expect(second.redacted).toBe(true);
    });
});

describe('redactText', () => {
    it('redacts free text and returns a string', () => {
        expect(redactText('use AKIAIOSFODNN7EXAMPLE now')).toBe(
            'use [REDACTED:aws-access-key-id:len=20] now'
        );
    });

    it('passes clean text through unchanged', () => {
        expect(redactText('nothing to see here')).toBe('nothing to see here');
    });
});
