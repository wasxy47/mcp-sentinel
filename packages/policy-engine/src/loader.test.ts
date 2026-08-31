/**
 * Loader tests.
 *
 * Validates that the bundle loader applies the same invariants as
 * `npm run policy:lint`: @id uniqueness, obligation on permits,
 * no obligation on forbids, reason presence.
 *
 * These tests use the real `policies/` bundle to ensure the loader actually
 * works against the shipped policy set, and use a temp-directory approach
 * for negative cases.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, afterEach } from 'vitest';

import { loadBundle, reloadBundle, PolicyLoadError } from './loader.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const POLICIES_DIR = path.resolve(__dirname, '../../../policies');
const SCHEMA_PATH = path.join(POLICIES_DIR, 'schema.cedarschema');

// ── Real bundle ───────────────────────────────────────────────────────────────

describe('loadBundle (real policies/)', () => {
    it('loads the real policy bundle without error', () => {
        const bundle = loadBundle(POLICIES_DIR, SCHEMA_PATH);
        expect(bundle.policyCount).toBeGreaterThan(0);
        expect(bundle.fileCount).toBeGreaterThan(0);
    });

    it('loads exactly 42 policies (the expected bundle size)', () => {
        const bundle = loadBundle(POLICIES_DIR, SCHEMA_PATH);
        // If this number changes, a policy was added or removed — update the count.
        expect(bundle.policyCount).toBe(42);
    });

    it('every permit has an obligation', () => {
        const bundle = loadBundle(POLICIES_DIR, SCHEMA_PATH);
        for (const [id, ann] of bundle.annotations) {
            if (ann.effect === 'permit') {
                expect(ann.obligation, `permit "${id}" should have an obligation`).toBeDefined();
                expect(['allow', 'review', 'approve']).toContain(ann.obligation);
            }
        }
    });

    it('no forbid has an obligation', () => {
        const bundle = loadBundle(POLICIES_DIR, SCHEMA_PATH);
        for (const [id, ann] of bundle.annotations) {
            if (ann.effect === 'forbid') {
                expect(ann.obligation, `forbid "${id}" should NOT have an obligation`).toBeUndefined();
            }
        }
    });

    it('every policy has a non-empty reason', () => {
        const bundle = loadBundle(POLICIES_DIR, SCHEMA_PATH);
        for (const [id, ann] of bundle.annotations) {
            expect(ann.reason, `policy "${id}" should have a reason`).toBeTruthy();
        }
    });

    it('schemaJson is a non-null object', () => {
        const bundle = loadBundle(POLICIES_DIR, SCHEMA_PATH);
        expect(bundle.schemaJson).toBeDefined();
        expect(typeof bundle.schemaJson).toBe('object');
        expect(bundle.schemaJson).not.toBeNull();
    });

    it('staticPolicies keys match annotation keys', () => {
        const bundle = loadBundle(POLICIES_DIR, SCHEMA_PATH);
        const policyKeys = new Set(Object.keys(bundle.staticPolicies));
        const annotationKeys = new Set(bundle.annotations.keys());
        expect(policyKeys).toEqual(annotationKeys);
    });
});

describe('reloadBundle', () => {
    it('returns a fresh object reference each time', () => {
        const b1 = loadBundle(POLICIES_DIR, SCHEMA_PATH);
        const b2 = reloadBundle(POLICIES_DIR, SCHEMA_PATH);
        expect(b1).not.toBe(b2); // different object instances
        expect(b1.policyCount).toBe(b2.policyCount); // same contents
    });
});

// ── Negative cases in a temp dir ──────────────────────────────────────────────

let tmpDir: string;

function setup(files: Record<string, string>): void {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), 'sentinel-loader-test-'));
    for (const [name, content] of Object.entries(files)) {
        writeFileSync(path.join(tmpDir, name), content, 'utf8');
    }
}

afterEach(() => {
    if (tmpDir) rmSync(tmpDir, { recursive: true, force: true });
});

const MINIMAL_POLICY = `
@id("test_allow")
@sentinel_obligation("allow")
@sentinel_reason("Test policy")
permit (
    principal,
    action == Sentinel::Action::"listTools",
    resource == Sentinel::Endpoint::"gateway"
);
`;

describe('loadBundle (validation failures)', () => {
    it('throws PolicyLoadError when no .cedar files exist', () => {
        setup({});
        expect(() => loadBundle(tmpDir, SCHEMA_PATH)).toThrow(PolicyLoadError);
    });

    it('throws on a file with no @id annotation', () => {
        setup({
            'bad.cedar': `
@sentinel_obligation("allow")
@sentinel_reason("missing id")
permit (principal, action, resource);
`,
        });
        expect(() => loadBundle(tmpDir, SCHEMA_PATH)).toThrow(PolicyLoadError);
    });

    it('throws on duplicate @id across files', () => {
        setup({
            '01.cedar': MINIMAL_POLICY,
            '02.cedar': MINIMAL_POLICY, // same @id
        });
        expect(() => loadBundle(tmpDir, SCHEMA_PATH)).toThrow(/uplicate|dup/i);
    });

    it('throws when a permit has no @sentinel_obligation', () => {
        setup({
            'bad.cedar': `
@id("missing_obligation")
@sentinel_reason("Some reason")
permit (principal, action, resource);
`,
        });
        expect(() => loadBundle(tmpDir, SCHEMA_PATH)).toThrow(PolicyLoadError);
    });

    it('throws when a permit has an invalid @sentinel_obligation', () => {
        setup({
            'bad.cedar': `
@id("bad_obligation")
@sentinel_obligation("maybe")
@sentinel_reason("Some reason")
permit (principal, action, resource);
`,
        });
        expect(() => loadBundle(tmpDir, SCHEMA_PATH)).toThrow(PolicyLoadError);
    });

    it('throws when a forbid carries @sentinel_obligation', () => {
        setup({
            'bad.cedar': `
@id("forbid_with_obligation")
@sentinel_obligation("allow")
@sentinel_reason("A forbid should never have an obligation")
forbid (principal, action, resource);
`,
        });
        expect(() => loadBundle(tmpDir, SCHEMA_PATH)).toThrow(PolicyLoadError);
    });

    it('throws when a policy has no @sentinel_reason', () => {
        setup({
            'bad.cedar': `
@id("no_reason")
@sentinel_obligation("allow")
permit (principal, action, resource);
`,
        });
        expect(() => loadBundle(tmpDir, SCHEMA_PATH)).toThrow(PolicyLoadError);
    });
});
