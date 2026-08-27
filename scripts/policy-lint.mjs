#!/usr/bin/env node
// policy-lint — validate the Cedar bundle in policies/ before anything loads it.
//
// Run with: npm run policy:lint
//
// This is deliberately a plain ESM script rather than part of a package: policy
// validation must be runnable in CI on a checkout with nothing built, and it is
// the one check that should never be blocked by a TypeScript error elsewhere in
// the tree. The typed loader in packages/policy-engine performs the same steps
// at startup; this script is the same contract enforced earlier.
//
// What it checks, in order:
//   1. the schema parses;
//   2. each policy file parses on its own (so errors name a file, not a bundle);
//   3. every policy carries @id, and every @id is unique across the bundle;
//   4. every permit carries a valid @sentinel_obligation, and no forbid does;
//   5. every policy carries a human-readable @sentinel_reason;
//   6. the combined bundle validates against the schema in strict mode, with
//      zero errors AND zero warnings.
//
// Rule 3 matters more than it looks. Cedar assigns positional ids (`policy0`,
// `policy1`, …) when a policy set is handed over as one blob of text, and those
// ids are what come back in `diagnostics.reason`. Positional ids shift the moment
// a policy is inserted, which would silently repoint every recorded decision's
// explanation at the wrong rule. So the loader keys the policy set by @id
// instead, and this script is what guarantees those keys exist and are unique.

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    checkParseSchema,
    getCedarVersion,
    policySetTextToParts,
    policyToJson,
    validate,
} from '@cedar-policy/cedar-wasm/nodejs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const POLICY_DIR = join(ROOT, 'policies');
const SCHEMA_PATH = join(POLICY_DIR, 'schema.cedarschema');

const VALID_OBLIGATIONS = new Set(['allow', 'review', 'approve']);

const problems = [];
const notes = [];

function fail(where, message, detail) {
    problems.push({ where, message, detail });
}

/** Cedar's DetailedError carries the useful text in nested fields. */
function formatCedarErrors(errors) {
    if (!Array.isArray(errors) || errors.length === 0) return '(no detail)';
    return errors
        .map(error => {
            const parts = [error.message ?? String(error)];
            if (error.help) parts.push(`help: ${error.help}`);
            const locations = error.sourceLocations ?? [];
            for (const location of locations) {
                if (location?.label) parts.push(`at: ${location.label}`);
            }
            return parts.join('\n      ');
        })
        .join('\n    - ');
}

// ─── 1. Schema ───────────────────────────────────────────────────────────────

const schema = readFileSync(SCHEMA_PATH, 'utf8');
const schemaParse = checkParseSchema(schema);
if (schemaParse.type !== 'success') {
    fail('schema.cedarschema', 'schema does not parse', formatCedarErrors(schemaParse.errors));
    report();
}

// ─── 2-5. Per-file parse and annotation rules ────────────────────────────────

const files = readdirSync(POLICY_DIR)
    .filter(name => name.endsWith('.cedar'))
    .sort();

if (files.length === 0) fail('policies/', 'no .cedar files found', undefined);

/** @type {Record<string, string>} policy id -> policy source */
const bundle = {};
/** @type {Map<string, string>} policy id -> declaring file, for duplicate reporting */
const origin = new Map();
const rows = [];

for (const file of files) {
    const text = readFileSync(join(POLICY_DIR, file), 'utf8');

    const parts = policySetTextToParts(text);
    if (parts.type !== 'success') {
        fail(file, 'file does not parse as a Cedar policy set', formatCedarErrors(parts.errors));
        continue;
    }
    if (parts.policy_templates.length > 0) {
        // Templates are a deliberate non-feature for now: they need link-time
        // ids, which would reintroduce exactly the positional-id problem the @id
        // convention exists to avoid.
        fail(file, `contains ${parts.policy_templates.length} policy template(s); templates are not supported`, undefined);
    }

    for (const [index, source] of parts.policies.entries()) {
        const json = policyToJson(source);
        if (json.type !== 'success') {
            fail(file, `policy #${index} does not convert to JSON`, formatCedarErrors(json.errors));
            continue;
        }

        const annotations = json.json.annotations ?? {};
        const effect = json.json.effect;
        const id = annotations.id;
        const label = id ?? `${file}#${index}`;

        if (id === undefined || id.length === 0) {
            fail(file, `policy #${index} has no @id annotation`, source.split('\n')[0]);
        } else if (origin.has(id)) {
            fail(file, `duplicate @id("${id}"), already declared in ${origin.get(id)}`, undefined);
        } else {
            origin.set(id, file);
            bundle[id] = source;
        }

        const obligation = annotations.sentinel_obligation;
        if (effect === 'permit') {
            if (obligation === undefined) {
                fail(file, `permit "${label}" has no @sentinel_obligation`, undefined);
            } else if (!VALID_OBLIGATIONS.has(obligation)) {
                fail(
                    file,
                    `permit "${label}" has @sentinel_obligation("${obligation}"), expected one of ${[...VALID_OBLIGATIONS].join(', ')}`,
                    undefined,
                );
            }
        } else if (obligation !== undefined) {
            // A forbid is unconditional; an obligation on one would imply the
            // denial could be softened by ceremony, which it cannot.
            fail(file, `forbid "${label}" carries @sentinel_obligation("${obligation}"); forbids take no obligation`, undefined);
        }

        if (annotations.sentinel_reason === undefined || annotations.sentinel_reason.length === 0) {
            // The reason is not decoration: it is the text a human reads in the
            // audit trail and the approval prompt.
            fail(file, `policy "${label}" has no @sentinel_reason`, undefined);
        }

        rows.push({
            file,
            id: label,
            effect,
            obligation: obligation ?? '—',
        });
    }
}

// ─── 6. Combined strict validation ───────────────────────────────────────────

if (Object.keys(bundle).length > 0) {
    const result = validate({
        schema,
        policies: { staticPolicies: bundle },
        validationSettings: { mode: 'strict' },
    });

    if (result.type !== 'success') {
        fail('bundle', 'validation call failed', formatCedarErrors(result.errors));
    } else {
        for (const error of result.validationErrors) {
            fail('bundle', `validation error in "${error.policyId ?? '?'}"`, formatCedarErrors([error.error ?? error]));
        }
        // Warnings are treated as failures. Cedar's warnings are things like an
        // impossible policy or an always-true condition — in an authorization
        // bundle those are bugs, not style notes.
        for (const warning of result.validationWarnings) {
            fail('bundle', `validation warning in "${warning.policyId ?? '?'}"`, formatCedarErrors([warning.error ?? warning]));
        }
        for (const warning of result.otherWarnings) {
            fail('bundle', 'validation warning', formatCedarErrors([warning]));
        }
    }
}

report();

// ─── Reporting ───────────────────────────────────────────────────────────────

function report() {
    const version = getCedarVersion();
    process.stdout.write(`policy-lint  (cedar ${version})\n\n`);

    let currentFile = '';
    for (const row of rows) {
        if (row.file !== currentFile) {
            currentFile = row.file;
            process.stdout.write(`  ${currentFile}\n`);
        }
        const effect = row.effect === 'forbid' ? 'forbid' : 'permit';
        process.stdout.write(`    ${effect.padEnd(7)} ${row.obligation.padEnd(8)} ${row.id}\n`);
    }

    const permits = rows.filter(row => row.effect === 'permit').length;
    const forbids = rows.length - permits;
    process.stdout.write(`\n  ${rows.length} policies (${permits} permit, ${forbids} forbid) in ${files?.length ?? 0} files\n`);

    for (const note of notes) process.stdout.write(`  note: ${note}\n`);

    if (problems.length === 0) {
        process.stdout.write('\n  OK — schema parses, annotations complete, bundle validates strictly.\n');
        process.exit(0);
    }

    process.stderr.write(`\n  ${problems.length} problem(s):\n`);
    for (const problem of problems) {
        process.stderr.write(`\n  [${problem.where}] ${problem.message}\n`);
        if (problem.detail) process.stderr.write(`    - ${problem.detail}\n`);
    }
    process.stderr.write('\n');
    process.exit(1);
}
