/**
 * Cedar policy bundle loader.
 *
 * Loads every `*.cedar` file in the policy directory and combines them into a
 * `PolicyBundle` that the `PolicyEngine` can evaluate against. The bundle is
 * an opaque value — callers never touch Cedar APIs directly.
 *
 * ## Why the loader exists as a separate module
 *
 * - **Startup validation.** A bad policy file (missing `@id`, schema mismatch)
 *   should cause a hard failure at startup, not a silent allow at evaluation time.
 * - **Hot reload.** `reloadBundle()` replaces the bundle reference atomically.
 *   Because JS is single-threaded there is no torn-read risk: any evaluation
 *   already in progress holds a reference to the previous bundle object and will
 *   complete against it; the next evaluation sees the new one.
 * - **Test isolation.** Tests can load a minimal bundle without touching the
 *   real `policies/` directory.
 *
 * ## What the loader checks
 *
 * The same invariants as `npm run policy:lint`:
 *   1. Each file parses as a valid Cedar policy set.
 *   2. Every policy has a unique `@id`.
 *   3. Every permit has a valid `@sentinel_obligation`.
 *   4. No forbid has a `@sentinel_obligation` (a forbid takes no ceremony).
 *   5. Every policy has a `@sentinel_reason`.
 *   6. The schema converts to JSON (required by `isAuthorized`).
 *
 * It does NOT re-run Cedar's `validate()` (that is the lint script's job). The
 * loader trusts that CI ran the linter; it does the minimum needed to evaluate
 * safely.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { policySetTextToParts, policyToJson, schemaToJson } from '@cedar-policy/cedar-wasm/nodejs';

import type { Obligation } from '@mcp-sentinel/mcp-core';

/** Per-policy metadata extracted from Cedar annotations. */
export interface PolicyAnnotations {
    /** The .cedar file this policy was loaded from. */
    readonly file?: string;
    /** `@sentinel_obligation` value — present only on permit policies. */
    readonly obligation?: Obligation;
    /** `@sentinel_reason` value — human-readable justification. */
    readonly reason: string;
    /** Cedar effect: `'permit'` or `'forbid'`. */
    readonly effect: 'permit' | 'forbid';
}

/**
 * The pre-loaded policy bundle. Treat as opaque outside this module and
 * `engine.ts` — the Cedar API types are not re-exported.
 */
export interface PolicyBundle {
    /**
     * Cedar policy source strings keyed by `@id`.
     * Passed directly to `isAuthorized({ policies: { staticPolicies } })`.
     */
    readonly staticPolicies: Record<string, string>;
    /**
     * Annotations indexed by the same `@id` keys as `staticPolicies`.
     * Used after evaluation to resolve obligations and reasons.
     */
    readonly annotations: ReadonlyMap<string, PolicyAnnotations>;
    /**
     * Cedar schema in JSON format (from `schemaToJson()`).
     * Passed to `isAuthorized({ schema })` to enable schema-aware evaluation.
     */
    readonly schemaJson: unknown;
    readonly policyCount: number;
    readonly fileCount: number;
}

/** Thrown when the policy bundle cannot be loaded safely. */
export class PolicyLoadError extends Error {
    constructor(
        message: string,
        public readonly detail?: string,
    ) {
        super(message);
        this.name = 'PolicyLoadError';
    }
}

const VALID_OBLIGATIONS: ReadonlySet<string> = new Set(['allow', 'review', 'approve']);

/**
 * Load the Cedar policy bundle from `policyDir`.
 *
 * Reads every `*.cedar` file in sorted order (so policy ordering is
 * deterministic across platforms), extracts `@id` and annotations from
 * each policy, and converts the schema to JSON.
 *
 * @param policyDir   Directory containing `*.cedar` files.
 * @param schemaPath  Path to `schema.cedarschema`.
 * @throws `PolicyLoadError` on any validation failure.
 */
export function loadBundle(policyDir: string, schemaPath: string): PolicyBundle {
    // ── schema ────────────────────────────────────────────────────────────────
    const schemaText = readFileSync(schemaPath, 'utf8');
    const schemaResult = schemaToJson(schemaText);
    if (schemaResult.type !== 'success') {
        throw new PolicyLoadError(
            'Cedar schema does not convert to JSON',
            formatErrors(schemaResult.errors),
        );
    }
    const schemaJson: unknown = schemaResult.json;

    // ── policy files ──────────────────────────────────────────────────────────
    const files = readdirSync(policyDir)
        .filter(name => name.endsWith('.cedar'))
        .sort();

    if (files.length === 0) {
        throw new PolicyLoadError(`No .cedar files found in ${policyDir}`);
    }

    const staticPolicies: Record<string, string> = {};
    const annotations = new Map<string, PolicyAnnotations>();
    /** Policy id → declaring file, for duplicate error messages. */
    const origin = new Map<string, string>();

    for (const file of files) {
        const text = readFileSync(join(policyDir, file), 'utf8');
        const parts = policySetTextToParts(text);

        if (parts.type !== 'success') {
            throw new PolicyLoadError(
                `${file} does not parse as a Cedar policy set`,
                formatErrors(parts.errors),
            );
        }

        for (const [index, source] of parts.policies.entries()) {
            const jsonResult = policyToJson(source);
            if (jsonResult.type !== 'success') {
                throw new PolicyLoadError(
                    `${file} policy #${index} does not convert to JSON`,
                    formatErrors(jsonResult.errors),
                );
            }

            const ann = jsonResult.json.annotations ?? {};
            const effect = jsonResult.json.effect as 'permit' | 'forbid';
            const id: string | undefined = ann['id'];
            const label = id ?? `${file}#${index}`;

            if (!id) {
                throw new PolicyLoadError(`${file} policy #${index} has no @id annotation`);
            }
            if (origin.has(id)) {
                throw new PolicyLoadError(
                    `Duplicate @id("${id}") — also declared in ${origin.get(id)}`,
                    `Second occurrence in ${file}`,
                );
            }
            origin.set(id, file);

            const obligation: string | undefined = ann['sentinel_obligation'];
            const reason: string | undefined = ann['sentinel_reason'];

            if (effect === 'permit') {
                if (!obligation) {
                    throw new PolicyLoadError(
                        `${file} permit "${label}" has no @sentinel_obligation`,
                    );
                }
                if (!VALID_OBLIGATIONS.has(obligation)) {
                    throw new PolicyLoadError(
                        `${file} permit "${label}" has @sentinel_obligation("${obligation}"), ` +
                            `expected one of: ${[...VALID_OBLIGATIONS].join(', ')}`,
                    );
                }
            } else if (obligation !== undefined) {
                throw new PolicyLoadError(
                    `${file} forbid "${label}" carries @sentinel_obligation("${obligation}"); ` +
                        `forbids take no obligation`,
                );
            }

            if (!reason || reason.length === 0) {
                throw new PolicyLoadError(`${file} policy "${label}" has no @sentinel_reason`);
            }

            staticPolicies[id] = source;
            const annotationEntry: PolicyAnnotations =
                effect === 'permit'
                    ? { file, effect, obligation: obligation as Obligation, reason }
                    : { file, effect, reason };
            annotations.set(id, annotationEntry);
        }
    }

    return {
        staticPolicies,
        annotations,
        schemaJson,
        policyCount: Object.keys(staticPolicies).length,
        fileCount: files.length,
    };
}

/**
 * Reload the bundle from the same directories.
 *
 * Returns a fresh `PolicyBundle` — the caller is responsible for replacing
 * its reference. Throws `PolicyLoadError` on any problem, leaving the
 * previous bundle intact.
 */
export function reloadBundle(policyDir: string, schemaPath: string): PolicyBundle {
    return loadBundle(policyDir, schemaPath);
}

// ── helpers ───────────────────────────────────────────────────────────────────

function formatErrors(errors: unknown): string {
    if (!Array.isArray(errors) || errors.length === 0) return '(no detail)';
    return errors
        .map((e: unknown) => {
            if (typeof e === 'object' && e !== null && 'message' in e) {
                return String((e as { message: unknown }).message);
            }
            return String(e);
        })
        .join('; ');
}
