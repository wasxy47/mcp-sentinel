/**
 * Deterministic JSON serialisation and hashing.
 *
 * The audit trail is a hash chain, so "the same record" must produce byte-identical
 * input to SHA-256 on every machine, in every Node version, forever — otherwise
 * verification fails on data that was never tampered with. `JSON.stringify` does
 * not give that guarantee: object key order follows insertion order, so two
 * semantically identical records can hash differently.
 *
 * We therefore implement JSON Canonicalisation Scheme (RFC 8785): keys sorted by
 * UTF-16 code unit, no insignificant whitespace, ECMAScript number formatting.
 * JCS was chosen over "just sort the keys" because it is a written-down standard
 * an auditor can re-implement in another language to verify our chain
 * independently — which is the entire point of a tamper-evident log.
 */

import { createHash, timingSafeEqual } from 'node:crypto';

/** Thrown when a value cannot be canonicalised deterministically. */
export class CanonicalizationError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'CanonicalizationError';
    }
}

/**
 * Serialise `value` to its RFC 8785 canonical JSON form.
 *
 * Deviations from `JSON.stringify`, all in the direction of determinism:
 * - Object keys are emitted in UTF-16 code-unit order, not insertion order.
 * - `NaN`, `Infinity`, `-Infinity` and `BigInt` throw rather than becoming
 *   `null` or raising deep in a caller.
 * - `toJSON()` is deliberately *not* honoured: a record's hash must depend only
 *   on its data, never on a method that a future refactor could change.
 *
 * Matching `JSON.stringify`: `undefined` object properties are omitted, and
 * `undefined` array elements become `null`. Both are deterministic.
 */
export function canonicalize(value: unknown): string {
    const out: string[] = [];
    writeValue(value, out, new Set());
    return out.join('');
}

function writeValue(value: unknown, out: string[], seen: Set<object>): void {
    if (value === null) {
        out.push('null');
        return;
    }

    switch (typeof value) {
        case 'boolean':
            out.push(value ? 'true' : 'false');
            return;
        case 'number':
            if (!Number.isFinite(value)) {
                throw new CanonicalizationError(`non-finite number cannot be canonicalised: ${value}`);
            }
            // JSON.stringify implements ECMAScript Number::toString, which is
            // exactly what RFC 8785 specifies. -0 renders as "0".
            out.push(JSON.stringify(value === 0 ? 0 : value));
            return;
        case 'string':
            // JSON.stringify's string escaping already matches JCS: shorthand
            // escapes for \b \f \n \r \t \" \\, \u00xx for other control
            // characters, and non-ASCII left as literal UTF-8.
            out.push(JSON.stringify(value));
            return;
        case 'bigint':
            throw new CanonicalizationError('bigint cannot be canonicalised; convert to string first');
        case 'undefined':
        case 'function':
        case 'symbol':
            throw new CanonicalizationError(`${typeof value} cannot appear as a canonical JSON value`);
        default:
            break;
    }

    const object = value as object;
    if (seen.has(object)) {
        throw new CanonicalizationError('cannot canonicalise a circular structure');
    }
    seen.add(object);
    try {
        if (Array.isArray(object)) {
            out.push('[');
            for (let index = 0; index < object.length; index += 1) {
                if (index > 0) out.push(',');
                const element = object[index];
                if (element === undefined || typeof element === 'function' || typeof element === 'symbol') {
                    out.push('null');
                } else {
                    writeValue(element, out, seen);
                }
            }
            out.push(']');
            return;
        }

        const record = object as Record<string, unknown>;
        // Own enumerable string keys only, sorted by UTF-16 code unit. The
        // default Array#sort comparator compares code units, which is what JCS
        // requires — no custom comparator needed.
        const keys = Object.keys(record).sort();

        out.push('{');
        let first = true;
        for (const key of keys) {
            const entry = record[key];
            // Omitted, exactly as JSON.stringify would. Deterministic because it
            // depends only on the value being absent.
            if (entry === undefined || typeof entry === 'function' || typeof entry === 'symbol') continue;
            if (!first) out.push(',');
            first = false;
            out.push(JSON.stringify(key), ':');
            writeValue(entry, out, seen);
        }
        out.push('}');
    } finally {
        seen.delete(object);
    }
}

/** Lowercase hex SHA-256 of a string (UTF-8) or raw bytes. */
export function sha256Hex(input: string | Uint8Array): string {
    return createHash('sha256').update(input).digest('hex');
}

/**
 * Content digest of an arbitrary value: SHA-256 over its canonical JSON.
 *
 * Used to record *what* a tool was called with in the audit log without storing
 * the arguments themselves. A digest proves the payload later if someone
 * produces it, while leaking nothing if the database is stolen.
 */
export function digestOf(value: unknown): string {
    return sha256Hex(canonicalize(value));
}

/** The all-zero hash that precedes the first row of a chain. */
export const GENESIS_HASH = '0'.repeat(64);

/** True when two hex hashes are equal, compared without an early-exit timing leak. */
export function hashesEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}
