/**
 * Identifier minting.
 *
 * Every audit row, approval request and task handle needs an id with three
 * properties:
 *
 *   1. **Unguessable.** Approval ids appear in signed URLs; a sequential id
 *      would let anyone enumerate pending requests.
 *   2. **Lexicographically sortable by creation time.** The audit log is a chain
 *      read in order, and `ORDER BY id` sorting the same way as `ORDER BY seq`
 *      makes pagination cheap and keeps the SQLite index clustered on insert.
 *   3. **Prefixed.** `dec_01J...` in a log line says what kind of thing it is
 *      without a lookup, and mixing an approval id into a decision lookup fails
 *      loudly instead of quietly returning nothing.
 *
 * ULID (48-bit millisecond timestamp + 80 random bits, Crockford base32) gives
 * (1) and (2) together, which a random UUID does not — UUIDv4 scatters across
 * the index and carries no ordering. We implement it here rather than adding a
 * dependency: it is forty lines, and a supply-chain dependency for identifier
 * generation is a poor trade in a security tool.
 */

import { randomBytes } from 'node:crypto';

/** Crockford base32: no I, L, O or U, so ids survive being read aloud. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const TIME_LENGTH = 10;
const RANDOM_LENGTH = 16;
export const ULID_LENGTH = TIME_LENGTH + RANDOM_LENGTH;

/** Largest timestamp representable in 48 bits: year 10889. */
const MAX_TIME = 2 ** 48 - 1;

export class IdError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'IdError';
    }
}

function assertTimestampInRange(timestamp: number): void {
    if (!Number.isInteger(timestamp) || timestamp < 0 || timestamp > MAX_TIME) {
        throw new IdError(`timestamp out of range for a ULID: ${timestamp}`);
    }
}

function encodeTime(timestamp: number): string {
    let remaining = timestamp;
    let out = '';
    for (let index = 0; index < TIME_LENGTH; index += 1) {
        out = ALPHABET[remaining % 32]! + out;
        remaining = Math.floor(remaining / 32);
    }
    return out;
}

function randomChars(): string {
    // One byte per character. 256 is an exact multiple of 32, so `byte % 32` is
    // uniform — no modulo bias and no rejection sampling needed.
    const bytes = randomBytes(RANDOM_LENGTH);
    let out = '';
    for (const byte of bytes) out += ALPHABET[byte % 32]!;
    return out;
}

/**
 * Increment a base32 string as a big-endian number, for monotonicity within a
 * millisecond. Returns undefined on overflow (all `Z`), which happens with
 * probability 2^-80 and is handled by falling back to fresh randomness.
 */
function incrementChars(chars: string): string | undefined {
    const digits = [...chars];
    for (let index = digits.length - 1; index >= 0; index -= 1) {
        const position = ALPHABET.indexOf(digits[index]!);
        if (position < 0) return undefined;
        if (position < 31) {
            digits[index] = ALPHABET[position + 1]!;
            return digits.join('');
        }
        digits[index] = ALPHABET[0]!;
    }
    return undefined;
}

/**
 * A monotonic ULID source.
 *
 * The monotonicity guarantee needs state — the previous timestamp and random
 * component — and state at module scope is state that cannot be tested
 * deterministically or reasoned about in isolation. So it lives here, and the
 * `ulid()` function is a thin wrapper over one shared instance.
 */
export class UlidFactory {
    #lastTime = -1;
    #lastRandom = '';

    /**
     * Mint the next ULID.
     *
     * Two ids minted in the same millisecond still sort in creation order,
     * because the second reuses the first's random component incremented by one.
     * Without that, same-millisecond ids sort arbitrarily — which would let two
     * audit rows appear out of order relative to their chain sequence.
     *
     * @throws {IdError} if `now` is not a millisecond value in the 48-bit range.
     *   Validation happens before any state is mutated, so a bad call cannot
     *   leave the factory unusable.
     */
    public next(now: number = Date.now()): string {
        const timestamp = Math.floor(now);
        assertTimestampInRange(timestamp);

        if (timestamp > this.#lastTime) {
            this.#lastTime = timestamp;
            this.#lastRandom = randomChars();
            return encodeTime(this.#lastTime) + this.#lastRandom;
        }

        // Either the same millisecond, or the clock moved backwards (an NTP step,
        // or suspend/resume). Both are handled by incrementing within the previous
        // timestamp rather than emitting a smaller id: the audit chain's own
        // sequence number is authoritative for ordering, and a regressing id would
        // break `ORDER BY id` pagination. A backwards clock stays visible anyway,
        // because wall-clock time is recorded separately on the row.
        const next = incrementChars(this.#lastRandom);
        this.#lastRandom = next ?? randomChars();
        return encodeTime(this.#lastTime) + this.#lastRandom;
    }
}

const sharedFactory = new UlidFactory();

/** Mint a monotonic ULID from the process-wide generator. */
export function ulid(now: number = Date.now()): string {
    return sharedFactory.next(now);
}

/** Extract the creation time encoded in a ULID, or undefined if malformed. */
export function ulidTime(id: string): number | undefined {
    const body = id.includes('_') ? id.slice(id.indexOf('_') + 1) : id;
    if (body.length !== ULID_LENGTH) return undefined;
    let timestamp = 0;
    for (let index = 0; index < TIME_LENGTH; index += 1) {
        const position = ALPHABET.indexOf(body[index]!);
        if (position < 0) return undefined;
        timestamp = timestamp * 32 + position;
    }
    return timestamp;
}

/** Known id namespaces. Adding one here is how a new entity gets an id type. */
export const ID_PREFIX = {
    decision: 'dec',
    approval: 'apv',
    task: 'tsk',
    finding: 'fnd',
    trace: 'trc',
    checkpoint: 'ckp'
} as const;

export type IdKind = keyof typeof ID_PREFIX;

/** Mint a prefixed, sortable, unguessable id for `kind`. */
export function newId(kind: IdKind): string {
    return `${ID_PREFIX[kind]}_${ulid()}`;
}

/** True when `id` is a well-formed id of the given kind. */
export function isId(kind: IdKind, id: string): boolean {
    const prefix = `${ID_PREFIX[kind]}_`;
    if (!id.startsWith(prefix)) return false;
    const body = id.slice(prefix.length);
    if (body.length !== ULID_LENGTH) return false;
    for (const char of body) {
        if (!ALPHABET.includes(char)) return false;
    }
    return true;
}

/** ISO-8601 timestamp with millisecond precision, always UTC. */
export function isoTimestamp(now: number = Date.now()): string {
    return new Date(now).toISOString();
}
