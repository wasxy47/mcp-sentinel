/**
 * Secret redaction for the audit trail.
 *
 * Sentinel logs every tool call, which means Sentinel is a natural place for
 * credentials to accumulate: an agent calling `execute_sql` or `http_request`
 * routinely passes tokens as arguments. An audit database that faithfully
 * records those is a liability — it converts "attacker read one log file" into
 * "attacker has every credential the agent ever used".
 *
 * So arguments are redacted *before* they are written, by two independent
 * mechanisms:
 *   1. Pattern matching on values, for credentials with recognisable shapes.
 *   2. Key-name matching, for the long tail (`{"password": "hunter2"}` has no
 *      recognisable shape at all).
 *
 * The unredacted payload is never stored; its digest is (see `digestOf`), which
 * still lets an investigator prove what a call contained if they can produce a
 * candidate payload.
 */

import { createHmac } from 'node:crypto';

/** Where and what was redacted. Recorded alongside the row for triage. */
export interface RedactionFinding {
    /** JSON-path-ish location, e.g. `arguments.headers.Authorization`. */
    readonly path: string;
    /** Which rule fired, e.g. `aws-access-key-id` or `key-name:password`. */
    readonly kind: string;
}

export interface RedactionResult {
    /** The value with every secret replaced by a placeholder. */
    readonly value: unknown;
    /** One entry per redaction, in traversal order. */
    readonly findings: readonly RedactionFinding[];
    /** True when anything at all was redacted. */
    readonly redacted: boolean;
}

export interface RedactOptions {
    /**
     * Strings longer than this are truncated (before pattern matching) so a
     * single call cannot write an unbounded audit row. Defaults to 4 KiB.
     */
    readonly maxStringLength?: number;
    /** Objects/arrays deeper than this are replaced with a marker. Defaults to 12. */
    readonly maxDepth?: number;
    /**
     * When set, placeholders include a keyed HMAC prefix so the *same* secret is
     * recognisable across records without being recoverable from them. Unkeyed
     * hashing would not be safe here: a bare digest of a low-entropy secret like
     * a password is trivially brute-forced.
     */
    readonly correlationKey?: string;
}

/** Value-shape rules. Ordered most-specific first; all are applied. */
const VALUE_PATTERNS: ReadonlyArray<{ kind: string; pattern: RegExp }> = [
    { kind: 'private-key', pattern: /-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z]+)* PRIVATE KEY-----/g },
    { kind: 'private-key-header', pattern: /-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----/g },
    { kind: 'aws-access-key-id', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
    { kind: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
    { kind: 'slack-token', pattern: /\bxox[abprse]-[A-Za-z0-9-]{10,}/g },
    { kind: 'groq-api-key', pattern: /\bgsk_[A-Za-z0-9]{20,}\b/g },
    { kind: 'xai-api-key', pattern: /\bxai-[A-Za-z0-9]{20,}\b/g },
    { kind: 'openai-api-key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
    { kind: 'stripe-key', pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
    { kind: 'npm-token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
    { kind: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { kind: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
    { kind: 'bearer-token', pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}/gi },
    // Credentials embedded in a connection string or URL userinfo.
    { kind: 'url-credentials', pattern: /\b([a-z][a-z0-9+.-]*):\/\/[^\s:@/]+:[^\s@/]+@/gi }
];

/**
 * Key names whose value is redacted wholesale regardless of shape.
 *
 * Matched against *tokens*, not substrings. Substring matching on key names is
 * how naive redactors get both halves wrong at once: `/pass/` fires on
 * `compass` while `/(^|_)token/` misses `myToken`. Tokenising first — splitting
 * on separators and camelCase boundaries — makes both cases behave.
 *
 * The list is deliberately broad. A false positive costs one unreadable audit
 * field; a false negative costs a leaked credential.
 */
const SENSITIVE_TOKENS: ReadonlySet<string> = new Set([
    'password',
    'passwd',
    'pass',
    'passphrase',
    'secret',
    'secrets',
    'token',
    'apikey',
    'credential',
    'credentials',
    'authorization',
    'auth',
    'privatekey',
    'privkey',
    'cookie',
    'cookies',
    'accesskey',
    'secretkey',
    'refreshtoken',
    'accesstoken',
    'idtoken',
    'clientsecret',
    'sessionid',
    'sessiontoken',
    'signature',
    'bearer',
    'jwt',
    'otp',
    'pin'
]);

/**
 * Split a key into lowercase word tokens, handling `snake_case`, `kebab-case`,
 * `dotted.paths`, `camelCase` and `SCREAMING_CASE` alike.
 */
function tokenizeKey(key: string): readonly string[] {
    return key
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2') // apiKey    -> api Key
        .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2') // APIKey    -> API Key
        .split(/[^A-Za-z0-9]+/)
        .filter(token => token.length > 0)
        .map(token => token.toLowerCase());
}

/**
 * True when a key name says its value is a secret. Adjacent token pairs are
 * also tested joined, so `api_key`, `apiKey` and `APIKey` all resolve to the
 * single token `apikey`.
 */
export function isSensitiveKey(key: string): boolean {
    const tokens = tokenizeKey(key);
    for (let index = 0; index < tokens.length; index += 1) {
        if (SENSITIVE_TOKENS.has(tokens[index]!)) return true;
        const next = tokens[index + 1];
        if (next !== undefined && SENSITIVE_TOKENS.has(`${tokens[index]!}${next}`)) return true;
    }
    return false;
}


const DEFAULT_MAX_STRING = 4096;
const DEFAULT_MAX_DEPTH = 12;

/** Redact secrets from an arbitrary JSON-ish value. */
export function redact(value: unknown, options: RedactOptions = {}): RedactionResult {
    const maxStringLength = options.maxStringLength ?? DEFAULT_MAX_STRING;
    const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
    const findings: RedactionFinding[] = [];

    const placeholder = (kind: string, secret: string): string => {
        const parts = [`REDACTED:${kind}`, `len=${secret.length}`];
        if (options.correlationKey !== undefined) {
            const mac = createHmac('sha256', options.correlationKey).update(secret).digest('hex');
            parts.push(`id=${mac.slice(0, 12)}`);
        }
        return `[${parts.join(':')}]`;
    };

    const redactString = (input: string, path: string): string => {
        let text = input;
        if (text.length > maxStringLength) {
            text = `${text.slice(0, maxStringLength)}…[truncated ${input.length - maxStringLength} chars]`;
        }
        for (const { kind, pattern } of VALUE_PATTERNS) {
            // Fresh lastIndex each pass: the patterns are module-level and global.
            pattern.lastIndex = 0;
            if (!pattern.test(text)) continue;
            pattern.lastIndex = 0;
            text = text.replace(pattern, match => {
                findings.push({ path, kind });
                return placeholder(kind, match);
            });
        }
        return text;
    };

    const walk = (node: unknown, path: string, depth: number): unknown => {
        if (depth > maxDepth) return '[REDACTED:max-depth-exceeded]';

        if (typeof node === 'string') return redactString(node, path);
        if (node === null || typeof node !== 'object') return node;

        if (Array.isArray(node)) {
            return node.map((element, index) => walk(element, `${path}[${index}]`, depth + 1));
        }

        const output: Record<string, unknown> = {};
        for (const [key, entry] of Object.entries(node as Record<string, unknown>)) {
            const childPath = path === '' ? key : `${path}.${key}`;
            if (isSensitiveKey(key) && entry !== null && entry !== undefined) {
                // The value's shape is irrelevant — the key says it is a secret.
                const rendered = typeof entry === 'string' ? entry : JSON.stringify(entry) ?? '';
                findings.push({ path: childPath, kind: `key-name:${key.toLowerCase()}` });
                output[key] = placeholder('by-key-name', rendered);
                continue;
            }
            output[key] = walk(entry, childPath, depth + 1);
        }
        return output;
    };

    const result = walk(value, '', 0);
    return { value: result, findings, redacted: findings.length > 0 };
}

/**
 * Convenience for free text (a tool description, an LLM rationale) where only
 * the string form matters.
 */
export function redactText(text: string, options: RedactOptions = {}): string {
    const result = redact(text, options);
    return typeof result.value === 'string' ? result.value : text;
}
