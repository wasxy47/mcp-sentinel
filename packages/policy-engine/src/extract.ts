/**
 * Context extraction — deterministic feature engineering for Cedar.
 *
 * Cedar policies operate on a `context` record whose fields are *features*
 * extracted from the request arguments. All extraction is static inspection —
 * no model, no external calls — so policy decisions are reproducible and
 * auditable with nothing but the argument values and the workspace config.
 *
 * This module is the most security-sensitive piece of M2: every field here
 * feeds directly into a policy decision. Conservative defaults are mandatory:
 * when in doubt, set the flag that triggers the stricter policy.
 *
 * ## Extraction strategy per field
 *
 * | Field                  | Approach                                              |
 * |------------------------|-------------------------------------------------------|
 * | `pathsWithinWorkspace` | `path.resolve` against workspaceRoot; prefix check    |
 * | `hasParentTraversal`   | raw string `..` segment detection (before resolution) |
 * | `hasSensitivePath`     | hardcoded sensitive path pattern list                 |
 * | `hasUrl` / `urlHosts`  | regex URL detection; hostname extraction              |
 * | `hasExternalUrl`       | hostname vs. allowlist                                |
 * | `sqlKind`              | first-keyword classification; `'unknown'` on failure  |
 * | `hasShellMetacharacters` | character set: `; | & $ > < ` \n {}` etc.           |
 * | `containsCredential`   | reuses `mcp-core` redaction patterns                  |
 * | `hasInvisibleUnicode`  | zero-width / bidi / tag character regex               |
 */

import * as path from 'node:path';

import { digestOf, isSensitiveKey, redact } from '@mcp-sentinel/mcp-core';

// ── Cedar context types (match schema.cedarschema exactly) ───────────────────

export interface BaseContext {
    readonly protocolVersion: string;
    readonly argsDigest: string;
    readonly hourUtc: number;
}

export interface ToolCallContext extends BaseContext {
    // shape
    readonly argCount: number;
    readonly argBytes: number;
    // filesystem
    readonly pathsWithinWorkspace: boolean;
    readonly hasAbsolutePath: boolean;
    readonly hasParentTraversal: boolean;
    readonly hasSensitivePath: boolean;
    readonly fileExtensions: readonly string[];
    // network
    readonly hasUrl: boolean;
    readonly urlHosts: readonly string[];
    readonly hasExternalUrl: boolean;
    // sql
    readonly sqlKind: SqlKind;
    readonly sqlIsDestructive: boolean;
    readonly sqlIsMultiStatement: boolean;
    // shell
    readonly hasShellMetacharacters: boolean;
    // payload
    readonly containsCredential: boolean;
    readonly hasInvisibleUnicode: boolean;
    // denormalised upstream posture
    readonly serverTrust: string;
    readonly toolScanVerdict: string;
    // second-pass only (optional)
    readonly riskScore?: number;
    readonly riskBand?: string;
    readonly approvalId?: string;
}

export interface ResourceReadContext extends BaseContext {
    readonly scheme: string;
    readonly pathsWithinWorkspace: boolean;
    readonly hasSensitivePath: boolean;
    readonly hasExternalUrl: boolean;
    readonly serverTrust: string;
}

export type SqlKind = 'none' | 'select' | 'insert' | 'update' | 'delete' | 'ddl' | 'unknown';

export interface ExtractConfig {
    /** Absolute path. Paths in arguments are resolved against this root. */
    readonly workspaceRoot: string;
    /** Hostnames that are considered internal. URLs pointing elsewhere are external. */
    readonly allowedHosts: readonly string[];
    /** MCP protocol version of the request. */
    readonly protocolVersion: string;
    /** Trust posture of the upstream server. */
    readonly serverTrust: string;
    /** Scanner verdict for this tool. */
    readonly toolScanVerdict: string;
}

// ── Public extraction API ─────────────────────────────────────────────────────

/**
 * Extract the Cedar `context` record for a `tools/call` request.
 *
 * `args` is `params.arguments` — may be any JSON value. Undefined/null are
 * treated as an empty argument set.
 */
export function extractToolCallContext(
    args: unknown,
    config: ExtractConfig,
): ToolCallContext {
    const argsObj = toObject(args);
    const strings = collectStrings(argsObj);
    const argBytes = Buffer.byteLength(JSON.stringify(args ?? {}), 'utf8');

    const paths = extractPaths(strings);
    const urls = extractUrls(strings);
    const sqlStr = extractSql(strings);

    const argsDigest = digestOf(args ?? {});

    return {
        protocolVersion: config.protocolVersion,
        argsDigest,
        hourUtc: new Date().getUTCHours(),

        argCount: Object.keys(argsObj).length,
        argBytes,

        pathsWithinWorkspace: paths.allWithin(config.workspaceRoot),
        hasAbsolutePath: paths.hasAbsolute,
        hasParentTraversal: paths.hasParentTraversal,
        hasSensitivePath: paths.hasSensitive,
        fileExtensions: paths.extensions,

        hasUrl: urls.found,
        urlHosts: urls.hosts,
        hasExternalUrl: urls.hasExternal(config.allowedHosts),

        sqlKind: sqlStr.kind,
        sqlIsDestructive: sqlStr.isDestructive,
        sqlIsMultiStatement: sqlStr.isMultiStatement,

        hasShellMetacharacters: strings.some(hasShellMetacharacters),
        containsCredential: detectCredential(args),
        hasInvisibleUnicode: strings.some(hasInvisibleUnicode),

        serverTrust: config.serverTrust,
        toolScanVerdict: config.toolScanVerdict,
    };
}

/**
 * Extract the Cedar `context` record for a `resources/read` request.
 *
 * `qualifiedUri` is the mcp-sentinel:// wrapped URI that was routed;
 * `rawUri` is the bare upstream URI after unwrapping.
 */
export function extractResourceReadContext(
    rawUri: string,
    config: ExtractConfig,
): ResourceReadContext {
    const scheme = extractScheme(rawUri);
    const argsDigest = digestOf({ uri: rawUri });

    return {
        protocolVersion: config.protocolVersion,
        argsDigest,
        hourUtc: new Date().getUTCHours(),

        scheme,
        pathsWithinWorkspace: isUriWithinWorkspace(rawUri, config.workspaceRoot),
        hasSensitivePath: isSensitivePath(rawUri),
        hasExternalUrl: isExternalUri(rawUri, config.allowedHosts),
        serverTrust: config.serverTrust,
    };
}

/** Extract the Cedar `context` record for listing/discovery/governance actions. */
export function extractBaseContext(protocolVersion: string, payload: unknown = {}): BaseContext {
    return {
        protocolVersion,
        argsDigest: digestOf(payload),
        hourUtc: new Date().getUTCHours(),
    };
}

// ── Internals ─────────────────────────────────────────────────────────────────

/** Invisible / direction-control Unicode codepoints.
 *
 * Targets:
 * - Soft hyphen, Hangul fillers, Arabic letter mark
 * - Variation selectors, Mongolian free variation selectors
 * - Zero-width space/non-joiner/joiner, word/line/paragraph separators
 * - Directional marks, isolates, embeddings, overrides (bidi)
 * - Interlinear/function annotation chars
 * - Tag characters (U+E0000 range) — invisible instruction injectors
 * - BOM / zero-width no-break space
 *
 * Does NOT match emoji or CJK supplementary characters — those use
 * surrogate pairs in UTF-16 but are NOT in any of the above ranges.
 */
const INVISIBLE_UNICODE_RE =
    /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\u3164\uFEFF\uFFA0\uFFF0-\uFFF8]|\u{E0000}|\u{E0001}|[\u{E0020}-\u{E007F}]/u;

export function hasInvisibleUnicode(s: string): boolean {
    // Reset lastIndex safety: using .test() with a regex without /g is fine,
    // but we keep the regex non-global to avoid stale lastIndex across calls.
    return INVISIBLE_UNICODE_RE.test(s);
}

/**
 * Shell metacharacters that have no place in a legitimate tool argument.
 *
 * Semicolons, pipes, ampersands, dollar signs (variable expansion), backticks,
 * angle brackets (redirection), and newlines all let a shell argument escape
 * its intended context.
 */
const SHELL_META_RE = /[;&|$`<>\n{}\\\r]/;

function hasShellMetacharacters(s: string): boolean {
    return SHELL_META_RE.test(s);
}

/**
 * URL regex — conservative, but enough to catch http/https/ftp URLs embedded
 * in argument values. Does not try to parse URLs that are not string values.
 */
const URL_RE = /\b(https?|ftp):\/\/([^\s/?#]+)([^\s]*)?/gi;

function extractUrls(strings: string[]): {
    found: boolean;
    hosts: string[];
    hasExternal: (allowlist: readonly string[]) => boolean;
} {
    const hosts: string[] = [];
    for (const s of strings) {
        URL_RE.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = URL_RE.exec(s)) !== null) {
            const host = m[2]?.toLowerCase();
            if (host) hosts.push(host);
        }
    }
    return {
        found: hosts.length > 0,
        hosts,
        hasExternal: (allowlist) =>
            hosts.some(h => !allowlist.some(a => h === a.toLowerCase() || h.endsWith('.' + a.toLowerCase()))),
    };
}

/** Known-sensitive path patterns (relative or absolute). */
const SENSITIVE_PATH_PATTERNS: ReadonlyArray<RegExp> = [
    /(?:^|[\\/])\.ssh(?:[\\/]|$)/i,
    /(?:^|[\\/])\.aws(?:[\\/]|$)/i,
    /(?:^|[\\/])\.gnupg(?:[\\/]|$)/i,
    /(?:^|[\\/])\.pgpass$/i,
    /(?:^|[\\/])\.netrc$/i,
    /(?:^|[\\/])\.env(?:\.[a-z]+)?$/i,
    /(?:^|[\\/])\.npmrc$/i,
    /(?:^|[\\/])\.pypirc$/i,
    /(?:^|[\\/])\.docker(?:[\\/]|$)/i,
    /(?:^|[\\/])id_(?:rsa|ecdsa|ed25519|dsa)(?:\.pub)?$/i,
    /\.pem$/i,
    /\.p12$/i,
    /\.pfx$/i,
    /(?:^|[\\/])keystore(?:\.jks)?$/i,
    /(?:^|[\\/])credentials$/i,
    /(?:^|[\\/])secrets(?:[\\/]|$)/i,
    /\/proc\/self\//i,
    /\/etc\/shadow$/i,
    /\/etc\/passwd$/i,
    /\/etc\/sudoers/i,
];

function isSensitivePath(p: string): boolean {
    return SENSITIVE_PATH_PATTERNS.some(re => re.test(p));
}

/** Detect a `..` *segment* (not just the characters) in a path-like string. */
function hasParentTraversalSegment(s: string): boolean {
    // Split on both / and \ to handle Windows-style paths too.
    return s.split(/[/\\]/).some(seg => seg === '..');
}

function extractPaths(strings: string[]): {
    allWithin: (root: string) => boolean;
    hasAbsolute: boolean;
    hasParentTraversal: boolean;
    hasSensitive: boolean;
    extensions: string[];
} {
    const pathLike = strings.filter(s => s.includes('/') || s.includes('\\') || s.startsWith('.'));
    const hasParentTraversal = pathLike.some(hasParentTraversalSegment);
    const hasAbsolute = pathLike.some(s => path.isAbsolute(s));
    const hasSensitive = strings.some(isSensitivePath);

    const extensions: string[] = [];
    for (const s of pathLike) {
        const ext = path.extname(s);
        if (ext && !extensions.includes(ext)) extensions.push(ext);
    }

    return {
        allWithin: (root: string) => {
            if (pathLike.length === 0) return true; // no paths → nothing escaped
            const normalRoot = path.resolve(root) + path.sep;
            return pathLike.every(p => {
                const resolved = path.resolve(root, p);
                return resolved === path.resolve(root) || resolved.startsWith(normalRoot);
            });
        },
        hasAbsolute,
        hasParentTraversal,
        hasSensitive,
        extensions,
    };
}

// ── SQL classification ────────────────────────────────────────────────────────

const DDL_KEYWORDS = new Set(['create', 'drop', 'alter', 'truncate', 'rename']);
const DESTRUCTIVE_KEYWORDS = new Set(['drop', 'delete', 'truncate', 'update']);

function extractSql(strings: string[]): {
    kind: SqlKind;
    isDestructive: boolean;
    isMultiStatement: boolean;
} {
    // Find the first string that looks like SQL (starts with a SQL keyword).
    const sqlCandidate = strings.find(s => {
        const first = firstWord(s);
        return ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'truncate', 'with', 'call', 'exec', 'merge'].includes(first);
    });

    if (!sqlCandidate) {
        // No SQL-looking string — return neutral values.
        return { kind: 'none', isDestructive: false, isMultiStatement: false };
    }

    const first = firstWord(sqlCandidate);
    let kind: SqlKind;

    if (DDL_KEYWORDS.has(first)) {
        kind = 'ddl';
    } else if (first === 'select' || first === 'with') {
        kind = 'select';
    } else if (first === 'insert') {
        kind = 'insert';
    } else if (first === 'update') {
        kind = 'update';
    } else if (first === 'delete') {
        kind = 'delete';
    } else {
        // exec, call, merge, anything else — can't safely classify
        kind = 'unknown';
    }

    // Multi-statement: semicolon outside of a string literal is the tell.
    // We use a conservative heuristic: strip quoted strings first, then look
    // for a `;` that is not the last character.
    const stripped = stripSqlStrings(sqlCandidate);
    const isMultiStatement = /;[^;]*[a-zA-Z]/.test(stripped);

    const lower = sqlCandidate.toLowerCase();
    const isDestructive =
        DESTRUCTIVE_KEYWORDS.has(first) ||
        // UPDATE without WHERE or with WHERE 1=1 is considered destructive;
        // we keep this simple: any UPDATE triggers it.
        first === 'update' ||
        // DELETE always destructive.
        first === 'delete' ||
        // Multi-statement injections are inherently dangerous
        isMultiStatement;

    return { kind, isDestructive, isMultiStatement };
}

function firstWord(s: string): string {
    return s.trim().split(/\s+/)[0]?.toLowerCase() ?? '';
}

/** Naively strip single- and double-quoted strings to avoid ; inside strings. */
function stripSqlStrings(s: string): string {
    return s.replace(/'(?:''|[^'])*'/g, "''").replace(/"(?:""|[^"])*"/g, '""');
}

// ── Credential detection ──────────────────────────────────────────────────────

function detectCredential(args: unknown): boolean {
    if (args === null || args === undefined) return false;
    const result = redact(args, {});
    return result.redacted;
}

// ── URI helpers ───────────────────────────────────────────────────────────────

function extractScheme(uri: string): string {
    const colon = uri.indexOf(':');
    if (colon <= 0) return 'unknown';
    return uri.slice(0, colon).toLowerCase();
}

function isUriWithinWorkspace(uri: string, workspaceRoot: string): boolean {
    // file:///abs/path → /abs/path
    const filePath = uri.startsWith('file:///') ? uri.slice(7) : uri.startsWith('file://') ? uri.slice(6) : null;
    if (!filePath) return false;
    const normalRoot = path.resolve(workspaceRoot) + path.sep;
    const resolved = path.resolve(filePath);
    return resolved === path.resolve(workspaceRoot) || resolved.startsWith(normalRoot);
}

function isExternalUri(uri: string, allowedHosts: readonly string[]): boolean {
    const scheme = extractScheme(uri);
    if (scheme === 'file') return false;
    URL_RE.lastIndex = 0;
    const m = URL_RE.exec(uri);
    if (!m) return false;
    const host = m[2]?.toLowerCase() ?? '';
    return !allowedHosts.some(a => host === a.toLowerCase() || host.endsWith('.' + a.toLowerCase()));
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/** Flatten a JSON value into all string leaves. */
function collectStrings(obj: unknown, depth = 0): string[] {
    if (depth > 12) return []; // DoS bound
    if (typeof obj === 'string') return [obj];
    if (Array.isArray(obj)) return obj.flatMap(v => collectStrings(v, depth + 1));
    if (obj !== null && typeof obj === 'object') {
        return Object.values(obj as Record<string, unknown>).flatMap(v =>
            collectStrings(v, depth + 1),
        );
    }
    return [];
}

/** Best-effort coercion to a plain object (for args that may be any JSON). */
function toObject(args: unknown): Record<string, unknown> {
    if (args !== null && typeof args === 'object' && !Array.isArray(args)) {
        return args as Record<string, unknown>;
    }
    return {};
}

// Re-export isSensitiveKey so tests can verify the import works.
export { isSensitiveKey };
