/**
 * Unicode abuse detector.
 *
 * Detects invisible and deceptive Unicode characters that can hide malicious
 * instructions in tool descriptions. These characters render as nothing to a
 * human reviewer, but are read by the model, creating a gap between what a
 * reviewer sees and what the model processes.
 *
 * Categories detected:
 *   - Zero-width characters (ZWJ, ZWNJ, ZWS, ZWSP, FEFF BOM, word joiner)
 *   - Bidirectional overrides and embeddings (can make text render reversed)
 *   - Tag characters (U+E0000 block — can carry entire hidden messages)
 *   - Invisible format characters (soft hyphen, function application, etc.)
 *   - Homoglyph/confusable characters from Cyrillic, Greek (looks like Latin)
 *
 * Threat reference: T2 in docs/threat-model.md
 */

import type { ScanFinding, Severity } from '@mcp-sentinel/mcp-core';

/** A detected span of invisible/deceptive characters. */
interface UnicodeMatch {
    readonly kind: string;
    readonly severity: Severity;
    readonly codePoints: string[];
    readonly start: number;
    readonly end: number;
}

// ── Pattern definitions ─────────────────────────────────────────────────────

/**
 * Zero-width and invisible formatting characters.
 *
 * U+200B  ZERO WIDTH SPACE
 * U+200C  ZERO WIDTH NON-JOINER
 * U+200D  ZERO WIDTH JOINER
 * U+200E  LEFT-TO-RIGHT MARK
 * U+200F  RIGHT-TO-LEFT MARK
 * U+FEFF  BYTE ORDER MARK (also ZWNBSP)
 * U+2060  WORD JOINER
 * U+2061  FUNCTION APPLICATION
 * U+2062  INVISIBLE TIMES
 * U+2063  INVISIBLE SEPARATOR
 * U+2064  INVISIBLE PLUS
 * U+00AD  SOFT HYPHEN
 * U+034F  COMBINING GRAPHEME JOINER
 */
const INVISIBLE_CHARS =
    /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u2060\u2061\u2062\u2063\u2064\u00AD\u034F]/g;

/**
 * Bidirectional control characters.
 *
 * U+202A  LEFT-TO-RIGHT EMBEDDING
 * U+202B  RIGHT-TO-LEFT EMBEDDING
 * U+202C  POP DIRECTIONAL FORMATTING
 * U+202D  LEFT-TO-RIGHT OVERRIDE
 * U+202E  RIGHT-TO-LEFT OVERRIDE
 * U+2066  LEFT-TO-RIGHT ISOLATE
 * U+2067  RIGHT-TO-LEFT ISOLATE
 * U+2068  FIRST STRONG ISOLATE
 * U+2069  POP DIRECTIONAL ISOLATE
 */
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g;

/**
 * Tag characters (U+E0001–U+E007F).
 *
 * Originally intended for language tagging, almost universally unused in
 * legitimate content. An attacker can encode an entire hidden message using
 * these since each maps to an ASCII character: U+E0041 = 'A', etc.
 */
const TAG_CHARACTERS = /[\u{E0001}-\u{E007F}]/gu;

/**
 * Common Cyrillic confusables that look identical to Latin letters.
 *
 * а (U+0430) → a,  е (U+0435) → e,  о (U+043E) → o,  р (U+0440) → p,
 * с (U+0441) → c,  х (U+0445) → x,  у (U+0443) → y,  і (U+0456) → i
 *
 * These are tracked at 'medium' severity because they *could* be legitimate
 * Cyrillic text, but in a tool description that is otherwise Latin-script,
 * they are almost certainly homoglyph confusion.
 */
const CYRILLIC_CONFUSABLES = /[\u0430\u0435\u043E\u0440\u0441\u0445\u0443\u0456]/g;

// ── Detection ───────────────────────────────────────────────────────────────

function collectMatches(
    text: string,
    pattern: RegExp,
    kind: string,
    severity: Severity
): UnicodeMatch[] {
    const matches: UnicodeMatch[] = [];
    let m: RegExpExecArray | null;
    // Reset the regex
    pattern.lastIndex = 0;
    while ((m = pattern.exec(text)) !== null) {
        const char = m[0]!;
        const codePoints = [...char].map(c => `U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`);
        matches.push({
            kind,
            severity,
            codePoints,
            start: m.index,
            end: m.index + char.length
        });
    }
    return matches;
}

/**
 * Scan a text string for invisible/deceptive Unicode.
 *
 * Returns one `ScanFinding` per category detected (not per character), with
 * evidence showing the first few offending code points. This keeps findings
 * concise while still identifying the threat.
 */
export function detectUnicode(text: string, location: string): ScanFinding[] {
    const findings: ScanFinding[] = [];

    const groups: Array<{ kind: string; severity: Severity; pattern: RegExp; title: string }> = [
        {
            kind: 'unicode-bidi',
            severity: 'high',
            pattern: BIDI_CONTROLS,
            title: 'Bidirectional control characters in text'
        },
        {
            kind: 'unicode-tags',
            severity: 'critical',
            pattern: TAG_CHARACTERS,
            title: 'Unicode tag characters (hidden message channel)'
        },
        {
            kind: 'unicode-invisible',
            severity: 'high',
            pattern: INVISIBLE_CHARS,
            title: 'Invisible formatting characters in text'
        },
        {
            kind: 'unicode-confusable',
            severity: 'medium',
            pattern: CYRILLIC_CONFUSABLES,
            title: 'Cyrillic homoglyph characters (Latin confusables)'
        }
    ];

    for (const group of groups) {
        const matches = collectMatches(text, group.pattern, group.kind, group.severity);
        if (matches.length === 0) continue;

        const uniqueCodePoints = [...new Set(matches.flatMap(m => m.codePoints))];
        const evidenceLimit = 10;
        const evidence = uniqueCodePoints.slice(0, evidenceLimit).join(', ')
            + (uniqueCodePoints.length > evidenceLimit ? `, … (+${uniqueCodePoints.length - evidenceLimit} more)` : '');

        findings.push({
            id: `${group.kind}-${location}`,
            detector: 'unicode',
            severity: group.severity,
            title: group.title,
            detail: `Found ${matches.length} ${group.kind} character(s). ` +
                    `Code points: ${evidence}. ` +
                    `These characters are invisible or deceptive and can hide instructions from human reviewers.`,
            location,
            evidence
        });
    }

    return findings;
}

/**
 * Strip all detected invisible/deceptive Unicode from a string.
 *
 * Used for normalization before other detectors run, so hidden payloads
 * don't bypass keyword matching.
 */
export function stripInvisibleUnicode(text: string): string {
    return text
        .replace(INVISIBLE_CHARS, '')
        .replace(BIDI_CONTROLS, '')
        .replace(TAG_CHARACTERS, '');
}
