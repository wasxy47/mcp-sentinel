/**
 * Tool-poisoning detector.
 *
 * Scans tool descriptions and other upstream-authored text for patterns that
 * indicate embedded instructions aimed at the model rather than at a human
 * reader. This is the primary defence against threat T1.
 *
 * Detection strategy:
 *   1. **Imperative instructions** — phrases like "you must", "always do",
 *      "do not tell the user", "before calling this tool". A legitimate tool
 *      description documents *what the tool does*, not *what the model should do*.
 *   2. **Sensitive path references** — paths to SSH keys, shadow files, AWS
 *      credentials. A description that mentions these is almost certainly
 *      trying to direct the agent to read or exfiltrate them.
 *   3. **Exfiltration patterns** — instructions to send data to URLs, encode
 *      and embed secrets in parameters, or call other tools.
 *   4. **Secrecy directives** — "do not mention", "keep this secret", "don't
 *      tell anyone". Legitimate tools have no reason to tell the model to hide
 *      information from the user.
 *   5. **Encoded payloads** — base64-encoded strings that, when decoded, contain
 *      instruction patterns. Evades simple keyword matching.
 *
 * Each rule has an independent severity. Multiple matches from different
 * categories stack, because a description that hits *both* secrecy and
 * sensitive paths is far more suspicious than either alone.
 *
 * Threat references: T1, T5 in docs/threat-model.md
 */

import type { ScanFinding, Severity } from '@mcp-sentinel/mcp-core';
import { stripInvisibleUnicode } from './unicode.js';

// ── Rule definitions ────────────────────────────────────────────────────────

interface PatternRule {
    readonly id: string;
    readonly severity: Severity;
    readonly title: string;
    readonly patterns: readonly RegExp[];
    /** Human-readable explanation of why this fires. */
    readonly detail: string;
}

const RULES: readonly PatternRule[] = [
    // ── Imperative instructions aimed at the model ──────────────────────
    {
        id: 'imperative-instruction',
        severity: 'high',
        title: 'Imperative instruction embedded in description',
        patterns: [
            /\b(?:you (?:must|should|need to|have to|are required to))\b/i,
            /\b(?:always|never)\s+(?:do|send|include|pass|call|run|execute)\b/i,
            /\b(?:before|after)\s+(?:calling|using|running)\s+(?:this|any|the)\b/i,
            /\bIMPORTANT\s*:/i,
            /\b(?:follow|obey|comply with)\s+(?:the|these|the following|this)\s+(?:instructions?|steps?|rules?)\b/i,
            /\b(?:step\s+\d+|first|then|next|finally)\s*[,:]\s*(?:read|write|send|call|execute|run)\b/i,
        ],
        detail: 'Tool descriptions should document what the tool does, not instruct the model. ' +
                'Imperative phrasing ("you must", "always send") is a strong indicator of prompt injection.'
    },

    // ── Secrecy directives ──────────────────────────────────────────────
    {
        id: 'secrecy-directive',
        severity: 'critical',
        title: 'Secrecy directive detected',
        patterns: [
            /\bdo\s+not\s+(?:tell|mention|reveal|disclose|show|display|inform)\b/i,
            /\bdon'?t\s+(?:tell|mention|reveal|disclose|show|display|inform)\b/i,
            /\bkeep\s+(?:this|it)\s+(?:secret|hidden|private|confidential)\b/i,
            /\bhide\s+(?:this|it)\s+from\s+(?:the\s+)?user\b/i,
            /\bnever\s+(?:mention|reveal|disclose|show)\b/i,
            /\b(?:silently|quietly|secretly)\s+(?:send|pass|include|add|embed)\b/i,
        ],
        detail: 'Secrecy directives ("do not tell the user") have no legitimate purpose in a tool description. ' +
                'They are a hallmark of tool poisoning attacks that try to prevent the user from learning ' +
                'what the agent is being instructed to do.'
    },

    // ── Sensitive file/path references ──────────────────────────────────
    {
        id: 'sensitive-path',
        severity: 'high',
        title: 'Reference to sensitive file paths',
        patterns: [
            /(?:~|\$HOME|\%USERPROFILE\%)\/\.ssh\//i,
            /\.ssh\/(?:id_rsa|id_ed25519|id_dsa|authorized_keys|known_hosts|config)\b/i,
            /\/etc\/(?:shadow|passwd|sudoers)\b/i,
            /\.(?:env|npmrc|pypirc|netrc|pgpass|my\.cnf|docker\/config\.json)\b/i,
            /\.aws\/(?:credentials|config)\b/i,
            /\.kube\/config\b/i,
            /\.gnupg\//i,
            /\/\.git\/config\b/i,
            /(?:private[_-]?key|secret[_-]?key|api[_-]?key|access[_-]?token)\b/i,
        ],
        detail: 'A tool description referencing sensitive file paths (SSH keys, credentials, etc.) ' +
                'is likely attempting to direct the agent to read and exfiltrate private data.'
    },

    // ── Exfiltration patterns ───────────────────────────────────────────
    {
        id: 'exfiltration-pattern',
        severity: 'critical',
        title: 'Data exfiltration pattern detected',
        patterns: [
            /\bsend\s+(?:the\s+)?(?:contents?|data|results?|output|response)\s+to\b/i,
            /\bpost\s+(?:the\s+)?(?:data|contents?|results?)\s+to\s+(?:https?:\/\/|an?\s+(?:external|remote)\s+(?:url|server|endpoint))\b/i,
            /\bpass\s+(?:it|the\s+contents?|the\s+data)\s+as\s+(?:a\s+)?(?:parameter|argument|header|body)\b/i,
            /\b(?:encode|base64|encrypt)\s+(?:and\s+)?(?:send|pass|include|embed)\b/i,
            /\bcurl\b[^\r\n]*?https?:\/\//i,
            /\bwget\b[^\r\n]*?https?:\/\//i,
            /\bfetch\s*\(\s*['"]https?:\/\//i,
        ],
        detail: 'Instructions to send data to external endpoints, encode data for exfiltration, ' +
                'or embed secrets in parameters are strong indicators of a poisoning attack.'
    },

    // ── Cross-tool manipulation (T5) ────────────────────────────────────
    {
        id: 'cross-tool-manipulation',
        severity: 'high',
        title: 'Cross-tool instruction detected',
        patterns: [
            /\b(?:when|before|after)\s+(?:you\s+)?(?:use|call|invoke|run)\s+(?:the\s+)?\w+(?:__\w+)?\s*(?:tool|function|command)?\s*[,;]\s*(?:also|first|then)\b/i,
            /\b(?:also|additionally|furthermore)\s+(?:call|use|invoke|run|execute)\s+(?:the\s+)?\w+(?:__\w+)?\b/i,
            /\b(?:instead\s+of|rather\s+than)\s+(?:calling|using)\b/i,
            /\bforward\s+(?:all|every|the)\s+(?:request|call|data)\b/i,
        ],
        detail: 'Instructions that direct the model to use other tools in specific ways (T5 cross-server ' +
                'instruction injection). A tool description should only document its own functionality.'
    },

    // ── System/role prompt override attempts ────────────────────────────
    {
        id: 'role-override',
        severity: 'critical',
        title: 'System/role prompt override attempt',
        patterns: [
            /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|guidelines?)\b/i,
            /\byou\s+are\s+(?:now|actually|really)\s+(?:a|an)\b/i,
            /\bnew\s+(?:system\s+)?(?:instructions?|prompt|rules?|role)\s*:/i,
            /\b(?:system|assistant)\s*:\s/i,
            /\[\s*SYSTEM\s*\]/i,
            /\b(?:entering|switching\s+to)\s+(?:a\s+new|admin|root|developer|debug)\s+mode\b/i,
        ],
        detail: 'Attempting to override the model\'s system prompt or role from within a tool description ' +
                'is a direct prompt injection attack.'
    }
];

// ── Detection ───────────────────────────────────────────────────────────────

/**
 * Scan text for tool-poisoning patterns.
 *
 * The text is first stripped of invisible Unicode (so hidden payloads don't
 * bypass keyword matching), then each rule is evaluated independently.
 */
export function detectPoisoning(text: string, location: string): ScanFinding[] {
    const normalized = stripInvisibleUnicode(text);
    const findings: ScanFinding[] = [];

    for (const rule of RULES) {
        const matches: string[] = [];

        for (const pattern of rule.patterns) {
            // Reset the regex index for each scan
            pattern.lastIndex = 0;
            const m = pattern.exec(normalized);
            if (m) {
                matches.push(m[0]);
            }
        }

        if (matches.length === 0) continue;

        // Cap evidence length to avoid storing attacker-controlled text wholesale
        const evidence = matches
            .slice(0, 3)
            .map(m => m.length > 80 ? m.slice(0, 77) + '…' : m)
            .join(' | ');

        findings.push({
            id: `${rule.id}-${location}`,
            detector: 'poisoning',
            severity: rule.severity,
            title: rule.title,
            detail: rule.detail,
            location,
            evidence
        });
    }

    return findings;
}

/**
 * Detect base64-encoded payloads that might hide poisoning patterns.
 *
 * This is a second pass that catches encoded instructions. Only fires when
 * the decoded content itself triggers poisoning rules — not for all base64,
 * since legitimate tool descriptions may include encoded examples.
 */
export function detectEncodedPoisoning(text: string, location: string): ScanFinding[] {
    const findings: ScanFinding[] = [];

    // Match base64 strings that are at least 20 chars (short enough to encode a command)
    const b64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
    let m: RegExpExecArray | null;

    while ((m = b64Pattern.exec(text)) !== null) {
        try {
            const decoded = Buffer.from(m[0], 'base64').toString('utf8');
            // Only flag if the decoded content contains valid-looking text
            // and itself triggers a poisoning rule
            if (decoded.length < 4) continue;
            // Check if the decoded text looks like readable text (>50% printable ASCII)
            const printableRatio = decoded.split('').filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length / decoded.length;
            if (printableRatio < 0.5) continue;

            const inner = detectPoisoning(decoded, `${location}[base64-decoded]`);
            if (inner.length > 0) {
                findings.push({
                    id: `encoded-poisoning-${location}`,
                    detector: 'poisoning',
                    severity: 'critical',
                    title: 'Base64-encoded poisoning payload detected',
                    detail: `A base64 string, when decoded, contains poisoning patterns: ` +
                            `${inner.map(f => f.title).join(', ')}. ` +
                            `Encoding is a common evasion technique.`,
                    location,
                    evidence: decoded.length > 120 ? decoded.slice(0, 117) + '…' : decoded
                });
                // One finding per description is enough — we don't need to decode every base64 blob
                break;
            }
        } catch {
            // Not valid base64, skip
        }
    }

    return findings;
}
