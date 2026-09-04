/**
 * Result-side Scanner.
 *
 * Scans the output of a tool call before returning it to the agent.
 * This defends against threat T18: a server returning instructions for the model
 * (indirect prompt injection) inside seemingly benign data, e.g. a web page
 * or a database row.
 *
 * Only string values are scanned (objects are JSON-stringified first).
 */

import type { ScanFinding, ScanSummary, Severity } from '@mcp-sentinel/mcp-core';
import { detectUnicode } from './detectors/unicode.js';
import { detectPoisoning, detectEncodedPoisoning } from './detectors/poisoning.js';
import { classifyWithPromptGuard, type PromptGuardOptions } from './classifier/prompt-guard.js';

export interface ResultScannerOptions {
    readonly promptGuard?: PromptGuardOptions;
}

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
};

function highest(findings: readonly ScanFinding[]): Severity | undefined {
    let max: Severity | undefined = undefined;
    for (const f of findings) {
        if (max === undefined || SEVERITY_RANK[f.severity] > SEVERITY_RANK[max]) {
            max = f.severity;
        }
    }
    return max;
}

export class ResultScanner {
    private readonly options: ResultScannerOptions;

    public constructor(options: ResultScannerOptions = {}) {
        this.options = options;
    }

    /**
     * Scan tool result text.
     * Returns a ScanSummary. If `highestSeverity` is 'high' or 'critical',
     * the caller must block the result from reaching the agent.
     */
    public async scanResult(resultContent: string): Promise<ScanSummary> {
        const findings: ScanFinding[] = [];

        findings.push(...detectUnicode(resultContent, 'result.content'));
        findings.push(...detectPoisoning(resultContent, 'result.content'));
        findings.push(...detectEncodedPoisoning(resultContent, 'result.content'));
        
        if (this.options.promptGuard) {
            const mlFinding = await classifyWithPromptGuard(resultContent, 'result.content', this.options.promptGuard);
            if (mlFinding) findings.push(mlFinding);
        }

        const highestSeverity = highest(findings);
        let verdict: 'clean' | 'suspicious' | 'malicious' = 'clean';
        if (highestSeverity === 'critical' || highestSeverity === 'high') {
            verdict = 'malicious';
        } else if (highestSeverity === 'medium' || highestSeverity === 'low') {
            verdict = 'suspicious';
        }

        return {
            verdict,
            highestSeverity,
            findings,
            scannedAt: new Date().toISOString()
        };
    }
}
