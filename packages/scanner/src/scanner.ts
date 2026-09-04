/**
 * Scanner Orchestrator.
 *
 * Runs a suite of static detectors and optional ML classifiers over a tool
 * definition to identify prompt injection, tool poisoning, and deceptive
 * annotations.
 *
 * Produces a `ScanSummary` with the highest severity found and an overall
 * verdict (`clean`, `suspicious`, `malicious`).
 */

import type { ScanFinding, ScanSummary, Severity, ToolDefinition } from '@mcp-sentinel/mcp-core';
import { detectUnicode } from './detectors/unicode.js';
import { detectPoisoning, detectEncodedPoisoning } from './detectors/poisoning.js';
import { detectShadowing } from './detectors/shadowing.js';
import { classifyWithPromptGuard, type PromptGuardOptions } from './classifier/prompt-guard.js';

export interface ScannerOptions {
    /** Optional Prompt Guard configuration. If provided, ML classification is run. */
    readonly promptGuard?: PromptGuardOptions;
}

/** Determines the aggregate verdict from a list of findings. */
function aggregateVerdict(highestSeverity: Severity | undefined): 'clean' | 'suspicious' | 'malicious' {
    if (highestSeverity === 'critical' || highestSeverity === 'high') {
        return 'malicious';
    }
    if (highestSeverity === 'medium' || highestSeverity === 'low') {
        return 'suspicious';
    }
    return 'clean';
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

export class Scanner {
    private readonly options: ScannerOptions;

    public constructor(options: ScannerOptions = {}) {
        this.options = options;
    }

    /**
     * Scan an entire tool definition (description, name, and schema).
     */
    public async scanTool(tool: ToolDefinition): Promise<ScanSummary> {
        const findings: ScanFinding[] = [];

        // 1. Static checks on description
        if (tool.description) {
            findings.push(...detectUnicode(tool.description, 'description'));
            findings.push(...detectPoisoning(tool.description, 'description'));
            findings.push(...detectEncodedPoisoning(tool.description, 'description'));
            
            // 2. Optional ML classification on description
            if (this.options.promptGuard) {
                const mlFinding = await classifyWithPromptGuard(tool.description, 'description', this.options.promptGuard);
                if (mlFinding) findings.push(mlFinding);
            }
        }

        // 3. Shadowing checks (name vs capabilities)
        findings.push(...detectShadowing(tool, 'definition'));

        // 4. Static checks on properties (e.g. parameter descriptions)
        const props = (tool.inputSchema as any)?.properties;
        if (props && typeof props === 'object') {
            for (const [key, val] of Object.entries(props)) {
                if (typeof (val as any)?.description === 'string') {
                    const propDesc = (val as any).description as string;
                    findings.push(...detectUnicode(propDesc, `inputSchema.properties.${key}.description`));
                    findings.push(...detectPoisoning(propDesc, `inputSchema.properties.${key}.description`));
                    
                    if (this.options.promptGuard) {
                         const mlFinding = await classifyWithPromptGuard(propDesc, `inputSchema.properties.${key}.description`, this.options.promptGuard);
                         if (mlFinding) findings.push(mlFinding);
                    }
                }
            }
        }

        const highestSeverity = highest(findings);
        const verdict = aggregateVerdict(highestSeverity);

        return {
            verdict,
            highestSeverity,
            findings,
            scannedAt: new Date().toISOString()
        };
    }
}
