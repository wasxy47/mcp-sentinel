/**
 * HuggingFace Prompt-Guard classifier.
 *
 * Calls the HuggingFace Inference API with `meta-llama/Prompt-Guard-86M` to
 * classify text as benign or containing a prompt injection / jailbreak attempt.
 *
 * This is an *optional* layer. It only runs if `HF_TOKEN` is provided.
 * The static detectors are the primary defence; this classifier is a
 * complementary signal that catches patterns the heuristics might miss.
 *
 * The model returns labels:
 *   - BENIGN — no injection detected
 *   - INJECTION — prompt injection detected
 *   - JAILBREAK — jailbreak attempt detected
 *
 * Design decisions:
 *   - Timeout is 10s by default. If the API is slow, the scanner proceeds
 *     without the classifier result (logged as degraded).
 *   - Results are never cached: tool descriptions change on refresh, and
 *     caching a "benign" verdict for text that later mutates is dangerous.
 *   - The classifier output is *one finding* on the ScanFinding list; it
 *     does not override the static detectors.
 *
 * Threat references: T1, T18 in docs/threat-model.md
 */

import type { ScanFinding, Severity } from '@mcp-sentinel/mcp-core';

export interface PromptGuardOptions {
    readonly hfToken: string;
    readonly model?: string;
    readonly timeoutMs?: number;
}

interface ClassificationResult {
    readonly label: string;
    readonly score: number;
}

/**
 * Classify text using the HuggingFace Inference API.
 *
 * Returns a `ScanFinding` if the classifier detects injection/jailbreak,
 * or `undefined` if the text is classified as benign or the API fails.
 */
export async function classifyWithPromptGuard(
    text: string,
    location: string,
    options: PromptGuardOptions
): Promise<ScanFinding | undefined> {
    const model = options.model ?? 'meta-llama/Prompt-Guard-86M';
    const timeoutMs = options.timeoutMs ?? 10_000;

    // Truncate to avoid excessive API payload (the model has a limited context window)
    const truncated = text.length > 4096 ? text.slice(0, 4096) : text;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetch(
            `https://api-inference.huggingface.co/models/${model}`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${options.hfToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ inputs: truncated }),
                signal: controller.signal
            }
        );

        if (!response.ok) {
            // API error — degrade gracefully, don't fail the scan
            return undefined;
        }

        const body: unknown = await response.json();

        // The API returns [[{label, score}, ...]] for text-classification
        const results = parseClassificationResults(body);
        if (!results) return undefined;

        // Find the highest-scoring non-benign label
        const injection = results.find(r =>
            (r.label === 'INJECTION' || r.label === 'JAILBREAK') && r.score > 0.5
        );

        if (!injection) return undefined;

        const severity: Severity = injection.score > 0.9 ? 'critical'
            : injection.score > 0.7 ? 'high'
            : 'medium';

        return {
            id: `prompt-guard-${location}`,
            detector: 'prompt-guard',
            severity,
            title: `Prompt Guard classified text as ${injection.label}`,
            detail: `The meta-llama/Prompt-Guard-86M classifier detected a ${injection.label.toLowerCase()} ` +
                    `attempt with ${(injection.score * 100).toFixed(1)}% confidence. ` +
                    `This is a machine learning classification and should be considered alongside ` +
                    `static detector findings.`,
            location,
            evidence: `label=${injection.label}, score=${injection.score.toFixed(4)}`
        };
    } catch (err) {
        // Timeout or network error — degrade gracefully
        return undefined;
    } finally {
        clearTimeout(timer);
    }
}

/**
 * Parse the HuggingFace classification response.
 *
 * The text-classification pipeline returns `[[{label, score}, ...]]`.
 * This function handles both the nested and flat formats defensively.
 */
function parseClassificationResults(body: unknown): ClassificationResult[] | undefined {
    if (!Array.isArray(body)) return undefined;

    // Handle [[{label, score}, ...]] format
    const inner = Array.isArray(body[0]) ? body[0] : body;

    const results: ClassificationResult[] = [];
    for (const item of inner) {
        if (
            typeof item === 'object' && item !== null &&
            typeof (item as any).label === 'string' &&
            typeof (item as any).score === 'number'
        ) {
            results.push({
                label: (item as any).label,
                score: (item as any).score
            });
        }
    }

    return results.length > 0 ? results : undefined;
}
