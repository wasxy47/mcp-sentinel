import type { RiskAssessment } from '@mcp-sentinel/mcp-core';

/**
 * Returns a risk assessment based solely on static heuristics of the request.
 * High scores indicate potentially unsafe payloads.
 */
export function heuristicRiskScore(
    method: string,
    toolOrResourceName: string,
    argsOrParams: unknown
): RiskAssessment {
    const signals: string[] = [];
    let score = 0;
    const start = performance.now();

    // Check payload size
    const payloadStr = JSON.stringify(argsOrParams || {});
    if (payloadStr.length > 50_000) {
        score += 80;
        signals.push('Payload exceeds 50KB heuristic threshold');
    } else if (payloadStr.length > 10_000) {
        score += 30;
        signals.push('Payload exceeds 10KB heuristic threshold');
    }

    // Heuristics for standard shell/SQL injection characters or suspicious patterns
    if (typeof argsOrParams === 'object' && argsOrParams !== null) {
        const values = Object.values(argsOrParams).map(String);
        for (const val of values) {
            if (val.includes('; rm -rf ') || val.includes('; curl ') || val.includes('; wget ')) {
                score += 100;
                signals.push('Suspicious shell commands detected');
            }
            if (val.includes('../') || val.includes('..\\')) {
                score += 50;
                signals.push('Directory traversal characters detected');
            }
            if (val.includes('/etc/shadow') || val.includes('.ssh/id_rsa')) {
                score += 100;
                signals.push('Sensitive file paths detected');
            }
        }
    }

    // Bound the score between 0 and 100
    const finalScore = Math.min(100, Math.max(0, score));
    const band = finalScore >= 80 ? 'critical' : finalScore >= 60 ? 'high' : finalScore >= 30 ? 'medium' : 'low';

    return {
        score: finalScore,
        band,
        rationale: signals.length > 0 ? `Flagged by heuristics: ${signals.join(', ')}` : 'No heuristic flags',
        signals,
        provider: 'heuristic',
        model: 'static-v1',
        cached: false,
        latencyMs: performance.now() - start
    };
}
