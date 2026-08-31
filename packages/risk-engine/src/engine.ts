import type { RiskAssessment, Obligation } from '@mcp-sentinel/mcp-core';
import { heuristicRiskScore } from './heuristic.js';
import type { LlmProvider } from './provider.js';

export interface RiskEngineConfig {
    readonly heuristicOnly?: boolean;
    readonly llmTimeoutMs?: number;
    readonly escalationThreshold?: number; // Score at which we override obligation
    readonly escalateObligation?: Obligation; // The obligation to escalate to
}

/**
 * Orchestrates heuristic and LLM-based risk assessments.
 */
export class RiskEngine {
    constructor(
        private readonly provider: LlmProvider | undefined,
        private readonly config: RiskEngineConfig = {}
    ) {}

    /**
     * Escalates an obligation based on a risk assessment.
     * Policy is the floor. Obligation ordering: allow < review < approve.
     * Can only escalate, never downgrade.
     */
    public escalateObligation(baseObligation: Obligation, assessment: RiskAssessment): Obligation {
        const threshold = this.config.escalationThreshold ?? 80;
        const escalateTo = this.config.escalateObligation ?? 'approve';
        
        if (assessment.score < threshold) {
            return baseObligation;
        }

        const ordering: Record<Obligation, number> = {
            'allow': 0,
            'review': 1,
            'approve': 2
        };

        if (ordering[escalateTo] > ordering[baseObligation]) {
            return escalateTo;
        }

        return baseObligation;
    }

    /**
     * Evaluates the risk of a tool call or resource read.
     * Uses heuristics first. If heuristics report low/medium risk and an LLM is configured,
     * queries the LLM for a deeper assessment.
     * 
     * Implement 'escalate-then-deny' posture: if the LLM backend is unreachable or times out,
     * we return a high risk score to fail closed.
     */
    public async evaluate(method: string, name: string, payload: unknown): Promise<RiskAssessment> {
        // 1. Synchronous Heuristics
        const heuristic = heuristicRiskScore(method, name, payload);
        
        // If heuristic is already very high or LLM is disabled, return heuristic
        if (heuristic.score >= (this.config.escalationThreshold ?? 80) || !this.provider || this.config.heuristicOnly) {
            return heuristic;
        }

        // 2. LLM Assessment
        const timeoutMs = this.config.llmTimeoutMs ?? 5000;
        
        try {
            const llmPromise = this.provider.evaluateRisk(method, name, payload);
            const timeoutPromise = new Promise<never>((_, reject) => 
                setTimeout(() => reject(new Error('LLM timeout')), timeoutMs)
            );
            
            const llmAssessment = await Promise.race([llmPromise, timeoutPromise]);
            
            // Return the highest score between heuristic and LLM
            if (llmAssessment.score > heuristic.score) {
                return {
                    ...llmAssessment,
                    signals: [...heuristic.signals, ...llmAssessment.signals]
                };
            }
            return heuristic;

        } catch (error) {
            // Escalate-then-deny posture: if the LLM fails, return max risk.
            return {
                score: 100,
                band: 'critical',
                rationale: `LLM assessment failed: ${error instanceof Error ? error.message : String(error)}. Overriding score to maximum.`,
                signals: [...heuristic.signals, 'llm_timeout_or_failure'],
                provider: heuristic.provider,
                model: heuristic.model,
                cached: false,
                latencyMs: heuristic.latencyMs // It took at least the heuristic latency plus timeout, but we report standard format
            };
        }
    }
}
