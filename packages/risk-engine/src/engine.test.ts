import { describe, it, expect, vi } from 'vitest';
import { RiskEngine } from './engine.js';
import type { LlmProvider } from './provider.js';
import type { RiskAssessment } from '@mcp-sentinel/mcp-core';

describe('RiskEngine', () => {
    it('escalates obligations correctly, bounded by floor', () => {
        const engine = new RiskEngine(undefined, { escalationThreshold: 80, escalateObligation: 'approve' });
        
        // Low risk -> obligation remains unchanged
        expect(engine.escalateObligation('allow', { score: 10 } as RiskAssessment)).toBe('allow');
        expect(engine.escalateObligation('review', { score: 10 } as RiskAssessment)).toBe('review');
        expect(engine.escalateObligation('approve', { score: 10 } as RiskAssessment)).toBe('approve');

        // High risk -> obligation escalates
        expect(engine.escalateObligation('allow', { score: 90 } as RiskAssessment)).toBe('approve');
        
        // High risk but base obligation is already higher/equal -> remains unchanged
        expect(engine.escalateObligation('approve', { score: 90 } as RiskAssessment)).toBe('approve');
    });

    it('uses only heuristics when LLM is unconfigured', async () => {
        const engine = new RiskEngine(undefined);
        const result = await engine.evaluate('tools/call', 'files__write', { content: '; rm -rf /' });
        
        expect(result.score).toBe(100);
        expect(result.provider).toBe('heuristic');
        expect(result.signals).toContain('Suspicious shell commands detected');
    });

    it('bypasses LLM when heuristic score is above threshold', async () => {
        const provider: LlmProvider = {
            evaluateRisk: vi.fn().mockResolvedValue({ score: 10, signals: ['llm_ok'] } as any)
        };
        const engine = new RiskEngine(provider, { escalationThreshold: 80 });
        
        const result = await engine.evaluate('tools/call', 'files__write', { path: '/etc/shadow' });
        
        expect(result.score).toBe(100);
        expect(result.provider).toBe('heuristic');
        expect(provider.evaluateRisk).not.toHaveBeenCalled();
    });

    it('uses LLM when heuristic score is low', async () => {
        const provider: LlmProvider = {
            evaluateRisk: vi.fn().mockResolvedValue({ score: 90, band: 'critical', rationale: 'LLM logic', signals: ['llm_flag'], provider: 'llm', model: 'test', cached: false, latencyMs: 10 } as RiskAssessment)
        };
        const engine = new RiskEngine(provider, { escalationThreshold: 80 });
        
        const result = await engine.evaluate('tools/call', 'files__read', { path: 'safe.txt' });
        
        expect(result.score).toBe(90);
        expect(result.provider).toBe('llm');
        expect(result.signals).toContain('llm_flag');
        expect(provider.evaluateRisk).toHaveBeenCalled();
    });

    it('escalates-then-denies if LLM fails', async () => {
        const provider: LlmProvider = {
            evaluateRisk: vi.fn().mockRejectedValue(new Error('Network error'))
        };
        const engine = new RiskEngine(provider);
        
        const result = await engine.evaluate('tools/call', 'files__read', { path: 'safe.txt' });
        
        expect(result.score).toBe(100);
        expect(result.rationale).toContain('LLM assessment failed');
    });
});
