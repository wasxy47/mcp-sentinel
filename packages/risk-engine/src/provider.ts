import type { RiskAssessment } from '@mcp-sentinel/mcp-core';
import * as z from 'zod';

export interface LlmProvider {
    /**
     * Evaluates the risk of an MCP request using an LLM.
     * @param method The MCP method being called (e.g., 'tools/call')
     * @param name The qualified tool or resource name.
     * @param payload The request parameters.
     * @returns A promise of the RiskAssessment.
     */
    evaluateRisk(method: string, name: string, payload: unknown): Promise<RiskAssessment>;
}

const StructuredOutputSchema = z.object({
    score: z.number().int().min(0).max(100),
    rationale: z.string(),
    signals: z.array(z.string())
});

/**
 * Common prompt used to evaluate the risk of an MCP request.
 */
function buildPrompt(method: string, name: string, payload: unknown): string {
    return `You are a security risk engine for an AI agent gateway.
Analyze the following tool/resource request from an autonomous AI agent and assign a risk score from 0 to 100.
0 = Completely safe, benign, read-only or harmless.
100 = Extremely dangerous, malicious, destructive, or clear attempt at system compromise.

Request Context:
Method: ${method}
Target: ${name}
Payload: ${JSON.stringify(payload, null, 2)}

Provide your response as a valid JSON object matching this schema:
{
  "score": number,
  "rationale": string,
  "signals": string[]
}`;
}

export class GroqProvider implements LlmProvider {
    constructor(private readonly apiKey: string, private readonly model: string = 'llama-3.1-8b-instant') {}

    async evaluateRisk(method: string, name: string, payload: unknown): Promise<RiskAssessment> {
        const prompt = buildPrompt(method, name, payload);
        const start = performance.now();
        
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.apiKey}`
            },
            body: JSON.stringify({
                model: this.model,
                messages: [{ role: 'user', content: prompt }],
                response_format: { type: 'json_object' }
            })
        });

        if (!response.ok) {
            throw new Error(`Groq API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json() as any;
        const content = data.choices[0]?.message?.content;
        if (!content) {
            throw new Error('No content in Groq response');
        }

        const parsed = JSON.parse(content);
        const result = StructuredOutputSchema.parse(parsed);
        const band = result.score >= 80 ? 'critical' : result.score >= 60 ? 'high' : result.score >= 30 ? 'medium' : 'low';

        return {
            score: result.score,
            band,
            rationale: result.rationale,
            signals: result.signals,
            provider: 'groq',
            model: this.model,
            cached: false,
            latencyMs: performance.now() - start
        };
    }
}

export class OllamaProvider implements LlmProvider {
    constructor(private readonly baseUrl: string, private readonly model: string) {}

    async evaluateRisk(method: string, name: string, payload: unknown): Promise<RiskAssessment> {
        const prompt = buildPrompt(method, name, payload);
        const start = performance.now();
        
        const response = await fetch(`${this.baseUrl}/api/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: this.model,
                prompt,
                format: 'json',
                stream: false
            })
        });

        if (!response.ok) {
            throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json() as any;
        const content = data.response;
        if (!content) {
            throw new Error('No response in Ollama payload');
        }

        const parsed = JSON.parse(content);
        const result = StructuredOutputSchema.parse(parsed);
        const band = result.score >= 80 ? 'critical' : result.score >= 60 ? 'high' : result.score >= 30 ? 'medium' : 'low';

        return {
            score: result.score,
            band,
            rationale: result.rationale,
            signals: result.signals,
            provider: 'ollama',
            model: this.model,
            cached: false,
            latencyMs: performance.now() - start
        };
    }
}
