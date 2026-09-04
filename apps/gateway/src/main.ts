/**
 * Gateway entry point.
 *
 * Startup sequence, in order:
 *
 *   1. Load and validate `GatewayConfig`.
 *   2. Build a structured logger (level from `SENTINEL_LOG_LEVEL`).
 *   3. Build the `UpstreamRegistry` and warm up all dialable upstreams in
 *      parallel, not waiting for them — the gateway starts serving immediately,
 *      and upstreams that connect later are reflected in the next request.
 *   4. Build the `ToolCatalog` and run an initial refresh. Tools are available
 *      immediately after startup; a refresh failure is logged but not fatal.
 *   5. Construct the `SentinelServer` (registers all request handlers).
 *   6. Start the HTTP server.
 *   7. Install `SIGTERM`/`SIGINT` handlers for graceful shutdown.
 *
 * Config resolution:
 *   - `SENTINEL_CONFIG` env var: path to a JSON config file.
 *   - Absent: looks for `sentinel.config.json` in the current directory.
 *   - Absent: uses all defaults (useful for `npm run gateway:dev` with an
 *     empty directory; it starts but has no upstreams and no audit database).
 *
 * What is NOT here:
 *   - Any policy evaluation (M2).
 *   - Any audit writes (M3).
 *   - Any risk scoring (M4).
 *   - Any approval flow (M5).
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { GatewayConfigSchema } from './config/schema.js';
import { Logger, parseLogLevel, stderrSink } from './observability/logger.js';
import { UpstreamRegistry } from './upstream/registry.js';
import { ToolCatalog } from './catalog/catalog.js';
import { SentinelServer } from './server/handlers.js';
import { startHttpServer } from './server/http.js';
import { AuditStore } from '@mcp-sentinel/audit';
import { RiskEngine, GroqProvider, OllamaProvider } from '@mcp-sentinel/risk-engine';
import { ApprovalStore, Signer, Notifier } from '@mcp-sentinel/approvals';
import { Scanner, ResultScanner } from '@mcp-sentinel/scanner';
import fs from 'node:fs';
import path from 'node:path';

const SERVER_INFO = { name: 'mcp-sentinel', version: '0.1.0' } as const;

/** Load raw config JSON from the configured path, or return an empty object. */
function loadRawConfig(logger: Logger): Record<string, unknown> {
    const configPath = process.env['SENTINEL_CONFIG'] ?? resolve(process.cwd(), 'sentinel.config.json');

    if (!existsSync(configPath)) {
        logger.info('no config file found; using all defaults', { configPath });
        return {};
    }

    try {
        const text = readFileSync(configPath, 'utf8');
        const parsed: unknown = JSON.parse(text);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            throw new Error('config file must be a JSON object');
        }
        logger.info('loaded config', { configPath });
        return parsed as Record<string, unknown>;
    } catch (cause) {
        logger.error('failed to read or parse config file', {
            configPath,
            error: cause instanceof Error ? cause.message : String(cause)
        });
        process.exit(1);
    }
}

async function main(): Promise<void> {
    // Build a bootstrap logger for the config-load phase; will be replaced by
    // the configured logger once the level is known.
    const bootstrapLogger = new Logger({ level: 'info', sink: stderrSink });

    const rawConfig = loadRawConfig(bootstrapLogger);
    const configResult = GatewayConfigSchema.safeParse(rawConfig);

    if (!configResult.success) {
        bootstrapLogger.error('invalid gateway configuration', {
            issues: configResult.error.issues.map(issue => ({
                path: issue.path.join('.') || '(root)',
                message: issue.message
            }))
        });
        process.exit(1);
    }

    const config = configResult.data;
    const level = parseLogLevel(process.env['SENTINEL_LOG_LEVEL'], 'info');
    const logger = new Logger({ level, sink: stderrSink, base: { instance: config.instanceName } });

    logger.info('gateway starting', {
        instanceName: config.instanceName,
        version: SERVER_INFO.version,
        upstreams: config.servers.length
    });

    // ── upstream registry ────────────────────────────────────────────────────────
    const registry = new UpstreamRegistry(config, { logger, clientInfo: SERVER_INFO });

    // Warm-up: dial all upstreams in parallel. Never throws; a failed upstream is
    // reflected in its health state and will be retried on the first call to it.
    // We do not await this: the gateway starts serving immediately, and the
    // warm-up result is logged when it completes. An agent's first request may
    // arrive before upstreams have connected; that is fine — the tool list will
    // be empty until the first catalog refresh, and forwarding will fail-fast.
    void registry.warmUp().then(snapshots => {
        const ready = snapshots.filter(s => s.health === 'ready').length;
        logger.info('upstream warm-up complete', { ready, total: snapshots.length });
    });

    // ── tool catalog ─────────────────────────────────────────────────────────────
    const hfToken = process.env['HF_TOKEN'];
    const promptGuard = hfToken ? { hfToken } : undefined;
    const scanner = new Scanner(promptGuard ? { promptGuard } : {});
    const resultScanner = new ResultScanner(promptGuard ? { promptGuard } : {});
    
    const catalog = new ToolCatalog({ registry, settings: config.catalog, logger, scanner });

    // Initial catalog refresh. Errors are absorbed so the gateway can start
    // even if no upstream is reachable yet. The catalog will be empty until an
    // upstream connects and a refresh succeeds.
    try {
        const result = await catalog.refresh();
        logger.info('initial catalog refresh complete', {
            tools: result.totalTools,
            outcomes: result.outcomes.map(o => ({ server: o.serverId, catalogued: o.catalogued, ok: o.ok }))
        });
    } catch (cause) {
        logger.warn('initial catalog refresh failed; starting with an empty catalog', {
            error: cause instanceof Error ? cause.message : String(cause)
        });
    }

    // ── Audit store ──────────────────────────────────────────────────────────────
    const auditDir = path.dirname(config.auditDb);
    if (!fs.existsSync(auditDir)) {
        fs.mkdirSync(auditDir, { recursive: true });
    }
    const auditStore = new AuditStore(config.auditDb, logger);

    // ── Risk Engine ──────────────────────────────────────────────────────────────
    let llmProvider;
    if (config.risk.provider) {
        if (config.risk.provider.kind === 'groq') {
            // resolve env: prefix
            const apiKeyRef = config.risk.provider.apiKey;
            const apiKey = apiKeyRef.startsWith('env:') ? process.env[apiKeyRef.slice(4)] : apiKeyRef;
            if (!apiKey) {
                logger.warn('Groq API key not found in environment, LLM evaluation will fail', { key: apiKeyRef });
            }
            llmProvider = new GroqProvider(apiKey ?? '', config.risk.provider.model);
        } else if (config.risk.provider.kind === 'ollama') {
            llmProvider = new OllamaProvider(config.risk.provider.url, config.risk.provider.model);
        }
    }
    const riskEngine = new RiskEngine(llmProvider, {
        heuristicOnly: config.risk.heuristicOnly,
        llmTimeoutMs: config.risk.llmTimeoutMs,
        escalationThreshold: config.risk.escalationThreshold,
        escalateObligation: config.risk.escalateObligation
    });

    // ── Approvals ────────────────────────────────────────────────────────────────
    let approvalStore;
    let signer;
    let notifier;
    if (config.approval) {
        const approvalDir = path.dirname(config.approvalDb);
        if (!fs.existsSync(approvalDir)) {
            fs.mkdirSync(approvalDir, { recursive: true });
        }
        approvalStore = new ApprovalStore(config.approvalDb);
        
        const hmacRef = config.approval.hmacSecret;
        const secretHex = hmacRef.startsWith('env:') ? process.env[hmacRef.slice(4)] : hmacRef;
        if (!secretHex || secretHex.length < 32) {
            logger.warn('Approval HMAC secret missing or too short, approvals will fail');
        }
        signer = new Signer(secretHex ?? '');
        
        const webhookRef = config.approval.discordWebhookUrl;
        const discordWebhookUrl = webhookRef?.startsWith('env:') ? process.env[webhookRef.slice(4)] : webhookRef;
        notifier = new Notifier({
            loopbackBaseUrl: config.approval.loopbackBaseUrl,
            ...(discordWebhookUrl ? { discordWebhookUrl } : {})
        });
    }

    // ── Sentinel server ──────────────────────────────────────────────────────────
    const sentinel = new SentinelServer({ 
        config, registry, catalog, logger, auditStore, riskEngine, resultScanner,
        approvalStore, signer, notifier
    });

    // ── HTTP server ──────────────────────────────────────────────────────────────
    const bound = await startHttpServer({ sentinel, settings: config.http, logger });

    logger.info('Sentinel ready', {
        instanceName: config.instanceName,
        host: bound.host,
        port: bound.port,
        mcpEndpoint: `http://${bound.host}:${bound.port}/mcp`
    });

    // ── graceful shutdown ────────────────────────────────────────────────────────
    let shutdownInProgress = false;

    const shutdown = async (signal: string): Promise<void> => {
        if (shutdownInProgress) return;
        shutdownInProgress = true;

        logger.info('shutdown signal received', { signal });

        try {
            await sentinel.close();
        } catch (cause) {
            logger.warn('error closing MCP handler', {
                error: cause instanceof Error ? cause.message : String(cause)
            });
        }

        try {
            await bound.close();
        } catch (cause) {
            logger.warn('error closing HTTP server', {
                error: cause instanceof Error ? cause.message : String(cause)
            });
        }

        try {
            await registry.close();
        } catch (cause) {
            logger.warn('error closing upstream registry', {
                error: cause instanceof Error ? cause.message : String(cause)
            });
        }

        try {
            auditStore.close();
        } catch (cause) {
            logger.warn('error closing audit store', {
                error: cause instanceof Error ? cause.message : String(cause)
            });
        }

        logger.info('shutdown complete');
        process.exit(0);
    };

    process.on('SIGTERM', () => void shutdown('SIGTERM'));
    process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch(cause => {
    // Unhandled rejection during startup — before the process is serving.
    // Write to stderr directly: the logger may not be initialised.
    process.stderr.write(
        JSON.stringify({
            level: 'error',
            msg: 'fatal error during gateway startup',
            error: cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause)
        }) + '\n'
    );
    process.exit(1);
});
