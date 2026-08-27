/**
 * Config loading: file → JSON → zod → resolved paths and secrets.
 *
 * The one interesting piece here is `env:NAME` indirection. Sentinel needs to
 * hand some upstreams a bearer token or an API key, and there is no version of
 * "put the token in the config file" that ends well — config files get committed,
 * pasted into issues, and copied between machines. So a value of `env:FILES_TOKEN`
 * means "read `FILES_TOKEN` from my environment at connect time".
 *
 * Resolution is strict: a named variable that is missing or empty is a startup
 * error, not a silently-omitted header. An upstream that expected credentials and
 * received none would otherwise fail later, in a way that looks like a network
 * problem rather than a configuration one.
 */

import { readFile } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';

import * as z from 'zod';

import { GatewayConfigSchema, type GatewayConfig } from './schema.js';

/** Prefix marking a value that must be read from the environment. */
export const ENV_REFERENCE_PREFIX = 'env:';

export class ConfigError extends Error {
    public readonly issues: readonly string[];

    public constructor(message: string, issues: readonly string[] = []) {
        super(issues.length === 0 ? message : `${message}\n  - ${issues.join('\n  - ')}`);
        this.name = 'ConfigError';
        this.issues = issues;
    }
}

/**
 * Resolve one `env:NAME` reference. Non-prefixed values pass through unchanged,
 * so a literal is always allowed — it is just visible as a literal.
 */
export function resolveEnvReference(
    value: string,
    where: string,
    env: Readonly<Record<string, string | undefined>>
): string {
    if (!value.startsWith(ENV_REFERENCE_PREFIX)) return value;

    const name = value.slice(ENV_REFERENCE_PREFIX.length).trim();
    if (name.length === 0) {
        throw new ConfigError(`${where}: "${ENV_REFERENCE_PREFIX}" reference has no variable name`);
    }

    const resolved = env[name];
    if (resolved === undefined || resolved.length === 0) {
        // Naming the variable is safe and necessary; printing its value would
        // not be. This message is the only place the name appears.
        throw new ConfigError(`${where}: environment variable ${name} is not set`);
    }
    return resolved;
}

function resolveRecord(
    record: Readonly<Record<string, string>>,
    where: string,
    env: Readonly<Record<string, string | undefined>>
): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(record)) {
        out[key] = resolveEnvReference(value, `${where}.${key}`, env);
    }
    return out;
}

/** Flatten a zod error into one line per issue, with a dotted path. */
function describeIssues(error: z.ZodError): readonly string[] {
    return error.issues.map(issue => {
        const path = issue.path.length === 0 ? '(root)' : issue.path.join('.');
        return `${path}: ${issue.message}`;
    });
}

export interface LoadConfigOptions {
    /** Base directory relative paths are resolved against. Defaults to cwd. */
    readonly baseDir?: string;
    readonly env?: Readonly<Record<string, string | undefined>>;
}

/**
 * Validate an already-parsed config object.
 *
 * Split out from file reading so tests — and the demo harness — can build a
 * config in memory and get exactly the same validation, path resolution and
 * secret resolution the real startup path performs.
 */
export function parseConfig(input: unknown, options: LoadConfigOptions = {}): GatewayConfig {
    const baseDir = options.baseDir ?? process.cwd();
    const env = options.env ?? process.env;

    const parsed = GatewayConfigSchema.safeParse(input);
    if (!parsed.success) {
        throw new ConfigError('Invalid gateway configuration', describeIssues(parsed.error));
    }
    const config = parsed.data;

    const absolute = (path: string): string => (isAbsolute(path) ? path : resolve(baseDir, path));

    return {
        ...config,
        policyDir: absolute(config.policyDir),
        auditDb: absolute(config.auditDb),
        workspaceRoot: absolute(config.workspaceRoot),
        servers: config.servers.map(server => {
            const where = `servers.${server.id}`;
            if (server.transport.kind === 'http') {
                return {
                    ...server,
                    transport: {
                        ...server.transport,
                        headers: resolveRecord(server.transport.headers, `${where}.transport.headers`, env)
                    }
                };
            }
            return {
                ...server,
                transport: {
                    ...server.transport,
                    env: resolveRecord(server.transport.env, `${where}.transport.env`, env),
                    // A relative `cwd` is relative to the config file, not to
                    // wherever the gateway happened to be launched from.
                    ...(server.transport.cwd === undefined ? {} : { cwd: absolute(server.transport.cwd) })
                }
            };
        })
    };
}

/** Read and validate a JSON config file. Relative paths resolve against it. */
export async function loadConfigFile(
    path: string,
    options: Omit<LoadConfigOptions, 'baseDir'> = {}
): Promise<GatewayConfig> {
    const absolutePath = isAbsolute(path) ? path : resolve(process.cwd(), path);

    let text: string;
    try {
        text = await readFile(absolutePath, 'utf8');
    } catch (cause) {
        throw new ConfigError(`Cannot read config file ${absolutePath}`, [
            cause instanceof Error ? cause.message : String(cause)
        ]);
    }

    let json: unknown;
    try {
        json = JSON.parse(text);
    } catch (cause) {
        throw new ConfigError(`Config file ${absolutePath} is not valid JSON`, [
            cause instanceof Error ? cause.message : String(cause)
        ]);
    }

    return parseConfig(json, {
        baseDir: resolve(absolutePath, '..'),
        ...(options.env === undefined ? {} : { env: options.env })
    });
}
