import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { ConfigError, loadConfigFile, parseConfig, resolveEnvReference } from './load.js';

const BASE = '/srv/sentinel';

/** The minimum a valid config needs: `workspaceRoot` has no safe default. */
function minimal(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return { workspaceRoot: 'workspace', ...overrides };
}

describe('resolveEnvReference', () => {
    it('passes a literal through unchanged', () => {
        expect(resolveEnvReference('Bearer abc', 'headers.Authorization', {})).toBe('Bearer abc');
    });

    it('reads a prefixed value from the environment', () => {
        expect(resolveEnvReference('env:TOKEN', 'headers.Authorization', { TOKEN: 'secret' })).toBe('secret');
    });

    it('tolerates surrounding whitespace in the variable name', () => {
        expect(resolveEnvReference('env: TOKEN ', 'headers.Authorization', { TOKEN: 'secret' })).toBe('secret');
    });

    it('rejects a reference with no variable name', () => {
        expect(() => resolveEnvReference('env:', 'headers.X', {})).toThrow(ConfigError);
    });

    it('rejects an unset variable rather than silently omitting it', () => {
        // An upstream that expected credentials and got none fails later, looking
        // like a network problem rather than the configuration problem it is.
        expect(() => resolveEnvReference('env:MISSING', 'headers.X', {})).toThrow(/MISSING is not set/u);
    });

    it('treats an empty variable as unset', () => {
        expect(() => resolveEnvReference('env:BLANK', 'headers.X', { BLANK: '' })).toThrow(/not set/u);
    });

    it('names the variable but never prints its value', () => {
        try {
            resolveEnvReference('env:MISSING', 'servers.files.transport.headers.Authorization', {});
            expect.unreachable('should have thrown');
        } catch (error) {
            const message = (error as Error).message;
            expect(message).toContain('MISSING');
            expect(message).toContain('servers.files.transport.headers.Authorization');
        }
    });
});

describe('parseConfig defaults', () => {
    it('fills in every optional section', () => {
        const config = parseConfig(minimal(), { baseDir: BASE, env: {} });

        expect(config.instanceName).toBe('mcp-sentinel');
        expect(config.http).toEqual({ host: '127.0.0.1', port: 8787, allowedOrigins: [], maxBodyBytes: 4194304 });
        expect(config.upstream.connectTimeoutMs).toBe(10_000);
        expect(config.upstream.requestTimeoutMs).toBe(30_000);
        expect(config.upstream.upstreamProtocol).toBe('auto');
        expect(config.servers).toEqual([]);
    });

    it('applies the nested reconnect defaults when the block is omitted', () => {
        // `.prefault({})` rather than `.default({})`: the latter would have to
        // restate the whole block, so a field added later would arrive undefined.
        const config = parseConfig(minimal(), { baseDir: BASE, env: {} });

        expect(config.upstream.reconnect).toEqual({
            initialDelayMs: 500,
            maxDelayMs: 30_000,
            factor: 2,
            failFastAfter: 3
        });
    });

    it('keeps a partially-specified reconnect block and defaults the rest', () => {
        const config = parseConfig(minimal({ upstream: { reconnect: { failFastAfter: 9 } } }), {
            baseDir: BASE,
            env: {}
        });

        expect(config.upstream.reconnect.failFastAfter).toBe(9);
        expect(config.upstream.reconnect.initialDelayMs).toBe(500);
    });

    it('defaults a server to untrusted and enabled', () => {
        const config = parseConfig(
            minimal({ servers: [{ id: 'files', transport: { kind: 'stdio', command: 'srv' } }] }),
            { baseDir: BASE, env: {} }
        );

        expect(config.servers[0]?.trust).toBe('untrusted');
        expect(config.servers[0]?.enabled).toBe(true);
        expect(config.servers[0]?.transport).toMatchObject({ args: [], env: {} });
    });

    it('binds to loopback unless told otherwise', () => {
        expect(parseConfig(minimal(), { baseDir: BASE, env: {} }).http.host).toBe('127.0.0.1');
    });
});

describe('parseConfig path resolution', () => {
    it('resolves relative paths against the base directory', () => {
        const config = parseConfig(minimal(), { baseDir: BASE, env: {} });

        expect(config.workspaceRoot).toBe(resolve(BASE, 'workspace'));
        expect(config.policyDir).toBe(resolve(BASE, 'policies'));
        expect(config.auditDb).toBe(resolve(BASE, 'data/audit.db'));
    });

    it('leaves absolute paths alone', () => {
        const config = parseConfig(
            minimal({ workspaceRoot: '/data/work', policyDir: '/etc/sentinel/policies' }),
            { baseDir: BASE, env: {} }
        );

        expect(config.workspaceRoot).toBe('/data/work');
        expect(config.policyDir).toBe('/etc/sentinel/policies');
    });

    it('resolves a stdio cwd against the config file, not the launch directory', () => {
        const config = parseConfig(
            minimal({
                servers: [{ id: 'files', transport: { kind: 'stdio', command: 'srv', cwd: 'sandbox' } }]
            }),
            { baseDir: BASE, env: {} }
        );

        const transport = config.servers[0]?.transport;
        expect(transport?.kind).toBe('stdio');
        expect(transport?.kind === 'stdio' ? transport.cwd : undefined).toBe(resolve(BASE, 'sandbox'));
    });
});

describe('parseConfig secret resolution', () => {
    it('resolves an env reference in an HTTP header', () => {
        const config = parseConfig(
            minimal({
                servers: [
                    {
                        id: 'remote',
                        transport: {
                            kind: 'http',
                            url: 'https://tools.example.com/mcp',
                            headers: { Authorization: 'env:FILES_TOKEN', 'X-Fixed': 'literal' }
                        }
                    }
                ]
            }),
            { baseDir: BASE, env: { FILES_TOKEN: 'Bearer live-token' } }
        );

        const transport = config.servers[0]?.transport;
        expect(transport?.kind === 'http' ? transport.headers : undefined).toEqual({
            Authorization: 'Bearer live-token',
            'X-Fixed': 'literal'
        });
    });

    it('resolves an env reference in a stdio child environment', () => {
        const config = parseConfig(
            minimal({
                servers: [
                    {
                        id: 'db',
                        transport: { kind: 'stdio', command: 'srv', env: { DSN: 'env:DATABASE_URL' } }
                    }
                ]
            }),
            { baseDir: BASE, env: { DATABASE_URL: 'postgres://localhost/app' } }
        );

        const transport = config.servers[0]?.transport;
        expect(transport?.kind === 'stdio' ? transport.env : undefined).toEqual({
            DSN: 'postgres://localhost/app'
        });
    });

    it('fails startup when a referenced variable is missing', () => {
        expect(() =>
            parseConfig(
                minimal({
                    servers: [
                        {
                            id: 'remote',
                            transport: {
                                kind: 'http',
                                url: 'https://tools.example.com/mcp',
                                headers: { Authorization: 'env:ABSENT' }
                            }
                        }
                    ]
                }),
                { baseDir: BASE, env: {} }
            )
        ).toThrow(/ABSENT is not set/u);
    });
});

describe('parseConfig validation', () => {
    it('requires workspaceRoot', () => {
        // Defaulting to cwd would move the security boundary whenever someone
        // changed directory before starting the gateway.
        expect(() => parseConfig({}, { baseDir: BASE, env: {} })).toThrow(ConfigError);
    });

    it('lists every issue rather than only the first', () => {
        try {
            parseConfig({ workspaceRoot: 'w', http: { port: 99999 }, instanceName: '' }, { baseDir: BASE, env: {} });
            expect.unreachable('should have thrown');
        } catch (error) {
            expect(error).toBeInstanceOf(ConfigError);
            expect((error as ConfigError).issues.length).toBeGreaterThanOrEqual(2);
        }
    });

    it('rejects a duplicate server id', () => {
        expect(() =>
            parseConfig(
                minimal({
                    servers: [
                        { id: 'files', transport: { kind: 'stdio', command: 'a' } },
                        { id: 'files', transport: { kind: 'stdio', command: 'b' } }
                    ]
                }),
                { baseDir: BASE, env: {} }
            )
        ).toThrow(/duplicate server id "files"/u);
    });

    it('rejects the reserved sentinel server id', () => {
        expect(() =>
            parseConfig(minimal({ servers: [{ id: 'sentinel', transport: { kind: 'stdio', command: 'a' } }] }), {
                baseDir: BASE,
                env: {}
            })
        ).toThrow(/reserved/u);
    });

    it('rejects a server id containing the namespace separator', () => {
        // `files__read_file` must split unambiguously into server and tool.
        expect(() =>
            parseConfig(minimal({ servers: [{ id: 'a__b', transport: { kind: 'stdio', command: 'a' } }] }), {
                baseDir: BASE,
                env: {}
            })
        ).toThrow(ConfigError);
    });

    it('rejects an unknown transport kind', () => {
        expect(() =>
            parseConfig(minimal({ servers: [{ id: 'x', transport: { kind: 'grpc', url: 'http://x' } }] }), {
                baseDir: BASE,
                env: {}
            })
        ).toThrow(ConfigError);
    });

    it('rejects a malformed upstream URL', () => {
        expect(() =>
            parseConfig(minimal({ servers: [{ id: 'x', transport: { kind: 'http', url: 'not a url' } }] }), {
                baseDir: BASE,
                env: {}
            })
        ).toThrow(ConfigError);
    });

    it('rejects an unknown trust tier', () => {
        expect(() =>
            parseConfig(
                minimal({
                    servers: [{ id: 'x', transport: { kind: 'stdio', command: 'a' }, trust: 'mostly-fine' }]
                }),
                { baseDir: BASE, env: {} }
            )
        ).toThrow(ConfigError);
    });

    it('accepts the quarantined trust tier', () => {
        const config = parseConfig(
            minimal({
                servers: [{ id: 'evil', transport: { kind: 'stdio', command: 'a' }, trust: 'quarantined' }]
            }),
            { baseDir: BASE, env: {} }
        );
        expect(config.servers[0]?.trust).toBe('quarantined');
    });
});

describe('loadConfigFile', () => {
    const dirs: string[] = [];

    afterAll(() => {
        // Temp dirs are left to the OS; nothing sensitive is written here.
        dirs.length = 0;
    });

    async function writeConfig(contents: string): Promise<string> {
        const dir = await mkdtemp(join(tmpdir(), 'sentinel-config-'));
        dirs.push(dir);
        const path = join(dir, 'sentinel.json');
        await writeFile(path, contents, 'utf8');
        return path;
    }

    it('reads a file and resolves paths relative to it', async () => {
        const path = await writeConfig(JSON.stringify({ workspaceRoot: './work' }));
        const config = await loadConfigFile(path, { env: {} });

        expect(config.workspaceRoot).toBe(resolve(path, '..', 'work'));
        expect(config.policyDir).toBe(resolve(path, '..', 'policies'));
    });

    it('reports a missing file as a config error', async () => {
        await expect(loadConfigFile(join(tmpdir(), 'definitely-absent-sentinel.json'))).rejects.toThrow(
            ConfigError
        );
    });

    it('reports malformed JSON as a config error, not a syntax error', async () => {
        const path = await writeConfig('{ "workspaceRoot": ');
        await expect(loadConfigFile(path, { env: {} })).rejects.toThrow(/not valid JSON/u);
    });

    it('surfaces schema issues from the file path too', async () => {
        const path = await writeConfig(JSON.stringify({ http: { port: 70_000 } }));
        await expect(loadConfigFile(path, { env: {} })).rejects.toThrow(ConfigError);
    });
});
