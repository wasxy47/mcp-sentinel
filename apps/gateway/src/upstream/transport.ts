/**
 * Building a client transport from operator configuration.
 *
 * Two security decisions live here, both about what does *not* get passed
 * through:
 *
 *  1. **The child process environment is an allowlist, not an inheritance.** The
 *     gateway process holds the risk-engine API key, the approval HMAC secret and
 *     the path to the audit database. An upstream MCP server is by definition the
 *     component not trusted with those. So the child gets the SDK's safe inherited
 *     subset (`HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM`, `USER`) plus exactly what
 *     the operator declared, and nothing else. `process.env` is never spread.
 *
 *  2. **Child stderr is captured, not inherited.** An upstream that writes to a
 *     shared stderr can interleave text into Sentinel's own log stream, which is
 *     the log a human reads when deciding whether that server misbehaved. Piping
 *     it means Sentinel can prefix, truncate and attribute every line.
 */

import { StreamableHTTPClientTransport, type Transport } from '@modelcontextprotocol/client';
import { getDefaultEnvironment, StdioClientTransport } from '@modelcontextprotocol/client/stdio';

import type { UpstreamServerSettings } from '../config/schema.js';

/** Cap on a single JSON-RPC message from an upstream, in bytes. */
const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;

export type TransportFactory = (server: UpstreamServerSettings) => Transport;

/**
 * Build the transport for one upstream.
 *
 * `headers` and `env` have already had their `env:NAME` references resolved by
 * the config loader, so this function never touches the environment for secrets.
 */
export function buildUpstreamTransport(server: UpstreamServerSettings): Transport {
    if (server.transport.kind === 'http') {
        return new StreamableHTTPClientTransport(new URL(server.transport.url), {
            requestInit: { headers: { ...server.transport.headers } },
            // Sentinel owns reconnection at the pool level, where it can also
            // update health, notify the dashboard and record the outage. Leaving
            // the transport to reconnect underneath would hide those transitions.
            reconnectionOptions: {
                maxRetries: 0,
                initialReconnectionDelay: 1_000,
                maxReconnectionDelay: 1_000,
                reconnectionDelayGrowFactor: 1
            }
        });
    }

    return new StdioClientTransport({
        command: server.transport.command,
        args: [...server.transport.args],
        env: { ...getDefaultEnvironment(), ...server.transport.env },
        // 'pipe' rather than the SDK default of 'inherit' — see the header note.
        stderr: 'pipe',
        maxBufferSize: MAX_MESSAGE_BYTES,
        ...(server.transport.cwd === undefined ? {} : { cwd: server.transport.cwd })
    });
}
