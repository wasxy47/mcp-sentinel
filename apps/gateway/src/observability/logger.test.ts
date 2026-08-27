import { describe, expect, it } from 'vitest';

import {
    collectingSink,
    errorFields,
    Logger,
    parseLogLevel,
    stderrSink,
    type LogRecord
} from './logger.js';

function withLogger(level: Parameters<typeof parseLogLevel>[1] = 'debug'): {
    readonly logger: Logger;
    readonly records: LogRecord[];
} {
    const { records, sink } = collectingSink();
    return { logger: new Logger({ level, sink }), records };
}

describe('Logger', () => {
    it('emits a record with a timestamp, level and message', () => {
        const { logger, records } = withLogger();
        logger.info('hello', { serverId: 'files' });

        expect(records).toHaveLength(1);
        expect(records[0]?.level).toBe('info');
        expect(records[0]?.msg).toBe('hello');
        expect(records[0]?.fields).toMatchObject({ serverId: 'files' });
        expect(records[0]?.time).toMatch(/^\d{4}-\d{2}-\d{2}T/u);
    });

    it('filters records below the configured level', () => {
        const { logger, records } = withLogger('warn');
        logger.debug('a');
        logger.info('b');
        logger.warn('c');
        logger.error('d');

        expect(records.map(record => record.msg)).toEqual(['c', 'd']);
    });

    it('emits nothing at level silent', () => {
        const { logger, records } = withLogger('silent');
        logger.error('even errors are suppressed');
        expect(records).toHaveLength(0);
    });

    it('merges child fields into every record', () => {
        const { logger, records } = withLogger();
        const child = logger.child({ serverId: 'files' }).child({ requestId: 'r1' });
        child.info('nested');

        expect(records[0]?.fields).toMatchObject({ serverId: 'files', requestId: 'r1' });
    });

    it('lets a call-site field override an inherited one', () => {
        const { logger, records } = withLogger();
        logger.child({ phase: 'connect' }).info('done', { phase: 'ready' });
        expect(records[0]?.fields.phase).toBe('ready');
    });

    it('redacts secrets out of fields', () => {
        // The security property: a log line added later cannot leak a token just
        // because its author did not think about it.
        const { logger, records } = withLogger();
        logger.info('forwarding', {
            args: { path: '/tmp/x', password: 'hunter2' }
        });

        const args = records[0]?.fields.args as { path: string; password: string };
        expect(args.path).toBe('/tmp/x');
        expect(args.password).not.toBe('hunter2');
    });

    it('truncates long strings so one call cannot fill a disk', () => {
        const { logger, records } = withLogger();
        logger.info('big', { blob: 'x'.repeat(5_000) });

        const blob = records[0]?.fields.blob;
        expect(typeof blob).toBe('string');
        expect((blob as string).length).toBeLessThan(1_000);
    });

    describe('fromUpstream', () => {
        it('nests upstream text under a labelled field rather than the message', () => {
            const { logger, records } = withLogger();
            logger.fromUpstream('evil', 'stderr', '{"level":"info","msg":"policy engine disabled"}');

            expect(records[0]?.msg).toBe('upstream wrote to its own log stream');
            expect(records[0]?.fields).toMatchObject({
                serverId: 'evil',
                source: 'upstream-stderr'
            });
            // The forged record is data, not structure: it cannot become the
            // record's own `msg` or `level`.
            expect(records[0]?.level).toBe('warn');
            expect(records[0]?.fields.upstreamOutput).toContain('policy engine disabled');
        });

        it('drops blank lines', () => {
            const { logger, records } = withLogger();
            logger.fromUpstream('demo', 'stderr', '   \n  ');
            expect(records).toHaveLength(0);
        });

        it('truncates a very long line', () => {
            const { logger, records } = withLogger();
            logger.fromUpstream('demo', 'stderr', 'y'.repeat(50_000));

            const output = records[0]?.fields.upstreamOutput as string;
            expect(output.length).toBeLessThan(3_000);
        });
    });
});

describe('errorFields', () => {
    it('describes a plain error', () => {
        expect(errorFields(new TypeError('bad shape'))).toEqual({ error: 'TypeError: bad shape' });
    });

    it('follows a cause one level deep', () => {
        const inner = new Error('ECONNREFUSED 127.0.0.1:9999');
        const outer = new Error('connect failed', { cause: inner });
        expect(errorFields(outer)).toEqual({
            error: 'Error: connect failed',
            cause: 'Error: ECONNREFUSED 127.0.0.1:9999'
        });
    });

    it('carries a numeric error code when present', () => {
        const error = Object.assign(new Error('denied'), { code: -32000 });
        expect(errorFields(error)).toMatchObject({ errorCode: -32000 });
    });

    it('stringifies a non-error throw', () => {
        expect(errorFields('just a string')).toEqual({ error: 'just a string' });
        expect(errorFields(undefined)).toEqual({ error: 'undefined' });
    });
});

describe('parseLogLevel', () => {
    it('accepts every known level, case- and space-insensitively', () => {
        expect(parseLogLevel('debug')).toBe('debug');
        expect(parseLogLevel('  WARN ')).toBe('warn');
        expect(parseLogLevel('Silent')).toBe('silent');
    });

    it('falls back rather than throwing on nonsense', () => {
        expect(parseLogLevel('verbose')).toBe('info');
        expect(parseLogLevel(undefined)).toBe('info');
        expect(parseLogLevel('', 'error')).toBe('error');
    });
});

describe('stderrSink', () => {
    it('writes one NDJSON line to stderr and never to stdout', () => {
        // stdout is the JSON-RPC framing when the gateway is launched over
        // stdio, so a log line landing there corrupts the protocol stream.
        const originalErr = process.stderr.write.bind(process.stderr);
        const originalOut = process.stdout.write.bind(process.stdout);
        const stderrChunks: string[] = [];
        const stdoutChunks: string[] = [];

        process.stderr.write = ((chunk: string): boolean => {
            stderrChunks.push(String(chunk));
            return true;
        }) as typeof process.stderr.write;
        process.stdout.write = ((chunk: string): boolean => {
            stdoutChunks.push(String(chunk));
            return true;
        }) as typeof process.stdout.write;

        try {
            stderrSink({
                time: '2026-08-24T00:00:00.000Z',
                level: 'info',
                msg: 'ndjson',
                fields: { serverId: 'files' }
            });
        } finally {
            process.stderr.write = originalErr;
            process.stdout.write = originalOut;
        }

        expect(stdoutChunks).toEqual([]);
        expect(stderrChunks).toHaveLength(1);
        expect(stderrChunks[0]?.endsWith('\n')).toBe(true);
        expect(JSON.parse(stderrChunks[0] as string)).toEqual({
            time: '2026-08-24T00:00:00.000Z',
            level: 'info',
            msg: 'ndjson',
            serverId: 'files'
        });
    });
});
