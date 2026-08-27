import { describe, expect, it } from 'vitest';

import {
    assertHeaderMatchesBody,
    buildRequestMetadataHeaders,
    decodeHeaderValue,
    encodeHeaderValue,
    HEADER_MCP_METHOD,
    HEADER_MCP_NAME,
    HEADER_PROTOCOL_VERSION,
    isHeaderSafe,
    looksBase64Encoded,
    readRequestMetadata,
    SENTINEL_PROTOCOL_VERSION
} from './headers.js';
import { HeaderMismatchError } from './errors.js';
import { McpErrorCode } from './errors.js';

describe('isHeaderSafe', () => {
    it('accepts visible ASCII, interior space and interior htab', () => {
        expect(isHeaderSafe('tools/call')).toBe(true);
        expect(isHeaderSafe('read_file')).toBe(true);
        expect(isHeaderSafe('a b')).toBe(true);
        expect(isHeaderSafe('a\tb')).toBe(true);
        expect(isHeaderSafe('')).toBe(true);
    });

    it('rejects non-ASCII and control characters', () => {
        expect(isHeaderSafe('café')).toBe(false);
        expect(isHeaderSafe('a\nb')).toBe(false);
        expect(isHeaderSafe('a\u0000b')).toBe(false);
        expect(isHeaderSafe('🙂')).toBe(false);
    });

    it('rejects leading or trailing whitespace, which intermediaries may strip', () => {
        expect(isHeaderSafe(' a')).toBe(false);
        expect(isHeaderSafe('a ')).toBe(false);
        expect(isHeaderSafe('\ta')).toBe(false);
        expect(isHeaderSafe('a\t')).toBe(false);
    });
});

describe('looksBase64Encoded', () => {
    it('recognises the exact sentinel wrapper', () => {
        expect(looksBase64Encoded('=?base64?QQ==?=')).toBe(true);
        expect(looksBase64Encoded('=?base64??=')).toBe(true);
    });

    it('is case-sensitive on the markers, as the spec requires', () => {
        expect(looksBase64Encoded('=?BASE64?QQ==?=')).toBe(false);
    });

    it('rejects partial wrappers', () => {
        expect(looksBase64Encoded('=?base64?QQ==')).toBe(false);
        expect(looksBase64Encoded('QQ==?=')).toBe(false);
        expect(looksBase64Encoded('read_file')).toBe(false);
    });
});

describe('encodeHeaderValue / decodeHeaderValue', () => {
    it('passes header-safe values through untouched', () => {
        expect(encodeHeaderValue('tools/call')).toBe('tools/call');
        expect(encodeHeaderValue('file:///tmp/a.txt')).toBe('file:///tmp/a.txt');
    });

    it('round-trips values that cannot travel literally', () => {
        for (const value of ['café', 'a\nb', ' padded ', '🙂 emoji', 'tab\there\t']) {
            const encoded = encodeHeaderValue(value);
            expect(looksBase64Encoded(encoded)).toBe(true);
            expect(decodeHeaderValue(encoded)).toBe(value);
        }
    });

    it('encodes a value that would itself look like the sentinel', () => {
        // Otherwise the peer would decode a literal tool name as base64.
        const literal = '=?base64?QQ==?=';
        const encoded = encodeHeaderValue(literal);
        expect(encoded).not.toBe(literal);
        expect(decodeHeaderValue(encoded)).toBe(literal);
    });

    it('leaves non-sentinel values alone when decoding', () => {
        expect(decodeHeaderValue('read_file')).toBe('read_file');
    });

    it('rejects a malformed base64 payload rather than passing it through', () => {
        expect(() => decodeHeaderValue('=?base64?!!!!?=')).toThrow(HeaderMismatchError);
        // Length not a multiple of four.
        expect(() => decodeHeaderValue('=?base64?QQQ?=')).toThrow(/not valid base64/);
    });

    it('rejects non-canonical base64', () => {
        // 'QR==' decodes to the same byte as 'QQ==' but is not the canonical form.
        expect(() => decodeHeaderValue('=?base64?QR==?=')).toThrow(/not canonical base64/);
    });

    it('rejects payloads that are not valid UTF-8', () => {
        // '/w==' is base64 of the lone byte 0xFF, which is not valid UTF-8.
        expect(() => decodeHeaderValue('=?base64?/w==?=')).toThrow(/not valid UTF-8/);
    });

    it('reports the offending header name in the error data', () => {
        try {
            decodeHeaderValue('=?base64?!!!!?=', HEADER_MCP_NAME);
            expect.unreachable('should have thrown');
        } catch (error) {
            expect(error).toBeInstanceOf(HeaderMismatchError);
            const mismatch = error as HeaderMismatchError;
            expect(mismatch.code).toBe(McpErrorCode.HeaderMismatch);
            expect(mismatch.httpStatus).toBe(400);
            expect(mismatch.data).toMatchObject({ header: HEADER_MCP_NAME });
        }
    });
});

describe('readRequestMetadata', () => {
    it('extracts and decodes the request-metadata headers', () => {
        const headers = new Headers({
            [HEADER_PROTOCOL_VERSION]: SENTINEL_PROTOCOL_VERSION,
            [HEADER_MCP_METHOD]: 'tools/call',
            [HEADER_MCP_NAME]: encodeHeaderValue('lire_fichier'),
            'Mcp-Param-Path': encodeHeaderValue('/tmp/naïve.txt'),
            'Mcp-Param-Mode': 'read',
            'X-Unrelated': 'ignored'
        });

        const metadata = readRequestMetadata(headers);

        expect(metadata.protocolVersion).toBe(SENTINEL_PROTOCOL_VERSION);
        expect(metadata.method).toBe('tools/call');
        expect(metadata.name).toBe('lire_fichier');
        expect(metadata.params.get('path')).toBe('/tmp/naïve.txt');
        expect(metadata.params.get('mode')).toBe('read');
        expect(metadata.params.has('x-unrelated')).toBe(false);
        expect(metadata.params.size).toBe(2);
    });

    it('reports absent headers as undefined rather than empty strings', () => {
        const metadata = readRequestMetadata(new Headers());
        expect(metadata.protocolVersion).toBeUndefined();
        expect(metadata.method).toBeUndefined();
        expect(metadata.name).toBeUndefined();
        expect(metadata.params.size).toBe(0);
    });
});

describe('assertHeaderMatchesBody', () => {
    const metadata = (method?: string, name?: string) =>
        readRequestMetadata(
            new Headers({
                ...(method === undefined ? {} : { [HEADER_MCP_METHOD]: method }),
                ...(name === undefined ? {} : { [HEADER_MCP_NAME]: encodeHeaderValue(name) })
            })
        );

    it('accepts a consistent request', () => {
        expect(() =>
            assertHeaderMatchesBody(metadata('tools/call', 'files__read_file'), {
                method: 'tools/call',
                params: { name: 'files__read_file', arguments: { path: '/tmp/a' } }
            })
        ).not.toThrow();
    });

    it('requires Mcp-Method on every request', () => {
        expect(() => assertHeaderMatchesBody(metadata(undefined), { method: 'tools/list' })).toThrow(
            /Mcp-Method header is required/
        );
    });

    it('rejects a method mismatch', () => {
        expect(() =>
            assertHeaderMatchesBody(metadata('tools/list'), { method: 'tools/call', params: { name: 'x' } })
        ).toThrow(/does not match body value/);
    });

    it('rejects a name mismatch — the smuggling case this check exists for', () => {
        // Header says a benign tool so policy allows it; body calls a dangerous one.
        expect(() =>
            assertHeaderMatchesBody(metadata('tools/call', 'files__read_file'), {
                method: 'tools/call',
                params: { name: 'shell__exec' }
            })
        ).toThrow(/does not match body params.name/);
    });

    it('requires Mcp-Name for the methods that define it', () => {
        expect(() =>
            assertHeaderMatchesBody(metadata('tools/call'), { method: 'tools/call', params: { name: 'x' } })
        ).toThrow(/Mcp-Name header is required for tools\/call/);
    });

    it('compares resources/read against params.uri, not params.name', () => {
        expect(() =>
            assertHeaderMatchesBody(metadata('resources/read', 'file:///a'), {
                method: 'resources/read',
                params: { uri: 'file:///a' }
            })
        ).not.toThrow();

        expect(() =>
            assertHeaderMatchesBody(metadata('resources/read', 'file:///a'), {
                method: 'resources/read',
                params: { name: 'file:///a' }
            })
        ).toThrow(/requires a string params.uri/);
    });

    it('ignores Mcp-Name for methods that do not define it', () => {
        // Intermediaries may add headers; a stray value is not a protocol error.
        expect(() =>
            assertHeaderMatchesBody(metadata('tools/list', 'stray'), { method: 'tools/list' })
        ).not.toThrow();
    });

    it('rejects a body with no method to compare against', () => {
        expect(() => assertHeaderMatchesBody(metadata('tools/list'), {})).toThrow(/no method to validate/);
    });
});

describe('buildRequestMetadataHeaders', () => {
    it('mirrors the rewritten tool name so the upstream server accepts the forward', () => {
        // The agent called `files__read_file`; upstream only knows `read_file`.
        const headers = buildRequestMetadataHeaders('tools/call', 'read_file');
        expect(headers[HEADER_MCP_METHOD]).toBe('tools/call');
        expect(headers[HEADER_MCP_NAME]).toBe('read_file');
        expect(headers[HEADER_PROTOCOL_VERSION]).toBe(SENTINEL_PROTOCOL_VERSION);
    });

    it('encodes a name that cannot travel literally', () => {
        const headers = buildRequestMetadataHeaders('resources/read', 'file:///tmp/naïve.txt');
        expect(headers[HEADER_MCP_NAME]).toBeDefined();
        expect(looksBase64Encoded(headers[HEADER_MCP_NAME]!)).toBe(true);
        expect(decodeHeaderValue(headers[HEADER_MCP_NAME]!)).toBe('file:///tmp/naïve.txt');
    });

    it('omits Mcp-Name for methods that do not define it', () => {
        expect(buildRequestMetadataHeaders('tools/list')).not.toHaveProperty(HEADER_MCP_NAME);
        expect(buildRequestMetadataHeaders('tools/list', 'stray')).not.toHaveProperty(HEADER_MCP_NAME);
    });

    it('produces headers that pass its own consistency check', () => {
        const built = buildRequestMetadataHeaders('tools/call', 'read_file');
        const parsed = readRequestMetadata(new Headers(built));
        expect(() =>
            assertHeaderMatchesBody(parsed, { method: 'tools/call', params: { name: 'read_file' } })
        ).not.toThrow();
    });
});
