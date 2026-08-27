import { describe, expect, it } from 'vitest';

import {
    isQualifiedResourceUri,
    isSentinelToolName,
    isValidServerId,
    isValidToolName,
    NAMESPACE_SEPARATOR,
    NamingError,
    parseQualifiedPromptName,
    parseQualifiedResourceUri,
    parseQualifiedToolName,
    qualifyPromptName,
    qualifyResourceUri,
    qualifyToolName,
    RESOURCE_URI_SCHEME,
    SENTINEL_SERVER_ID
} from './naming.js';

describe('isValidServerId', () => {
    it('accepts lowercase alphanumeric with dashes', () => {
        expect(isValidServerId('files')).toBe(true);
        expect(isValidServerId('github-api')).toBe(true);
        expect(isValidServerId('db2')).toBe(true);
        expect(isValidServerId('a')).toBe(true);
    });

    it('rejects underscores, which are reserved for the separator', () => {
        expect(isValidServerId('my_server')).toBe(false);
        expect(isValidServerId('a__b')).toBe(false);
    });

    it('rejects uppercase, leading dashes, dots and empty ids', () => {
        expect(isValidServerId('Files')).toBe(false);
        expect(isValidServerId('-files')).toBe(false);
        expect(isValidServerId('my.server')).toBe(false);
        expect(isValidServerId('')).toBe(false);
    });

    it('bounds the length', () => {
        expect(isValidServerId('a'.repeat(64))).toBe(true);
        expect(isValidServerId('a'.repeat(65))).toBe(false);
    });
});

describe('isValidToolName', () => {
    it('accepts the character set clients generally allow', () => {
        expect(isValidToolName('read_file')).toBe(true);
        expect(isValidToolName('readFile')).toBe(true);
        expect(isValidToolName('read-file')).toBe(true);
        expect(isValidToolName('a__b')).toBe(true);
    });

    it('rejects names that would break clients or the namespace', () => {
        expect(isValidToolName('')).toBe(false);
        expect(isValidToolName('read file')).toBe(false);
        expect(isValidToolName('read/file')).toBe(false);
        expect(isValidToolName('read.file')).toBe(false);
        expect(isValidToolName('a'.repeat(129))).toBe(false);
    });
});

describe('qualifyToolName', () => {
    it('joins with the namespace separator', () => {
        expect(qualifyToolName('files', 'read_file')).toBe('files__read_file');
    });

    it('refuses an invalid server id with an explanatory message', () => {
        expect(() => qualifyToolName('my_server', 'read_file')).toThrow(NamingError);
        expect(() => qualifyToolName('my_server', 'read_file')).toThrow(/underscores/);
    });

    it('refuses an invalid tool name', () => {
        expect(() => qualifyToolName('files', 'read file')).toThrow(/invalid tool name/);
    });
});

describe('parseQualifiedToolName', () => {
    it('round-trips with qualifyToolName', () => {
        for (const [serverId, toolName] of [
            ['files', 'read_file'],
            ['github-api', 'create-issue'],
            ['db', 'a']
        ] as const) {
            const parsed = parseQualifiedToolName(qualifyToolName(serverId, toolName));
            expect(parsed).toEqual({ serverId, toolName });
        }
    });

    it('splits on the FIRST separator so tool names may contain one', () => {
        // Splitting on the last `__` would silently reroute this call to a
        // different server, which is exactly the ambiguity we are avoiding.
        expect(parseQualifiedToolName('files__read__file')).toEqual({
            serverId: 'files',
            toolName: 'read__file'
        });
    });

    it('returns undefined for unparseable names instead of throwing', () => {
        // Client-supplied input, so this is an ordinary "unknown tool" condition.
        expect(parseQualifiedToolName('read_file')).toBeUndefined();
        expect(parseQualifiedToolName('__read_file')).toBeUndefined();
        expect(parseQualifiedToolName('files__')).toBeUndefined();
        expect(parseQualifiedToolName('')).toBeUndefined();
        expect(parseQualifiedToolName('Files__read_file')).toBeUndefined();
        expect(parseQualifiedToolName('files__read file')).toBeUndefined();
    });
});

describe('isSentinelToolName', () => {
    it('recognises the gateway\'s own namespace', () => {
        expect(isSentinelToolName('sentinel__query_audit_log')).toBe(true);
        expect(isSentinelToolName('files__read_file')).toBe(false);
        // A server literally named `sentinel` cannot be registered, so this
        // prefix is unforgeable from upstream.
        expect(isSentinelToolName('sentinel')).toBe(false);
    });

    it('is consistent with the exported constants', () => {
        const name = `${SENTINEL_SERVER_ID}${NAMESPACE_SEPARATOR}explain_decision`;
        expect(isSentinelToolName(name)).toBe(true);
        expect(parseQualifiedToolName(name)).toEqual({
            serverId: SENTINEL_SERVER_ID,
            toolName: 'explain_decision'
        });
    });
});

describe('prompt names', () => {
    it('round-trip through the same namespace as tools', () => {
        expect(qualifyPromptName('docs', 'summarise')).toBe('docs__summarise');
        expect(parseQualifiedPromptName('docs__summarise')).toEqual({
            serverId: 'docs',
            promptName: 'summarise'
        });
    });

    it('name the right thing when refusing', () => {
        expect(() => qualifyPromptName('docs', 'bad name')).toThrow(/invalid prompt name/);
    });

    it('return undefined for unparseable names', () => {
        expect(parseQualifiedPromptName('summarise')).toBeUndefined();
        expect(parseQualifiedPromptName('docs__')).toBeUndefined();
    });
});

describe('qualifyResourceUri', () => {
    it('wraps the upstream uri as one opaque path segment', () => {
        expect(qualifyResourceUri('files', 'file:///etc/hosts')).toBe(
            'mcp-sentinel://files/file%3A%2F%2F%2Fetc%2Fhosts'
        );
    });

    it('uses the exported scheme', () => {
        expect(qualifyResourceUri('files', 'a:b').startsWith(`${RESOURCE_URI_SCHEME}://`)).toBe(true);
    });

    it('refuses an invalid server id and an empty uri', () => {
        expect(() => qualifyResourceUri('my_server', 'a:b')).toThrow(NamingError);
        expect(() => qualifyResourceUri('files', '')).toThrow(/empty resource uri/);
    });
});

describe('parseQualifiedResourceUri', () => {
    it('round-trips byte-exactly over uris that would defeat a URL-based wrapper', () => {
        const cases = [
            'file:///etc/passwd',
            'https://example.com/a b?q=1&r=2#frag',
            'urn:isbn:0451450523',
            'custom://хост/путь',
            'mcp-sentinel://other/already-wrapped',
            // WHATWG URL parsing normalises these away; literal splitting does not.
            '..',
            '../../etc/passwd',
            'a/../b',
            '%2E%2E'
        ] as const;

        for (const uri of cases) {
            const qualified = qualifyResourceUri('files', uri);
            expect(parseQualifiedResourceUri(qualified)).toEqual({ serverId: 'files', uri });
        }
    });

    it('accepts a server id starting with a digit', () => {
        // The property that ruled out a scheme-prefix wrapper: `9files:` is not a
        // legal URI scheme, but `mcp-sentinel://9files/…` is a legal authority.
        expect(parseQualifiedResourceUri(qualifyResourceUri('9files', 'a:b'))).toEqual({
            serverId: '9files',
            uri: 'a:b'
        });
    });

    it('rejects non-canonical spellings that decode to the same uri', () => {
        // Both of these decode to `file:///x`. Accepting an alias would let an
        // agent slip past a policy written against the canonical form.
        expect(parseQualifiedResourceUri('mcp-sentinel://files/file%3A%2F%2F%2Fx')).toEqual({
            serverId: 'files',
            uri: 'file:///x'
        });
        expect(parseQualifiedResourceUri('mcp-sentinel://files/file:%2F%2F%2Fx')).toBeUndefined();
        expect(parseQualifiedResourceUri('mcp-sentinel://files/file%3a%2F%2F%2Fx')).toBeUndefined();
    });

    it('returns undefined for anything it did not produce', () => {
        expect(parseQualifiedResourceUri('file:///etc/passwd')).toBeUndefined();
        expect(parseQualifiedResourceUri('mcp-sentinel://files')).toBeUndefined();
        expect(parseQualifiedResourceUri('mcp-sentinel://files/')).toBeUndefined();
        expect(parseQualifiedResourceUri('mcp-sentinel:///x')).toBeUndefined();
        expect(parseQualifiedResourceUri('mcp-sentinel://my_server/x')).toBeUndefined();
        expect(parseQualifiedResourceUri('mcp-sentinel://Files/x')).toBeUndefined();
        // Malformed percent escape: decodeURIComponent throws, we do not.
        expect(parseQualifiedResourceUri('mcp-sentinel://files/%zz')).toBeUndefined();
        expect(parseQualifiedResourceUri('mcp-sentinel://files/%ED%A0%80')).toBeUndefined();
    });
});

describe('isQualifiedResourceUri', () => {
    it('recognises wrapped uris only', () => {
        expect(isQualifiedResourceUri(qualifyResourceUri('files', 'a:b'))).toBe(true);
        expect(isQualifiedResourceUri('file:///etc/hosts')).toBe(false);
    });
});
