/**
 * Shadowing and annotation-lying detector.
 *
 * Detects tool definitions that misrepresent themselves:
 *   - **Name/description mismatch**: a tool named `get_weather` whose
 *     description talks about reading files or executing commands.
 *   - **Schema lying**: `inputSchema` that lists dangerous parameters
 *     (shell commands, URLs, file paths) that the tool name doesn't suggest.
 *
 * This catches a subtler attack than poisoning: the description *doesn't*
 * contain imperative instructions, but the tool itself does something
 * different from what its name implies. The agent calls `get_weather` and
 * unknowingly triggers file system access because the schema asked for a
 * `filePath` parameter the agent filled in from context.
 *
 * Threat references: T4 (tool shadowing), T1 (annotation lying) in docs/threat-model.md
 */

import type { ScanFinding, Severity, ToolDefinition } from '@mcp-sentinel/mcp-core';

// ── Capability vocabularies ─────────────────────────────────────────────────

/** Keywords that indicate specific capabilities. */
const CAPABILITY_KEYWORDS: ReadonlyArray<{
    capability: string;
    keywords: readonly RegExp[];
}> = [
    {
        capability: 'filesystem',
        keywords: [
            /\bread[_\s-]?file\b/i, /\bwrite[_\s-]?file\b/i, /\bdelete[_\s-]?file\b/i,
            /\bfile[_\s-]?path\b/i, /\bdirectory\b/i, /\bfolder\b/i,
            /\bfilesystem\b/i, /\bfile\s+system\b/i,
        ]
    },
    {
        capability: 'network',
        keywords: [
            /\bhttp[s]?:\/\//i, /\bfetch\b/i, /\bcurl\b/i, /\bwget\b/i,
            /\burl\b/i, /\bendpoint\b/i, /\bapi[_\s-]?call\b/i,
            /\bsend\s+request\b/i, /\bweb\s*hook\b/i,
        ]
    },
    {
        capability: 'shell',
        keywords: [
            /\bexecute\b/i, /\bshell\b/i, /\bbash\b/i, /\bcommand\b/i,
            /\bsubprocess\b/i, /\bterminal\b/i, /\brun\s+command\b/i,
        ]
    },
    {
        capability: 'database',
        keywords: [
            /\bsql\b/i, /\bquery\b/i, /\bdatabase\b/i, /\btable\b/i,
            /\bschema\b/i, /\bdrop\b/i, /\binsert\b/i, /\bupdate\b/i, /\bdelete\b/i,
        ]
    },
    {
        capability: 'credentials',
        keywords: [
            /\bpassword\b/i, /\bsecret\b/i, /\btoken\b/i, /\bapi[_\s-]?key\b/i,
            /\bcredential\b/i, /\bauth\b/i,
        ]
    }
];

/** Benign name fragments that indicate a tool's expected capability. */
const NAME_CAPABILITY_MAP: ReadonlyArray<{ pattern: RegExp; capabilities: string[] }> = [
    { pattern: /weather|forecast|climate/i, capabilities: ['weather'] },
    { pattern: /search|find|lookup|query/i, capabilities: ['search'] },
    { pattern: /math|calc|compute/i, capabilities: ['math'] },
    { pattern: /time|clock|date/i, capabilities: ['time'] },
    { pattern: /translate|language/i, capabilities: ['translation'] },
    { pattern: /file|read|write|fs|directory/i, capabilities: ['filesystem'] },
    { pattern: /http|api|fetch|request|web/i, capabilities: ['network'] },
    { pattern: /shell|exec|command|run|bash/i, capabilities: ['shell'] },
    { pattern: /sql|db|database|query/i, capabilities: ['database'] },
];

// ── Detection ───────────────────────────────────────────────────────────────

/**
 * Detect capabilities in text by scanning for known keywords.
 */
function detectCapabilities(text: string): Set<string> {
    const found = new Set<string>();
    for (const { capability, keywords } of CAPABILITY_KEYWORDS) {
        for (const kw of keywords) {
            kw.lastIndex = 0;
            if (kw.test(text)) {
                found.add(capability);
                break;
            }
        }
    }
    return found;
}

/**
 * Determine the expected capabilities of a tool from its name alone.
 */
function expectedCapabilities(name: string): Set<string> {
    const expected = new Set<string>();
    for (const { pattern, capabilities } of NAME_CAPABILITY_MAP) {
        pattern.lastIndex = 0;
        if (pattern.test(name)) {
            for (const c of capabilities) expected.add(c);
        }
    }
    return expected;
}

/**
 * Scan a tool definition for shadowing and annotation lying.
 *
 * Returns findings when the description or schema reference capabilities
 * that the tool name does not suggest — e.g. a tool named `get_weather`
 * whose description mentions file paths or SQL queries.
 */
export function detectShadowing(tool: ToolDefinition, location: string): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const name = tool.name;
    const description = tool.description ?? '';

    // What capabilities does the name suggest?
    const nameCapabilities = expectedCapabilities(name);

    // What capabilities does the description reference?
    const descCapabilities = detectCapabilities(description);

    // What capabilities do the schema property names suggest?
    const schemaCapabilities = new Set<string>();
    const props = (tool.inputSchema as any)?.properties;
    if (props && typeof props === 'object') {
        const propText = Object.keys(props).join(' ') + ' ' +
            Object.values(props)
                .map((v: any) => typeof v?.description === 'string' ? v.description : '')
                .join(' ');
        for (const cap of detectCapabilities(propText)) {
            schemaCapabilities.add(cap);
        }
    }

    // Dangerous capabilities that are unexpected given the name
    const DANGEROUS = new Set(['filesystem', 'network', 'shell', 'database', 'credentials']);
    const allDetected = new Set([...descCapabilities, ...schemaCapabilities]);

    for (const cap of allDetected) {
        // Only flag dangerous capabilities not implied by the name
        if (!DANGEROUS.has(cap)) continue;
        if (nameCapabilities.has(cap)) continue;

        const severity: Severity = (cap === 'shell' || cap === 'credentials') ? 'critical' : 'high';
        const source = descCapabilities.has(cap)
            ? 'description'
            : 'input schema';

        findings.push({
            id: `shadowing-${cap}-${location}`,
            detector: 'shadowing',
            severity,
            title: `Tool "${name}" references ${cap} capability in ${source} but name does not suggest it`,
            detail: `The tool is named "${name}" but its ${source} references ${cap}-related ` +
                    `concepts. This could indicate annotation lying: the tool name suggests one ` +
                    `purpose while the implementation does something more dangerous.`,
            location,
            evidence: `name="${name}", unexpected capability: ${cap}`
        });
    }

    return findings;
}
