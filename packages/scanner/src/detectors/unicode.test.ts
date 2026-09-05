import { describe, test, expect } from 'vitest';
import { detectUnicode, stripInvisibleUnicode } from './unicode.js';

describe('Unicode Abuse Detector (T2)', () => {
    test('detects zero-width space (ZWSP) and invisible characters', () => {
        const text = 'Normal text \u200B with hidden zero-width space';
        const findings = detectUnicode(text, 'description');
        expect(findings.length).toBeGreaterThanOrEqual(1);
        const f = findings.find(x => x.id.startsWith('unicode-invisible'));
        expect(f).toBeDefined();
        expect(f?.severity).toBe('high');
        expect(f?.evidence).toContain('U+200B');
    });

    test('detects byte order mark (BOM / ZWNBSP)', () => {
        const text = 'Prefix \uFEFF hidden instruction';
        const findings = detectUnicode(text, 'description');
        const f = findings.find(x => x.id.startsWith('unicode-invisible'));
        expect(f).toBeDefined();
        expect(f?.evidence).toContain('U+FEFF');
    });

    test('detects word joiner and invisible separators', () => {
        const text = 'Joiner \u2060 and invisible separator \u2063';
        const findings = detectUnicode(text, 'description');
        const f = findings.find(x => x.id.startsWith('unicode-invisible'));
        expect(f).toBeDefined();
        expect(f?.evidence).toContain('U+2060');
        expect(f?.evidence).toContain('U+2063');
    });

    test('detects bidirectional override controls (LTR/RTL override)', () => {
        const text = 'Harmless prefix \u202Ereversed command\u202C';
        const findings = detectUnicode(text, 'description');
        const f = findings.find(x => x.id.startsWith('unicode-bidi'));
        expect(f).toBeDefined();
        expect(f?.severity).toBe('high');
        expect(f?.evidence).toContain('U+202E');
    });

    test('detects directional isolates', () => {
        const text = 'Text with isolate \u2067 RTL isolate \u2069';
        const findings = detectUnicode(text, 'description');
        const f = findings.find(x => x.id.startsWith('unicode-bidi'));
        expect(f).toBeDefined();
        expect(f?.evidence).toContain('U+2067');
    });

    test('detects unicode tag characters (U+E0000 block steganography)', () => {
        // Tag 'A' is U+E0041
        const tagA = String.fromCodePoint(0xE0041);
        const text = `Innocent looking string ${tagA}`;
        const findings = detectUnicode(text, 'description');
        const f = findings.find(x => x.id.startsWith('unicode-tags'));
        expect(f).toBeDefined();
        expect(f?.severity).toBe('critical');
        expect(f?.evidence).toContain('U+E0041');
    });

    test('detects Cyrillic homoglyph confusables in Latin text', () => {
        // 'а' is Cyrillic small letter a (U+0430)
        const text = 'execute_comm\u0430nd';
        const findings = detectUnicode(text, 'description');
        const f = findings.find(x => x.id.startsWith('unicode-confusable'));
        expect(f).toBeDefined();
        expect(f?.severity).toBe('medium');
        expect(f?.evidence).toContain('U+0430');
    });

    test('clean text returns zero findings', () => {
        const clean = 'This is a completely normal tool description explaining arithmetic operations: a + b.';
        const findings = detectUnicode(clean, 'description');
        expect(findings).toEqual([]);
    });

    test('stripInvisibleUnicode strips invisible and bidi characters', () => {
        const contaminated = 'Hello\u200B \u202DWorld\u202C \uFEFF!';
        const stripped = stripInvisibleUnicode(contaminated);
        expect(stripped).toBe('Hello World !');
    });
});
