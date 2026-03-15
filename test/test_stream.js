const { describe, it } = require('node:test');
const assert = require('node:assert');
const { StreamDesanitizer } = require('../src/stream');
const { TokenMap } = require('../src/tokenizer');

function makeTokenMap(mappings) {
    const tm = new TokenMap();
    for (const [original, token] of Object.entries(mappings)) {
        tm.forward.set(original, token);
        tm.reverse.set(token, original);
    }
    return tm;
}

describe('StreamDesanitizer', () => {
    describe('basic', () => {
        it('passes through plain text', () => {
            const tm = makeTokenMap({ 'john@acme.com': '[EMAIL_0]' });
            const sd = new StreamDesanitizer(tm);
            assert.strictEqual(sd.feed('Hello world'), 'Hello world');
            assert.strictEqual(sd.flush(), '');
        });

        it('resolves token split across chunks', () => {
            const tm = makeTokenMap({ 'john@acme.com': '[EMAIL_0]' });
            const sd = new StreamDesanitizer(tm);
            assert.strictEqual(sd.feed('Contact '), 'Contact ');
            assert.strictEqual(sd.feed('[EM'), '');
            assert.strictEqual(sd.feed('AIL_0]'), 'john@acme.com');
            assert.strictEqual(sd.feed(' for details'), ' for details');
            assert.strictEqual(sd.flush(), '');
        });

        it('handles non-token brackets', () => {
            const tm = new TokenMap();
            const sd = new StreamDesanitizer(tm);
            assert.strictEqual(sd.feed('array[0]'), 'array[0]');
        });

        it('handles char-by-char token arrival', () => {
            const tm = makeTokenMap({ 'John Smith': '[PERSON_0]' });
            const sd = new StreamDesanitizer(tm);
            assert.strictEqual(sd.feed('Hi '), 'Hi ');
            assert.strictEqual(sd.feed('['), '');
            assert.strictEqual(sd.feed('PERSON'), '');
            assert.strictEqual(sd.feed('_0'), '');
            assert.strictEqual(sd.feed(']!'), 'John Smith!');
        });
    });

    describe('edge cases', () => {
        it('is case insensitive', () => {
            const tm = makeTokenMap({ 'jane@test.com': '[EMAIL_0]' });
            const sd = new StreamDesanitizer(tm);
            assert.strictEqual(sd.feed('[email_0]'), 'jane@test.com');
        });

        it('handles multiple tokens in one chunk', () => {
            const tm = makeTokenMap({
                'john@acme.com': '[EMAIL_0]',
                'John Smith': '[PERSON_0]',
            });
            const sd = new StreamDesanitizer(tm);
            const result = sd.feed('Hi [PERSON_0], your email is [EMAIL_0].');
            assert.strictEqual(result, 'Hi John Smith, your email is john@acme.com.');
            assert.strictEqual(sd.flush(), '');
        });

        it('flushes partial buffer', () => {
            const tm = makeTokenMap({ 'john@acme.com': '[EMAIL_0]' });
            const sd = new StreamDesanitizer(tm);
            assert.strictEqual(sd.feed('text [UNKN'), 'text ');
            assert.strictEqual(sd.flush(), '[UNKN');
        });

        it('handles buffer overflow beyond max token length', () => {
            const tm = new TokenMap();
            const sd = new StreamDesanitizer(tm);
            const longText = '[' + 'A'.repeat(50);
            const result = sd.feed(longText);
            assert.strictEqual(result.length, 51);
            assert.strictEqual(sd.flush(), '');
        });

        it('handles empty input', () => {
            const tm = makeTokenMap({ 'john@acme.com': '[EMAIL_0]' });
            const sd = new StreamDesanitizer(tm);
            assert.strictEqual(sd.feed(''), '');
            assert.strictEqual(sd.flush(), '');
        });

        it('handles token at stream end', () => {
            const tm = makeTokenMap({ 'john@acme.com': '[EMAIL_0]' });
            const sd = new StreamDesanitizer(tm);
            assert.strictEqual(sd.feed('Contact [EMAIL_0]'), 'Contact john@acme.com');
            assert.strictEqual(sd.flush(), '');
        });

        it('handles consecutive tokens', () => {
            const tm = makeTokenMap({
                'john@acme.com': '[EMAIL_0]',
                'Jane Doe': '[PERSON_0]',
            });
            const sd = new StreamDesanitizer(tm);
            assert.strictEqual(sd.feed('[EMAIL_0][PERSON_0]'), 'john@acme.comJane Doe');
        });

        it('handles mixed tokens and normal brackets', () => {
            const tm = makeTokenMap({ 'john@acme.com': '[EMAIL_0]' });
            const sd = new StreamDesanitizer(tm);
            const result = sd.feed('array[0] then [EMAIL_0] then obj[key]');
            assert.strictEqual(result, 'array[0] then john@acme.com then obj[key]');
        });
    });
});
