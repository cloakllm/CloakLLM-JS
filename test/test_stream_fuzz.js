/**
 * v0.11.5: streaming desanitize must byte-equal batch desanitize for every
 * chunking, including the token-injection case (a literal [CAT_N] in the user's
 * text is fullwidth-escaped on sanitize and must unescape across chunk
 * boundaries). Mirror of the Python regression guard.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { Shield, ShieldConfig } = require('../src');
const { StreamDesanitizer } = require('../src/stream');

const sh = new Shield(new ShieldConfig({ auditEnabled: false }));
const TEXTS = [
  '[EMAIL_0] starts the line; ends with a@b.com',
  'Email a@b.com and SSN 123-45-6789 now.',
  'adjacent a@b.com c@d.com e@f.com tight',
  'two literals [PERSON_1] and [EMAIL_0], real x@y.com',
  'unicode cafe [SSN_0] resume jose@example.es end',
  '[TOKEN_LIKE_9] not a real token, email z@z.io',
];

function san(text) {
  const r = sh.sanitize(text);
  return Array.isArray(r) ? r : [r.sanitized, r.tokenMap];
}

describe('v0.11.5 streaming-vs-batch fuzz', () => {
  it('streamed === batch for random small-chunk splits', () => {
    let s = 0xC0FFEE >>> 0;
    const rnd = () => (s = (s * 1664525 + 1013904223) >>> 0) / 0x100000000;
    for (const text of TEXTS) {
      const [sanitized, tm] = san(text);
      const batch = sh.desanitize(sanitized, tm);
      for (let k = 0; k < 300; k++) {
        const sd = new StreamDesanitizer(tm);
        let out = '', i = 0;
        while (i < sanitized.length) {
          const sz = 1 + Math.floor(rnd() * 4);
          out += sd.feed(sanitized.slice(i, i + sz));
          i += sz;
        }
        out += sd.flush();
        assert.equal(out, batch, `streamed != batch for ${JSON.stringify(text)}`);
      }
    }
  });

  it('streamed === batch for whole + char-by-char', () => {
    for (const text of TEXTS) {
      const [sanitized, tm] = san(text);
      const batch = sh.desanitize(sanitized, tm);
      for (const chunks of [[sanitized], [...sanitized]]) {
        const sd = new StreamDesanitizer(tm);
        let out = '';
        for (const c of chunks) out += sd.feed(c);
        out += sd.flush();
        assert.equal(out, batch);
      }
    }
  });

  it('literal token round-trips (injection case)', () => {
    const text = '[EMAIL_0] starts; ends a@b.com';
    const [sanitized, tm] = san(text);
    const sd = new StreamDesanitizer(tm);
    let out = '';
    for (let i = 0; i < sanitized.length; i += 2) out += sd.feed(sanitized.slice(i, i + 2));
    out += sd.flush();
    assert.equal(out, sh.desanitize(sanitized, tm));
    assert.equal(out, text);
  });
});
