/**
 * v0.6.3 H9 — JS prototype pollution defenses across detector/tokenizer.
 *
 * Closes four surfaces where user-controlled keys flowed into object writes:
 *   1. Audit metadata: __proto__/constructor/prototype keys must throw, not
 *      silently skip (was: `continue` hid the issue from callers)
 *   2. ShieldConfig.customPatterns names must pass CATEGORY_NAME_PATTERN
 *      (was: only customLlmCategories validated — parity gap)
 *   3. _legacyCanonicalJson must filter prototype-pollution keys (the new
 *      canonicalJson at line 84 already did)
 *   4. Shield._accumulate / batch metrics must skip prototype keys so a
 *      misbehaving backend can't silently lose metrics or affect global state
 */

'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');
const { _legacyCanonicalJson } = require('../src/_canonical');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-h9-js-'));
}

// ─── Surface 1: audit metadata rejects prototype-pollution keys ───────────

describe('H9 — audit metadata rejects __proto__/constructor/prototype keys', () => {
  let dir, shield;
  beforeEach(() => {
    dir = tmpDir();
    shield = new Shield(new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      complianceMode: 'eu_ai_act_article12',
    }));
  });

  it('rejects __proto__ at top level', () => {
    // `{__proto__: x}` literal syntax invokes the prototype setter rather
    // than creating an own property — Object.keys() never sees `__proto__`
    // that way. The realistic attack vector is JSON.parse(...) which DOES
    // create __proto__ as an own data property. Build via JSON.parse.
    const metadata = JSON.parse('{"__proto__":{"polluted":true}}');
    assert.throws(
      () => shield.sanitize('hi', { metadata }),
      /prototype-pollution vector|metadata key/i,
    );
  });

  it('rejects constructor at top level', () => {
    assert.throws(
      () => shield.sanitize('hi', { metadata: { constructor: 'evil' } }),
      /prototype-pollution vector/i,
    );
  });

  it('rejects prototype at top level', () => {
    assert.throws(
      () => shield.sanitize('hi', { metadata: { prototype: 'evil' } }),
      /prototype-pollution vector/i,
    );
  });

  it('rejects __proto__ nested in metadata', () => {
    // Same caveat as the top-level test — must use JSON.parse to construct
    // a real own __proto__ property at the nested path.
    const metadata = JSON.parse(
      '{"user":{"profile":{"__proto__":{"polluted":true}}}}'
    );
    assert.throws(
      () => shield.sanitize('hi', { metadata }),
      /prototype-pollution vector/i,
    );
  });

  it('clean metadata still passes', () => {
    // Sanity: legitimate metadata isn't broken by H9.
    assert.doesNotThrow(() => {
      shield.sanitize('contact john@example.com', {
        metadata: { user_id: 'u_1', trace_id: 't_2', counts: [1, 2, 3] },
      });
    });
  });

  it('JSON.parse-derived metadata with __proto__ still rejected', () => {
    // The realistic attack: caller does JSON.parse(req.body) and forwards.
    const malicious = JSON.parse('{"__proto__":{"polluted":true},"trace":"t1"}');
    assert.throws(
      () => shield.sanitize('hi', { metadata: malicious }),
      /prototype-pollution vector/i,
    );
  });
});

// ─── Surface 2: customPatterns name validation parity ─────────────────────

describe('H9 — ShieldConfig.customPatterns validates pattern names', () => {
  it('rejects __proto__ as a pattern name', () => {
    assert.throws(
      () => new ShieldConfig({
        customPatterns: [{ name: '__proto__', pattern: 'x' }],
      }),
      /Invalid custom pattern name/,
    );
  });

  it('rejects constructor as a pattern name', () => {
    assert.throws(
      () => new ShieldConfig({
        customPatterns: [{ name: 'constructor', pattern: 'x' }],
      }),
      /Invalid custom pattern name/,
    );
  });

  it('rejects lowercase or non-conforming names', () => {
    // Same regex used as customLlmCategories — must start with uppercase.
    assert.throws(
      () => new ShieldConfig({
        customPatterns: [{ name: 'lowercase', pattern: 'x' }],
      }),
      /Invalid custom pattern name/,
    );
  });

  it('accepts valid uppercase names', () => {
    assert.doesNotThrow(() => new ShieldConfig({
      customPatterns: [{ name: 'CUSTOM_THING', pattern: 'x' }],
    }));
  });

  it('rejects non-string names (defense vs. JSON-injected nulls)', () => {
    assert.throws(
      () => new ShieldConfig({
        customPatterns: [{ name: null, pattern: 'x' }],
      }),
      /Invalid custom pattern name/,
    );
  });
});

// ─── Surface 3: _legacyCanonicalJson filters prototype keys ───────────────

describe('H9 — _legacyCanonicalJson filters prototype-pollution keys', () => {
  it('skips __proto__ in legacy canonical output', () => {
    const malicious = JSON.parse('{"__proto__":{"polluted":true},"a":1}');
    const result = _legacyCanonicalJson(malicious);
    // Result should serialize only the legitimate `a` field.
    assert.equal(result, '{"a":1}');
  });

  it('skips constructor and prototype too', () => {
    // Build an object with these as own enumerable properties (JSON.parse
    // is the easy way; bracket assignment for `__proto__` would trigger
    // the setter, but `constructor`/`prototype` are regular property names).
    const malicious = JSON.parse('{"constructor":"evil","prototype":"evil","b":2}');
    const result = _legacyCanonicalJson(malicious);
    assert.equal(result, '{"b":2}');
  });

  it('does NOT pollute Object.prototype during legacy canonicalization', () => {
    const malicious = JSON.parse('{"__proto__":{"polluted":"yes"}}');
    _legacyCanonicalJson(malicious);
    // After calling the legacy serializer, no random object should have
    // gained a `polluted` property on its prototype.
    assert.equal({}.polluted, undefined);
    assert.equal([].polluted, undefined);
  });
});

// ─── Surface 4: shield metrics skip prototype keys ────────────────────────

describe('H9 — Shield metrics tolerate (but skip) prototype-pollution keys', () => {
  // Note: detection backend categories ARE validated upstream by
  // CATEGORY_NAME_PATTERN, so this surface is defense-in-depth. We can't
  // easily build a malicious detection from outside; instead we verify
  // that Object.prototype isn't polluted after a normal sanitize cycle.
  it('clean sanitize cycle does not leak any property onto Object.prototype', () => {
    const dir = tmpDir();
    const shield = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
    shield.sanitize('contact john@example.com please');
    // No new own properties on Object.prototype
    const baseline = Object.getOwnPropertyNames(Object.prototype).length;
    shield.sanitize('contact jane@example.com too');
    assert.equal(
      Object.getOwnPropertyNames(Object.prototype).length,
      baseline,
      'Object.prototype gained a property during sanitize',
    );
  });
});

// ─── Cross-cutting: pollution attempts don't bleed into other callers ─────

describe('H9 — global hygiene check', () => {
  it('after H9 changes, an unrelated empty object is unpolluted', () => {
    // Sanity: confirm no test in this file accidentally polluted the prototype.
    assert.equal({}.polluted, undefined);
    assert.equal({}.constructor.name, 'Object');
  });
});
