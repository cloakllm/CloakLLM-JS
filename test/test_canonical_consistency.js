/**
 * Canonical JSON conformance — verifies the JS serializer produces the exact
 * expected bytes for every entry in the shared cross-SDK fixture corpus.
 *
 * The same corpus is consumed by `cloakllm-py/tests/test_canonical_consistency.py`.
 * If the two implementations diverge, cross-language certificate/audit-chain
 * verification breaks for the divergent input shapes.
 *
 * The fixture file MUST stay byte-identical between the two repos.
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { canonicalJson, _legacyCanonicalJson } = require('../src/_canonical');

const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'canonical_corpus.json');
const CORPUS = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf-8'));

describe('canonicalJson — fixture corpus', () => {
  for (const c of CORPUS) {
    it(c.name, () => {
      const actual = canonicalJson(c.input);
      assert.equal(
        actual,
        c.expected,
        `\n  case:     ${c.name}\n  expected: ${JSON.stringify(c.expected)}\n  actual:   ${JSON.stringify(actual)}`
      );
    });
  }
});

describe('canonicalJson — error handling', () => {
  it('rejects NaN', () => {
    assert.throws(() => canonicalJson({ x: NaN }), /non-finite/);
  });

  it('rejects Infinity', () => {
    assert.throws(() => canonicalJson({ x: Infinity }), /non-finite/);
  });

  it('rejects -Infinity', () => {
    assert.throws(() => canonicalJson({ x: -Infinity }), /non-finite/);
  });

  it('rejects undefined as a top-level value', () => {
    assert.throws(() => canonicalJson(undefined));
  });

  it('rejects BigInt', () => {
    assert.throws(() => canonicalJson({ x: 1n }), /BigInt/);
  });

  it('rejects function', () => {
    assert.throws(() => canonicalJson({ f: () => 1 }));
  });

  it('rejects symbol', () => {
    assert.throws(() => canonicalJson({ s: Symbol('x') }));
  });
});

describe('canonicalJson — prototype-pollution defense', () => {
  it('skips __proto__ key', () => {
    const out = canonicalJson({ __proto__: { polluted: true }, a: 1 });
    assert.ok(!out.includes('__proto__'));
    assert.ok(!out.includes('polluted'));
    assert.equal(out, '{"a":1}');
  });

  it('skips constructor key', () => {
    const out = canonicalJson({ constructor: 'evil', a: 1 });
    assert.equal(out, '{"a":1}');
  });
});

describe('canonicalJson — non-ASCII preservation (B1 regression)', () => {
  it('preserves UTF-8, does not escape', () => {
    const out = canonicalJson({ x: 'café' });
    assert.ok(out.includes('café'));
    assert.ok(!out.includes('\\u00e9'));
  });
});

describe('_legacyCanonicalJson — backward-compat shim', () => {
  it('preserves v0.6.0 replacer-based output for ASCII', () => {
    const out = _legacyCanonicalJson({ b: 'hello', a: 1 });
    assert.equal(out, '{"a":1,"b":"hello"}');
  });

  it('does NOT escape non-ASCII (v0.6.0 used native JSON.stringify)', () => {
    // Note: v0.6.0 JS already preserved UTF-8 — the divergence with Python was
    // that v0.6.0 Python escaped to \u and v0.6.0 JS did not. The legacy JS
    // shim here matches what v0.6.0 JS produced (so an old JS-side audit
    // chain still verifies under legacy mode).
    const out = _legacyCanonicalJson({ x: 'café' });
    assert.ok(out.includes('café'));
  });
});
