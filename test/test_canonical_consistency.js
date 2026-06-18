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

const { canonicalJson } = require('../src/_canonical');

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
  // v0.10.3 HIGH-5: these key names are now REJECTED (hard error) rather than
  // silently dropped. Silent-drop diverged from Python (which serialized them)
  // and was itself a forgery seam (the dropped key is invisible in the hash).
  // Both SDKs now throw, keeping the canonicalizers in lock-step.
  it('throws on an own __proto__ key (as produced by JSON.parse)', () => {
    // Object-literal `{__proto__: x}` sets the prototype, not an own key, so
    // the real data path is JSON.parse, which makes __proto__ an own property.
    const obj = JSON.parse('{"__proto__": {"polluted": true}, "a": 1}');
    assert.throws(() => canonicalJson(obj), /disallowed object key/);
  });

  it('throws on a constructor key', () => {
    assert.throws(() => canonicalJson({ constructor: 'evil', a: 1 }), /disallowed object key/);
  });

  it('throws on a prototype key', () => {
    assert.throws(() => canonicalJson({ prototype: 1, a: 1 }), /disallowed object key/);
  });

  it('throws on a nested forbidden key', () => {
    assert.throws(() => canonicalJson({ a: { b: JSON.parse('{"constructor": 1}') } }),
      /disallowed object key/);
  });
});

describe('canonicalJson — non-ASCII preservation (B1 regression)', () => {
  it('preserves UTF-8, does not escape', () => {
    const out = canonicalJson({ x: 'café' });
    assert.ok(out.includes('café'));
    assert.ok(!out.includes('\\u00e9'));
  });
});

// v0.9.0 LC-1: the _legacyCanonicalJson shim was removed (sunset phase 2).
// The removal itself is defended below + the raise-with-message behavior
// is covered in test_v090_lc1.js.
describe('_legacyCanonicalJson removed (v0.9.0 LC-1)', () => {
  it('the shim must NOT be exported anymore', () => {
    const can = require('../src/_canonical');
    assert.equal(can._legacyCanonicalJson, undefined);
  });
});
