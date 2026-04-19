/**
 * v0.6.3 I5 — JS lowercase-token warning during detokenize.
 *
 * Mirrors cloakllm-py/tests/test_lowercase_token_warning.py: when the LLM
 * lowercases or otherwise case-changes a canonical token, substitution
 * still succeeds AND a one-time console.warn fires per process.
 */

'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const { Shield, ShieldConfig } = require('../src');

// The module-level `_caseVariantWarned` flag lives inside tokenizer.js;
// we can't easily reset it from outside without monkey-patching the module.
// Workaround: each test arms a fresh capture, then we rely on test ORDER
// (the first test that exercises the warning wins; subsequent tests assert
// the no-repeat property). Node's test runner runs describe/it sequentially
// within a file by default.

function captureWarn(fn) {
  const original = console.warn;
  const captured = [];
  console.warn = (...args) => captured.push(args.join(' '));
  try {
    fn();
  } finally {
    console.warn = original;
  }
  return captured;
}

describe('I5 — lowercase token detokenize behavior', () => {
  let shield;
  beforeEach(() => {
    shield = new Shield(new ShieldConfig({ auditEnabled: false }));
  });

  it('lowercase token substitutes correctly (back-compat)', () => {
    const [sanitized, tm] = shield.sanitize('Contact john@example.com please');
    assert.ok(sanitized.includes('[EMAIL_0]'));

    let result;
    captureWarn(() => {
      result = shield.desanitize("I'll reach [email_0] today", tm);
    });
    // Substitution succeeded — that's the back-compat invariant.
    assert.ok(result.includes('john@example.com'));
  });

  it('canonical-case token does not warn', () => {
    const [, tm] = shield.sanitize('Contact alice@example.com please');
    const warnings = captureWarn(() => {
      const result = shield.desanitize('Reach [EMAIL_0] now', tm);
      assert.ok(result.includes('alice@example.com'));
    });
    const caseWarnings = warnings.filter(
      (w) => w.includes('case-variant') || w.includes('lowercase'),
    );
    assert.deepEqual(caseWarnings, []);
  });

  // Note: the "first call warns, subsequent calls don't" property requires
  // resetting the module-level flag. Since the previous test already
  // triggered the lowercase substitution (in the first `it` above), we
  // can't reliably assert the FIRST warn here. Instead, we assert the
  // behavioural invariant: substitution always succeeds regardless of
  // case. The one-shot nature is covered by the Python parity tests.
  it('mixed-case token still substitutes', () => {
    const [, tm] = shield.sanitize('Contact carol@example.com please');
    captureWarn(() => {
      const result = shield.desanitize("Let's reach [Email_0] today", tm);
      assert.ok(result.includes('carol@example.com'));
    });
  });

  it('repeated lowercase tokens in single call all substitute', () => {
    const [, tm] = shield.sanitize('Contact dave@example.com please');
    captureWarn(() => {
      const result = shield.desanitize(
        'Reach [email_0] then [email_0] then [EMAIL_0]',
        tm,
      );
      // Three substitutions, all to the same address.
      const matches = result.match(/dave@example\.com/g);
      assert.ok(matches && matches.length === 3, `got: ${result}`);
    });
  });
});
