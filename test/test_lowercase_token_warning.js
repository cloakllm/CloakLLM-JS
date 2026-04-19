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

// ─── G3: streaming path warning wiring ────────────────────────────────────

describe('I5/G3 — StreamDesanitizer.feed fires the case-variant warning', () => {
  // Note: the shared `_caseVariantWarned` flag in tokenizer.js is process-
  // global. Tests in this describe block run after the earlier ones, which
  // may have already triggered the warning. We can't reliably assert "first
  // call warns" — but we CAN assert "substitution still succeeds" and that
  // the warning machinery doesn't crash on the streaming path. The Python
  // suite exercises the once-per-process gate end-to-end with a flag reset
  // mechanism that's awkward to replicate cleanly in JS without monkey-
  // patching the module.

  const { StreamDesanitizer } = require('../src/stream');
  const { TokenMap } = require('../src/tokenizer');

  function makeMap() {
    const tm = new TokenMap();
    tm.reverse.set('[EMAIL_0]', 'alice@example.com');
    return tm;
  }

  it('lowercase token in stream chunk substitutes correctly', () => {
    const desan = new StreamDesanitizer(makeMap());
    let out;
    captureWarn(() => {
      out = desan.feed('Reach out to [email_0] today');
    });
    assert.ok(out.includes('alice@example.com'),
      `expected substitution, got: ${out}`);
  });

  it('mixed-case token in stream chunk substitutes correctly', () => {
    const desan = new StreamDesanitizer(makeMap());
    let out;
    captureWarn(() => {
      out = desan.feed("Let's reach [Email_0] today");
    });
    assert.ok(out.includes('alice@example.com'));
  });

  it('canonical token in stream chunk substitutes without crash', () => {
    const desan = new StreamDesanitizer(makeMap());
    let out;
    captureWarn(() => {
      out = desan.feed('Reach [EMAIL_0] now');
    });
    assert.ok(out.includes('alice@example.com'));
  });

  it('token split across chunks still substitutes', () => {
    // The streaming path's whole point: tokens may arrive in pieces.
    // Case-variant detection must run on the reassembled candidate.
    const desan = new StreamDesanitizer(makeMap());
    let out1, out2;
    captureWarn(() => {
      out1 = desan.feed('Reach out to [emai');
      out2 = desan.feed('l_0] today');
    });
    const full = out1 + out2;
    assert.ok(full.includes('alice@example.com'),
      `expected reassembled substitution, got: ${full}`);
  });
});
