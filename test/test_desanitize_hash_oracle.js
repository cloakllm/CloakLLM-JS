/**
 * v0.6.3 G2 — JS mirror of the desanitize sanitized_hash oracle fix.
 *
 * See cloakllm-py/tests/test_desanitize_hash_oracle.py for the full
 * threat model. Pre-v0.6.3, sanitized_hash on desanitize entries equaled
 * sha256(restored_PII) — a direct PII oracle. v0.6.3 makes it equal
 * sha256(tokenized_input) instead, so the restored PII never enters the
 * audit log via any field (including hashes).
 */

'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const { Shield, ShieldConfig } = require('../src');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-g2-js-'));
}

function readEntries(logDir) {
  const out = [];
  for (const f of fs.readdirSync(logDir).filter(n => n.startsWith('audit_')).sort()) {
    const text = fs.readFileSync(path.join(logDir, f), 'utf-8');
    for (const line of text.split('\n').filter(l => l.trim())) {
      out.push(JSON.parse(line));
    }
  }
  return out;
}

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

describe('G2 — sanitized_hash oracle closed in JS desanitize', () => {
  let dir, shield;
  beforeEach(() => {
    dir = tmpDir();
    shield = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
  });

  it('sanitized_hash equals prompt_hash on desanitize entries', () => {
    const [, tm] = shield.sanitize('Email john@example.com about it');
    const token = [...tm.reverse.keys()][0];
    const llmResponse = `Reply to ${token} please`;
    const result = shield.desanitize(llmResponse, tm);
    assert.ok(result.includes('john@example.com'));

    const entries = readEntries(dir);
    const desan = entries.filter(e => e.event_type === 'desanitize').slice(-1)[0];
    assert.equal(
      desan.sanitized_hash, desan.prompt_hash,
      'desanitize entries must hash the tokenized input twice — not the ' +
      'restored PII (which would be a hash oracle).',
    );
    const expected = sha256(llmResponse);
    assert.equal(desan.prompt_hash, expected);
    assert.equal(desan.sanitized_hash, expected);
  });

  it('restored PII hash does NOT appear in any audit field', () => {
    const original = 'Email diana-test-7g4@cloakllm.example about it';
    const [, tm] = shield.sanitize(original);
    const token = [...tm.reverse.keys()][0];
    const llmResponse = `reply to ${token}`;
    const restored = shield.desanitize(llmResponse, tm);
    const restoredHash = sha256(restored);

    for (const e of readEntries(dir)) {
      assert.notEqual(e.prompt_hash, restoredHash,
        `prompt_hash leaked restored PII via hash match: ${JSON.stringify(e)}`);
      assert.notEqual(e.sanitized_hash, restoredHash,
        `sanitized_hash leaked restored PII via hash match: ${JSON.stringify(e)}`);
    }
  });

  it('chain still verifies after G2 changes', () => {
    const [, tm] = shield.sanitize('a@b.com');
    const token = [...tm.reverse.keys()][0];
    shield.desanitize(`out: ${token}`, tm);
    shield.desanitize(`again: ${token}`, tm);
    const { valid, errors } = shield.audit.verifyChain();
    assert.ok(valid, `chain broken after G2: ${JSON.stringify(errors)}`);
  });
});
