/**
 * v0.6.3 H3 — JS desanitize oracle tests.
 *
 * Mirrors cloakllm-py/tests/test_desanitize_oracle.py:
 *   1. tokens_used / entity_details on a desanitize entry must be the present
 *      subset, not the full map.
 *   2. latency_ms / timing.* in the audit log must be bucketed to 10ms.
 */

'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-h3-js-'));
}

function readEntries(auditDir) {
  const entries = [];
  for (const fname of fs.readdirSync(auditDir).sort()) {
    if (!fname.startsWith('audit_')) continue;
    const text = fs.readFileSync(path.join(auditDir, fname), 'utf-8');
    for (const line of text.split('\n').filter(l => l.trim())) {
      entries.push(JSON.parse(line));
    }
  }
  return entries;
}

function lastEvent(entries, eventType) {
  const matches = entries.filter(e => e.event_type === eventType);
  assert.ok(matches.length > 0, `no ${eventType} entry found`);
  return matches[matches.length - 1];
}

function isBucket10(value) {
  if (value === 0) return true;
  return Math.abs(value % 10) < 1e-9;
}

// ─── present-subset filter ────────────────────────────────────────────────

describe('H3 — desanitize logs present-subset, not full map', () => {
  let dir, shield;
  beforeEach(() => {
    dir = tmpDir();
    shield = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
  });

  it('tokens_used contains only tokens present in input', () => {
    const original = 'Email me at john@a.com or jane@b.com. SSN 123-45-6789.';
    const [, tokenMap] = shield.sanitize(original);
    const fullMap = [...tokenMap.reverse.keys()].sort();
    assert.ok(fullMap.length >= 3);

    const firstToken = [...tokenMap.reverse.keys()][0];
    shield.desanitize(`User contact: ${firstToken}`, tokenMap);

    const entries = readEntries(dir);
    const desan = lastEvent(entries, 'desanitize');
    assert.deepEqual(desan.tokens_used, [firstToken]);
    assert.notDeepEqual(desan.tokens_used, fullMap);
    assert.equal(desan.entity_count, 1);
  });

  it('logs empty when no tokens are in the input', () => {
    const [, tokenMap] = shield.sanitize('contact john@a.com please');
    shield.desanitize('plain response no tokens', tokenMap);

    const entries = readEntries(dir);
    const desan = lastEvent(entries, 'desanitize');
    assert.deepEqual(desan.tokens_used, []);
    assert.equal(desan.entity_count, 0);
    assert.deepEqual(desan.entity_details, []);
  });

  it('entity_details filtered to the present subset', () => {
    const original = 'Contact john@a.com or jane@b.com or bob@c.com please';
    const [, tokenMap] = shield.sanitize(original);
    const tokens = [...tokenMap.reverse.keys()].sort();
    assert.ok(tokens.length >= 3);

    const text = `User one: ${tokens[0]}. User two: ${tokens[1]}.`;
    shield.desanitize(text, tokenMap);

    const entries = readEntries(dir);
    const desan = lastEvent(entries, 'desanitize');
    assert.equal(desan.entity_details.length, 2);
    const present = new Set(desan.entity_details.map(e => e.token));
    assert.deepEqual(present, new Set([tokens[0], tokens[1]]));
  });

  it('regression — sanitize entry still logs the full map', () => {
    const [, tokenMap] = shield.sanitize('Email john@a.com or jane@b.com please');
    const entries = readEntries(dir);
    const san = lastEvent(entries, 'sanitize');
    assert.deepEqual(
      [...san.tokens_used].sort(),
      [...tokenMap.reverse.keys()].sort(),
    );
  });
});

// ─── timing bucketing ─────────────────────────────────────────────────────

describe('H3 — desanitize timing fields bucketed in audit log', () => {
  let dir, shield;
  beforeEach(() => {
    dir = tmpDir();
    shield = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
  });

  it('latency_ms is a 10ms bucket', () => {
    const [, tokenMap] = shield.sanitize('ssn 123-45-6789');
    shield.desanitize('ok', tokenMap);
    const entries = readEntries(dir);
    const desan = lastEvent(entries, 'desanitize');
    assert.ok(isBucket10(desan.latency_ms), `latency_ms=${desan.latency_ms} not bucketed`);
  });

  it('timing.total_ms and timing.tokenization_ms are 10ms buckets', () => {
    const [, tokenMap] = shield.sanitize('ssn 123-45-6789');
    shield.desanitize('ok', tokenMap);
    const entries = readEntries(dir);
    const desan = lastEvent(entries, 'desanitize');
    assert.ok(isBucket10(desan.timing.total_ms));
    assert.ok(isBucket10(desan.timing.tokenization_ms));
  });

  it('internal metrics() keeps full-precision values', () => {
    const [, tokenMap] = shield.sanitize('ssn 123-45-6789');
    for (let i = 0; i < 50; i++) {
      shield.desanitize('hi'.repeat(100), tokenMap);
    }
    const m = shield.metrics();
    assert.ok(m.calls.desanitize > 0);
  });
});

// ─── batch path ───────────────────────────────────────────────────────────

describe('H3 — desanitizeBatch logs union-of-present', () => {
  let dir, shield;
  beforeEach(() => {
    dir = tmpDir();
    shield = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
  });

  it('logs union of tokens present across the batch only', () => {
    const original = 'Contact john@a.com or jane@b.com or bob@c.com';
    const [, tokenMap] = shield.sanitize(original);
    const tokens = [...tokenMap.reverse.keys()].sort();
    assert.ok(tokens.length >= 3);

    shield.desanitizeBatch(
      [`first: ${tokens[0]}`, `second: ${tokens[1]}`],
      tokenMap,
    );

    const entries = readEntries(dir);
    const batch = lastEvent(entries, 'desanitize_batch');
    assert.deepEqual(new Set(batch.tokens_used), new Set([tokens[0], tokens[1]]));
    assert.ok(!batch.tokens_used.includes(tokens[2]));
    assert.equal(batch.entity_count, 2);
  });
});

// ─── round-trip regression ────────────────────────────────────────────────

describe('H3 — desanitize behavior unchanged (audit shape only)', () => {
  it('desanitize still restores PII correctly', () => {
    const dir = tmpDir();
    const shield = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
    const [, tokenMap] = shield.sanitize('email john@a.com please');
    const token = [...tokenMap.reverse.keys()][0];
    const result = shield.desanitize(`reply to ${token}`, tokenMap);
    assert.ok(result.includes('john@a.com'));
  });
});
