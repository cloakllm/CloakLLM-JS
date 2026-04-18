/**
 * v0.6.3 H4 — JS audit chain restart / corruption recovery tests.
 *
 * Mirrors cloakllm-py/tests/test_audit_chain_restart.py:
 *   1. Corrupt trailing line must NOT strand earlier valid entries.
 *   2. All-files-corrupt must NOT silently restart from GENESIS when
 *      auditStrictChain is on.
 *   3. Normal restart must produce a verifiable chain (regression).
 */

'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');
const { AuditLogger, GENESIS_HASH } = require('../src/audit');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-h4-js-'));
}

function todayLogPath(logDir) {
  const today = new Date().toISOString().slice(0, 10);
  return path.join(logDir, `audit_${today}.jsonl`);
}

function readEntries(logPath) {
  const lines = fs.readFileSync(logPath, 'utf-8').split('\n').filter(l => l.trim());
  const out = [];
  for (const line of lines) {
    try {
      out.push(JSON.parse(line));
    } catch {
      // skip corrupt
    }
  }
  return out;
}

// ─── Bug 1: corrupt trailing line ─────────────────────────────────────────

describe('H4 — corrupt trailing line does not strand earlier valid entries', () => {
  let dir;
  beforeEach(() => { dir = tmpDir(); });

  it('recovery links new entry to last VALID, not to prior file or GENESIS', () => {
    // Write a few entries from "process 1"
    const shield1 = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
    for (let i = 0; i < 3; i++) {
      shield1.sanitize(`contact user${i}@example.com please`);
    }
    const logPath = todayLogPath(dir);
    const entries = readEntries(logPath);
    assert.ok(entries.length >= 3);
    const lastValid = entries[entries.length - 1];

    // Simulate crash mid-write — append a partial JSON line
    fs.appendFileSync(logPath, '{"seq":99,"timestamp":"2026-04-', 'utf-8');

    // "Process 2" starts and writes a new entry
    const shield2 = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
    shield2.sanitize('a new entry');

    // The new entry's prev_hash must be the last valid entry's entry_hash,
    // NOT GENESIS, NOT some older file's tail, NOT a value from the corrupt line.
    const allEntries = readEntries(logPath);
    const postCorruption = allEntries.filter(e => e.seq > lastValid.seq);
    assert.ok(postCorruption.length > 0, 'expected new entries after corruption');
    assert.equal(postCorruption[0].prev_hash, lastValid.entry_hash);
    assert.equal(postCorruption[0].seq, lastValid.seq + 1);
  });

  it('walks to older file when newest is all-corrupt', () => {
    // Older file with a valid anchor entry
    const olderPath = path.join(dir, 'audit_2026-01-01.jsonl');
    const anchor = {
      seq: 42,
      timestamp: '2026-01-01T00:00:00.000Z',
      event_type: 'sanitize',
      entity_count: 0,
      categories: {},
      tokens_used: [],
      prompt_hash: '',
      sanitized_hash: '',
      model: null,
      provider: null,
      latency_ms: 0,
      metadata: null,
      prev_hash: GENESIS_HASH,
      mode: 'tokenize',
      entity_details: [],
      timing: { total_ms: 0 },
      entry_hash: 'a'.repeat(64),  // synthetic
    };
    fs.writeFileSync(olderPath, JSON.stringify(anchor) + '\n', 'utf-8');

    // Today's file is just garbage
    fs.writeFileSync(todayLogPath(dir), 'garbage\nmore garbage\n{not json', 'utf-8');

    const audit = new AuditLogger(new ShieldConfig({ logDir: dir, auditEnabled: true }));
    audit._ensureInit();
    assert.equal(audit._prevHash, anchor.entry_hash);
    assert.equal(audit._seq, 43);
  });
});

// ─── Bug 2: silent GENESIS restart ────────────────────────────────────────

describe('H4 — auditStrictChain refuses silent GENESIS restart', () => {
  let dir;
  beforeEach(() => { dir = tmpDir(); });

  it('strict mode raises when log files exist but recovery returns nothing', () => {
    fs.writeFileSync(path.join(dir, 'audit_2026-01-01.jsonl'), 'garbage');
    fs.writeFileSync(path.join(dir, 'audit_2026-01-02.jsonl'), 'more garbage');
    const cfg = new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      auditStrictChain: true,
    });
    const audit = new AuditLogger(cfg);
    assert.throws(
      () => audit._ensureInit(),
      /Refusing to silently restart from GENESIS|auditStrictChain=true/,
    );
  });

  it('non-strict (default) silently restarts on full corruption', () => {
    fs.writeFileSync(path.join(dir, 'audit_2026-01-01.jsonl'), 'garbage');
    const audit = new AuditLogger(new ShieldConfig({ logDir: dir, auditEnabled: true }));
    audit._ensureInit();
    assert.equal(audit._prevHash, GENESIS_HASH);
    assert.equal(audit._seq, 0);
  });

  it('strict mode + empty dir starts at GENESIS without raising (first run)', () => {
    const cfg = new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      auditStrictChain: true,
    });
    const audit = new AuditLogger(cfg);
    audit._ensureInit();  // must not throw
    assert.equal(audit._prevHash, GENESIS_HASH);
    assert.equal(audit._seq, 0);
  });

  it('strict mode happy-path restart still works', () => {
    const opts = { logDir: dir, auditEnabled: true, auditStrictChain: true };
    const shield1 = new Shield(new ShieldConfig(opts));
    shield1.sanitize('john@example.com');
    const shield2 = new Shield(new ShieldConfig(opts));
    shield2.sanitize('jane@example.com');
    const { valid, errors } = shield2.audit.verifyChain();
    assert.ok(valid, `chain broken: ${JSON.stringify(errors)}`);
  });
});

// ─── Restart continuity regression ────────────────────────────────────────

describe('H4 — normal restart produces a verifiable chain', () => {
  it('chain verifies across simulated process restart', () => {
    const dir = tmpDir();
    const shield1 = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
    shield1.sanitize('a@example.com');
    shield1.sanitize('b@example.com');
    // Simulated restart: build a fresh Shield from the same dir.
    const shield2 = new Shield(new ShieldConfig({ logDir: dir, auditEnabled: true }));
    shield2.sanitize('c@example.com');
    const { valid, errors } = shield2.audit.verifyChain();
    assert.ok(valid, `chain broken: ${JSON.stringify(errors)}`);
  });
});

// ─── _scanForLastValidEntry direct unit tests ─────────────────────────────

describe('H4 — _scanForLastValidEntry helper', () => {
  let dir, audit;
  beforeEach(() => {
    dir = tmpDir();
    audit = new AuditLogger(new ShieldConfig({ logDir: dir, auditEnabled: true }));
  });

  it('returns null for empty list', () => {
    assert.equal(audit._scanForLastValidEntry([]), null);
  });

  it('skips corrupt lines within a file', () => {
    const f = path.join(dir, 'audit_2026-01-01.jsonl');
    const content =
      JSON.stringify({ seq: 1, entry_hash: 'h1' }) + '\n'
      + JSON.stringify({ seq: 2, entry_hash: 'h2' }) + '\n'
      + '{partial-corrupt\n';
    fs.writeFileSync(f, content, 'utf-8');
    const result = audit._scanForLastValidEntry([f]);
    assert.equal(result.seq, 2);
    assert.equal(result.entry_hash, 'h2');
  });

  it('walks to older file when newer is all-corrupt', () => {
    const oldP = path.join(dir, 'audit_2026-01-01.jsonl');
    const newP = path.join(dir, 'audit_2026-01-02.jsonl');
    fs.writeFileSync(oldP, JSON.stringify({ seq: 5, entry_hash: 'old_h' }) + '\n');
    fs.writeFileSync(newP, 'garbage\n{partial\n');
    const result = audit._scanForLastValidEntry([oldP, newP]);
    assert.equal(result.seq, 5);
    assert.equal(result.entry_hash, 'old_h');
  });

  it('requires both seq and entry_hash to count as valid', () => {
    const f = path.join(dir, 'audit_2026-01-01.jsonl');
    fs.writeFileSync(f, JSON.stringify({ seq: 1, no_hash: true }) + '\n');
    assert.equal(audit._scanForLastValidEntry([f]), null);
  });
});
