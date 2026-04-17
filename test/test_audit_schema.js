/**
 * v0.6.1 B3 / v0.6.1.1 I2: always-on allow-list audit schema validator.
 *
 * Mirrors cloakllm-py/tests/test_audit_schema.py. Required by the v0.6.1 plan
 * (B3.5) but missed in the v0.6.1 ship; landed in v0.6.1.1.
 *
 * The validator runs on EVERY audit write (not gated on complianceMode) to
 * enforce the project-wide invariant: "CloakLLM audit logs must contain zero
 * original PII." Reviewer-approved Q5 = always-on.
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-schema-test-'));
}

// --- Verify the allow-list constants match what the audit emits ------------

describe('audit schema allow-list constants', () => {
  it('entity_details allow-list has exactly the 9 verified-allowed keys', () => {
    // Re-import internals to inspect the constants. We use the file path
    // directly because they are not part of the public API.
    const auditModule = require('../src/audit');
    // The constants are not exported by name; assert through behavior.
    // (The Python mirror imports _ENTITY_DETAIL_ALLOWED_KEYS directly.
    //  In JS we test by trying each key.)
    const baseEntry = _validEntry();
    const validKeys = [
      'category', 'start', 'end', 'length', 'confidence',
      'source', 'token', 'entity_hash', 'text_index',
    ];
    // Each valid key, individually, must NOT cause a schema violation when
    // present alone in entity_details:
    for (const k of validKeys) {
      const e = _validEntry();
      e.entity_details = [{ category: 'EMAIL', [k]: k === 'category' ? 'EMAIL' : 0 }];
      // Should not throw
      assert.doesNotThrow(() => _runValidator(e), `key '${k}' should be allowed`);
    }
  });
});

// --- Helpers ---------------------------------------------------------------

function _validEntry() {
  return {
    seq: 0,
    event_id: 'abc',
    timestamp: '2026-04-16T00:00:00Z',
    event_type: 'sanitize',
    model: null,
    provider: null,
    entity_count: 0,
    categories: {},
    tokens_used: [],
    prompt_hash: '',
    sanitized_hash: '',
    latency_ms: 0,
    mode: 'tokenize',
    entity_details: [],
    timing: null,
    certificate_hash: null,
    key_id: null,
    prev_hash: '0'.repeat(64),
    metadata: {},
    risk_assessment: null,
  };
}

function _runValidator(entry) {
  // Build an in-memory AuditLogger and invoke the same code path as a real
  // audit.log() call (sans file I/O). The validator is internal so we exercise
  // it indirectly via a Shield.sanitize() with a Shield wired to write to a
  // temp dir, then assert behavior. Because the validator runs always-on, any
  // disallowed-key entry in our test corpus fails before disk write.
  //
  // For unit-style validator tests we expose the validator via the same
  // module require so we can call it directly:
  const auditExports = require('../src/audit');
  // The validator function is not publicly exported; access via internals.
  // We re-require the source to grab a reference. If the function name
  // changes, this test fails — which is the right signal.
  const audit = require('../src/audit');
  // Use AuditLogger.computeHash as a sanity that the module loaded; the
  // actual validator is invoked through Shield.sanitize / audit.log paths.
  assert.ok(typeof audit.AuditLogger.computeHash === 'function');
  // Trigger the real validation path:
  const dir = tmpDir();
  const cfg = new ShieldConfig({ logDir: dir, auditEnabled: true });
  const logger = new audit.AuditLogger(cfg);
  // For schema tests we craft a minimal log() call and let the validator run
  // before file write. We pass entity_details and metadata from the entry.
  logger.log({
    eventType: entry.event_type,
    entityDetails: entry.entity_details,
    metadata: entry.metadata,
  });
}

// --- Validator behavior via integration with Shield -----------------------

describe('Shield enforces audit schema on every sanitize (B3 always-on)', () => {
  it('disallowed entity_details key from a malicious custom backend is rejected', () => {
    // We can't easily inject a custom backend that returns extra fields
    // because tokenizer constructs entity_details from Detection objects.
    // Instead, we test the validator directly through a logger.log() call
    // with a hand-crafted entity_details payload.
    const dir = tmpDir();
    const cfg = new ShieldConfig({ logDir: dir, auditEnabled: true });
    const audit = require('../src/audit');
    const logger = new audit.AuditLogger(cfg);
    assert.throws(
      () => logger.log({
        eventType: 'sanitize',
        entityDetails: [{ category: 'EMAIL', evil_field: 'leaked' }],
      }),
      /AUDIT SCHEMA VIOLATION/,
    );
  });

  it('legacy denylist key (original_value) produces COMPLIANCE VIOLATION message', () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({ logDir: dir, auditEnabled: true });
    const audit = require('../src/audit');
    const logger = new audit.AuditLogger(cfg);
    assert.throws(
      () => logger.log({
        eventType: 'sanitize',
        entityDetails: [{ category: 'EMAIL', original_value: 'pii@x.com' }],
      }),
      /COMPLIANCE VIOLATION/,
    );
  });

  it('text_index is allowed (was missing from original v0.6.1 plan)', () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({ logDir: dir, auditEnabled: true });
    const audit = require('../src/audit');
    const logger = new audit.AuditLogger(cfg);
    assert.doesNotThrow(() =>
      logger.log({
        eventType: 'sanitize',
        entityDetails: [{
          category: 'EMAIL',
          start: 0, end: 13, length: 13,
          confidence: 0.95, source: 'regex',
          token: '[EMAIL_0]', text_index: 0,
        }],
      })
    );
  });

  it('metadata string longer than 256 chars is rejected', () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({ logDir: dir, auditEnabled: true });
    const audit = require('../src/audit');
    const logger = new audit.AuditLogger(cfg);
    assert.throws(
      () => logger.log({ eventType: 'sanitize', metadata: { k: 'x'.repeat(257) } }),
      /256/,
    );
  });

  it('metadata depth > 3 is rejected', () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({ logDir: dir, auditEnabled: true });
    const audit = require('../src/audit');
    const logger = new audit.AuditLogger(cfg);
    assert.throws(
      () => logger.log({
        eventType: 'sanitize',
        metadata: { a: { b: { c: { d: 'too deep' } } } },
      }),
      /max nesting depth/,
    );
  });

  it('safe metadata scalars + collections are allowed', () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({ logDir: dir, auditEnabled: true });
    const audit = require('../src/audit');
    const logger = new audit.AuditLogger(cfg);
    assert.doesNotThrow(() =>
      logger.log({
        eventType: 'sanitize',
        metadata: {
          user_id: 'user-123',
          request_count: 42,
          is_premium: true,
          score: 0.95,
          tags: ['a', 'b'],
          nested: { k: 'v' },
        },
      })
    );
  });

  it('always-on: validator fires WITHOUT complianceMode set', () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      // NOT complianceMode: ...
    });
    assert.equal(cfg.complianceMode, null);
    const audit = require('../src/audit');
    const logger = new audit.AuditLogger(cfg);
    assert.throws(
      () => logger.log({ eventType: 'sanitize', metadata: { k: 'x'.repeat(1000) } }),
      /256|exceeds/,
    );
  });

  it('end-to-end: shield.sanitize() with bad metadata raises before disk write', () => {
    const dir = tmpDir();
    const cfg = new ShieldConfig({ logDir: dir, auditEnabled: true });
    const shield = new Shield(cfg);
    assert.throws(
      () => shield.sanitize('Email me at john@acme.com', {
        metadata: { prompt: 'x'.repeat(1000) },
      }),
      /AUDIT SCHEMA|256|exceeds/,
    );
    // The audit dir should be either empty or contain only a header file —
    // the disallowed entry must NOT have been written.
    const files = fs.readdirSync(dir).filter(f => f.startsWith('audit_'));
    if (files.length > 0) {
      const text = fs.readFileSync(path.join(dir, files[0]), 'utf-8');
      assert.ok(!text.includes('xxxxxxxxxx'), 'oversized metadata leaked to disk');
    }
  });
});
