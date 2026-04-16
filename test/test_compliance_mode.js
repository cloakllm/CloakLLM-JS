const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig, AuditLogger } = require('../src');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-compliance-test-'));
}

function readEntries(logDir) {
  const files = fs.readdirSync(logDir).filter(f => f.startsWith('audit_'));
  const entries = [];
  for (const f of files) {
    const text = fs.readFileSync(path.join(logDir, f), 'utf-8');
    for (const line of text.split('\n').filter(l => l.trim())) {
      entries.push(JSON.parse(line));
    }
  }
  return entries;
}

// --- ShieldConfig validation ---

describe('ShieldConfig compliance mode validation', () => {
  it('defaults complianceMode to null', () => {
    const cfg = new ShieldConfig();
    assert.equal(cfg.complianceMode, null);
    assert.equal(cfg.retentionHintDays, 180);
  });

  it('accepts eu_ai_act_article12', () => {
    const cfg = new ShieldConfig({ complianceMode: 'eu_ai_act_article12' });
    assert.equal(cfg.complianceMode, 'eu_ai_act_article12');
  });

  it('rejects invalid compliance mode', () => {
    assert.throws(
      () => new ShieldConfig({ complianceMode: 'not_a_mode' }),
      /Invalid complianceMode/,
    );
  });

  it('rejects zero or negative retentionHintDays', () => {
    assert.throws(
      () => new ShieldConfig({ retentionHintDays: 0 }),
      /retentionHintDays/,
    );
  });
});

// --- Audit entry compliance fields ---

describe('Audit entry compliance fields', () => {
  it('adds compliance fields when complianceMode is set', () => {
    const logDir = tmpDir();
    const cfg = new ShieldConfig({
      logDir,
      complianceMode: 'eu_ai_act_article12',
      retentionHintDays: 365,
      auditEnabled: true,
    });
    const shield = new Shield(cfg);
    shield.sanitize('Email me at john@acme.com');

    const entries = readEntries(logDir);
    assert.ok(entries.length > 0);
    for (const e of entries) {
      assert.equal(e.compliance_version, 'eu_ai_act_article12_v1');
      assert.deepEqual(e.article_ref, ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_19']);
      assert.equal(e.retention_hint_days, 365);
      assert.equal(e.pii_in_log, false);
    }
  });

  it('omits compliance fields when complianceMode is null', () => {
    const logDir = tmpDir();
    const cfg = new ShieldConfig({ logDir, auditEnabled: true });
    const shield = new Shield(cfg);
    shield.sanitize('Email me at john@acme.com');

    const entries = readEntries(logDir);
    for (const e of entries) {
      assert.equal('compliance_version' in e, false);
      assert.equal('pii_in_log' in e, false);
    }
  });

  it('compliance fields are part of the hash chain (tamper detection)', () => {
    const logDir = tmpDir();
    const cfg = new ShieldConfig({
      logDir,
      complianceMode: 'eu_ai_act_article12',
      auditEnabled: true,
    });
    const shield = new Shield(cfg);
    shield.sanitize('john@acme.com');

    const logFile = path.join(logDir, fs.readdirSync(logDir).find(f => f.startsWith('audit_')));
    const text = fs.readFileSync(logFile, 'utf-8');
    const tampered = text.replace('"pii_in_log":false', '"pii_in_log":true');
    assert.notEqual(tampered, text);
    fs.writeFileSync(logFile, tampered);

    const audit = new AuditLogger(cfg);
    const { valid, errors } = audit.verifyChain();
    assert.equal(valid, false);
    assert.ok(errors.some(err => /tampered/i.test(err)));
  });
});

// --- verifyAudit compliance_report ---

describe('Shield.verifyAudit with compliance_report', () => {
  it('returns COMPLIANT verdict for clean audit logs', () => {
    const logDir = tmpDir();
    const cfg = new ShieldConfig({
      logDir,
      complianceMode: 'eu_ai_act_article12',
      auditEnabled: true,
    });
    const shield = new Shield(cfg);
    shield.sanitize('Email me at john@acme.com');
    shield.sanitize('Call +1-555-1234');

    const report = shield.verifyAudit({ outputFormat: 'compliance_report' });
    assert.equal(report.verdict, 'COMPLIANT');
    assert.equal(report.chain_integrity, 'verified');
    assert.equal(report.pii_in_logs, false);
    assert.equal(report.total_entries, 2);
    assert.equal(report.compliance_mode_entries, 2);
    assert.ok('EMAIL' in report.pii_categories_detected);
  });

  it('returns NON_COMPLIANT verdict when entries are tampered', () => {
    const logDir = tmpDir();
    const cfg = new ShieldConfig({
      logDir,
      complianceMode: 'eu_ai_act_article12',
      auditEnabled: true,
    });
    const shield = new Shield(cfg);
    shield.sanitize('john@acme.com');

    const logFile = path.join(logDir, fs.readdirSync(logDir).find(f => f.startsWith('audit_')));
    const text = fs.readFileSync(logFile, 'utf-8');
    fs.writeFileSync(logFile, text.replace('"pii_in_log":false', '"pii_in_log":true'));

    const report = shield.verifyAudit({ outputFormat: 'compliance_report' });
    assert.equal(report.verdict, 'NON_COMPLIANT');
    assert.ok(report.anomalies.length > 0);
  });

  it('default call shape is unchanged (backward compat)', () => {
    const logDir = tmpDir();
    const cfg = new ShieldConfig({ logDir, auditEnabled: true });
    const shield = new Shield(cfg);
    shield.sanitize('john@acme.com');
    const result = shield.verifyAudit();
    assert.ok('valid' in result);
    assert.ok('errors' in result);
    assert.ok('finalSeq' in result);
  });
});
