const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-summary-test-'));
}

describe('Shield.complianceSummary', () => {
  it('returns the expected structure', () => {
    const cfg = new ShieldConfig({ complianceMode: 'eu_ai_act_article12' });
    const shield = new Shield(cfg);
    const summary = shield.complianceSummary();

    assert.equal(summary.compliance_mode, 'eu_ai_act_article12');
    assert.equal(summary.articles_addressed.length, 6);

    const articleNames = new Set(summary.articles_addressed.map(a => a.article));
    assert.ok(articleNames.has('EU_AI_Act_Art_12'));
    assert.ok(articleNames.has('EU_AI_Act_Art_19'));
    assert.ok(articleNames.has('EU_AI_Act_Art_4a'));
    assert.ok(articleNames.has('GDPR_Art_5_data_minimisation'));
    assert.ok(articleNames.has('GDPR_Art_5_storage_limitation'));
    assert.ok(articleNames.has('GDPR_Art_25_privacy_by_design'));

    const art4a = summary.articles_addressed.find(a => a.article === 'EU_AI_Act_Art_4a');
    // v0.8.0 doc-fix: BiasDetectionSession shipped in v0.7.0, so status was
    // incorrectly stuck on 'partial' from v0.6.x; now 'satisfied'.
    assert.equal(art4a.status, 'satisfied');

    assert.equal(summary.config_snapshot.compliance_mode, 'eu_ai_act_article12');
    assert.equal(summary.config_snapshot.retention_hint_days, 180);
    assert.ok('generated_at' in summary);
    assert.ok('cloakllm_version' in summary);
  });

  it('handles compliance_mode=null gracefully', () => {
    const shield = new Shield(new ShieldConfig());
    const summary = shield.complianceSummary();
    assert.equal(summary.compliance_mode, null);
    assert.equal(summary.articles_addressed.length, 6); // structure is always the same
  });
});

describe('Shield.exportComplianceConfig', () => {
  it('writes a valid JSON snapshot with a note field', () => {
    const dir = tmpDir();
    const outPath = path.join(dir, 'compliance.json');
    const cfg = new ShieldConfig({ complianceMode: 'eu_ai_act_article12' });
    const shield = new Shield(cfg);
    const written = shield.exportComplianceConfig(outPath);

    assert.equal(written, outPath);
    assert.ok(fs.existsSync(outPath));
    const data = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
    assert.equal(data.compliance_mode, 'eu_ai_act_article12');
    assert.ok('note' in data);
    assert.ok(/cloakllm/i.test(data.note));
  });
});
