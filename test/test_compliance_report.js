/**
 * v0.8.0 CR8 JS mirror of cloakllm-py/tests/test_compliance_report.py.
 *
 * Covers: per-article rollup, decision_id reconciliation, schema shape,
 * verdict, Markdown output, compliance_summary v0.8.0 fields,
 * attestation forward-compat. PDF tests live in the Python suite only.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig, BiasDetectionSession } = require('../src');
const { buildReport, renderMarkdown, SCHEMA_VERSION, ATTESTATION_SCHEMA_VERSION,
        COVERAGE_SCHEMA_VERSION, _articleCoverage } =
  require('../src/compliance-report');
const { canonicalJson } = require('../src/attestation');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-cr8-test-'));
}

function makeShield(extra = {}) {
  const dir = tmpDir();
  const cfg = new ShieldConfig({
    auditEnabled: true,
    logDir: dir,
    complianceMode: 'eu_ai_act_article12',
    deploymentVersion: 'prod-2026-q2',
    instructionVersion: 'v4.1',
    ...extra,
  });
  return { shield: new Shield(cfg), dir };
}

function readChain(dir) {
  const entries = [];
  for (const f of fs.readdirSync(dir).filter(f => f.startsWith('audit_') && f.endsWith('.jsonl')).sort()) {
    for (const line of fs.readFileSync(path.join(dir, f), 'utf-8').split('\n')) {
      const t = line.trim();
      if (t) entries.push(JSON.parse(t));
    }
  }
  return entries;
}

describe('CR8 per-article rollup', () => {
  it('emits article 12 + article 19 for plain sanitize events', () => {
    const { shield, dir } = makeShield();
    shield.sanitize('email me at alice@example.com');
    shield.sanitize('call bob at 555-1234');
    const r = buildReport({
      auditEntries: readChain(dir),
      cloakllmVersion: '0.8.0',
    });
    assert.ok('EU_AI_Act_Art_12' in r.per_article);
    assert.ok('EU_AI_Act_Art_19' in r.per_article);
    assert.equal(r.per_article.EU_AI_Act_Art_12.evidence_event_count, 2);
    assert.equal(r.per_article.EU_AI_Act_Art_12.pii_in_log, false);
  });

  it('article whitelist preserves zero-row for unobserved articles', () => {
    const { shield, dir } = makeShield();
    shield.sanitize('email me at alice@example.com');
    const r = buildReport({
      auditEntries: readChain(dir),
      cloakllmVersion: '0.8.0',
      articles: ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_4a'],
    });
    assert.equal(r.per_article.EU_AI_Act_Art_4a.evidence_event_count, 0);
    assert.equal(r.per_article.EU_AI_Act_Art_12.evidence_event_count, 1);
    assert.deepEqual(r.articles_in_scope, ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_4a']);
  });

  it('bias stats attach ONLY to Article 4a, not Art_12/Art_19', async () => {
    const { shield, dir } = makeShield();
    shield.sanitize('contact alice@x.com');
    await BiasDetectionSession.run({
      shield,
      purpose: 'Pre-deployment fairness audit of model X',
      necessityJustification: 'Quarterly fairness audit of model X v4.1',
      categoriesAllowed: ['RACE', 'ETHNICITY'],
      maxLifetimeSeconds: 3600,
    }, async (sess) => {
      const txt = 'German national';
      const start = txt.indexOf('German');
      sess.pseudonymise(txt, {
        forceCategories: [[start, start + 'German'.length, 'ETHNICITY']],
      });
      sess.recordFinding({
        findingSummary: 'FPR delta exceeds threshold for German cohort',
        biasMetrics: { false_positive_rate: 0.12 },
      });
    });
    const r = buildReport({
      auditEntries: readChain(dir),
      cloakllmVersion: '0.8.0',
    });
    // Art_4a has the bias stats
    assert.ok('bias_sessions' in r.per_article.EU_AI_Act_Art_4a);
    assert.equal(r.per_article.EU_AI_Act_Art_4a.bias_sessions, 1);
    assert.equal(r.per_article.EU_AI_Act_Art_4a.findings_recorded, 1);
    // Art_12 / Art_19 do NOT (correctness invariant from the spec)
    assert.ok(!('bias_sessions' in r.per_article.EU_AI_Act_Art_12));
    assert.ok(!('bias_sessions' in r.per_article.EU_AI_Act_Art_19));
  });
});

describe('CR8 decision_id reconciliation', () => {
  it('counts unique decision_ids per article', () => {
    const { shield, dir } = makeShield();
    for (let i = 0; i < 5; i++) shield.sanitize(`msg ${i}: a${i}@x.com`);
    const r = buildReport({
      auditEntries: readChain(dir),
      cloakllmVersion: '0.8.0',
    });
    assert.equal(r.per_article.EU_AI_Act_Art_12.decision_count, 5);
  });

  it('include_decisions emits per-decision rollup', () => {
    const { shield, dir } = makeShield();
    for (let i = 0; i < 5; i++) shield.sanitize(`msg ${i}: a${i}@x.com`);
    const r = buildReport({
      auditEntries: readChain(dir),
      cloakllmVersion: '0.8.0',
      includeDecisions: true,
    });
    assert.equal(Object.keys(r.decisions).length, 5);
  });

  it('include_decisions defaults to false', () => {
    const { shield, dir } = makeShield();
    shield.sanitize('a@x.com');
    const r = buildReport({
      auditEntries: readChain(dir),
      cloakllmVersion: '0.8.0',
    });
    assert.ok(!('decisions' in r));
  });
});

describe('CR8 schema contract', () => {
  it('shape matches examples/compliance_report_schema.json', () => {
    const { shield, dir } = makeShield();
    shield.sanitize('email a@x.com');
    const r = buildReport({
      auditEntries: readChain(dir),
      cloakllmVersion: '0.8.0',
      auditDir: dir,
    });
    assert.equal(r.report_metadata.schema_version, SCHEMA_VERSION);
    assert.equal(r.attestation.schema_version, ATTESTATION_SCHEMA_VERSION);
    assert.ok('verdict' in r);
    assert.ok('verdict_reasons' in r);
    assert.ok('chain_integrity' in r);
    assert.ok('per_article' in r);
    assert.ok('attestation' in r);
  });

  it('empty chain produces valid COMPLIANT report', () => {
    const r = buildReport({
      auditEntries: [],
      cloakllmVersion: '0.8.0',
    });
    assert.equal(r.verdict, 'COMPLIANT');
    assert.equal(r.chain_integrity.total_entries, 0);
    assert.deepEqual(r.per_article, {});
  });
});

describe('CR8 verdict', () => {
  it('clean chain => COMPLIANT', () => {
    const { shield, dir } = makeShield();
    shield.sanitize('email a@x.com');
    const r = buildReport({
      auditEntries: readChain(dir),
      cloakllmVersion: '0.8.0',
    });
    assert.equal(r.verdict, 'COMPLIANT');
    assert.deepEqual(r.verdict_reasons, []);
  });

  it('pii_in_log=true => NON_COMPLIANT with human-readable reason', () => {
    const fake = [{
      seq: 0,
      timestamp: '2026-05-30T12:00:00+00:00',
      article_ref: ['EU_AI_Act_Art_12'],
      event_type: 'sanitize',
      pii_in_log: true,
      categories: { EMAIL: 1 },
    }];
    const r = buildReport({ auditEntries: fake, cloakllmVersion: '0.8.0' });
    assert.equal(r.verdict, 'NON_COMPLIANT');
    // pii_in_log triggers a per_article reason (anomaly is logged into
    // chain_integrity.anomalies but doesn't flip chain_valid in v0.8.0;
    // chain validation is the caller's responsibility).
    assert.equal(r.verdict_reasons.length, 1);
    assert.ok(r.verdict_reasons.some(x => x.includes('pii_in_log=true')));
    assert.equal(r.chain_integrity.anomalies.length, 1);
  });
});

describe('CR8 Markdown output', () => {
  it('renders ASCII-only Markdown', () => {
    const { shield, dir } = makeShield();
    shield.sanitize('email a@x.com');
    const md = shield.generateComplianceReport({ format: 'markdown' });
    assert.equal(typeof md, 'string');
    assert.ok(md.startsWith('# CloakLLM Compliance Report'));
    assert.ok(md.includes('Verdict'));
    // ASCII only — no smart quotes, arrows, em-dashes (v0.7.0 cp1252 lesson)
    // Allow -> (ASCII) but reject any non-ASCII char
    for (const ch of md) {
      assert.ok(ch.charCodeAt(0) < 128, `non-ASCII char in markdown: U+${ch.charCodeAt(0).toString(16)}`);
    }
  });

  it('writes markdown to outPath', () => {
    const { shield, dir } = makeShield();
    shield.sanitize('email a@x.com');
    const out = path.join(dir, 'report.md');
    shield.generateComplianceReport({ format: 'markdown', outPath: out });
    assert.ok(fs.existsSync(out));
    assert.ok(fs.readFileSync(out, 'utf-8').includes('CloakLLM Compliance Report'));
  });
});

describe('CR8 format validation', () => {
  it('rejects PDF in JS SDK', () => {
    const { shield } = makeShield();
    assert.throws(
      () => shield.generateComplianceReport({ format: 'pdf' }),
      /PDF is Python-only/,
    );
  });

  it('rejects unknown format', () => {
    const { shield } = makeShield();
    assert.throws(
      () => shield.generateComplianceReport({ format: 'xml' }),
      /unsupported format/,
    );
  });
});

describe('CR8 attestation forward-compat (v0.8.1)', () => {
  it('emits provenance_summary slot with all-null KeyManifest fields', () => {
    const r = buildReport({ auditEntries: [], cloakllmVersion: '0.8.0' });
    const ps = r.attestation.provenance_summary;
    assert.equal(ps.manifests_found, null);
    assert.equal(ps.manifests_valid, null);
    assert.equal(ps.within_validity_window_pct, null);
    assert.equal(ps.root_signature_status_distribution, null);
    assert.equal(r.attestation.schema_version, '1.0');
  });
});

// v0.8.0 AUDIT-3: buildReport() must not crash on malformed audit entries.
describe('CR8 AUDIT-3 adversarial inputs', () => {
  const adversarial = [
    {seq: 0, timestamp: '2026-05-30T12:00:00+00:00', article_ref: ['EU_AI_Act_Art_12']},
    {seq: 1},
    {timestamp: null, article_ref: null},
    {seq: 'string', timestamp: 42, article_ref: 'not-a-list'},
    {},
    {seq: 5, timestamp: '2026-05-30T12:00:00+00:00', article_ref: [], pii_in_log: true},
  ];

  it('does not crash on malformed entries', () => {
    const r = buildReport({auditEntries: adversarial, cloakllmVersion: '0.8.0'});
    // v0.10.3 MEDIUM-6: the adversarial set includes a pii_in_log=true entry
    // (seq 5) with empty article_ref. Before the fix this was silently ignored
    // (no per_article row -> verdict stayed COMPLIANT) -- the exact bug. The
    // no-PII-in-logs invariant is global, so it must now read NON_COMPLIANT.
    assert.equal(r.verdict, 'NON_COMPLIANT');
    assert.ok(r.verdict_reasons.some(x => x.includes('pii_in_log=true')));
    assert.equal(r.chain_integrity.total_entries, 2);
  });

  it('does not crash with includeDecisions=true', () => {
    const r = buildReport({auditEntries: adversarial, cloakllmVersion: '0.8.0', includeDecisions: true});
    assert.ok('decisions' in r);
  });

  it('string article_ref does not corrupt per_article', () => {
    const r = buildReport({
      auditEntries: [{seq: 0, timestamp: '2026-05-30T12:00:00+00:00', article_ref: 'EU_AI_Act_Art_12'}],
      cloakllmVersion: '0.8.0',
    });
    assert.deepEqual(r.per_article, {});
  });
});

// v0.8.1 KM-9: ProvenanceReport aggregator wires into attestation.provenance_summary
describe('KM-9 provenance_summary aggregator', () => {
  it('pre-v0.8.1 chain stays all-null', () => {
    const entries = [{
      seq: 0, timestamp: '2026-05-30T12:00:00+00:00',
      event_type: 'sanitize', article_ref: ['EU_AI_Act_Art_12'],
      key_id: 'k1', certificate_hash: 'h0',
    }];
    const r = buildReport({ auditEntries: entries, cloakllmVersion: '0.8.1' });
    const ps = r.attestation.provenance_summary;
    assert.equal(ps.manifests_found, null);
    assert.equal(ps.manifests_valid, null);
    assert.equal(ps.within_validity_window_pct, null);
    assert.equal(ps.root_signature_status_distribution, null);
  });

  it('v0.8.1 chain fills provenance_summary fields', () => {
    const { shield, dir } = makeShield({
      attestationKey: require('../src').DeploymentKeyPair.generate(),
      deployerId: 'acme',
      keyValidFrom: '2026-01-01T00:00:00+00:00',
      keyValidUntil: '2027-01-01T00:00:00+00:00',
    });
    shield.sanitize('email a@b.com');
    shield.sanitize('email c@d.com');
    const r = shield.generateComplianceReport();
    const ps = r.attestation.provenance_summary;
    assert.equal(ps.manifests_found, 1);
    assert.equal(ps.manifests_valid, 1);
    assert.equal(ps.root_signature_status_distribution.NOT_REQUESTED, 1);
  });
});

describe('CR8-9 compliance_summary v0.8.0 fields', () => {
  it('decision_id_enabled is always true', () => {
    const { shield } = makeShield();
    const s = shield.complianceSummary();
    assert.equal(s.config_snapshot.decision_id_enabled, true);
  });

  it('system_version_pin_configured true iff both versions set', () => {
    const { shield: shieldWith } = makeShield();
    assert.equal(shieldWith.complianceSummary().config_snapshot.system_version_pin_configured, true);

    const cfgWithout = new ShieldConfig({
      auditEnabled: true,
      logDir: tmpDir(),
      complianceMode: 'eu_ai_act_article12',
    });
    const shieldWithout = new Shield(cfgWithout);
    assert.equal(shieldWithout.complianceSummary().config_snapshot.system_version_pin_configured, false);
  });

  it('compliance_reporting_available is true', () => {
    const { shield } = makeShield();
    assert.equal(shield.complianceSummary().config_snapshot.compliance_reporting_available, true);
  });
});


// ===================================================================
// v0.10.3: cross-SDK parity for wipe_confirmed_pct (routes through _pct now;
// regression guard against the banker's-vs-half-up + 1dp-vs-2dp divergence).
// ===================================================================

function _biasEntry(seq, etype, bc) {
  return {
    seq, event_id: 'e' + seq, timestamp: '2026-05-01T10:00:0' + (seq % 10) + '.000000+00:00',
    event_type: etype, model: null, provider: null, entity_count: 0, categories: {},
    tokens_used: [], prompt_hash: '', sanitized_hash: '', latency_ms: 0, mode: null,
    entity_details: [], timing: null, certificate_hash: null, key_id: null,
    prev_hash: '0'.repeat(64), entry_hash: 'x', metadata: {}, risk_assessment: null,
    article_ref: ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_19', 'EU_AI_Act_Art_4a'],
    decision_id: 'd' + seq, bias_context: bc,
  };
}

describe('v0.10.3 wipe_confirmed_pct parity', () => {
  it('fractional wipe (1 of 3) is 33.33, matching Python (was 33.3)', () => {
    const entries = [
      _biasEntry(0, 'bias_session_start', { session_id: 's0', purpose: 'audit' }),
      _biasEntry(1, 'bias_session_start', { session_id: 's1', purpose: 'audit' }),
      _biasEntry(2, 'bias_session_start', { session_id: 's2', purpose: 'audit' }),
      _biasEntry(3, 'bias_session_end', { session_id: 's0', wipe_confirmed: true }),
      _biasEntry(4, 'bias_session_end', { session_id: 's1', wipe_confirmed: false }),
      _biasEntry(5, 'bias_session_end', { session_id: 's2', wipe_confirmed: false }),
    ];
    const rep = buildReport({ auditEntries: entries, periodFrom: null, periodTo: null,
      chainValid: true, chainAnomalies: [], cloakllmVersion: '0.10.3' });
    assert.equal(rep.per_article.EU_AI_Act_Art_4a.wipe_confirmed_pct, 33.33);
  });

  it('full wipe is int 100 (serializes without .0)', () => {
    const entries = [
      _biasEntry(0, 'bias_session_start', { session_id: 's0', purpose: 'audit' }),
      _biasEntry(1, 'bias_session_end', { session_id: 's0', wipe_confirmed: true }),
    ];
    const rep = buildReport({ auditEntries: entries, periodFrom: null, periodTo: null,
      chainValid: true, chainAnomalies: [], cloakllmVersion: '0.10.3' });
    const v = rep.per_article.EU_AI_Act_Art_4a.wipe_confirmed_pct;
    assert.equal(v, 100);
    assert.ok(Number.isInteger(v));
  });
});

// v0.12.0: the honest per-article coverage matrix (mirror of Python).
describe('coverage matrix', () => {
  const report = () => buildReport({ auditEntries: [], periodFrom: null, periodTo: null,
    chainValid: true, chainAnomalies: [], cloakllmVersion: '0.12.0' });

  it('report includes the coverage block', () => {
    const cov = report().coverage;
    assert.equal(cov.schema_version, COVERAGE_SCHEMA_VERSION);
    const arts = new Set(cov.articles.map((a) => a.article));
    assert.deepEqual([...arts].sort(),
      ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_19', 'EU_AI_Act_Art_4a', 'EU_AI_Act_Art_50']);
    for (const a of cov.articles) {
      assert.ok(a.cloakllm_provides && a.deployer_responsibility);
    }
    assert.ok(cov.out_of_scope.length);
  });

  it('schema_version is bumped to 1.1', () => {
    assert.equal(SCHEMA_VERSION, '1.1');
    assert.equal(report().report_metadata.schema_version, '1.1');
  });

  it('coverage is ASCII-only', () => {
    const s = canonicalJson(_articleCoverage());
    assert.ok(/^[\x00-\x7F]*$/.test(s), 'coverage block must be ASCII (AUDIT-6)');
  });

  it('coverage canonical matches the cross-SDK fixture', () => {
    // The SAME fixture bytes are committed in cloakllm-py/tests/fixtures/.
    const expected = fs.readFileSync(
      path.join(__dirname, 'fixtures', 'coverage_canonical.txt'), 'utf-8');
    assert.equal(canonicalJson(_articleCoverage()), expected);
  });

  it('Markdown renders the coverage section', () => {
    const md = renderMarkdown(report());
    assert.ok(md.includes('## Coverage matrix'));
    assert.ok(md.includes('Your responsibility'));
    assert.ok(md.includes('Out of scope for CloakLLM'));
  });
});
