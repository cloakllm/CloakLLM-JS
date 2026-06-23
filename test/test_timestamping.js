/**
 * v0.11.0 TS-* JS test suite: RFC 3161 trusted timestamping.
 *
 * Deterministic + OFFLINE: drives the zero-dep verifier and the report rollup
 * from the same committed mock-TSA token fixture as the Python suite
 * (test/fixtures/timestamp_token.json). CI never touches a live TSA.
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');
const {
  verifyTimestampToken, buildTimestampRequest, parseTimestampResponse, requestTimestamp,
} = require('../src/timestamping');
const { buildReport } = require('../src/compliance-report');

const FIX = JSON.parse(fs.readFileSync(
  path.join(__dirname, 'fixtures', 'timestamp_token.json'), 'utf-8'));

// --- TS-4 verifier ---
describe('TS-4 verifyTimestampToken', () => {
  it('valid, no anchor', () => {
    const r = verifyTimestampToken(FIX.tst_token_b64, FIX.stamped_entry_hash);
    assert.ok(r.valid && r.message_imprint_matches && r.signature_valid);
    assert.equal(r.gen_time, FIX.expected_gen_time);
    assert.equal(r.chain_valid, null);
  });

  it('valid, with correct anchor', () => {
    const r = verifyTimestampToken(FIX.tst_token_b64, FIX.stamped_entry_hash, [FIX.tsa_ca_cert_pem]);
    assert.ok(r.valid && r.chain_valid === true);
  });

  it('wrong digest rejected', () => {
    const r = verifyTimestampToken(FIX.tst_token_b64, 'cd'.repeat(32));
    assert.ok(!r.valid && !r.message_imprint_matches);
  });

  it('tampered token rejected', () => {
    const b = Buffer.from(FIX.tst_token_b64, 'base64'); b[b.length - 5] ^= 0xFF;
    const r = verifyTimestampToken(b.toString('base64'), FIX.stamped_entry_hash);
    assert.ok(!r.valid && !r.signature_valid);
  });

  it('garbage token does not crash', () => {
    for (const bad of ['not base64 !!', '', Buffer.from([0x30, 0x00]).toString('base64')]) {
      const r = verifyTimestampToken(bad, FIX.stamped_entry_hash);
      assert.equal(r.valid, false);
    }
  });
});

// --- TS-2 client ---
describe('TS-2 client', () => {
  it('buildTimestampRequest produces parseable DER (certReq set)', () => {
    const der = buildTimestampRequest(Buffer.from('ab'.repeat(32), 'hex'), 'sha256');
    // parse: SEQ { version INT, messageImprint SEQ, nonce INT, certReq BOOL TRUE }
    assert.equal(der[0], 0x30);
    assert.ok(der.includes(0x01) && der[der.length - 1] === 0xff); // BOOLEAN TRUE at end
  });

  it('buildTimestampRequest rejects a bad algorithm', () => {
    assert.throws(() => buildTimestampRequest(Buffer.alloc(32), 'md5'), /sha256 or sha512/);
  });

  it('requestTimestamp rejects non-https', async () => {
    await assert.rejects(() => requestTimestamp('http://tsa.example', Buffer.alloc(32)), /https/);
  });
});

// --- TS-3 Shield.checkpoint (offline paths) ---
describe('TS-3 Shield.checkpoint', () => {
  function shield(opts) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-cp-'));
    return new Shield(new ShieldConfig({ auditEnabled: true, logDir: dir, complianceMode: 'eu_ai_act_article12', ...opts }));
  }
  it('no TSA configured -> null', async () => {
    const sh = shield({});
    sh.recordContentGeneration({ modality: 'text', labeled: true });
    assert.equal(await sh.checkpoint(), null);
  });
  it('empty chain -> null', async () => {
    const sh = shield({ timestampAuthorityUrl: 'https://tsa.example' });
    assert.equal(await sh.checkpoint(), null);
  });
});

// --- TS-5 report rollup (offline, fixture-driven) ---
describe('TS-5 report rollup', () => {
  function checkpointEntry(seq, cc) {
    return {
      seq, event_id: 'e' + seq, timestamp: '2026-07-01T10:05:00.000000+00:00',
      event_type: 'chain_checkpoint', model: null, provider: null, entity_count: 0,
      categories: {}, tokens_used: [], prompt_hash: '', sanitized_hash: '',
      latency_ms: 0, mode: null, entity_details: [], timing: null,
      certificate_hash: null, key_id: null, prev_hash: '0'.repeat(64), entry_hash: 'x',
      metadata: {}, risk_assessment: null,
      article_ref: ['EU_AI_Act_Art_12', 'EU_AI_Act_Art_19'],
      checkpoint_context: cc,
    };
  }
  const cc = () => ({
    stamped_entry_hash: FIX.stamped_entry_hash, tsa_url: 'https://freetsa.org/tsr',
    tst_token_b64: FIX.tst_token_b64, hash_algorithm: 'sha256', stamped_seq: 0,
  });

  it('valid checkpoint rolls up + COMPLIANT', () => {
    const rep = buildReport({ auditEntries: [checkpointEntry(0, cc())], periodFrom: null, periodTo: null, cloakllmVersion: '0.11.0', chainValid: true });
    const ps = rep.attestation.provenance_summary;
    assert.equal(ps.timestamped_checkpoints, 1);
    assert.equal(ps.checkpoints_verified, 1);
    assert.equal(ps.earliest_provable_time, FIX.expected_gen_time);
    assert.deepEqual(ps.checkpoint_tsa_distribution, { 'https://freetsa.org/tsr': 1 });
    assert.equal(rep.verdict, 'COMPLIANT');
  });

  it('invalid checkpoint -> NON_COMPLIANT (verify-dont-assert)', () => {
    const c = cc();
    const b = Buffer.from(c.tst_token_b64, 'base64'); b[b.length - 5] ^= 0xFF;
    c.tst_token_b64 = b.toString('base64');
    const rep = buildReport({ auditEntries: [checkpointEntry(0, c)], periodFrom: null, periodTo: null, cloakllmVersion: '0.11.0', chainValid: true });
    const ps = rep.attestation.provenance_summary;
    assert.equal(ps.timestamped_checkpoints, 1);
    assert.equal(ps.checkpoints_verified, 0);
    assert.equal(rep.verdict, 'NON_COMPLIANT');
    assert.ok(rep.verdict_reasons.some(r => r.includes('checkpoints verified')));
  });

  it('no checkpoints -> fields null', () => {
    const e = {
      seq: 0, event_id: 'e', timestamp: '2026-07-01T10:00:00+00:00', event_type: 'sanitize',
      model: null, provider: null, entity_count: 0, categories: {}, tokens_used: [],
      prompt_hash: '', sanitized_hash: '', latency_ms: 0, mode: null, entity_details: [],
      timing: null, certificate_hash: null, key_id: null, prev_hash: '0'.repeat(64),
      entry_hash: 'x', metadata: {}, risk_assessment: null, article_ref: ['EU_AI_Act_Art_12'],
    };
    const rep = buildReport({ auditEntries: [e], periodFrom: null, periodTo: null, cloakllmVersion: '0.11.0', chainValid: true });
    assert.equal(rep.attestation.provenance_summary.timestamped_checkpoints, null);
  });
});


// --- v0.11.0 adversarial-review fixes (MEDIUM-2 / HIGH-1) ---
describe('signer-cert hardening + SSRF', () => {
  it('rejects an expired signer cert (MEDIUM-2)', () => {
    if (!FIX.expired_token_b64) return;
    const r = verifyTimestampToken(FIX.expired_token_b64, FIX.stamped_entry_hash, [FIX.tsa_ca_cert_pem]);
    assert.ok(!r.valid && /not valid at genTime/.test(r.reason));
  });
  it('rejects a non-timestamping signer cert (MEDIUM-2)', () => {
    if (!FIX.no_eku_token_b64) return;
    const r = verifyTimestampToken(FIX.no_eku_token_b64, FIX.stamped_entry_hash, [FIX.tsa_ca_cert_pem]);
    assert.ok(!r.valid && /timeStamping/.test(r.reason));
  });
  it('requestTimestamp blocks cloud-metadata IP (HIGH-1 SSRF)', async () => {
    await assert.rejects(() => requestTimestamp('https://169.254.169.254/tsr', Buffer.alloc(32)), /disallowed/);
  });
});
