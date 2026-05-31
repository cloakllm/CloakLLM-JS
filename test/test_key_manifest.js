/**
 * v0.8.1 KM-* JS test suite: externally-verifiable key provenance.
 *
 * Covers KM-1, KM-2, KM-3 (audit B3 extension), KM-4 (folded into KM-1/2),
 * KM-7 (back-compat), and AUDIT-3 hardening. KM-9 (compliance_report
 * aggregator) is covered separately in test_compliance_report.js.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const c = require('../src');
const {
  KeyManifest, deriveKeyManifest,
  ProvenanceReport, verifyKeyProvenance,
  DeploymentKeyPair, SanitizationCertificate,
  Shield, ShieldConfig,
  KEY_MANIFEST_SCHEMA_VERSION,
} = c;

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-km-js-'));
}

function makeKp() { return DeploymentKeyPair.generate(); }

function makeCert(kp) {
  return SanitizationCertificate.create({
    originalText: 'x', sanitizedText: 'y',
    entityCount: 0, categories: {},
    detectionPasses: ['regex'], mode: 'tokenize', keypair: kp,
  });
}


// ===================================================================
// KM-1: deriveKeyManifest + KeyManifest
// ===================================================================

describe('KM-1 deriveKeyManifest', () => {
  it('happy path', () => {
    const kp = makeKp();
    const m = deriveKeyManifest(kp, { deployerId: 'acme' });
    assert.equal(m.key_id, kp.keyId);
    assert.equal(m.public_key, kp.publicKeyB64);
    assert.equal(m.deployer_id, 'acme');
    assert.equal(m.purpose, 'cloakllm-audit-attestation');
    assert.equal(m.manifest_version, KEY_MANIFEST_SCHEMA_VERSION);
    assert.ok(m.manifest_hash);
    assert.equal(m.root_signature, null);
    assert.equal(m.root_key_id, null);
  });

  it('determinism', () => {
    const kp = makeKp();
    const opts = { deployerId: 'x', validFrom: '2026-01-01T00:00:00+00:00' };
    assert.equal(deriveKeyManifest(kp, opts).manifest_hash,
                 deriveKeyManifest(kp, opts).manifest_hash);
  });

  it('JSON round-trip', () => {
    const kp = makeKp();
    const m = deriveKeyManifest(kp, { deployerId: 'acme' });
    const m2 = KeyManifest.fromDict(m.toDict());
    assert.equal(m.manifest_hash, m2.manifest_hash);
    assert.deepEqual(m.toDict(), m2.toDict());
  });

  it('root signing', () => {
    const kp = makeKp();
    const rootKp = makeKp();
    const m = deriveKeyManifest(kp, {
      deployerId: 'acme', validFrom: '2026-01-01T00:00:00+00:00',
      rootSigningCallback: (d) => rootKp.sign(d), rootKeyId: 'r',
    });
    assert.ok(m.root_signature);
    assert.equal(m.root_key_id, 'r');
    assert.ok(DeploymentKeyPair.verify(
      rootKp.publicKey,
      Buffer.from(m.manifest_hash, 'ascii'),
      Buffer.from(m.root_signature, 'base64'),
    ));
  });

  it('rejects empty deployerId', () => {
    assert.throws(() => deriveKeyManifest(makeKp(), { deployerId: '' }), /deployerId/);
  });

  it('rejects oversized deployerId', () => {
    assert.throws(() => deriveKeyManifest(makeKp(), { deployerId: 'x'.repeat(257) }), /256 chars/);
  });

  it('rejects NUL-byte deployerId', () => {
    assert.throws(() => deriveKeyManifest(makeKp(), { deployerId: 'bad\x00name' }), /NUL/);
  });

  it('rejects unknown purpose', () => {
    assert.throws(
      () => deriveKeyManifest(makeKp(), { deployerId: 'x', purpose: 'evil' }),
      /purpose/,
    );
  });

  it('rejects naive timestamp', () => {
    assert.throws(
      () => deriveKeyManifest(makeKp(), { deployerId: 'x', validFrom: '2026-01-01T00:00:00' }),
      /UTC/,
    );
  });

  it('rejects validUntil before validFrom', () => {
    assert.throws(
      () => deriveKeyManifest(makeKp(), {
        deployerId: 'x',
        validFrom: '2027-01-01T00:00:00+00:00',
        validUntil: '2026-01-01T00:00:00+00:00',
      }),
      /validUntil/,
    );
  });

  it('rejects root callback without rootKeyId', () => {
    const kp = makeKp();
    assert.throws(
      () => deriveKeyManifest(kp, { deployerId: 'x', rootSigningCallback: (d) => kp.sign(d) }),
      /rootKeyId/,
    );
  });
});


// ===================================================================
// KM-2: verifyKeyProvenance + ProvenanceReport
// ===================================================================

describe('KM-2 verifyKeyProvenance', () => {
  function setup() {
    const kp = makeKp();
    const m = deriveKeyManifest(kp, {
      deployerId: 'acme',
      validFrom: '2026-01-01T00:00:00+00:00',
      validUntil: '2027-01-01T00:00:00+00:00',
    });
    const cert = makeCert(kp);
    return { kp, m, cert };
  }

  it('happy path', () => {
    const { m, cert } = setup();
    const r = verifyKeyProvenance(cert, m);
    assert.equal(r.overall_valid, true);
    assert.equal(r.provenance_status, 'VERIFIED');
    assert.equal(r.signature_valid, true);
    assert.equal(r.key_id_matches, true);
    assert.equal(r.within_validity_window, true);
    assert.equal(r.root_signature_status, 'NOT_REQUESTED');
    assert.equal(r.manifest_hash_consistent, true);
  });

  it('manifest=null back-compat', () => {
    const { cert } = setup();
    const r = verifyKeyProvenance(cert, null);
    assert.equal(r.provenance_status, 'UNVERIFIED');
    assert.equal(r.signature_valid, true);
    assert.equal(r.overall_valid, true);
    assert.equal(r.key_id_matches, null);
  });

  it('tampered key_id', () => {
    const { m, cert } = setup();
    const tampered = KeyManifest.fromDict({ ...m.toDict(), key_id: 'bogus' });
    const r = verifyKeyProvenance(cert, tampered);
    assert.equal(r.overall_valid, false);
    assert.equal(r.key_id_matches, false);
    assert.equal(r.manifest_hash_consistent, false);
  });

  it('expired key', () => {
    const { kp, cert } = setup();
    const expired = deriveKeyManifest(kp, {
      deployerId: 'acme',
      validFrom: '2025-01-01T00:00:00+00:00',
      validUntil: '2025-12-31T00:00:00+00:00',
    });
    const r = verifyKeyProvenance(cert, expired);
    assert.equal(r.within_validity_window, false);
    assert.ok(r.notes.some(n => n.includes('expired')));
  });

  it('root-signed correct root pk', () => {
    const { kp, cert } = setup();
    const rootKp = makeKp();
    const m = deriveKeyManifest(kp, {
      deployerId: 'acme',
      validFrom: '2026-01-01T00:00:00+00:00',
      validUntil: '2027-01-01T00:00:00+00:00',
      rootSigningCallback: (d) => rootKp.sign(d), rootKeyId: 'r',
    });
    const r = verifyKeyProvenance(cert, m, { rootPublicKey: rootKp.publicKey });
    assert.equal(r.root_signature_status, 'VALID');
    assert.equal(r.overall_valid, true);
  });

  it('root-signed wrong root pk', () => {
    const { kp, cert } = setup();
    const rootKp = makeKp();
    const wrongRoot = makeKp();
    const m = deriveKeyManifest(kp, {
      deployerId: 'acme',
      validFrom: '2026-01-01T00:00:00+00:00',
      validUntil: '2027-01-01T00:00:00+00:00',
      rootSigningCallback: (d) => rootKp.sign(d), rootKeyId: 'r',
    });
    const r = verifyKeyProvenance(cert, m, { rootPublicKey: wrongRoot.publicKey });
    assert.equal(r.root_signature_status, 'INVALID');
    assert.equal(r.overall_valid, false);
  });

  it('root-signed without root pk supplied', () => {
    const { kp, cert } = setup();
    const rootKp = makeKp();
    const m = deriveKeyManifest(kp, {
      deployerId: 'acme',
      validFrom: '2026-01-01T00:00:00+00:00',
      validUntil: '2027-01-01T00:00:00+00:00',
      rootSigningCallback: (d) => rootKp.sign(d), rootKeyId: 'r',
    });
    const r = verifyKeyProvenance(cert, m);
    assert.equal(r.root_signature_status, 'UNVERIFIED_NO_KEY');
    assert.equal(r.overall_valid, true);
  });

  it('clock_skew_seconds tolerance', () => {
    const { kp, cert } = setup();
    const now = Date.now();
    const past_end = new Date(now - 60 * 1000).toISOString().replace('Z', '+00:00');
    const past_start = new Date(now - 3600 * 1000).toISOString().replace('Z', '+00:00');
    const m = deriveKeyManifest(kp, {
      deployerId: 'acme', validFrom: past_start, validUntil: past_end,
    });
    assert.equal(verifyKeyProvenance(cert, m).within_validity_window, false);
    assert.equal(
      verifyKeyProvenance(cert, m, { clockSkewSeconds: 90 }).within_validity_window,
      true,
    );
  });
});


// ===================================================================
// KM-3: key_registered audit event + Shield auto-emit
// ===================================================================

describe('KM-3 key_registered audit event', () => {
  it('Shield emits on init when deployerId set', () => {
    const dir = tmpDir();
    const kp = makeKp();
    new Shield(new ShieldConfig({
      auditEnabled: true, logDir: dir,
      attestationKey: kp, deployerId: 'acme',
      complianceMode: 'eu_ai_act_article12',
    }));
    const entries = readChain(dir);
    const kr = entries.filter(e => e.event_type === 'key_registered');
    assert.equal(kr.length, 1);
    assert.equal(kr[0].key_manifest.deployer_id, 'acme');
  });

  it('no emit without deployerId', () => {
    const dir = tmpDir();
    new Shield(new ShieldConfig({
      auditEnabled: true, logDir: dir,
      attestationKey: makeKp(),
    }));
    const kr = readChain(dir).filter(e => e.event_type === 'key_registered');
    assert.equal(kr.length, 0);
  });

  it('allow-duplicate emission, single unique manifest_hash', () => {
    const dir = tmpDir();
    const kp = makeKp();
    const cfgFactory = () => new ShieldConfig({
      auditEnabled: true, logDir: dir,
      attestationKey: kp, deployerId: 'acme',
      keyValidFrom: '2026-01-01T00:00:00+00:00',
    });
    new Shield(cfgFactory());
    new Shield(cfgFactory());
    const kr = readChain(dir).filter(e => e.event_type === 'key_registered');
    assert.equal(kr.length, 2);
    const hashes = new Set(kr.map(e => e.key_manifest.manifest_hash));
    assert.equal(hashes.size, 1);
  });
});


function readChain(dir) {
  const out = [];
  for (const f of fs.readdirSync(dir).filter(f => f.startsWith('audit_')).sort()) {
    for (const line of fs.readFileSync(path.join(dir, f), 'utf-8').split('\n')) {
      if (line.trim()) out.push(JSON.parse(line));
    }
  }
  return out;
}


// ===================================================================
// AUDIT-3 hardening: adversarial inputs
// ===================================================================

describe('KM AUDIT-3 adversarial inputs', () => {
  it('verifyKeyProvenance does not crash on malformed timestamps', () => {
    const kp = makeKp();
    const cert = makeCert(kp);
    // Manually construct a manifest with a bad valid_from
    const km = new KeyManifest({
      key_id: kp.keyId, public_key: kp.publicKeyB64,
      deployer_id: 'x', valid_from: 'not-a-timestamp',
      valid_until: null, purpose: 'cloakllm-audit-attestation',
      manifest_version: '1.0', manifest_hash: 'whatever',
    });
    const r = verifyKeyProvenance(cert, km);
    assert.equal(r.within_validity_window, false);
    assert.ok(r.notes.some(n => n.includes('cannot compare timestamps')));
  });
});


// ===================================================================
// KM-7: Backward compatibility
// ===================================================================

describe('KM-7 backward compat', () => {
  it('pre-v0.8.1 chain (no deployerId) still verifies', () => {
    const dir = tmpDir();
    const sh = new Shield(new ShieldConfig({
      auditEnabled: true, logDir: dir,
      attestationKey: makeKp(),
      complianceMode: 'eu_ai_act_article12',
    }));
    sh.sanitize('a@b.com');
    const r = new Shield(new ShieldConfig({
      auditEnabled: false, logDir: dir,
    })).verifyAudit();
    assert.equal(r.valid, true);
  });

  it('SanitizationCertificate.verify(pk) v0.6.x API unchanged', () => {
    const kp = makeKp();
    const cert = makeCert(kp);
    assert.equal(cert.verify(kp.publicKey), true);
  });
});
