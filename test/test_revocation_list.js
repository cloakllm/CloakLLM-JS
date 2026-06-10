/**
 * v0.9.0 RV-* JS test suite: root-signed key revocation.
 * Mirror of cloakllm-py tests/test_revocation_list.py.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const c = require('../src');
const {
  DeploymentKeyPair, SanitizationCertificate,
  deriveKeyManifest, deriveRevocationList,
  RevocationList, verifyKeyProvenance,
  Shield, ShieldConfig,
} = c;

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-rv-js-'));
}

function kit() {
  const kp = DeploymentKeyPair.generate();
  const rootKp = DeploymentKeyPair.generate();
  const manifest = deriveKeyManifest(kp, {
    deployerId: 'acme',
    validFrom: '2026-01-01T00:00:00+00:00',
    validUntil: '2027-01-01T00:00:00+00:00',
  });
  const cert = SanitizationCertificate.create({
    originalText: 'x', sanitizedText: 'y',
    entityCount: 0, categories: {},
    detectionPasses: ['regex'], mode: 'tokenize', keypair: kp,
  });
  return { kp, rootKp, manifest, cert };
}


describe('RV-1 deriveRevocationList', () => {
  it('empty list is valid and signable', () => {
    const { rootKp } = kit();
    const rl = deriveRevocationList({
      deployerId: 'acme', entries: [],
      issuedAt: '2026-06-01T00:00:00+00:00',
      rootSigningCallback: d => rootKp.sign(d), rootKeyId: 'root-1',
    });
    assert.equal(rl.entries.length, 0);
    assert.ok(rl.list_hash);
    assert.ok(rl.root_signature);
  });

  it('hash deterministic', () => {
    const opts = {
      deployerId: 'acme',
      entries: [{ key_id: 'k1', revoked_at: '2026-01-01T00:00:00+00:00', reason: 'compromised' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
    };
    assert.equal(deriveRevocationList(opts).list_hash,
                 deriveRevocationList(opts).list_hash);
  });

  it('entry order is part of the hash', () => {
    const e1 = { key_id: 'k1', revoked_at: '2026-01-01T00:00:00+00:00', reason: 'compromised' };
    const e2 = { key_id: 'k2', revoked_at: '2026-02-01T00:00:00+00:00', reason: 'superseded' };
    const a = deriveRevocationList({ deployerId: 'x', entries: [e1, e2], issuedAt: '2026-06-01T00:00:00+00:00' });
    const b = deriveRevocationList({ deployerId: 'x', entries: [e2, e1], issuedAt: '2026-06-01T00:00:00+00:00' });
    assert.notEqual(a.list_hash, b.list_hash);
  });

  it('JSON round-trip', () => {
    const rl = deriveRevocationList({
      deployerId: 'acme',
      entries: [{ key_id: 'k1', revoked_at: '2026-01-01T00:00:00+00:00', reason: 'ceased_operation' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
    });
    const rt = RevocationList.fromDict(rl.toDict());
    assert.equal(rt.list_hash, rl.list_hash);
    assert.equal(rt.entries[0].reason, 'ceased_operation');
  });

  it('rejects duplicate key_id', () => {
    assert.throws(() => deriveRevocationList({
      deployerId: 'x',
      entries: [
        { key_id: 'k1', revoked_at: '2026-01-01T00:00:00+00:00', reason: 'compromised' },
        { key_id: 'k1', revoked_at: '2026-02-01T00:00:00+00:00', reason: 'superseded' },
      ],
      issuedAt: '2026-06-01T00:00:00+00:00',
    }), /duplicated/);
  });

  it('rejects unknown reason', () => {
    assert.throws(() => deriveRevocationList({
      deployerId: 'x',
      entries: [{ key_id: 'k1', revoked_at: '2026-01-01T00:00:00+00:00', reason: 'oops' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
    }), /reason/);
  });

  it('findEntry earliest-revoked_at wins on duplicates', () => {
    const rl = RevocationList.fromDict({
      deployer_id: 'x',
      entries: [
        { key_id: 'k1', revoked_at: '2026-03-01T00:00:00+00:00', reason: 'superseded' },
        { key_id: 'k1', revoked_at: '2026-01-01T00:00:00+00:00', reason: 'compromised' },
      ],
      issued_at: 't', list_version: '1.0', list_hash: 'h',
    });
    assert.equal(rl.findEntry('k1').revoked_at, '2026-01-01T00:00:00+00:00');
  });
});


describe('RV-2 revocation check #6', () => {
  it('NOT_CHECKED without list', () => {
    const { manifest, cert } = kit();
    const r = verifyKeyProvenance(cert, manifest);
    assert.equal(r.revocation_status, 'NOT_CHECKED');
    assert.equal(r.overall_valid, true);
  });

  it('REVOKED fails overall', () => {
    const { kp, rootKp, manifest, cert } = kit();
    const rl = deriveRevocationList({
      deployerId: 'acme',
      entries: [{ key_id: kp.keyId, revoked_at: '2026-01-15T00:00:00+00:00', reason: 'compromised' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
      rootSigningCallback: d => rootKp.sign(d), rootKeyId: 'r',
    });
    const r = verifyKeyProvenance(cert, manifest, {
      revocationList: rl, rootPublicKey: rootKp.publicKey,
    });
    assert.equal(r.revocation_status, 'REVOKED');
    assert.equal(r.overall_valid, false);
  });

  it('REVOKED_BUT_CERT_PREDATES stays valid (X.509/OCSP semantics)', () => {
    const { kp, manifest, cert } = kit();
    const rl = deriveRevocationList({
      deployerId: 'acme',
      entries: [{ key_id: kp.keyId, revoked_at: '2030-01-01T00:00:00+00:00', reason: 'superseded' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
    });
    const r = verifyKeyProvenance(cert, manifest, { revocationList: rl });
    assert.equal(r.revocation_status, 'REVOKED_BUT_CERT_PREDATES');
    assert.equal(r.overall_valid, true);
  });

  it('tampered list is LIST_INVALID and fails', () => {
    const { kp, manifest, cert } = kit();
    const rl = deriveRevocationList({
      deployerId: 'acme',
      entries: [{ key_id: kp.keyId, revoked_at: '2026-01-15T00:00:00+00:00', reason: 'compromised' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
    });
    const tampered = RevocationList.fromDict({ ...rl.toDict(), deployer_id: 'evil' });
    const r = verifyKeyProvenance(cert, manifest, { revocationList: tampered });
    assert.equal(r.revocation_status, 'LIST_INVALID');
    assert.equal(r.overall_valid, false);
  });

  it('deployer mismatch is LIST_INVALID', () => {
    const { manifest, cert } = kit();
    const other = deriveRevocationList({
      deployerId: 'other-corp', entries: [],
      issuedAt: '2026-06-01T00:00:00+00:00',
    });
    const r = verifyKeyProvenance(cert, manifest, { revocationList: other });
    assert.equal(r.revocation_status, 'LIST_INVALID');
  });

  it('revocation runs standalone without manifest', () => {
    const { kp, cert } = kit();
    const rl = deriveRevocationList({
      deployerId: 'acme',
      entries: [{ key_id: kp.keyId, revoked_at: '2026-01-15T00:00:00+00:00', reason: 'compromised' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
    });
    const r = verifyKeyProvenance(cert, null, { revocationList: rl });
    assert.equal(r.revocation_status, 'REVOKED');
    assert.equal(r.overall_valid, false);
  });

  it('toDict includes revocation_status', () => {
    const { manifest, cert } = kit();
    const d = verifyKeyProvenance(cert, manifest).toDict();
    assert.equal(d.revocation_status, 'NOT_CHECKED');
  });
});


describe('RV-3 advisory event + own-key fail-hard', () => {
  it('recordKeyRevocation writes advisory event and chain verifies', () => {
    const dir = tmpDir();
    const sh = new Shield(new ShieldConfig({
      auditEnabled: true, logDir: dir,
      complianceMode: 'eu_ai_act_article12',
    }));
    sh.recordKeyRevocation('old-key', 'superseded', '2026-05-01T00:00:00+00:00');
    sh.sanitize('a@b.com');
    const entries = [];
    for (const f of fs.readdirSync(dir).filter(f => f.startsWith('audit_')).sort()) {
      for (const line of fs.readFileSync(path.join(dir, f), 'utf-8').split('\n')) {
        if (line.trim()) entries.push(JSON.parse(line));
      }
    }
    const ev = entries.filter(e => e.event_type === 'key_revoked');
    assert.equal(ev.length, 1);
    assert.equal(ev[0].metadata.advisory, true);
    const r = new Shield(new ShieldConfig({ auditEnabled: false, logDir: dir })).verifyAudit();
    assert.equal(r.valid, true);
  });

  it('Shield constructor throws when own key revoked', () => {
    const dir = tmpDir();
    const kp = DeploymentKeyPair.generate();
    const rl = deriveRevocationList({
      deployerId: 'acme',
      entries: [{ key_id: kp.keyId, revoked_at: '2026-01-01T00:00:00+00:00', reason: 'compromised' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
    });
    const p = path.join(dir, 'rl.json');
    fs.writeFileSync(p, JSON.stringify(rl.toDict()));
    assert.throws(() => new Shield(new ShieldConfig({
      auditEnabled: true, logDir: path.join(dir, 'audit'),
      attestationKey: kp, revocationListPath: p,
    })), /REVOKED/);
  });

  it('clean key passes with list configured', () => {
    const dir = tmpDir();
    const kp = DeploymentKeyPair.generate();
    const rl = deriveRevocationList({
      deployerId: 'acme',
      entries: [{ key_id: 'other-key', revoked_at: '2026-01-01T00:00:00+00:00', reason: 'compromised' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
    });
    const p = path.join(dir, 'rl.json');
    fs.writeFileSync(p, JSON.stringify(rl.toDict()));
    new Shield(new ShieldConfig({
      auditEnabled: true, logDir: path.join(dir, 'audit'),
      attestationKey: kp, revocationListPath: p,
    }));
  });

  it('unreadable list throws (configured check must not run blind)', () => {
    const dir = tmpDir();
    const kp = DeploymentKeyPair.generate();
    assert.throws(() => new Shield(new ShieldConfig({
      auditEnabled: true, logDir: path.join(dir, 'audit'),
      attestationKey: kp,
      revocationListPath: path.join(dir, 'missing.json'),
    })), /could not be loaded/);
  });
});


describe('RV-4 provenance_summary revocation fields', () => {
  function shieldKit() {
    const dir = tmpDir();
    const kp = DeploymentKeyPair.generate();
    const sh = new Shield(new ShieldConfig({
      auditEnabled: true, logDir: dir,
      complianceMode: 'eu_ai_act_article12',
      attestationKey: kp, deployerId: 'acme',
      keyValidFrom: '2026-01-01T00:00:00+00:00',
      keyValidUntil: '2027-01-01T00:00:00+00:00',
    }));
    sh.sanitize('a@b.com');
    sh.sanitize('c@d.com');
    return { dir, kp, sh };
  }

  it('defaults without list (+ KM-9 fields coexist -- merge-fix guard)', () => {
    const { sh } = shieldKit();
    const ps = sh.generateComplianceReport().attestation.provenance_summary;
    assert.equal(ps.revocation_checked, false);
    assert.equal(ps.revoked_keys_found, null);
    assert.equal(ps.certs_after_revocation, null);
    assert.equal(ps.manifests_found, 1);
  });

  it('filled with revoked key', () => {
    const { dir, kp, sh } = shieldKit();
    const rl = deriveRevocationList({
      deployerId: 'acme',
      entries: [{ key_id: kp.keyId, revoked_at: '2026-01-01T00:00:00+00:00', reason: 'compromised' }],
      issuedAt: '2026-06-01T00:00:00+00:00',
    });
    const p = path.join(dir, 'rl.json');
    fs.writeFileSync(p, JSON.stringify(rl.toDict()));
    const ps = sh.generateComplianceReport({ revocationListPath: p })
      .attestation.provenance_summary;
    assert.equal(ps.revocation_checked, true);
    assert.equal(ps.revoked_keys_found, 1);
    assert.equal(ps.certs_after_revocation, 2);
  });
});


describe('LC-1 legacyCanonical removal phase 2', () => {
  it('verifyChain throws actionable error on legacyCanonical=true', () => {
    const dir = tmpDir();
    const sh = new Shield(new ShieldConfig({ auditEnabled: true, logDir: dir }));
    sh.sanitize('a@b.com');
    assert.throws(
      () => sh.verifyAudit({ legacyCanonical: true }),
      /removed in v0\.9\.0/,
    );
  });

  it('default verify unchanged', () => {
    const dir = tmpDir();
    const sh = new Shield(new ShieldConfig({ auditEnabled: true, logDir: dir }));
    sh.sanitize('a@b.com');
    assert.equal(sh.verifyAudit().valid, true);
  });
});
