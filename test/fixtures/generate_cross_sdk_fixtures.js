/**
 * v0.6.3 I7 — generate cross-SDK fixture corpus from the JS SDK.
 *
 * Run from cloakllm-js root:
 *
 *     node test/fixtures/generate_cross_sdk_fixtures.js
 *
 * Produces (and mirrors into cloakllm-py/tests/fixtures/):
 *   * audit_chain_js.jsonl    — audit chain written by JS
 *   * certificate_js.json     — signed certificate from JS
 *   * cross_sdk_metadata.json — merged with the python_* keys; JS sets js_*
 *
 * Each SDK's I7 tests verify the OTHER SDK's fixture, so a regression in
 * canonical JSON / chain hashing / signature scheme breaks CI on both sides.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const { Shield, ShieldConfig } = require('../../src');
const { DeploymentKeyPair, SanitizationCertificate } = require('../../src/attestation');

const HERE = __dirname;
const JS_FIXTURES = HERE;
const PY_FIXTURES = path.resolve(HERE, '..', '..', '..', 'cloakllm-py', 'tests', 'fixtures');

// SPKI/PKCS8 prefixes for raw-bytes ↔ Node crypto API conversion. Same
// values as src/attestation.js; duplicated here to avoid leaking module
// internals just for the fixture script.
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

// Same 32-byte test seed as the Python generator so cross-SDK certificate
// verification is meaningful (signatures from JS verify with the public
// key written by the Python keypair, and vice versa).
function buildPinnedKeypair() {
  const seedRaw = Buffer.concat([
    Buffer.from('cloakllm_i7_seed_v063'),
    Buffer.alloc(32),
  ]).subarray(0, 32);

  const privateDer = Buffer.concat([PKCS8_PREFIX, seedRaw]);
  const privKeyObj = crypto.createPrivateKey({
    key: privateDer,
    format: 'der',
    type: 'pkcs8',
  });
  const publicDer = crypto.createPublicKey(privKeyObj).export({
    format: 'der',
    type: 'spki',
  });
  const publicKey = publicDer.subarray(SPKI_PREFIX.length);

  return new DeploymentKeyPair(seedRaw, publicKey, 'cross_sdk_test_v063');
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-i7-chain-js-'));
}

function writeAuditChainFixture(outPath) {
  const dir = tmpDir();
  try {
    const shield = new Shield(new ShieldConfig({
      logDir: dir,
      auditEnabled: true,
      complianceMode: 'eu_ai_act_article12',
    }));
    shield.sanitize('Email john@example.com about the meeting.');
    shield.sanitize('Reach Sarah at sarah@example.org or call 555-123-4567.');
    shield.sanitize('SSN 123-45-6789 should never appear in logs.');
    const chainFiles = fs.readdirSync(dir).filter(f => f.startsWith('audit_')).sort();
    if (chainFiles.length === 0) {
      throw new Error('no audit file produced');
    }
    const content = fs.readFileSync(path.join(dir, chainFiles[chainFiles.length - 1]), 'utf-8');
    fs.writeFileSync(outPath, content, 'utf-8');
    const { valid, errors, finalSeq } = shield.audit.verifyChain();
    return {
      format: 'jsonl',
      writer_sdk: 'javascript',
      writer_version: '0.6.3',
      chain_valid: valid,
      chain_errors: errors,
      final_seq: finalSeq,
      entries: content.split('\n').filter(l => l.trim()).length,
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Recursively sort object keys so JSON.stringify produces stable output.
function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((acc, k) => {
      acc[k] = sortKeys(value[k]);
      return acc;
    }, {});
  }
  return value;
}

function writeCertificateFixture(outPath) {
  const keypair = buildPinnedKeypair();
  const cert = SanitizationCertificate.create({
    originalText: 'Email john@example.com please',
    sanitizedText: 'Email [EMAIL_0] please',
    entityCount: 1,
    categories: { EMAIL: 1 },
    detectionPasses: ['regex'],
    mode: 'tokenize',
    keypair,
  });
  const certDict = cert.toDict();
  const wrapper = {
    certificate: certDict,
    public_key_b64: keypair.publicKeyB64,
    key_id: keypair.keyId,
  };
  fs.writeFileSync(
    outPath,
    // sortKeys gives stable byte output across regenerations; the prior
    // version mistakenly passed an array as JSON.stringify's REPLACER,
    // which acts as a property-name FILTER and dropped most fields.
    JSON.stringify(sortKeys(wrapper), null, 2) + '\n',
    'utf-8',
  );
  const selfVerifyOk = cert.verify(keypair.publicKey);
  return {
    writer_sdk: 'javascript',
    writer_version: '0.6.3',
    self_verify_ok: selfVerifyOk,
    input_hash: certDict.input_hash,
    output_hash: certDict.output_hash,
    entity_count: certDict.entity_count,
  };
}

function main() {
  fs.mkdirSync(JS_FIXTURES, { recursive: true });
  fs.mkdirSync(PY_FIXTURES, { recursive: true });

  const chainPathJs = path.join(JS_FIXTURES, 'audit_chain_js.jsonl');
  const certPathJs = path.join(JS_FIXTURES, 'certificate_js.json');

  const chainMeta = writeAuditChainFixture(chainPathJs);
  const certMeta = writeCertificateFixture(certPathJs);

  fs.copyFileSync(chainPathJs, path.join(PY_FIXTURES, 'audit_chain_js.jsonl'));
  fs.copyFileSync(certPathJs, path.join(PY_FIXTURES, 'certificate_js.json'));

  // Merge with existing metadata (Python writer's keys preserved).
  const metaPathJs = path.join(JS_FIXTURES, 'cross_sdk_metadata.json');
  const metaPathPy = path.join(PY_FIXTURES, 'cross_sdk_metadata.json');
  let existing = {};
  if (fs.existsSync(metaPathJs)) {
    try {
      existing = JSON.parse(fs.readFileSync(metaPathJs, 'utf-8'));
    } catch { /* ignore */ }
  }
  existing.javascript_chain = chainMeta;
  existing.javascript_certificate = certMeta;
  existing.regenerated_at_utc = new Date().toISOString().slice(0, 10);
  // sortKeys recursive helper for stable byte output — `JSON.stringify(x, [..keys..])`
  // would treat the array as a property-FILTER, dropping nested fields.
  const payload = JSON.stringify(sortKeys(existing), null, 2) + '\n';
  fs.writeFileSync(metaPathJs, payload, 'utf-8');
  fs.writeFileSync(metaPathPy, payload, 'utf-8');

  console.log(`wrote audit_chain_js.jsonl (${chainMeta.entries} entries, valid=${chainMeta.chain_valid})`);
  console.log(`wrote certificate_js.json (self_verify_ok=${certMeta.self_verify_ok})`);
  console.log(`mirrored both into ../cloakllm-py/tests/fixtures/`);
  console.log(`updated cross_sdk_metadata.json in both repos`);
}

main();
