/**
 * Unit tests for the cryptographic attestation module.
 *
 * Tests: DeploymentKeyPair, SanitizationCertificate, MerkleTree, deriveEntityHashKey.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {
  DeploymentKeyPair,
  SanitizationCertificate,
  MerkleTree,
  deriveEntityHashKey,
  canonicalJson,
} = require('../src/attestation');

// ── DeploymentKeyPair ──────────────────────────────────────────

describe('DeploymentKeyPair', () => {
  it('generate creates valid keypair', () => {
    const kp = DeploymentKeyPair.generate();
    assert.strictEqual(kp.privateKey.length, 32);
    assert.strictEqual(kp.publicKey.length, 32);
    assert.strictEqual(kp.keyId.length, 16);
    assert.ok(/^[0-9a-f]{16}$/.test(kp.keyId));
  });

  it('sign and verify roundtrip', () => {
    const kp = DeploymentKeyPair.generate();
    const sig = kp.sign(Buffer.from('hello world'));
    assert.strictEqual(sig.length, 64);
    assert.ok(DeploymentKeyPair.verify(kp.publicKey, Buffer.from('hello world'), sig));
  });

  it('verify wrong data fails', () => {
    const kp = DeploymentKeyPair.generate();
    const sig = kp.sign(Buffer.from('correct data'));
    assert.strictEqual(DeploymentKeyPair.verify(kp.publicKey, Buffer.from('wrong data'), sig), false);
  });

  it('verify wrong key fails', () => {
    const kp1 = DeploymentKeyPair.generate();
    const kp2 = DeploymentKeyPair.generate();
    const sig = kp1.sign(Buffer.from('data'));
    assert.strictEqual(DeploymentKeyPair.verify(kp2.publicKey, Buffer.from('data'), sig), false);
  });

  it('save and load roundtrip', () => {
    const kp = DeploymentKeyPair.generate();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-'));
    const filePath = path.join(tmpDir, 'key.json');
    try {
      kp.save(filePath);
      const loaded = DeploymentKeyPair.fromFile(filePath);
      assert.deepStrictEqual(loaded.privateKey, kp.privateKey);
      assert.deepStrictEqual(loaded.publicKey, kp.publicKey);
      assert.strictEqual(loaded.keyId, kp.keyId);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('key_id is deterministic', () => {
    const kp = DeploymentKeyPair.generate();
    const expected = crypto.createHash('sha256').update(kp.publicKey).digest('hex').substring(0, 16);
    assert.strictEqual(kp.keyId, expected);
  });

  it('signB64 format', () => {
    const kp = DeploymentKeyPair.generate();
    const sigB64 = kp.signB64(Buffer.from('test'));
    const raw = Buffer.from(sigB64, 'base64');
    assert.strictEqual(raw.length, 64);
  });

  it('publicKeyB64 property', () => {
    const kp = DeploymentKeyPair.generate();
    const decoded = Buffer.from(kp.publicKeyB64, 'base64');
    assert.deepStrictEqual(decoded, kp.publicKey);
    assert.strictEqual(decoded.length, 32);
  });

  it('verifyB64 roundtrip', () => {
    const kp = DeploymentKeyPair.generate();
    const sigB64 = kp.signB64(Buffer.from('verify b64 test'));
    assert.ok(DeploymentKeyPair.verifyB64(kp.publicKey, Buffer.from('verify b64 test'), sigB64));
    assert.strictEqual(DeploymentKeyPair.verifyB64(kp.publicKey, Buffer.from('wrong'), sigB64), false);
  });

  it('loaded key can sign', () => {
    const kp = DeploymentKeyPair.generate();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-'));
    const filePath = path.join(tmpDir, 'key.json');
    try {
      kp.save(filePath);
      const loaded = DeploymentKeyPair.fromFile(filePath);
      const sig = loaded.sign(Buffer.from('loaded key test'));
      assert.ok(DeploymentKeyPair.verify(loaded.publicKey, Buffer.from('loaded key test'), sig));
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});

// ── SanitizationCertificate ────────────────────────────────────

describe('SanitizationCertificate', () => {
  const keypair = DeploymentKeyPair.generate();

  it('create produces valid cert', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'input text',
      sanitizedText: 'output text',
      entityCount: 2,
      categories: { EMAIL: 1, PHONE: 1 },
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    assert.strictEqual(cert.version, '1.0');
    assert.ok(cert.timestamp !== '');
    assert.ok(cert.input_hash !== '');
    assert.ok(cert.output_hash !== '');
    assert.strictEqual(cert.entity_count, 2);
    assert.deepStrictEqual(cert.categories, { EMAIL: 1, PHONE: 1 });
    assert.deepStrictEqual(cert.detection_passes, ['regex']);
    assert.strictEqual(cert.mode, 'tokenize');
    assert.strictEqual(cert.key_id, keypair.keyId);
    assert.ok(cert.signature !== '');
    assert.ok(cert.public_key !== '');
  });

  it('create and verify roundtrip', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 1,
      categories: { EMAIL: 1 },
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    assert.ok(cert.verify(keypair.publicKey));
  });

  it('verify tampered input_hash fails', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 1,
      categories: { EMAIL: 1 },
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    cert.input_hash = 'tampered';
    assert.strictEqual(cert.verify(keypair.publicKey), false);
  });

  it('verify tampered entity_count fails', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 1,
      categories: { EMAIL: 1 },
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    cert.entity_count = 999;
    assert.strictEqual(cert.verify(keypair.publicKey), false);
  });

  it('verify tampered signature fails', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 1,
      categories: { EMAIL: 1 },
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    cert.signature = Buffer.alloc(64, 0).toString('base64');
    assert.strictEqual(cert.verify(keypair.publicKey), false);
  });

  it('verify wrong key fails', () => {
    const kp2 = DeploymentKeyPair.generate();
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 1,
      categories: { EMAIL: 1 },
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    assert.strictEqual(cert.verify(kp2.publicKey), false);
  });

  it('toDict contains all fields', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 0,
      categories: {},
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    const d = cert.toDict();
    const expectedFields = new Set([
      'version', 'timestamp', 'input_hash', 'output_hash',
      'entity_count', 'categories', 'detection_passes', 'mode',
      'key_id', 'nonce', 'signature', 'public_key',
    ]);
    assert.deepStrictEqual(new Set(Object.keys(d)), expectedFields);
  });

  it('input_hash is sha256', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 0,
      categories: {},
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    assert.strictEqual(cert.input_hash.length, 64);
    assert.strictEqual(cert.input_hash, crypto.createHash('sha256').update('hello').digest('hex'));
  });

  it('output_hash is sha256', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 0,
      categories: {},
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    assert.strictEqual(cert.output_hash, crypto.createHash('sha256').update('world').digest('hex'));
  });

  it('fromDict roundtrip', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 1,
      categories: { EMAIL: 1 },
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    const d = cert.toDict();
    const cert2 = SanitizationCertificate.fromDict(d);
    assert.ok(cert2.verify(keypair.publicKey));
    assert.deepStrictEqual(cert2.toDict(), d);
  });

  it('batch cert with merkle roots', () => {
    const cert = SanitizationCertificate.create({
      entityCount: 3,
      categories: { EMAIL: 2, PHONE: 1 },
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
      inputMerkleRoot: 'abc123',
      outputMerkleRoot: 'def456',
    });
    assert.strictEqual(cert.input_hash, 'abc123');
    assert.strictEqual(cert.output_hash, 'def456');
    assert.ok(cert.verify(keypair.publicKey));
  });

  it('create no text no merkle throws', () => {
    assert.throws(() => SanitizationCertificate.create({
      sanitizedText: 'out',
      entityCount: 0,
      categories: {},
      detectionPasses: [],
      mode: 'tokenize',
      keypair,
    }), /originalText or inputMerkleRoot/);
    assert.throws(() => SanitizationCertificate.create({
      originalText: 'in',
      entityCount: 0,
      categories: {},
      detectionPasses: [],
      mode: 'tokenize',
      keypair,
    }), /sanitizedText or outputMerkleRoot/);
  });

  it('public_key in dict matches keypair', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'hello',
      sanitizedText: 'world',
      entityCount: 0,
      categories: {},
      detectionPasses: ['regex'],
      mode: 'tokenize',
      keypair,
    });
    assert.strictEqual(cert.public_key, keypair.publicKeyB64);
  });

  it('empty categories and passes', () => {
    const cert = SanitizationCertificate.create({
      originalText: 'no pii',
      sanitizedText: 'no pii',
      entityCount: 0,
      categories: {},
      detectionPasses: [],
      mode: 'tokenize',
      keypair,
    });
    assert.ok(cert.verify(keypair.publicKey));
    assert.strictEqual(cert.entity_count, 0);
    assert.deepStrictEqual(cert.categories, {});
    assert.deepStrictEqual(cert.detection_passes, []);
  });
});

// ── MerkleTree ─────────────────────────────────────────────────

describe('MerkleTree', () => {
  it('single leaf', () => {
    const tree = new MerkleTree(['abc123']);
    assert.strictEqual(tree.root, 'abc123');
  });

  it('two leaves', () => {
    const tree = new MerkleTree(['aaa', 'bbb']);
    const expected = crypto.createHash('sha256').update('aaabbb').digest('hex');
    assert.strictEqual(tree.root, expected);
  });

  it('three leaves odd promotion', () => {
    const tree = new MerkleTree(['aaa', 'bbb', 'ccc']);
    const level1Left = crypto.createHash('sha256').update('aaabbb').digest('hex');
    const level1Right = 'ccc';
    const expected = crypto.createHash('sha256').update(level1Left + level1Right).digest('hex');
    assert.strictEqual(tree.root, expected);
  });

  it('four leaves', () => {
    const tree = new MerkleTree(['a', 'b', 'c', 'd']);
    const hAb = crypto.createHash('sha256').update('ab').digest('hex');
    const hCd = crypto.createHash('sha256').update('cd').digest('hex');
    const expected = crypto.createHash('sha256').update(hAb + hCd).digest('hex');
    assert.strictEqual(tree.root, expected);
  });

  it('proof and verify all indices', () => {
    const leaves = [];
    for (let i = 0; i < 8; i++) {
      leaves.push(crypto.createHash('sha256').update(`leaf${i}`).digest('hex'));
    }
    const tree = new MerkleTree(leaves);
    for (let i = 0; i < 8; i++) {
      const proof = tree.proof(i);
      assert.ok(MerkleTree.verifyProof(leaves[i], proof, tree.root));
    }
  });

  it('proof tampered leaf fails', () => {
    const tree = new MerkleTree(['aaa', 'bbb', 'ccc', 'ddd']);
    const proof = tree.proof(0);
    assert.strictEqual(MerkleTree.verifyProof('TAMPERED', proof, tree.root), false);
  });

  it('empty leaves throws', () => {
    assert.throws(() => new MerkleTree([]), /no leaves/);
  });

  it('proof out of range throws', () => {
    const tree = new MerkleTree(['a', 'b']);
    assert.throws(() => tree.proof(2), RangeError);
    assert.throws(() => tree.proof(-1), RangeError);
  });

  it('five leaves odd', () => {
    const leaves = ['a', 'b', 'c', 'd', 'e'];
    const tree = new MerkleTree(leaves);
    for (let i = 0; i < 5; i++) {
      const proof = tree.proof(i);
      assert.ok(MerkleTree.verifyProof(leaves[i], proof, tree.root));
    }
  });

  it('single leaf proof empty', () => {
    const tree = new MerkleTree(['only']);
    const proof = tree.proof(0);
    assert.deepStrictEqual(proof, []);
    assert.ok(MerkleTree.verifyProof('only', proof, tree.root));
  });
});

// ── HKDF ───────────────────────────────────────────────────────

describe('HKDF', () => {
  it('derive produces 64-char hex', () => {
    const key = deriveEntityHashKey(Buffer.from('master'));
    assert.strictEqual(key.length, 64);
    assert.ok(/^[0-9a-f]{64}$/.test(key));
  });

  it('derive deterministic', () => {
    const k1 = deriveEntityHashKey(Buffer.from('same-key'));
    const k2 = deriveEntityHashKey(Buffer.from('same-key'));
    assert.strictEqual(k1, k2);
  });

  it('derive different salt different key', () => {
    const saltA = Buffer.alloc(32, 0);
    saltA.write('salt-a');
    const saltB = Buffer.alloc(32, 0);
    saltB.write('salt-b');
    const k1 = deriveEntityHashKey(Buffer.from('key'), saltA);
    const k2 = deriveEntityHashKey(Buffer.from('key'), saltB);
    assert.notStrictEqual(k1, k2);
  });

  it('derive different info different key', () => {
    const k1 = deriveEntityHashKey(Buffer.from('key'), null, 'info-a');
    const k2 = deriveEntityHashKey(Buffer.from('key'), null, 'info-b');
    assert.notStrictEqual(k1, k2);
  });

  it('derive known vector (cross-language)', () => {
    const result = deriveEntityHashKey(Buffer.from('test-master-key-1234567890abcdef'));
    assert.strictEqual(result, '2836bb676c8d77ebbf3c5101a6d25d674123ebd0eff8b4354060119bfd182e49');
  });
});

// ── Canonical JSON ─────────────────────────────────────────────

describe('Canonical JSON', () => {
  it('sorted keys', () => {
    const result = canonicalJson({ b: 2, a: 1 });
    assert.strictEqual(result, '{"a":1,"b":2}');
  });

  it('nested sorted keys', () => {
    const result = canonicalJson({ z: { b: 2, a: 1 } });
    assert.strictEqual(result, '{"z":{"a":1,"b":2}}');
  });

  it('compact separators', () => {
    const result = canonicalJson({ key: 'value' });
    assert.ok(!result.includes(' '));
  });

  it('integer not float', () => {
    const result = canonicalJson({ n: 3 });
    assert.strictEqual(result, '{"n":3}');
  });
});
