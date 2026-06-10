/**
 * Cryptographic Attestation Module.
 *
 * Ed25519 digital signatures for sanitization certificates.
 * Merkle trees for batch attestation. HKDF for key derivation.
 *
 * Uses only Node.js built-in `crypto` module — zero runtime dependencies.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// DER prefix constants for Ed25519 key encoding
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');   // 12 bytes
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex'); // 16 bytes

// --- Canonical JSON (must match Python exactly) ---

// --- Canonical JSON ---
// Delegated to ./_canonical for cross-SDK byte-equivalence (v0.6.1+).
// Pre-v0.6.1 the local replacer-based version produced different bytes than
// Python's `ensure_ascii=True` default; see `_canonical.js` for details.
const { canonicalJson } = require('./_canonical');

// --- DeploymentKeyPair ---

class DeploymentKeyPair {
  /**
   * @param {Buffer} privateKey - 32-byte raw Ed25519 private key
   * @param {Buffer} publicKey - 32-byte raw Ed25519 public key
   * @param {string} keyId - first 16 hex chars of SHA-256(publicKey)
   */
  constructor(privateKey, publicKey, keyId) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.keyId = keyId;
  }

  /**
   * Generate a new Ed25519 keypair.
   * @returns {DeploymentKeyPair}
   */
  static generate() {
    const { privateKey: privDer, publicKey: pubDer } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding: { type: 'spki', format: 'der' },
    });
    const privateKey = privDer.subarray(PKCS8_PREFIX.length);
    const publicKey = pubDer.subarray(SPKI_PREFIX.length);
    const keyId = crypto.createHash('sha256').update(publicKey).digest('hex').substring(0, 16);
    return new DeploymentKeyPair(privateKey, publicKey, keyId);
  }

  /**
   * Sign data with Ed25519. Returns 64-byte raw signature.
   * @param {Buffer|string} data
   * @returns {Buffer}
   */
  sign(data) {
    const derKey = Buffer.concat([PKCS8_PREFIX, this.privateKey]);
    const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' });
    return crypto.sign(null, Buffer.from(data), keyObj);
  }

  /**
   * Sign data and return base64-encoded signature.
   * @param {Buffer|string} data
   * @returns {string}
   */
  signB64(data) {
    return this.sign(data).toString('base64');
  }

  /**
   * Verify an Ed25519 signature. Returns true if valid.
   * @param {Buffer} publicKey - 32-byte raw public key
   * @param {Buffer|string} data
   * @param {Buffer} signature - 64-byte raw signature
   * @returns {boolean}
   */
  static verify(publicKey, data, signature) {
    try {
      const derKey = Buffer.concat([SPKI_PREFIX, publicKey]);
      const keyObj = crypto.createPublicKey({ key: derKey, format: 'der', type: 'spki' });
      return crypto.verify(null, Buffer.from(data), keyObj, signature);
    } catch {
      return false;
    }
  }

  /**
   * Verify a base64-encoded Ed25519 signature.
   * @param {Buffer} publicKey
   * @param {Buffer|string} data
   * @param {string} signatureB64
   * @returns {boolean}
   */
  static verifyB64(publicKey, data, signatureB64) {
    return DeploymentKeyPair.verify(publicKey, data, Buffer.from(signatureB64, 'base64'));
  }

  /**
   * Base64-encoded public key.
   * @returns {string}
   */
  get publicKeyB64() {
    return this.publicKey.toString('base64');
  }

  /**
   * Save keypair to JSON file.
   * @param {string} filePath
   */
  save(filePath) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const data = JSON.stringify({
      key_id: this.keyId,
      private_key: this.privateKey.toString('base64'),
      public_key: this.publicKey.toString('base64'),
    }, null, 2);
    try {
      fs.writeFileSync(filePath, data, { mode: 0o600 });
    } catch (err) {
      fs.writeFileSync(filePath, data);
      if (process.platform === 'win32') {
        console.warn(`CloakLLM: Cannot set restrictive file permissions on Windows for '${filePath}'.`);
      }
    }
  }

  /**
   * Load keypair from JSON file.
   * @param {string} filePath
   * @returns {DeploymentKeyPair}
   */
  static fromFile(filePath) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    return new DeploymentKeyPair(
      Buffer.from(data.private_key, 'base64'),
      Buffer.from(data.public_key, 'base64'),
      data.key_id,
    );
  }
}

// --- SanitizationCertificate ---

const SIGNED_FIELDS = [
  'version', 'timestamp', 'input_hash', 'output_hash',
  'entity_count', 'categories', 'detection_passes', 'mode', 'key_id', 'nonce',
];

class SanitizationCertificate {
  /**
   * @param {Object} fields
   */
  constructor(fields = {}) {
    this.version = fields.version ?? '1.0';
    this.timestamp = fields.timestamp ?? '';
    this.input_hash = fields.input_hash ?? '';
    this.output_hash = fields.output_hash ?? '';
    this.entity_count = fields.entity_count ?? 0;
    this.categories = fields.categories ?? {};
    this.detection_passes = fields.detection_passes ?? [];
    this.mode = fields.mode ?? 'tokenize';
    this.key_id = fields.key_id ?? '';
    this.nonce = fields.nonce ?? '';
    this.signature = fields.signature ?? '';
    this.public_key = fields.public_key ?? '';
  }

  /**
   * Extract only the fields that are signed.
   * @returns {Object}
   */
  _signedPayload() {
    const payload = {};
    for (const k of SIGNED_FIELDS) {
      payload[k] = this[k];
    }
    return payload;
  }

  /**
   * Return all fields as a dict.
   * @returns {Object}
   */
  toDict() {
    const d = this._signedPayload();
    d.signature = this.signature;
    d.public_key = this.public_key;
    d.nonce = this.nonce;
    return d;
  }

  /**
   * Create and sign a new certificate.
   * @param {Object} options
   * @param {string|null} options.originalText
   * @param {string|null} options.sanitizedText
   * @param {number} options.entityCount
   * @param {Object} options.categories
   * @param {string[]} options.detectionPasses
   * @param {string} options.mode
   * @param {DeploymentKeyPair} options.keypair
   * @param {string|null} [options.inputMerkleRoot]
   * @param {string|null} [options.outputMerkleRoot]
   * @returns {SanitizationCertificate}
   */
  static create({
    originalText = null,
    sanitizedText = null,
    entityCount,
    categories,
    detectionPasses,
    mode,
    keypair,
    inputMerkleRoot = null,
    outputMerkleRoot = null,
  }) {
    if (originalText == null && inputMerkleRoot == null) {
      throw new Error('Either originalText or inputMerkleRoot must be provided');
    }
    if (sanitizedText == null && outputMerkleRoot == null) {
      throw new Error('Either sanitizedText or outputMerkleRoot must be provided');
    }

    const inputHash = inputMerkleRoot ??
      crypto.createHash('sha256').update(originalText).digest('hex');
    const outputHash = outputMerkleRoot ??
      crypto.createHash('sha256').update(sanitizedText).digest('hex');

    const cert = new SanitizationCertificate({
      timestamp: new Date().toISOString(),
      input_hash: inputHash,
      output_hash: outputHash,
      entity_count: entityCount,
      categories: { ...categories },
      detection_passes: [...detectionPasses],
      mode,
      key_id: keypair.keyId,
      nonce: crypto.randomUUID(),
    });

    const payload = canonicalJson(cert._signedPayload());
    cert.signature = keypair.signB64(payload);
    cert.public_key = keypair.publicKeyB64;
    return cert;
  }

  /**
   * Verify this certificate's signature against a public key.
   * @param {Buffer} publicKey - 32-byte raw public key
   * @returns {boolean}
   */
  verify(publicKey) {
    const payload = canonicalJson(this._signedPayload());
    return DeploymentKeyPair.verifyB64(publicKey, payload, this.signature);
  }

  /**
   * Reconstruct a certificate from a dict (e.g., from JSON).
   * @param {Object} d
   * @returns {SanitizationCertificate}
   */
  static fromDict(d) {
    return new SanitizationCertificate({
      ...d,
      nonce: d.nonce ?? '',
    });
  }
}

// --- MerkleTree ---

/**
 * Binary Merkle tree for batch attestation.
 *
 * Builds a bottom-up SHA-256 hash tree from an array of leaf hashes.
 * When a level has an odd number of nodes, the last node is promoted
 * to the next level without hashing (odd-leaf promotion). This matches
 * the Python SDK implementation for cross-language compatibility.
 */
class MerkleTree {
  /**
   * @param {string[]} leaves - Array of hex hash strings
   */
  constructor(leaves) {
    if (!leaves || leaves.length === 0) {
      throw new Error('Cannot build Merkle tree with no leaves');
    }
    this._leaves = [...leaves];
    this._tree = [this._leaves];
    this._build();
  }

  /**
   * Hash two sibling nodes: SHA-256(left + right).
   * @param {string} left
   * @param {string} right
   * @returns {string}
   */
  static _hashPair(left, right) {
    return crypto.createHash('sha256').update(left + right).digest('hex');
  }

  /**
   * Build the tree bottom-up. Odd leaves are promoted.
   */
  _build() {
    let current = this._leaves;
    while (current.length > 1) {
      const nextLevel = [];
      for (let i = 0; i < current.length; i += 2) {
        if (i + 1 < current.length) {
          nextLevel.push(MerkleTree._hashPair(current[i], current[i + 1]));
        } else {
          nextLevel.push(current[i]); // odd leaf promoted
        }
      }
      this._tree.push(nextLevel);
      current = nextLevel;
    }
  }

  /**
   * Root hash of the Merkle tree.
   * @returns {string}
   */
  get root() {
    return this._tree[this._tree.length - 1][0];
  }

  /**
   * Generate a Merkle proof for the leaf at the given index.
   * @param {number} index
   * @returns {Array<[string, string]>} Array of [siblingHash, side] tuples
   */
  proof(index) {
    if (index < 0 || index >= this._leaves.length) {
      throw new RangeError(`Leaf index ${index} out of range`);
    }
    const proofPath = [];
    let idx = index;
    for (let level = 0; level < this._tree.length - 1; level++) {
      const nodes = this._tree[level];
      if (idx % 2 === 0) {
        if (idx + 1 < nodes.length) {
          proofPath.push([nodes[idx + 1], 'right']);
        }
      } else {
        proofPath.push([nodes[idx - 1], 'left']);
      }
      idx = Math.floor(idx / 2);
    }
    return proofPath;
  }

  /**
   * Verify a Merkle proof against a root hash.
   * @param {string} leafHash
   * @param {Array<[string, string]>} proof
   * @param {string} root
   * @returns {boolean}
   */
  static verifyProof(leafHash, proof, root) {
    let current = leafHash;
    for (const [siblingHash, side] of proof) {
      if (side === 'left') {
        current = MerkleTree._hashPair(siblingHash, current);
      } else {
        current = MerkleTree._hashPair(current, siblingHash);
      }
    }
    return current === root;
  }
}

// --- HKDF Key Derivation ---

/**
 * Derive an entity hash key from a master key using HKDF-SHA256.
 * Uses Node.js built-in crypto.hkdfSync.
 *
 * @param {Buffer|string} masterKey - Raw key material
 * @param {Buffer} [salt] - Optional salt (defaults to 32 zero bytes)
 * @param {Buffer|string} [info] - Context info (defaults to "cloakllm-entity-hash")
 * @returns {string} 64-char hex string (32 bytes)
 */
function deriveEntityHashKey(masterKey, salt = null, info = 'cloakllm-entity-hash') {
  if (!salt) {
    salt = Buffer.alloc(32, 0);
  }
  const derived = crypto.hkdfSync('sha256', masterKey, salt, info, 32);
  return Buffer.from(derived).toString('hex');
}

// ===================================================================
// v0.8.1 KM-1: KeyManifest -- externally-verifiable key provenance
// ===================================================================
//
// Mirror of cloakllm-py/cloakllm/attestation.py KeyManifest. Cross-SDK
// invariant: Python-generated manifests verify in JS and vice versa.
// See PLAN_v081.md + COMPLIANCE.md "Externally-Verifiable Key Provenance"
// for the threat model and explicit boundary callouts.

const KEY_MANIFEST_SCHEMA_VERSION = '1.0';
const _KEY_MANIFEST_PURPOSE_WHITELIST = new Set(['cloakllm-audit-attestation']);
const _KEY_MANIFEST_DEPLOYER_ID_MAX = 256;
const _KEY_MANIFEST_ROOT_KEY_ID_MAX = 256;

const _MANIFEST_HASH_FIELDS = [
  'key_id', 'public_key', 'deployer_id',
  'valid_from', 'valid_until', 'purpose',
  'manifest_version', 'root_key_id',
];

function _validateIso8601Utc(value, fieldName) {
  // v0.8.1 AUDIT-3 hardening from day 1: defensive parsing at the boundary.
  if (typeof value !== 'string' || value.length === 0) {
    throw new RangeError(`${fieldName} must be a non-empty ISO 8601 string`);
  }
  if (!(value.endsWith('+00:00') || value.endsWith('Z'))) {
    throw new RangeError(
      `${fieldName} must be UTC (end with '+00:00' or 'Z'); got '${value}'`
    );
  }
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    throw new RangeError(`${fieldName} is not a valid ISO 8601 timestamp: '${value}'`);
  }
}

/**
 * v0.8.1 externally-verifiable binding of a signing key to a deployer
 * identity and validity window.
 *
 * Mirror of the Python KeyManifest dataclass. Frozen via Object.freeze
 * to match the dataclass(frozen=True) semantics.
 */
class KeyManifest {
  constructor(fields) {
    this.key_id = fields.key_id;
    this.public_key = fields.public_key;
    this.deployer_id = fields.deployer_id;
    this.valid_from = fields.valid_from;
    this.valid_until = fields.valid_until;
    this.purpose = fields.purpose;
    this.manifest_version = fields.manifest_version;
    this.manifest_hash = fields.manifest_hash;
    this.root_signature = fields.root_signature !== undefined ? fields.root_signature : null;
    this.root_key_id = fields.root_key_id !== undefined ? fields.root_key_id : null;
    Object.freeze(this);
  }

  /**
   * Return all fields as a plain object for JSON serialization.
   * Field order matches Python KeyManifest.to_dict for cross-SDK byte parity.
   * @returns {Object}
   */
  toDict() {
    return {
      key_id: this.key_id,
      public_key: this.public_key,
      deployer_id: this.deployer_id,
      valid_from: this.valid_from,
      valid_until: this.valid_until,
      purpose: this.purpose,
      manifest_version: this.manifest_version,
      manifest_hash: this.manifest_hash,
      root_signature: this.root_signature,
      root_key_id: this.root_key_id,
    };
  }

  /**
   * Reconstruct a KeyManifest from a dict (e.g. from JSON.parse).
   * Does NOT re-validate field semantics or recompute manifest_hash --
   * use verifyKeyProvenance() to check integrity.
   * @param {Object} d
   * @returns {KeyManifest}
   */
  static fromDict(d) {
    if (d === null || typeof d !== 'object' || Array.isArray(d)) {
      throw new TypeError('KeyManifest.fromDict expects a plain object');
    }
    return new KeyManifest({
      key_id: String(d.key_id || ''),
      public_key: String(d.public_key || ''),
      deployer_id: String(d.deployer_id || ''),
      valid_from: String(d.valid_from || ''),
      valid_until: d.valid_until == null ? null : d.valid_until,
      purpose: String(d.purpose || ''),
      manifest_version: String(d.manifest_version || KEY_MANIFEST_SCHEMA_VERSION),
      manifest_hash: String(d.manifest_hash || ''),
      root_signature: d.root_signature == null ? null : d.root_signature,
      root_key_id: d.root_key_id == null ? null : d.root_key_id,
    });
  }
}

function _computeManifestHash(fields) {
  const payload = {
    key_id: fields.key_id,
    public_key: fields.public_key,
    deployer_id: fields.deployer_id,
    valid_from: fields.valid_from,
    valid_until: fields.valid_until,
    purpose: fields.purpose,
    manifest_version: fields.manifest_version,
    root_key_id: fields.root_key_id,
  };
  return crypto.createHash('sha256')
    .update(canonicalJson(payload), 'utf-8')
    .digest('hex');
}

/**
 * Produce a KeyManifest binding `keypair` to `deployerId`.
 *
 * If `rootSigningCallback` is provided, the manifest_hash bytes are handed
 * to the callback (typically an HSM call or an offline ceremony script)
 * which returns a 64-byte Ed25519 signature. CloakLLM runtime NEVER holds
 * the root key -- the callback is the trust boundary.
 *
 * @param {DeploymentKeyPair} keypair
 * @param {Object} opts
 * @param {string} opts.deployerId             Required, 1..256 chars.
 * @param {string} [opts.validFrom]            ISO 8601 UTC. Default: now.
 * @param {string|null} [opts.validUntil]      ISO 8601 UTC or null.
 * @param {string} [opts.purpose]              Must be 'cloakllm-audit-attestation'.
 * @param {Function} [opts.rootSigningCallback]   (Buffer) => Buffer (64-byte sig).
 * @param {string} [opts.rootKeyId]            Required iff rootSigningCallback is set.
 * @returns {KeyManifest}
 */
function deriveKeyManifest(keypair, opts) {
  if (!opts || typeof opts.deployerId !== 'string' || opts.deployerId.length === 0) {
    throw new RangeError('deployerId must be a non-empty string');
  }
  if (opts.deployerId.length > _KEY_MANIFEST_DEPLOYER_ID_MAX) {
    throw new RangeError(
      `deployerId must be <= ${_KEY_MANIFEST_DEPLOYER_ID_MAX} chars `
      + `(got ${opts.deployerId.length})`
    );
  }
  if (opts.deployerId.includes('\x00')) {
    throw new RangeError('deployerId must not contain NUL bytes');
  }

  const purpose = opts.purpose || 'cloakllm-audit-attestation';
  if (!_KEY_MANIFEST_PURPOSE_WHITELIST.has(purpose)) {
    throw new RangeError(
      `purpose must be one of [${[..._KEY_MANIFEST_PURPOSE_WHITELIST].sort().map(p => `'${p}'`).join(',')}]; `
      + `got '${purpose}'`
    );
  }

  let validFrom = opts.validFrom;
  if (validFrom == null) {
    // Match Python isoformat() with +00:00 suffix.
    validFrom = new Date().toISOString().replace('Z', '+00:00');
  }
  _validateIso8601Utc(validFrom, 'validFrom');

  const validUntil = opts.validUntil == null ? null : opts.validUntil;
  if (validUntil !== null) {
    _validateIso8601Utc(validUntil, 'validUntil');
    if (validUntil < validFrom) {
      throw new RangeError(
        `validUntil (${validUntil}) must be >= validFrom (${validFrom})`
      );
    }
  }

  const rootSigningCallback = opts.rootSigningCallback || null;
  const rootKeyId = opts.rootKeyId == null ? null : opts.rootKeyId;

  if (rootSigningCallback !== null && typeof rootKeyId !== 'string') {
    throw new RangeError(
      'rootKeyId is required when rootSigningCallback is provided '
      + '(auditors need it to look up the root public key)'
    );
  }
  if (rootKeyId !== null) {
    if (typeof rootKeyId !== 'string' || rootKeyId.length === 0) {
      throw new RangeError('rootKeyId must be a non-empty string');
    }
    if (rootKeyId.length > _KEY_MANIFEST_ROOT_KEY_ID_MAX) {
      throw new RangeError(
        `rootKeyId must be <= ${_KEY_MANIFEST_ROOT_KEY_ID_MAX} chars`
      );
    }
    if (rootKeyId.includes('\x00')) {
      throw new RangeError('rootKeyId must not contain NUL bytes');
    }
  }

  const manifestHash = _computeManifestHash({
    key_id: keypair.keyId,
    public_key: keypair.publicKeyB64,
    deployer_id: opts.deployerId,
    valid_from: validFrom,
    valid_until: validUntil,
    purpose,
    manifest_version: KEY_MANIFEST_SCHEMA_VERSION,
    root_key_id: rootKeyId,
  });

  let rootSignature = null;
  if (rootSigningCallback !== null) {
    const sigBuf = rootSigningCallback(Buffer.from(manifestHash, 'ascii'));
    if (!Buffer.isBuffer(sigBuf) || sigBuf.length !== 64) {
      throw new RangeError(
        `rootSigningCallback must return a 64-byte Buffer (raw Ed25519 signature); `
        + `got length ${sigBuf && sigBuf.length}`
      );
    }
    rootSignature = sigBuf.toString('base64');
  }

  return new KeyManifest({
    key_id: keypair.keyId,
    public_key: keypair.publicKeyB64,
    deployer_id: opts.deployerId,
    valid_from: validFrom,
    valid_until: validUntil,
    purpose,
    manifest_version: KEY_MANIFEST_SCHEMA_VERSION,
    manifest_hash: manifestHash,
    root_signature: rootSignature,
    root_key_id: rootKeyId,
  });
}

// ===================================================================
// v0.8.1 KM-2: verifyKeyProvenance + ProvenanceReport
// ===================================================================
//
// Mirror of cloakllm-py KM-2. ProvenanceReport JSON shape is identical
// across SDKs so KM-9 aggregator (compliance_report) produces byte-equal
// output in both languages.

const ROOT_SIG_VALID = 'VALID';
const ROOT_SIG_INVALID = 'INVALID';
const ROOT_SIG_NOT_REQUESTED = 'NOT_REQUESTED';
const ROOT_SIG_UNVERIFIED_NO_KEY = 'UNVERIFIED_NO_KEY';

const PROVENANCE_VERIFIED = 'VERIFIED';
const PROVENANCE_FAILED = 'FAILED';
const PROVENANCE_UNVERIFIED = 'UNVERIFIED';

/**
 * v0.8.1 KM-2: structured ProvenanceReport.
 *
 * Auditors cite individual fields, not a single bool. KM-9 aggregates
 * these into compliance_report.attestation.provenance_summary.
 */
class ProvenanceReport {
  constructor(fields) {
    this.overall_valid = fields.overall_valid;
    this.provenance_status = fields.provenance_status;
    this.signature_valid = fields.signature_valid;
    this.key_id_matches = fields.key_id_matches;
    this.within_validity_window = fields.within_validity_window;
    this.root_signature_status = fields.root_signature_status;
    this.manifest_hash_consistent = fields.manifest_hash_consistent;
    this.checked_at = fields.checked_at;
    this.notes = Array.isArray(fields.notes) ? fields.notes : [];
    // v0.9.0 RV-2 (additive; defaults preserve pre-v0.9.0 construction sites)
    this.revocation_status = fields.revocation_status !== undefined
      ? fields.revocation_status : 'NOT_CHECKED';
    Object.freeze(this);
  }

  toDict() {
    return {
      overall_valid: this.overall_valid,
      provenance_status: this.provenance_status,
      signature_valid: this.signature_valid,
      key_id_matches: this.key_id_matches,
      within_validity_window: this.within_validity_window,
      root_signature_status: this.root_signature_status,
      manifest_hash_consistent: this.manifest_hash_consistent,
      checked_at: this.checked_at,
      notes: Array.from(this.notes),
      revocation_status: this.revocation_status,
    };
  }
}

function _parseIso8601Safe(value) {
  // Defensive parse: returns null for any non-string or unparseable value.
  if (typeof value !== 'string' || value.length === 0) return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

/**
 * v0.8.1 KM-2: verify a certificate's signature AND the key's provenance.
 *
 * @param {SanitizationCertificate} certificate
 * @param {KeyManifest|null} manifest                Null -> backward-compat mode.
 * @param {Object} [opts]
 * @param {Buffer} [opts.rootPublicKey]              32-byte raw Ed25519 root public key.
 * @param {string} [opts.now]                        ISO 8601 UTC. Default: now.
 * @param {number} [opts.clockSkewSeconds=0]         Default: strict zero tolerance.
 * @returns {ProvenanceReport}
 */
function verifyKeyProvenance(certificate, manifest, opts) {
  opts = opts || {};
  const rootPublicKey = opts.rootPublicKey || null;
  const clockSkewSeconds = Number.isFinite(opts.clockSkewSeconds) ? opts.clockSkewSeconds : 0;
  const checkedAt = opts.now != null ? opts.now : new Date().toISOString().replace('Z', '+00:00');
  const revocationList = opts.revocationList || null;  // v0.9.0 RV-2
  const notes = [];

  // --- Check 1: signature_valid ---
  // JS SanitizationCertificate uses snake_case fields (cert.public_key,
  // cert.key_id) to match the wire JSON shape -- mirrors Py.
  let signatureValid = false;
  try {
    const pkBytes = manifest !== null
      ? Buffer.from(manifest.public_key, 'base64')
      : (certificate.public_key
          ? Buffer.from(certificate.public_key, 'base64')
          : Buffer.alloc(0));
    if (pkBytes.length > 0) {
      signatureValid = certificate.verify(pkBytes);
    }
  } catch (e) {
    notes.push(`signature check raised: ${e.name}: ${e.message}`);
    signatureValid = false;
  }

  // --- Backward-compat short-circuit ---
  if (manifest === null) {
    notes.push('manifest=null: signature-only check (UNVERIFIED provenance)');
    // v0.9.0 RV-2: revocation runs standalone even without a manifest --
    // a revoked key is a revoked key regardless of provenance status.
    const revocationStatus = _checkRevocation(
      certificate, null, revocationList, rootPublicKey, notes,
    );
    const revOk = revocationStatus !== 'REVOKED' && revocationStatus !== 'LIST_INVALID';
    return new ProvenanceReport({
      overall_valid: signatureValid && revOk,
      provenance_status: PROVENANCE_UNVERIFIED,
      signature_valid: signatureValid,
      key_id_matches: null,
      within_validity_window: null,
      root_signature_status: ROOT_SIG_NOT_REQUESTED,
      manifest_hash_consistent: null,
      checked_at: checkedAt,
      notes,
      revocation_status: revocationStatus,
    });
  }

  // --- Check 2: key_id_matches ---
  const keyIdMatches = certificate.key_id === manifest.key_id;
  if (!keyIdMatches) {
    notes.push(
      `key_id mismatch: cert.key_id='${certificate.key_id}' != manifest.key_id='${manifest.key_id}'`
    );
  }

  // --- Check 3: within_validity_window ---
  const certTs = _parseIso8601Safe(certificate.timestamp);
  const validFromTs = _parseIso8601Safe(manifest.valid_from);
  const validUntilTs = _parseIso8601Safe(manifest.valid_until);
  let withinValidityWindow;
  if (certTs === null || validFromTs === null) {
    withinValidityWindow = false;
    notes.push(
      `cannot compare timestamps: cert.timestamp='${certificate.timestamp}', `
      + `manifest.valid_from='${manifest.valid_from}'`
    );
  } else {
    const skewMs = clockSkewSeconds * 1000;
    const lowerMs = validFromTs.getTime() - skewMs;
    const certMs = certTs.getTime();
    if (validUntilTs === null) {
      withinValidityWindow = certMs >= lowerMs;
    } else {
      const upperMs = validUntilTs.getTime() + skewMs;
      withinValidityWindow = certMs >= lowerMs && certMs <= upperMs;
    }
    if (!withinValidityWindow) {
      if (validUntilTs !== null && certMs > validUntilTs.getTime() + skewMs) {
        notes.push(`key expired: cert.timestamp=${certificate.timestamp} > valid_until=${manifest.valid_until}`);
      } else if (certMs < validFromTs.getTime() - skewMs) {
        notes.push(`cert before key validity: cert.timestamp=${certificate.timestamp} < valid_from=${manifest.valid_from}`);
      }
    }
  }

  // --- Check 5: manifest_hash_consistent ---
  const expectedHash = _computeManifestHash({
    key_id: manifest.key_id,
    public_key: manifest.public_key,
    deployer_id: manifest.deployer_id,
    valid_from: manifest.valid_from,
    valid_until: manifest.valid_until,
    purpose: manifest.purpose,
    manifest_version: manifest.manifest_version,
    root_key_id: manifest.root_key_id,
  });
  const manifestHashConsistent = expectedHash === manifest.manifest_hash;
  if (!manifestHashConsistent) {
    notes.push('manifest_hash mismatch: manifest fields have been tampered with');
  }

  // --- Check 4: root_signature_status ---
  let rootSignatureStatus;
  if (manifest.root_signature === null || manifest.root_signature === undefined) {
    rootSignatureStatus = ROOT_SIG_NOT_REQUESTED;
    notes.push('no root_signature on manifest (self-published, not load-bearing)');
  } else if (rootPublicKey === null) {
    rootSignatureStatus = ROOT_SIG_UNVERIFIED_NO_KEY;
    notes.push(
      `manifest has root_signature but caller did not supply rootPublicKey `
      + `(root_key_id='${manifest.root_key_id}')`
    );
  } else {
    try {
      const sigBuf = Buffer.from(manifest.root_signature, 'base64');
      const valid = DeploymentKeyPair.verify(
        rootPublicKey,
        Buffer.from(manifest.manifest_hash, 'ascii'),
        sigBuf,
      );
      rootSignatureStatus = valid ? ROOT_SIG_VALID : ROOT_SIG_INVALID;
      if (!valid) {
        notes.push(
          `root_signature INVALID: claimed signer root_key_id='${manifest.root_key_id}' `
          + 'but signature does not verify'
        );
      }
    } catch (e) {
      rootSignatureStatus = ROOT_SIG_INVALID;
      notes.push(`root_signature parse/verify raised: ${e.name}: ${e.message}`);
    }
  }

  // --- Check 6 (v0.9.0 RV-2): revocation ---
  const revocationStatus = _checkRevocation(
    certificate, manifest, revocationList, rootPublicKey, notes,
  );

  // --- overall_valid ---
  const requiredChecks = [signatureValid, keyIdMatches, withinValidityWindow, manifestHashConsistent];
  if (manifest.root_signature !== null && manifest.root_signature !== undefined
      && rootPublicKey !== null) {
    requiredChecks.push(rootSignatureStatus === ROOT_SIG_VALID);
  }
  // v0.9.0: REVOKED and LIST_INVALID fail; NOT_CHECKED / NOT_REVOKED /
  // REVOKED_BUT_CERT_PREDATES do not (the last per X.509/OCSP semantics).
  if (revocationList !== null) {
    requiredChecks.push(
      revocationStatus !== 'REVOKED' && revocationStatus !== 'LIST_INVALID'
    );
  }
  const overallValid = requiredChecks.every(Boolean);

  return new ProvenanceReport({
    overall_valid: overallValid,
    provenance_status: overallValid ? PROVENANCE_VERIFIED : PROVENANCE_FAILED,
    signature_valid: signatureValid,
    key_id_matches: keyIdMatches,
    within_validity_window: withinValidityWindow,
    root_signature_status: rootSignatureStatus,
    manifest_hash_consistent: manifestHashConsistent,
    checked_at: checkedAt,
    notes,
    revocation_status: revocationStatus,
  });
}

// ===================================================================
// v0.9.0 RV-1: RevocationList -- root-signed key revocation
// ===================================================================
//
// Mirror of cloakllm-py RV-1. OUT-OF-BAND artifact (PLAN_v090.md Design
// Decision 1): a compromised runtime controls the audit chain, so the
// revocation list lives outside the attacker's write path -- published
// by the deployer, root-signed, handed to the auditor out-of-band.
// Inline key_revoked audit events are advisory only.

const REVOCATION_LIST_SCHEMA_VERSION = '1.0';
const _REVOCATION_REASON_WHITELIST = new Set([
  'compromised', 'superseded', 'ceased_operation', 'unspecified',
]);
const _REVOCATION_MAX_ENTRIES = 4096;

// Revocation status values (cross-SDK enum)
const REVOCATION_NOT_REVOKED = 'NOT_REVOKED';
const REVOCATION_REVOKED = 'REVOKED';
const REVOCATION_REVOKED_BUT_CERT_PREDATES = 'REVOKED_BUT_CERT_PREDATES';
const REVOCATION_NOT_CHECKED = 'NOT_CHECKED';
const REVOCATION_LIST_INVALID = 'LIST_INVALID';

class RevocationEntry {
  constructor({ key_id, revoked_at, reason }) {
    this.key_id = key_id;
    this.revoked_at = revoked_at;
    this.reason = reason;
    Object.freeze(this);
  }
  toDict() {
    return { key_id: this.key_id, revoked_at: this.revoked_at, reason: this.reason };
  }
}

class RevocationList {
  constructor(fields) {
    this.deployer_id = fields.deployer_id;
    this.entries = Object.freeze(Array.from(fields.entries || []));
    this.issued_at = fields.issued_at;
    this.list_version = fields.list_version;
    this.list_hash = fields.list_hash;
    this.root_signature = fields.root_signature !== undefined ? fields.root_signature : null;
    this.root_key_id = fields.root_key_id !== undefined ? fields.root_key_id : null;
    Object.freeze(this);
  }

  toDict() {
    return {
      deployer_id: this.deployer_id,
      entries: this.entries.map(e => e.toDict()),
      issued_at: this.issued_at,
      list_version: this.list_version,
      list_hash: this.list_hash,
      root_signature: this.root_signature,
      root_key_id: this.root_key_id,
    };
  }

  static fromDict(d) {
    if (d === null || typeof d !== 'object' || Array.isArray(d)) {
      throw new TypeError('RevocationList.fromDict expects a plain object');
    }
    const entries = [];
    if (Array.isArray(d.entries)) {
      for (const item of d.entries) {
        if (item && typeof item === 'object' && !Array.isArray(item)) {
          entries.push(new RevocationEntry({
            key_id: String(item.key_id || ''),
            revoked_at: String(item.revoked_at || ''),
            reason: String(item.reason || ''),
          }));
        }
      }
    }
    return new RevocationList({
      deployer_id: String(d.deployer_id || ''),
      entries,
      issued_at: String(d.issued_at || ''),
      list_version: String(d.list_version || REVOCATION_LIST_SCHEMA_VERSION),
      list_hash: String(d.list_hash || ''),
      root_signature: d.root_signature == null ? null : d.root_signature,
      root_key_id: d.root_key_id == null ? null : d.root_key_id,
    });
  }

  /** Earliest revoked_at wins if a key is (incorrectly) listed twice. */
  findEntry(keyId) {
    let found = null;
    for (const e of this.entries) {
      if (e.key_id === keyId) {
        if (found === null || e.revoked_at < found.revoked_at) found = e;
      }
    }
    return found;
  }
}

function _computeRevocationListHash(fields) {
  const payload = {
    deployer_id: fields.deployer_id,
    entries: fields.entries,  // array of {key_id, revoked_at, reason}
    issued_at: fields.issued_at,
    list_version: fields.list_version,
    root_key_id: fields.root_key_id,
  };
  return crypto.createHash('sha256')
    .update(canonicalJson(payload), 'utf-8')
    .digest('hex');
}

/**
 * v0.9.0 RV-1: produce a RevocationList. Empty list is valid (a signed,
 * dated "nothing revoked" claim). Same root-signing ceremony contract
 * as deriveKeyManifest.
 */
function deriveRevocationList({
  deployerId,
  entries,
  issuedAt = null,
  rootSigningCallback = null,
  rootKeyId = null,
}) {
  if (typeof deployerId !== 'string' || deployerId.length === 0) {
    throw new RangeError('deployerId must be a non-empty string');
  }
  if (deployerId.length > _KEY_MANIFEST_DEPLOYER_ID_MAX) {
    throw new RangeError(`deployerId must be <= ${_KEY_MANIFEST_DEPLOYER_ID_MAX} chars`);
  }
  if (deployerId.includes('\x00')) {
    throw new RangeError('deployerId must not contain NUL bytes');
  }

  if (issuedAt == null) {
    issuedAt = new Date().toISOString().replace('Z', '+00:00');
  }
  _validateIso8601Utc(issuedAt, 'issuedAt');

  if (!Array.isArray(entries)) {
    throw new RangeError('entries must be an array');
  }
  if (entries.length > _REVOCATION_MAX_ENTRIES) {
    throw new RangeError(`entries exceeds ${_REVOCATION_MAX_ENTRIES} cap`);
  }
  const normalized = [];
  const seenKeyIds = new Set();
  entries.forEach((item, i) => {
    let entry;
    if (item instanceof RevocationEntry) {
      entry = item;
    } else if (item && typeof item === 'object' && !Array.isArray(item)) {
      entry = new RevocationEntry({
        key_id: item.key_id, revoked_at: item.revoked_at, reason: item.reason,
      });
    } else {
      throw new RangeError(`entries[${i}] must be RevocationEntry or object`);
    }
    if (typeof entry.key_id !== 'string' || entry.key_id.length === 0) {
      throw new RangeError(`entries[${i}].key_id must be a non-empty string`);
    }
    if (entry.key_id.length > 64 || entry.key_id.includes('\x00')) {
      throw new RangeError(`entries[${i}].key_id invalid (cap 64, no NUL)`);
    }
    if (seenKeyIds.has(entry.key_id)) {
      throw new RangeError(
        `entries[${i}].key_id '${entry.key_id}' is duplicated. One entry per `
        + 'key; revocation is permanent (rotate instead of re-revoking).'
      );
    }
    seenKeyIds.add(entry.key_id);
    _validateIso8601Utc(entry.revoked_at, `entries[${i}].revoked_at`);
    if (!_REVOCATION_REASON_WHITELIST.has(entry.reason)) {
      throw new RangeError(
        `entries[${i}].reason must be one of `
        + `[${[..._REVOCATION_REASON_WHITELIST].sort().join(', ')}]; got '${entry.reason}'`
      );
    }
    normalized.push(entry);
  });

  if (rootSigningCallback !== null && typeof rootKeyId !== 'string') {
    throw new RangeError('rootKeyId is required when rootSigningCallback is provided');
  }
  if (rootKeyId !== null) {
    if (typeof rootKeyId !== 'string' || rootKeyId.length === 0
        || rootKeyId.length > _KEY_MANIFEST_ROOT_KEY_ID_MAX
        || rootKeyId.includes('\x00')) {
      throw new RangeError('rootKeyId invalid (non-empty, cap 256, no NUL)');
    }
  }

  const listHash = _computeRevocationListHash({
    deployer_id: deployerId,
    entries: normalized.map(e => e.toDict()),
    issued_at: issuedAt,
    list_version: REVOCATION_LIST_SCHEMA_VERSION,
    root_key_id: rootKeyId,
  });

  let rootSignature = null;
  if (rootSigningCallback !== null) {
    const sigBuf = rootSigningCallback(Buffer.from(listHash, 'ascii'));
    if (!Buffer.isBuffer(sigBuf) || sigBuf.length !== 64) {
      throw new RangeError('rootSigningCallback must return a 64-byte Buffer');
    }
    rootSignature = sigBuf.toString('base64');
  }

  return new RevocationList({
    deployer_id: deployerId,
    entries: normalized,
    issued_at: issuedAt,
    list_version: REVOCATION_LIST_SCHEMA_VERSION,
    list_hash: listHash,
    root_signature: rootSignature,
    root_key_id: rootKeyId,
  });
}

/**
 * v0.9.0 RV-2: compute revocation_status (check #6). Integrity-first:
 * tampered/mismatched list -> LIST_INVALID (worse than no list).
 * Mirror of cloakllm-py _check_revocation.
 */
function _checkRevocation(certificate, manifest, revocationList, rootPublicKey, notes) {
  if (revocationList == null) return REVOCATION_NOT_CHECKED;

  const expected = _computeRevocationListHash({
    deployer_id: revocationList.deployer_id,
    entries: revocationList.entries.map(e => e.toDict()),
    issued_at: revocationList.issued_at,
    list_version: revocationList.list_version,
    root_key_id: revocationList.root_key_id,
  });
  if (expected !== revocationList.list_hash) {
    notes.push('revocation list_hash mismatch: list has been tampered with');
    return REVOCATION_LIST_INVALID;
  }

  if (manifest !== null && revocationList.deployer_id !== manifest.deployer_id) {
    notes.push(
      `revocation list deployer_id '${revocationList.deployer_id}' does not `
      + `match manifest deployer_id '${manifest.deployer_id}'`
    );
    return REVOCATION_LIST_INVALID;
  }

  if (revocationList.root_signature !== null && rootPublicKey != null) {
    let ok = false;
    try {
      ok = DeploymentKeyPair.verify(
        rootPublicKey,
        Buffer.from(revocationList.list_hash, 'ascii'),
        Buffer.from(revocationList.root_signature, 'base64'),
      );
    } catch (e) {
      notes.push(`revocation list root_signature parse raised: ${e.name}`);
    }
    if (!ok) {
      notes.push('revocation list root_signature INVALID');
      return REVOCATION_LIST_INVALID;
    }
  }

  const entry = revocationList.findEntry(certificate.key_id);
  if (entry === null) return REVOCATION_NOT_REVOKED;

  const certTs = _parseIso8601Safe(certificate.timestamp);
  const revokedTs = _parseIso8601Safe(entry.revoked_at);
  if (certTs === null || revokedTs === null) {
    notes.push(
      `key ${entry.key_id} is revoked and timestamps are unparseable; `
      + 'treating cert as post-revocation (conservative)'
    );
    return REVOCATION_REVOKED;
  }
  if (certTs.getTime() >= revokedTs.getTime()) {
    notes.push(
      `key ${entry.key_id} revoked at ${entry.revoked_at} `
      + `(reason: ${entry.reason}); cert signed at ${certificate.timestamp}`
    );
    return REVOCATION_REVOKED;
  }
  notes.push(
    `key ${entry.key_id} was revoked at ${entry.revoked_at} but this cert `
    + `predates revocation (${certificate.timestamp}); cert remains valid`
  );
  return REVOCATION_REVOKED_BUT_CERT_PREDATES;
}

module.exports = {
  DeploymentKeyPair,
  SanitizationCertificate,
  MerkleTree,
  deriveEntityHashKey,
  canonicalJson,
  // v0.8.1 KM-1
  KeyManifest,
  deriveKeyManifest,
  KEY_MANIFEST_SCHEMA_VERSION,
  // v0.8.1 KM-2
  ProvenanceReport,
  verifyKeyProvenance,
  ROOT_SIG_VALID,
  ROOT_SIG_INVALID,
  ROOT_SIG_NOT_REQUESTED,
  ROOT_SIG_UNVERIFIED_NO_KEY,
  PROVENANCE_VERIFIED,
  PROVENANCE_FAILED,
  PROVENANCE_UNVERIFIED,
  // v0.9.0 RV-1 / RV-2
  RevocationEntry,
  RevocationList,
  deriveRevocationList,
  REVOCATION_LIST_SCHEMA_VERSION,
  REVOCATION_NOT_REVOKED,
  REVOCATION_REVOKED,
  REVOCATION_REVOKED_BUT_CERT_PREDATES,
  REVOCATION_NOT_CHECKED,
  REVOCATION_LIST_INVALID,
};
