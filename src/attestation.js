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

/**
 * Deterministic JSON: recursively sorted keys, compact separators, no floats.
 * @param {Object} data
 * @returns {string}
 */
function canonicalJson(data) {
  return JSON.stringify(data, (_, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return Object.keys(v).sort().reduce((o, k) => { o[k] = v[k]; return o; }, {});
    }
    return v;
  });
}

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

module.exports = {
  DeploymentKeyPair,
  SanitizationCertificate,
  MerkleTree,
  deriveEntityHashKey,
  canonicalJson,
};
