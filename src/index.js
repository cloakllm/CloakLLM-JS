/**
 * CloakLLM — AI Compliance Middleware for Node.js
 * PII protection, tamper-evident audit logs, and EU AI Act compliance.
 *
 * With OpenAI SDK:
 *   const cloakllm = require('cloakllm');
 *   const OpenAI = require('openai');
 *   const client = new OpenAI();
 *   cloakllm.enable(client);  // All calls are now cloaked
 *
 * Standalone:
 *   const { Shield } = require('cloakllm');
 *   const shield = new Shield();
 *   const [sanitized, tokenMap] = shield.sanitize("Send to john@acme.com");
 */

const { Shield } = require('./shield');
const { ShieldConfig } = require('./config');
const { TokenMap, Tokenizer } = require('./tokenizer');
const { DetectionEngine } = require('./detector');
const { isNerAvailable } = require('./ner-detector');
const { AuditLogger } = require('./audit');
const { StreamDesanitizer } = require('./stream');
const { enable, disable, getShield, isEnabled } = require('./middleware');
const { createCloakLLMMiddleware } = require('./vercel-middleware');
const {
  DeploymentKeyPair,
  SanitizationCertificate,
  MerkleTree,
  deriveEntityHashKey,
  // v0.8.1 KM-1
  KeyManifest,
  deriveKeyManifest,
  KEY_MANIFEST_SCHEMA_VERSION,
  // v0.8.1 KM-2
  ProvenanceReport,
  verifyKeyProvenance,
} = require('./attestation');
const {
  validateToken,
  parseToken,
  validateCategoryName,
  isRedactedToken,
  BUILTIN_CATEGORIES,
  SPECIAL_CATEGORY_CATEGORIES,
  CLOAKLLM_TOKEN_PATTERN,
  MAX_TOKEN_LENGTH,
} = require('./token-spec');
const {
  DetectorBackend,
  RegexBackend,
  NerBackend,
  LlmBackend,
} = require('./backends');
const {
  BiasDetectionSession,
  BiasDetectionError,
  BiasDetectionScopeError,
  BiasDetectionTimeoutError,
  BiasDetectionStateError,
} = require('./bias-detection');

module.exports = {
  Shield,
  ShieldConfig,
  TokenMap,
  Tokenizer,
  DetectionEngine,
  isNerAvailable,
  AuditLogger,
  StreamDesanitizer,
  enable,
  disable,
  getShield,
  isEnabled,
  createCloakLLMMiddleware,
  DeploymentKeyPair,
  SanitizationCertificate,
  MerkleTree,
  deriveEntityHashKey,
  validateToken,
  parseToken,
  validateCategoryName,
  isRedactedToken,
  BUILTIN_CATEGORIES,
  SPECIAL_CATEGORY_CATEGORIES,
  CLOAKLLM_TOKEN_PATTERN,
  MAX_TOKEN_LENGTH,
  DetectorBackend,
  RegexBackend,
  NerBackend,
  LlmBackend,
  // v0.7.0 A4a — Article 4a bias-detection workflow
  BiasDetectionSession,
  BiasDetectionError,
  BiasDetectionScopeError,
  BiasDetectionTimeoutError,
  BiasDetectionStateError,
  // v0.8.1 KM-1 — externally-verifiable key provenance
  KeyManifest,
  deriveKeyManifest,
  KEY_MANIFEST_SCHEMA_VERSION,
  // v0.8.1 KM-2 — verifyKeyProvenance + ProvenanceReport
  ProvenanceReport,
  verifyKeyProvenance,
};
