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
} = require('./attestation');

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
};
