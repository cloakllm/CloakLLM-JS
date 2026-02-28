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
const { AuditLogger } = require('./audit');
const { enable, disable, getShield, isEnabled } = require('./middleware');

module.exports = {
  Shield,
  ShieldConfig,
  TokenMap,
  Tokenizer,
  DetectionEngine,
  AuditLogger,
  enable,
  disable,
  getShield,
  isEnabled,
};
