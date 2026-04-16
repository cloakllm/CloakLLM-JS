/**
 * CloakLLM Configuration.
 *
 * All settings have sensible defaults. Override via constructor:
 *   const config = new ShieldConfig({ logDir: './my-audit-logs' });
 *   const shield = new Shield(config);
 *
 * Or via environment variables:
 *   CLOAKLLM_LOG_DIR=./my-audit-logs
 */

const path = require('path');
const { RESERVED_CATEGORIES } = require('./token-spec');

function _validatePath(pathValue, name) {
  if (!pathValue) return;
  const resolved = path.resolve(pathValue);
  const cwd = process.cwd();
  if (!resolved.startsWith(cwd)) {
    console.warn(`CloakLLM: ${name} '${resolved}' is outside the current working directory.`);
  }
}

class ShieldConfig {
  constructor(options = {}) {
    // --- Locale ---
    this.locale = options.locale ?? process.env.CLOAKLLM_LOCALE ?? 'en';

    // --- Detection ---
    this.detectEmails = options.detectEmails ?? true;
    this.detectPhones = options.detectPhones ?? true;
    this.detectSsns = options.detectSsns ?? true;
    this.detectCreditCards = options.detectCreditCards ?? true;
    this.detectApiKeys = options.detectApiKeys ?? true;
    this.detectIpAddresses = options.detectIpAddresses ?? true;
    this.detectIban = options.detectIban ?? true;
    /** @type {Array<{name: string, pattern: string}>} */
    this.customPatterns = options.customPatterns ?? [];
    /** @type {Array<{name: string, description: string}>} */
    this.customLlmCategories = options.customLlmCategories ?? [];
    // Validate custom LLM category names
    for (const { name } of this.customLlmCategories) {
      if (!/^[A-Z][A-Z0-9_]*$/.test(name)) {
        throw new Error(
          `Invalid custom LLM category name '${name}'. Must match ^[A-Z][A-Z0-9_]*$`
        );
      }
      if (RESERVED_CATEGORIES.has(name)) {
        throw new Error(
          `Custom LLM category '${name}' conflicts with built-in category.`
        );
      }
    }

    // --- LLM Detection (Pass 2: local LLM via Ollama) ---
    this.llmDetection = options.llmDetection ??
      (process.env.CLOAKLLM_LLM_DETECTION ?? 'false').toLowerCase() === 'true';
    this.llmModel = options.llmModel ?? process.env.CLOAKLLM_LLM_MODEL ?? 'llama3.2';
    this.llmOllamaUrl = options.llmOllamaUrl ?? process.env.CLOAKLLM_OLLAMA_URL ?? 'http://localhost:11434';
    this.llmTimeout = options.llmTimeout ?? 10000;
    this.llmConfidence = options.llmConfidence ?? 0.85;
    this.llmAllowRemote = options.llmAllowRemote ??
      (process.env.CLOAKLLM_LLM_ALLOW_REMOTE ?? 'false').toLowerCase() === 'true';

    // --- Tokenization ---
    this.mode = options.mode ?? 'tokenize';
    if (this.mode !== 'tokenize' && this.mode !== 'redact') {
      throw new Error(`Invalid mode '${this.mode}'. Must be 'tokenize' or 'redact'.`);
    }
    this.descriptiveTokens = options.descriptiveTokens ?? true;

    // --- Entity Hashing ---
    this.entityHashing = options.entityHashing ??
      (process.env.CLOAKLLM_ENTITY_HASHING ?? 'false').toLowerCase() === 'true';
    this.entityHashKey = options.entityHashKey ?? process.env.CLOAKLLM_ENTITY_HASH_KEY ?? '';

    // --- Audit Logging ---
    this.auditEnabled = options.auditEnabled ?? true;
    this.logDir = options.logDir ?? process.env.CLOAKLLM_LOG_DIR ?? './cloakllm_audit';

    // --- Attestation (Ed25519 signing) ---
    /** @type {import('./attestation').DeploymentKeyPair|null} Pre-loaded keypair */
    this.attestationKey = options.attestationKey ?? null;
    /** @type {string|null} Path to keypair JSON file */
    this.attestationKeyPath = options.attestationKeyPath ?? process.env.CLOAKLLM_SIGNING_KEY_PATH ?? null;

    // --- Compliance Mode (v0.6.0) ---
    // When set, enforces Article 12-compliant audit log structure.
    // Accepted values: "eu_ai_act_article12" | null
    /** @type {'eu_ai_act_article12'|null} */
    this.complianceMode = options.complianceMode ?? process.env.CLOAKLLM_COMPLIANCE_MODE ?? null;
    const _validComplianceModes = [null, 'eu_ai_act_article12'];
    if (!_validComplianceModes.includes(this.complianceMode)) {
      throw new Error(
        `Invalid complianceMode '${this.complianceMode}'. Must be 'eu_ai_act_article12' or null.`
      );
    }
    // Retention hint included in compliance-mode audit entries (180 = Article 12 minimum).
    this.retentionHintDays = options.retentionHintDays ?? 180;
    if (this.retentionHintDays < 1) {
      throw new Error(`retentionHintDays must be >= 1 (got ${this.retentionHintDays}).`);
    }
    // Note: KMS-based key providers are Python-only for v0.6. JS uses local Ed25519 keys.

    // --- Context Analysis ---
    this.contextAnalysis = options.contextAnalysis ??
      (process.env.CLOAKLLM_CONTEXT_ANALYSIS ?? 'false').toLowerCase() === 'true';
    this.contextRiskThreshold = options.contextRiskThreshold ?? 0.7;

    _validatePath(this.logDir, 'logDir');
    _validatePath(this.attestationKeyPath, 'attestationKeyPath');

    // --- Middleware ---
    this.autoMode = options.autoMode ?? true;
    /** @type {string[]} Model prefixes to skip sanitization */
    this.skipModels = options.skipModels ?? [];
  }
}

module.exports = { ShieldConfig };
