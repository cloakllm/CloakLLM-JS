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

class ShieldConfig {
  constructor(options = {}) {
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

    // --- LLM Detection (Pass 2: local LLM via Ollama) ---
    this.llmDetection = options.llmDetection ??
      (process.env.CLOAKLLM_LLM_DETECTION ?? 'false').toLowerCase() === 'true';
    this.llmModel = options.llmModel ?? process.env.CLOAKLLM_LLM_MODEL ?? 'llama3.2';
    this.llmOllamaUrl = options.llmOllamaUrl ?? process.env.CLOAKLLM_OLLAMA_URL ?? 'http://localhost:11434';
    this.llmTimeout = options.llmTimeout ?? 10000;
    this.llmConfidence = options.llmConfidence ?? 0.85;

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
    this.logOriginalValues = options.logOriginalValues ?? false;

    // --- Attestation (Ed25519 signing) ---
    /** @type {import('./attestation').DeploymentKeyPair|null} Pre-loaded keypair */
    this.attestationKey = options.attestationKey ?? null;
    /** @type {string|null} Path to keypair JSON file */
    this.attestationKeyPath = options.attestationKeyPath ?? process.env.CLOAKLLM_SIGNING_KEY_PATH ?? null;

    // --- Middleware ---
    this.autoMode = options.autoMode ?? true;
    /** @type {string[]} Model prefixes to skip sanitization */
    this.skipModels = options.skipModels ?? [];
  }
}

module.exports = { ShieldConfig };
