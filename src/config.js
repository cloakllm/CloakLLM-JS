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
const fs = require('fs');
const { RESERVED_CATEGORIES } = require('./token-spec');

/**
 * v0.6.3 H5: Centralized path validation. Always rejects:
 *   * paths containing NUL bytes (defense vs C-string truncation)
 *   * paths that exist as symlinks (attacker-replaceable surface)
 * Conditionally rejects (when strictPaths=true): paths outside CWD.
 * Otherwise emits a console.warn for the outside-CWD case (back-compat).
 */
function _validatePath(pathValue, name, { strictPaths = false } = {}) {
  if (!pathValue) return;
  if (typeof pathValue !== 'string') {
    pathValue = String(pathValue);
  }
  if (pathValue.includes('\0')) {
    throw new Error(
      `CloakLLM: ${name} contains a NUL byte. Refusing for security.`
    );
  }
  // lstatSync throws if the path doesn't exist; that's fine — only existing
  // paths can be symlinks. Mkdir/open will create or fail later as appropriate.
  try {
    const stats = fs.lstatSync(pathValue);
    if (stats.isSymbolicLink()) {
      let target = '<unreadable>';
      try { target = fs.readlinkSync(pathValue); } catch { /* ignore */ }
      throw new Error(
        `CloakLLM: ${name} '${pathValue}' is a symlink (target: '${target}'). ` +
        `Refusing for security — set the config to the real destination.`
      );
    }
  } catch (e) {
    if (e.code !== 'ENOENT' && e.code !== 'ENOTDIR') {
      throw e;
    }
    // doesn't exist — fine, will be created later
  }

  const resolved = path.resolve(pathValue);
  const cwd = process.cwd();
  if (!resolved.startsWith(cwd)) {
    const msg = `CloakLLM: ${name} '${resolved}' is outside the current working directory.`;
    if (strictPaths) {
      throw new Error(msg + ' (auditStrictPaths: true)');
    }
    console.warn(msg);
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
    // v0.6.3 H9: validate customPatterns names (was: only customLlmCategories
    // validated — parity gap that allowed `__proto__`/`constructor`/`prototype`
    // through to the regex backend, where the category name then flowed into
    // dynamic object-key writes downstream).
    for (const { name } of this.customPatterns) {
      if (typeof name !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(name)) {
        throw new Error(
          `Invalid custom pattern name ${JSON.stringify(name)}. Must be a string matching ^[A-Z][A-Z0-9_]*$`
        );
      }
    }
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
    // v0.6.3 H4: when true, refuse to silently restart the audit chain from
    // GENESIS if the log dir contains files but recovery couldn't find any
    // well-formed entry. Defaults to false for backward-compat. Set true (or
    // env CLOAKLLM_AUDIT_STRICT_CHAIN=true) for compliance-grade deployments
    // where a silent chain restart could mask tampering.
    this.auditStrictChain = options.auditStrictChain
      ?? (process.env.CLOAKLLM_AUDIT_STRICT_CHAIN ?? '').toLowerCase() === 'true';
    // v0.6.3 H5: when true, the existing "outside CWD" advisory warning
    // becomes a hard Error. Defaults to false. Symlink and NUL-byte
    // rejection are ALWAYS on regardless — they're security invariants.
    this.auditStrictPaths = options.auditStrictPaths
      ?? (process.env.CLOAKLLM_AUDIT_STRICT_PATHS ?? '').toLowerCase() === 'true';

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

    // --- v0.7.1 C7.1-2: system_version_pin components ---
    // Deployer-supplied components composed into AuditEntry.system_version_pin
    // at write time: "<model>@<deploymentVersion>/<instructionVersion>".
    // All three required for the pin to be emitted; otherwise null.
    /** @type {string|null} */
    this.deploymentVersion = options.deploymentVersion
      ?? process.env.CLOAKLLM_DEPLOYMENT_VERSION ?? null;
    /** @type {string|null} */
    this.instructionVersion = options.instructionVersion
      ?? process.env.CLOAKLLM_INSTRUCTION_VERSION ?? null;

    // Note: KMS-based key providers are Python-only for v0.6. JS uses local Ed25519 keys.

    // --- Input length cap (v0.6.1 H1.4) ---
    // Hard cap on text length passed to detection backends. Prevents pathological
    // inputs from exercising worst-case backtracking on built-in patterns.
    // Default: 1 MB. Set to 0 to disable (not recommended).
    this.maxInputLength = options.maxInputLength
      ?? parseInt(process.env.CLOAKLLM_MAX_INPUT_LENGTH ?? '1000000', 10);
    if (this.maxInputLength < 0) {
      throw new Error(`maxInputLength must be >= 0 (got ${this.maxInputLength}).`);
    }

    // --- Context Analysis ---
    this.contextAnalysis = options.contextAnalysis ??
      (process.env.CLOAKLLM_CONTEXT_ANALYSIS ?? 'false').toLowerCase() === 'true';
    this.contextRiskThreshold = options.contextRiskThreshold ?? 0.7;

    _validatePath(this.logDir, 'logDir', { strictPaths: this.auditStrictPaths });
    _validatePath(this.attestationKeyPath, 'attestationKeyPath', { strictPaths: this.auditStrictPaths });

    // --- Middleware ---
    this.autoMode = options.autoMode ?? true;
    /** @type {string[]} Model prefixes to skip sanitization */
    this.skipModels = options.skipModels ?? [];
  }
}

module.exports = {
  ShieldConfig,
  // v0.6.3 SEC-3: exported for runtime callers (shield.exportComplianceConfig)
  // that need to apply the same path validation as ShieldConfig construction.
  _validatePath,
};
