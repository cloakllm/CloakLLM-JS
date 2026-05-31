/**
 * CloakLLM — TypeScript type definitions.
 */

export interface ShieldConfigOptions {
  locale?: string;
  detectEmails?: boolean;
  detectPhones?: boolean;
  detectSsns?: boolean;
  detectCreditCards?: boolean;
  detectApiKeys?: boolean;
  detectIpAddresses?: boolean;
  detectIban?: boolean;
  customPatterns?: Array<{ name: string; pattern: string }>;
  customLlmCategories?: Array<{ name: string; description?: string }>;
  llmDetection?: boolean;
  llmModel?: string;
  llmOllamaUrl?: string;
  llmTimeout?: number;
  llmConfidence?: number;
  llmAllowRemote?: boolean;
  mode?: 'tokenize' | 'redact';
  descriptiveTokens?: boolean;
  entityHashing?: boolean;
  entityHashKey?: string;
  auditEnabled?: boolean;
  logDir?: string;
  /**
   * v0.6.3 H4: refuse silent GENESIS chain restart when log files exist
   * but recovery returned nothing. Closes the surface where an attacker
   * who can corrupt all logs masks tampering as a routine restart.
   * Default false for back-compat. Env: CLOAKLLM_AUDIT_STRICT_CHAIN=true.
   */
  auditStrictChain?: boolean;
  /**
   * v0.6.3 H5: promote outside-CWD path warnings to hard errors for
   * `logDir` and `attestationKeyPath`. Default false for back-compat.
   * Env: CLOAKLLM_AUDIT_STRICT_PATHS=true.
   */
  auditStrictPaths?: boolean;
  autoMode?: boolean;
  skipModels?: string[];
  attestationKey?: DeploymentKeyPair | null;
  attestationKeyPath?: string | null;
  complianceMode?: 'eu_ai_act_article12' | null;
  retentionHintDays?: number;
  maxInputLength?: number;
  contextAnalysis?: boolean;
  contextRiskThreshold?: number;
}

export class ShieldConfig {
  constructor(options?: ShieldConfigOptions);
  locale: string;
  detectEmails: boolean;
  detectPhones: boolean;
  detectSsns: boolean;
  detectCreditCards: boolean;
  detectApiKeys: boolean;
  detectIpAddresses: boolean;
  detectIban: boolean;
  customPatterns: Array<{ name: string; pattern: string }>;
  customLlmCategories: Array<{ name: string; description?: string }>;
  llmDetection: boolean;
  llmModel: string;
  llmOllamaUrl: string;
  llmTimeout: number;
  llmConfidence: number;
  llmAllowRemote: boolean;
  mode: 'tokenize' | 'redact';
  descriptiveTokens: boolean;
  entityHashing: boolean;
  entityHashKey: string;
  auditEnabled: boolean;
  logDir: string;
  /** v0.6.3 H4: refuse silent GENESIS chain restart on full log corruption. */
  auditStrictChain: boolean;
  /** v0.6.3 H5: promote outside-CWD path warnings to errors. */
  auditStrictPaths: boolean;
  autoMode: boolean;
  skipModels: string[];
  attestationKey: DeploymentKeyPair | null;
  attestationKeyPath: string | null;
  complianceMode: 'eu_ai_act_article12' | null;
  retentionHintDays: number;
  maxInputLength: number;
  contextAnalysis: boolean;
  contextRiskThreshold: number;
}

export interface RiskAssessment {
  token_density: number;
  identifying_descriptors: number;
  relationship_edges: number;
  risk_score: number;
  risk_level: 'low' | 'medium' | 'high';
  warnings: string[];
}

export interface Detection {
  text: string;
  category: string;
  start: number;
  end: number;
  confidence: number;
  source: string;
}

export interface EntityDetail {
  category: string;
  start: number;
  end: number;
  length: number;
  confidence: number;
  source: string;
  token: string;
  entity_hash?: string;
}

export interface BatchEntityDetail extends EntityDetail {
  text_index: number;
}

export class TokenMap {
  constructor(options?: { mode?: 'tokenize' | 'redact'; entityHashing?: boolean; entityHashKey?: string });
  forward: Map<string, string>;
  reverse: Map<string, string>;
  detections: Detection[];
  mode: 'tokenize' | 'redact';
  entityHashing: boolean;
  entityHashKey: string;
  certificate: SanitizationCertificate | null;
  batchCertificate: SanitizationCertificate | null;
  merkleTree: { input: MerkleTree; output: MerkleTree } | null;
  riskAssessment: RiskAssessment | null;
  readonly entityCount: number;
  readonly categories: Record<string, number>;
  readonly entityDetails: EntityDetail[];
  getOrCreate(original: string, category: string): string;
  toSummary(): { entity_count: number; categories: Record<string, number>; tokens: string[] };
  toReport(): { entity_count: number; categories: Record<string, number>; tokens: string[]; mode: string; entity_details: EntityDetail[] };
}

export class Shield {
  constructor(config?: ShieldConfig, options?: { backends?: DetectorBackend[] | null });
  config: ShieldConfig;
  detector: DetectionEngine;
  audit: AuditLogger;

  sanitize(
    text: string,
    options?: {
      tokenMap?: TokenMap | null;
      model?: string | null;
      provider?: string | null;
      metadata?: Record<string, any>;
    }
  ): [string, TokenMap];

  desanitize(
    text: string,
    tokenMap: TokenMap,
    options?: {
      model?: string | null;
      provider?: string | null;
      metadata?: Record<string, any>;
    }
  ): string;

  sanitizeBatch(
    texts: string[],
    options?: {
      tokenMap?: TokenMap | null;
      model?: string | null;
      provider?: string | null;
      metadata?: Record<string, any>;
    }
  ): [string[], TokenMap];

  desanitizeBatch(
    texts: string[],
    tokenMap: TokenMap,
    options?: {
      model?: string | null;
      provider?: string | null;
      metadata?: Record<string, any>;
    }
  ): string[];

  analyze(text: string, options?: { redactValues?: boolean }): {
    entity_count: number;
    entities: Detection[];
  };

  analyzeContextRisk(sanitizedText: string): RiskAssessment;

  metrics(): Metrics;
  resetMetrics(): void;
  verifyAudit(options?: {
    logDir?: string | null;
    outputFormat?: 'compliance_report' | null;
    legacyCanonical?: boolean;
  }): { valid: boolean; errors: string[]; finalSeq: number } | ComplianceReport;
  auditStats(): Record<string, any>;
  complianceSummary(): ComplianceSummary;
  exportComplianceConfig(outPath?: string): string;
  generateComplianceReport(opts?: {
    periodFrom?: string | null;
    periodTo?: string | null;
    articles?: string[] | null;
    format?: 'json' | 'markdown';
    outPath?: string | null;
    includeDecisions?: boolean;
  }): ComplianceReportV080 | string;
  verifyCertificate(certificate: SanitizationCertificate | Record<string, any>, publicKey?: Buffer | null): boolean;
  static generateAttestationKey(): DeploymentKeyPair;
}

export interface ComplianceArticleEntry {
  article: string;
  status: 'satisfied' | 'partial' | 'not_addressed';
  notes: string;
}

export interface ComplianceSummary {
  compliance_mode: 'eu_ai_act_article12' | null;
  articles_addressed: ComplianceArticleEntry[];
  config_snapshot: {
    audit: boolean;
    compliance_mode: 'eu_ai_act_article12' | null;
    mode: 'tokenize' | 'redact';
    entity_hashing: boolean;
    attestation_enabled: boolean;
    retention_hint_days: number;
    /** v0.8.0 CR8-9: decision_id has been always-on since v0.7.1. */
    decision_id_enabled: boolean;
    /** v0.8.0 CR8-9: true iff both deployment_version and instruction_version are set. */
    system_version_pin_configured: boolean;
    /** v0.8.0 CR8-9: signals shield.generateComplianceReport() is available. */
    compliance_reporting_available: boolean;
  };
  generated_at: string;
  cloakllm_version: string;
  note?: string;
}

/**
 * v0.8.0 CR8: end-to-end compliance report produced by
 * `shield.generateComplianceReport()`. Schema mirror of
 * `examples/compliance_report_schema.json`.
 */
export interface ComplianceReportV080 {
  report_metadata: {
    generated_at: string;
    cloakllm_version: string;
    schema_version: string;
    audit_dir?: string;
  };
  period: { from: string | null; to: string | null };
  articles_in_scope: string[] | null;
  chain_integrity: {
    verdict: 'verified' | 'broken';
    total_entries: number;
    anomalies: string[];
  };
  per_article: Record<string, {
    evidence_event_count: number;
    decision_count: number;
    categories_detected: Record<string, number>;
    pii_in_log: boolean;
    bias_sessions?: number;
    findings_recorded?: number;
    wipe_confirmed_pct?: number;
  }>;
  attestation: {
    schema_version: string;
    entries_with_certificates: number;
    signatures_valid: number;
    key_ids: string[];
    /** v0.8.1 KeyManifest forward-compat slot. All fields null in v0.8.0. */
    provenance_summary: {
      manifests_found: number | null;
      manifests_valid: number | null;
      within_validity_window_pct: number | null;
      root_signature_status_distribution: Record<string, number> | null;
    };
  };
  decisions?: Record<string, {
    entry_count: number;
    articles_touched: string[];
    categories: Record<string, number>;
    first_timestamp: string;
    last_timestamp: string;
  }>;
  verdict: 'COMPLIANT' | 'NON_COMPLIANT';
  verdict_reasons: string[];
}

export interface ComplianceReport {
  audit_dir: string;
  period: { from: string | null; to: string | null };
  total_entries: number;
  chain_integrity: 'verified' | 'broken';
  pii_in_logs: boolean;
  compliance_mode_entries: number;
  non_compliance_mode_entries: number;
  pii_categories_detected: Record<string, number>;
  certificates_present: number;
  anomalies: string[];
  generated_at: string;
  verdict: 'COMPLIANT' | 'NON_COMPLIANT';
}

export interface Timing {
  total_ms: number;
  detection_ms?: number;
  regex_ms?: number;
  ner_ms?: number;
  llm_ms?: number;
  tokenization_ms: number;
}

export interface DetectorTiming {
  regex_ms?: number;
  ner_ms?: number;
  llm_ms?: number;
  [key: string]: number | undefined;
}

export interface Metrics {
  calls: {
    sanitize: number;
    desanitize: number;
    sanitizeBatch: number;
    desanitizeBatch: number;
  };
  total_ms: number;
  avg_ms: number;
  detection: Record<string, number>;
  tokenization_ms: number;
  entities_detected: number;
  categories: Record<string, number>;
}

export function isNerAvailable(): boolean;

export class DetectionEngine {
  constructor(config: ShieldConfig, backends?: DetectorBackend[] | null);
  detect(text: string): { detections: Detection[]; timing: Record<string, number> };
}

export class Tokenizer {
  constructor(config: ShieldConfig);
  tokenize(text: string, detections: Detection[], tokenMap?: TokenMap | null): [string, TokenMap];
  detokenize(text: string, tokenMap: TokenMap): string;
}

export class StreamDesanitizer {
  /**
   * @param tokenMap TokenMap with forward/reverse mappings.
   * @param options.maxInputLength v0.6.3 (NEW-3.e): hard cap on cumulative
   *   characters fed via `feed()`. Default 0 = no cap. Throws if exceeded.
   */
  constructor(tokenMap: TokenMap, options?: { maxInputLength?: number });
  /** Feed a chunk of text; returns text safe to emit (may be empty if buffering). */
  feed(chunk: string): string;
  /** Flush any remaining buffered text at end of stream. */
  flush(): string;
  /** Cumulative characters fed via feed() (v0.6.3 NEW-3.e/P2-1). */
  charsProcessed: number;
  /** @deprecated v0.6.3: use `charsProcessed`. Removed in v0.7.0. */
  readonly bytesProcessed: number;
}

export class AuditLogger {
  constructor(config: ShieldConfig);
  log(options: {
    eventType: string;
    originalText?: string;
    sanitizedText?: string;
    model?: string | null;
    provider?: string | null;
    entityCount?: number;
    categories?: Record<string, number>;
    tokensUsed?: string[];
    latencyMs?: number;
    mode?: string | null;
    entityDetails?: EntityDetail[];
    timing?: Timing | null;
    metadata?: Record<string, any>;
    certificateHash?: string | null;
    keyId?: string | null;
  }): Record<string, any> | null;
  verifyChain(
    options?:
      | string
      | {
          logFilePath?: string;
          outputFormat?: 'compliance_report';
          /**
           * v0.6.4: recompute hashes using the v0.6.0 canonicalizer. Required
           * for chains written by Python v0.5.x or v0.6.0 containing non-ASCII.
           * Sunset in v0.7.0.
           */
          legacyCanonical?: boolean;
        }
      | null
  ): { valid: boolean; errors: string[]; finalSeq: number } | ComplianceReport;
  getStats(): Record<string, any>;
}

export function enable(client: any, config?: ShieldConfig): void;
export function disable(client?: any): void;
export function getShield(): Shield | null;
export function isEnabled(): boolean;

export interface CloakLLMMiddleware {
  transformParams(options: {
    params: { prompt: any[]; [key: string]: any };
    type: string;
    model?: { modelId: string; [key: string]: any };
  }): Promise<{ prompt: any[]; [key: string]: any }>;

  wrapGenerate(options: {
    doGenerate: () => Promise<any>;
    params: { prompt: any[]; [key: string]: any };
    model: { modelId: string; [key: string]: any };
  }): Promise<any>;

  wrapStream(options: {
    doStream: () => Promise<{ stream: ReadableStream; [key: string]: any }>;
    params: { prompt: any[]; [key: string]: any };
    model: { modelId: string; [key: string]: any };
  }): Promise<{ stream: ReadableStream; [key: string]: any }>;
}

export function createCloakLLMMiddleware(
  config?: ShieldConfig | ShieldConfigOptions
): CloakLLMMiddleware;

// --- Attestation ---

export class DeploymentKeyPair {
  privateKey: Buffer;
  publicKey: Buffer;
  keyId: string;
  constructor(privateKey: Buffer, publicKey: Buffer, keyId: string);
  static generate(): DeploymentKeyPair;
  sign(data: Buffer | string): Buffer;
  signB64(data: Buffer | string): string;
  static verify(publicKey: Buffer, data: Buffer | string, signature: Buffer): boolean;
  static verifyB64(publicKey: Buffer, data: Buffer | string, signatureB64: string): boolean;
  readonly publicKeyB64: string;
  save(filePath: string): void;
  static fromFile(filePath: string): DeploymentKeyPair;
}

export class SanitizationCertificate {
  version: string;
  timestamp: string;
  input_hash: string;
  output_hash: string;
  entity_count: number;
  categories: Record<string, number>;
  detection_passes: string[];
  mode: string;
  key_id: string;
  nonce: string;
  signature: string;
  public_key: string;
  constructor(fields?: Partial<SanitizationCertificate>);
  static create(options: {
    originalText?: string | null;
    sanitizedText?: string | null;
    entityCount: number;
    categories: Record<string, number>;
    detectionPasses: string[];
    mode: string;
    keypair: DeploymentKeyPair;
    inputMerkleRoot?: string | null;
    outputMerkleRoot?: string | null;
  }): SanitizationCertificate;
  verify(publicKey: Buffer): boolean;
  toDict(): Record<string, any>;
  static fromDict(d: Record<string, any>): SanitizationCertificate;
}

export class MerkleTree {
  constructor(leaves: string[]);
  readonly root: string;
  proof(index: number): Array<[string, string]>;
  static verifyProof(leafHash: string, proof: Array<[string, string]>, root: string): boolean;
}

export function deriveEntityHashKey(
  masterKey: Buffer | string,
  salt?: Buffer | null,
  info?: Buffer | string
): string;

// --- Context Analysis ---

export class ContextAnalyzer {
  analyze(sanitizedText: string): RiskAssessment;
}

// --- Token Specification ---

/** Canonical regex pattern string for matching CloakLLM tokens. */
export const CLOAKLLM_TOKEN_PATTERN: string;

/** Maximum token length (including brackets). */
export const MAX_TOKEN_LENGTH: number;

/** Set of all built-in category names. */
export const BUILTIN_CATEGORIES: Set<string>;

/**
 * Special-category (GDPR Article 9 / EU AI Act Article 4a) categories.
 * Deliberately NOT auto-detected by regex; introduced via
 * `BiasDetectionSession` or opt-in LLM detection.
 */
export const SPECIAL_CATEGORY_CATEGORIES: Set<string>;

/** Return true if the string is a valid CloakLLM token. */
export function validateToken(token: string): boolean;

/** Parse a token string into { category, suffix } or null. */
export function parseToken(token: string): { category: string; suffix: string } | null;

/** Return true if the token is a redacted token ([CATEGORY_REDACTED]). */
export function isRedactedToken(token: string): boolean;

/** Check if a category name is valid (format only). */
export function validateCategoryName(name: string): boolean;

// --- Detection Backends ---

/** Abstract base class for pluggable detection backends. */
export class DetectorBackend {
  /** Unique name for this backend (used in timing keys). */
  get name(): string;
  /** Detect sensitive entities in text. */
  detect(text: string, coveredSpans: Array<[number, number]>): Detection[];
}

/** Regex-based PII detection backend. */
export class RegexBackend extends DetectorBackend {
  constructor(config: ShieldConfig);
  get name(): 'regex';
}

/** NER detection backend via compromise (optional). */
export class NerBackend extends DetectorBackend {
  constructor();
  get name(): 'ner';
  /** Whether NER is actually available (compromise installed). */
  get available(): boolean;
}

/** LLM-based semantic detection backend via Ollama. */
export class LlmBackend extends DetectorBackend {
  constructor(config: ShieldConfig);
  get name(): 'llm';
  addExcludedCategories(categories: string[]): void;
}

// --- v0.7.0 A4a: Bias Detection (Article 4a) ---

/** Base class for all Article 4a bias-detection errors. */
export class BiasDetectionError extends Error {}

/**
 * Raised when a pseudonymise() call requests a category not in the session's
 * categoriesAllowed set. Article 4a safeguard #4 enforcement.
 */
export class BiasDetectionScopeError extends BiasDetectionError {}

/**
 * Raised when an operation runs after maxLifetimeSeconds has elapsed.
 * The session is force-ended and wiped before the error is thrown.
 */
export class BiasDetectionTimeoutError extends BiasDetectionError {}

/**
 * Raised when an operation is attempted on a session in the wrong state
 * (used before .start(), or after .end()).
 */
export class BiasDetectionStateError extends BiasDetectionError {}

export interface BiasDetectionSessionOptions {
  shield: Shield;
  purpose: string;
  necessityJustification: string;
  categoriesAllowed: Iterable<string>;
  maxLifetimeSeconds: number;
}

export interface BiasDetectionFindingOptions {
  findingSummary: string;
  biasMetrics?: Record<string, number | string | boolean | null>;
}

/**
 * Article 4a-compliant bias-detection workflow over a Shield. Sibling
 * class via composition — does NOT subclass Shield.
 *
 * Requires shield.config.complianceMode === 'eu_ai_act_article12'.
 *
 * Use the static `.run()` helper for guaranteed cleanup, or call `.start()`
 * and `.end()` explicitly inside a try/finally.
 */
export class BiasDetectionSession {
  constructor(options: BiasDetectionSessionOptions);

  readonly sessionId: string;
  readonly purpose: string;
  readonly necessityJustification: string;
  readonly categoriesAllowed: Set<string>;
  readonly maxLifetimeSeconds: number;
  readonly closed: boolean;
  readonly entriesProcessed: number;

  /** Mark the session as entered and log bias_session_start. Idempotent within a single session. */
  start(): void;

  /**
   * Run callback with a fresh session; guarantees .end() runs on success or throw.
   * Mirrors Python's `with BiasDetectionSession(...) as session:` block.
   */
  static run<T>(
    options: BiasDetectionSessionOptions,
    fn: (session: BiasDetectionSession) => T | Promise<T>,
  ): Promise<T>;

  /**
   * Pseudonymise text using caller-declared special-category spans.
   * @returns [pseudonymisedText, categoriesUsedCounts]
   */
  pseudonymise(
    text: string,
    options: { forceCategories: Array<[number, number, string]> },
  ): [string, Record<string, number>];

  /** Record a bias-detection finding (logs bias_finding event). */
  recordFinding(options: BiasDetectionFindingOptions): void;

  /** Explicit close. Idempotent. Logs bias_session_end and wipes token map. */
  end(): void;
}
