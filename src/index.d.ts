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
  };
  generated_at: string;
  cloakllm_version: string;
  note?: string;
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
  constructor(tokenMap: TokenMap);
  /** Feed a chunk of text; returns text safe to emit (may be empty if buffering). */
  feed(chunk: string): string;
  /** Flush any remaining buffered text at end of stream. */
  flush(): string;
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
    options?: string | { logFilePath?: string; outputFormat?: 'compliance_report' } | null
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
