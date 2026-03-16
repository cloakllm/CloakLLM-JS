/**
 * CloakLLM — TypeScript type definitions.
 */

export interface ShieldConfigOptions {
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
  mode?: 'tokenize' | 'redact';
  descriptiveTokens?: boolean;
  entityHashing?: boolean;
  entityHashKey?: string;
  auditEnabled?: boolean;
  logDir?: string;
  logOriginalValues?: boolean;
  autoMode?: boolean;
  skipModels?: string[];
  attestationKey?: DeploymentKeyPair | null;
  attestationKeyPath?: string | null;
}

export class ShieldConfig {
  constructor(options?: ShieldConfigOptions);
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
  mode: 'tokenize' | 'redact';
  descriptiveTokens: boolean;
  entityHashing: boolean;
  entityHashKey: string;
  auditEnabled: boolean;
  logDir: string;
  logOriginalValues: boolean;
  autoMode: boolean;
  skipModels: string[];
  attestationKey: DeploymentKeyPair | null;
  attestationKeyPath: string | null;
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
  readonly entityCount: number;
  readonly categories: Record<string, number>;
  readonly entityDetails: EntityDetail[];
  getOrCreate(original: string, category: string): string;
  toSummary(): { entity_count: number; categories: Record<string, number>; tokens: string[] };
  toReport(): { entity_count: number; categories: Record<string, number>; tokens: string[]; mode: string; entity_details: EntityDetail[] };
}

export class Shield {
  constructor(config?: ShieldConfig);
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

  analyze(text: string): {
    entity_count: number;
    entities: Detection[];
  };

  metrics(): Metrics;
  resetMetrics(): void;
  verifyAudit(): { valid: boolean; errors: string[] };
  auditStats(): Record<string, any>;
  verifyCertificate(certificate: SanitizationCertificate | Record<string, any>, publicKey?: Buffer | null): boolean;
  static generateAttestationKey(): DeploymentKeyPair;
}

export interface Timing {
  total_ms: number;
  detection_ms?: number;
  regex_ms?: number;
  llm_ms?: number;
  tokenization_ms: number;
}

export interface DetectorTiming {
  regex_ms: number;
  llm_ms: number;
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
  detection: {
    regex_ms: number;
    llm_ms: number;
  };
  tokenization_ms: number;
  entities_detected: number;
  categories: Record<string, number>;
}

export class DetectionEngine {
  constructor(config: ShieldConfig);
  detect(text: string): { detections: Detection[]; timing: DetectorTiming };
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
  verifyChain(logFilePath?: string | null): { valid: boolean; errors: string[] };
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
