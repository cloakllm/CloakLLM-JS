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
  auditEnabled?: boolean;
  logDir?: string;
  logOriginalValues?: boolean;
  autoMode?: boolean;
  skipModels?: string[];
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
  auditEnabled: boolean;
  logDir: string;
  logOriginalValues: boolean;
  autoMode: boolean;
  skipModels: string[];
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
}

export interface BatchEntityDetail extends EntityDetail {
  text_index: number;
}

export class TokenMap {
  constructor(options?: { mode?: 'tokenize' | 'redact' });
  forward: Map<string, string>;
  reverse: Map<string, string>;
  detections: Detection[];
  mode: 'tokenize' | 'redact';
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
