/**
 * LLM-based PII Detection (Pass 2 for JS SDK).
 *
 * Uses a local Ollama instance via child_process.execFileSync + curl
 * to detect semantic/contextual PII (names, orgs, addresses, medical, etc.).
 *
 * Opt-in via config: new ShieldConfig({ llmDetection: true })
 * Data never leaves the user's machine.
 */

const cp = require('child_process');

// Categories the LLM should detect (JS has no spaCy, so includes PERSON/ORG/GPE)
const LLM_CATEGORIES = new Set([
  'PERSON', 'ORG', 'GPE',
  'ADDRESS', 'DATE_OF_BIRTH', 'MEDICAL', 'FINANCIAL',
  'NATIONAL_ID', 'BIOMETRIC', 'USERNAME', 'PASSWORD', 'VEHICLE',
]);

// Categories already covered by regex — LLM should NOT detect these
const EXCLUDED_CATEGORIES = new Set([
  'EMAIL', 'PHONE', 'SSN', 'CREDIT_CARD', 'IP_ADDRESS',
  'API_KEY', 'IBAN', 'JWT',
]);

class LlmDetector {
  /**
   * @param {import('./config').ShieldConfig} config
   */
  constructor(config) {
    this._model = config.llmModel;
    this._baseUrl = config.llmOllamaUrl.replace(/\/+$/, '');
    this._timeout = Math.ceil(config.llmTimeout / 1000); // curl uses seconds
    this._confidence = config.llmConfidence;
    /** @type {boolean|null} null = not checked yet */
    this._available = null;
    /** @type {Map<string, Array<{value: string, category: string}>>} */
    this._cache = new Map();
    /** @type {Function} Overridable for testing */
    this._execFileSync = cp.execFileSync;
  }

  _checkAvailable() {
    if (this._available !== null) return this._available;
    try {
      this._execFileSync('curl', [
        '-s', '-o', '/dev/null', '-w', '%{http_code}',
        '--max-time', '3',
        `${this._baseUrl}/api/tags`,
      ], { encoding: 'utf-8', timeout: 5000 });
      this._available = true;
    } catch {
      console.warn(`CloakLLM: Ollama not available at ${this._baseUrl} — LLM detection disabled`);
      this._available = false;
    }
    return this._available;
  }

  _systemPrompt() {
    const cats = [...LLM_CATEGORIES].sort().join(', ');
    const excluded = [...EXCLUDED_CATEGORIES].sort().join(', ');
    return (
      'You are a PII detection engine. Given text, extract sensitive entities.\n' +
      `Return ONLY entities in these categories: ${cats}\n` +
      `Do NOT detect: ${excluded} (already handled by other systems).\n` +
      'Return valid JSON: {"entities": [{"value": "exact text from input", "category": "CATEGORY"}]}\n' +
      'Rules:\n' +
      '- "value" must be an EXACT substring of the input text\n' +
      '- Do not paraphrase or modify values\n' +
      '- If no entities found, return {"entities": []}\n' +
      '- Only return high-confidence detections'
    );
  }

  _buildPrompt(text) {
    return `Extract PII entities from this text:\n\n${text}`;
  }

  /**
   * Query Ollama via curl (sync).
   * @param {string} text
   * @returns {Array<{value: string, category: string}>}
   */
  _queryOllama(text) {
    const payload = JSON.stringify({
      model: this._model,
      messages: [
        { role: 'system', content: this._systemPrompt() },
        { role: 'user', content: this._buildPrompt(text) },
      ],
      format: 'json',
      stream: false,
      options: { temperature: 0.0 },
    });

    try {
      const stdout = this._execFileSync('curl', [
        '-s',
        '--max-time', String(this._timeout),
        '-X', 'POST',
        '-H', 'Content-Type: application/json',
        '-d', payload,
        `${this._baseUrl}/api/chat`,
      ], { encoding: 'utf-8', timeout: (this._timeout + 2) * 1000 });

      const body = JSON.parse(stdout);
      const content = body?.message?.content ?? '{}';
      const parsed = JSON.parse(content);
      const entities = parsed?.entities;
      if (!Array.isArray(entities)) return [];
      return entities;
    } catch (err) {
      console.warn(`CloakLLM: Ollama query failed: ${err.message}`);
      return [];
    }
  }

  /**
   * Detect semantic PII via LLM.
   * @param {string} text - The original text to scan.
   * @param {Array<[number, number]>} coveredSpans - Spans already detected by regex.
   * @returns {Array<import('./detector').Detection>}
   */
  detect(text, coveredSpans) {
    if (!this._checkAvailable()) return [];

    let entities;
    if (this._cache.has(text)) {
      entities = this._cache.get(text);
    } else {
      entities = this._queryOllama(text);
      this._cache.set(text, entities);
    }

    // Sort by value length desc (longer matches first)
    entities.sort((a, b) => (b.value?.length ?? 0) - (a.value?.length ?? 0));

    const detections = [];
    for (const ent of entities) {
      const value = ent.value ?? '';
      const category = (ent.category ?? '').toUpperCase();

      if (value.length < 2) continue;
      if (!LLM_CATEGORIES.has(category)) continue;

      // Find all occurrences in text
      const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escaped, 'g');
      let match;
      while ((match = regex.exec(text)) !== null) {
        const start = match.index;
        const end = start + match[0].length;

        // Skip if overlapping with covered spans
        if (coveredSpans.some(([s, e]) => start < e && end > s)) continue;

        detections.push({
          text: value,
          category,
          start,
          end,
          confidence: this._confidence,
          source: 'llm',
        });
        coveredSpans.push([start, end]);
      }
    }

    return detections;
  }
}

module.exports = { LlmDetector };
