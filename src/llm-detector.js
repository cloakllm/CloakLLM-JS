/**
 * LLM-based PII Detection (Pass 3 for JS SDK).
 *
 * Uses a local Ollama instance via child_process.execFileSync + curl
 * to detect semantic/contextual PII (names, orgs, addresses, medical, etc.).
 *
 * Opt-in via config: new ShieldConfig({ llmDetection: true })
 * Data never leaves the user's machine.
 *
 * SECURITY NOTE: LLM-based detection is advisory and non-deterministic.
 * It must never be the sole detection mechanism. The LLM prompt is not
 * hardened against prompt injection.
 */

const cp = require('child_process');
const crypto = require('crypto');
const net = require('net');

// Categories the LLM should detect (excludes regex + NER covered ones)
const LLM_CATEGORIES = new Set([
  'ADDRESS', 'DATE_OF_BIRTH', 'MEDICAL', 'FINANCIAL',
  'NATIONAL_ID', 'BIOMETRIC', 'USERNAME', 'PASSWORD', 'VEHICLE',
]);

// Categories already covered by regex or NER — LLM should NOT detect these
const EXCLUDED_CATEGORIES = new Set([
  'EMAIL', 'PHONE', 'SSN', 'CREDIT_CARD', 'IP_ADDRESS',
  'API_KEY', 'IBAN', 'JWT', 'ORG', 'GPE', 'PERSON',
]);

const LOCALE_HINTS = {
  de: 'The input text is in German. Look for German PII formats (Steuer-ID, IBAN DE, German phone numbers, addresses).',
  fr: 'The input text is in French. Look for French PII formats (NIR/Sécu, IBAN FR, French phone numbers, addresses).',
  es: 'The input text is in Spanish. Look for Spanish PII formats (DNI, NIE, IBAN ES, Spanish phone numbers, addresses).',
  nl: 'The input text is in Dutch. Look for Dutch PII formats (BSN, IBAN NL, Dutch phone numbers, addresses).',
  he: 'The input text is in Hebrew. Look for Israeli PII formats (Teudat Zehut, Israeli phone numbers, addresses).',
  zh: 'The input text is in Chinese. Look for Chinese PII formats (身份证号, Chinese phone numbers, addresses).',
  ja: 'The input text is in Japanese. Look for Japanese PII formats (マイナンバー, Japanese phone numbers, addresses).',
  ru: 'The input text is in Russian. Look for Russian PII formats (ИНН, СНИЛС, Russian passport, phone numbers, addresses).',
  ko: 'The input text is in Korean. Look for Korean PII formats (주민등록번호/RRN, Korean phone numbers, addresses).',
  it: 'The input text is in Italian. Look for Italian PII formats (Codice Fiscale, IBAN IT, Italian phone numbers, addresses).',
  pl: 'The input text is in Polish. Look for Polish PII formats (PESEL, NIP, IBAN PL, Polish phone numbers, addresses).',
  pt: 'The input text is in Portuguese. Look for Portuguese/Brazilian PII formats (CPF, NIF, IBAN PT, phone numbers, addresses).',
  hi: 'The input text is in Hindi. Look for Indian PII formats (Aadhaar, PAN card, Indian phone numbers, addresses).',
};

class BoundedCache {
  constructor(maxSize = 1024) {
    this._cache = new Map();
    this._maxSize = maxSize;
  }

  get(key) {
    if (!this._cache.has(key)) return undefined;
    const value = this._cache.get(key);
    this._cache.delete(key);
    this._cache.set(key, value);
    return value;
  }

  set(key, value) {
    if (this._cache.has(key)) this._cache.delete(key);
    this._cache.set(key, value);
    if (this._cache.size > this._maxSize) {
      const oldest = this._cache.keys().next().value;
      this._cache.delete(oldest);
    }
  }

  has(key) {
    return this._cache.has(key);
  }

  clear() {
    this._cache.clear();
  }

  get size() {
    return this._cache.size;
  }
}

function _validateOllamaUrl(url, allowRemote) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`CloakLLM: Invalid Ollama URL '${url}'.`);
  }
  const hostname = parsed.hostname;

  // Fast path for common localhost
  if (['localhost', '127.0.0.1', '::1', '[::1]'].includes(hostname)) {
    return url;
  }

  // Check if it's a private IP
  if (net.isIP(hostname)) {
    const parts = hostname.split('.').map(Number);
    const isPrivate = (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 127
    );
    if (isPrivate) return url;
  }

  if (allowRemote) {
    console.warn(
      `CloakLLM: Ollama URL '${url}' points to a non-local address. ` +
      'PII data will be sent to this remote server.'
    );
    return url;
  }

  throw new Error(
    `CloakLLM: Ollama URL '${url}' points to a non-local address. ` +
    'Set llmAllowRemote: true to allow remote Ollama instances. ' +
    'WARNING: PII data will be sent to the remote server.'
  );
}

class LlmDetector {
  /**
   * @param {import('./config').ShieldConfig} config
   */
  constructor(config) {
    this._model = config.llmModel;
    this._baseUrl = _validateOllamaUrl(
      config.llmOllamaUrl.replace(/\/+$/, ''),
      config.llmAllowRemote ?? false,
    );
    this._timeout = Math.ceil(config.llmTimeout / 1000); // curl uses seconds
    this._confidence = config.llmConfidence;
    this._locale = config.locale ?? 'en';
    /** @type {boolean|null} null = not checked yet */
    this._available = null;
    /** @type {BoundedCache} LRU cache with max 1024 entries */
    this._cache = new BoundedCache(1024);
    /** @type {Set<string>} Instance-level copy of excluded categories */
    this._excludedCategories = new Set(EXCLUDED_CATEGORIES);
    /** @type {Map<string, string>} Custom LLM categories: name → description */
    this._customCategories = new Map();
    for (const { name, description = '' } of (config.customLlmCategories ?? [])) {
      if (this._excludedCategories.has(name)) {
        console.warn(`CloakLLM: Custom LLM category '${name}' conflicts with excluded category — skipped`);
        continue;
      }
      this._customCategories.set(name, description);
    }
    /** @type {Function} Overridable for testing */
    this._execFileSync = cp.execFileSync;
  }

  /**
   * Add categories to the excluded list (instance-level, does not affect other instances).
   * Used for NER/LLM coordination when compromise handles PERSON/ORG/GPE.
   * @param {string[]} cats
   */
  static _cacheKey(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
  }

  addExcludedCategories(cats) {
    for (const cat of cats) {
      this._excludedCategories.add(cat);
    }
  }

  get _effectiveCategories() {
    const cats = new Set(LLM_CATEGORIES);
    for (const name of this._customCategories.keys()) {
      cats.add(name);
    }
    // Remove instance-level excluded categories
    for (const cat of this._excludedCategories) {
      cats.delete(cat);
    }
    return cats;
  }

  _checkAvailable() {
    if (this._available !== null) return this._available;
    try {
      const nullDevice = process.platform === 'win32' ? 'NUL' : '/dev/null';
      const stdout = this._execFileSync('curl', [
        '-s', '-o', nullDevice, '-w', '%{http_code}',
        '--max-time', '3',
        `${this._baseUrl}/api/tags`,
      ], { encoding: 'utf-8', timeout: 5000 });
      const statusCode = parseInt(stdout.trim(), 10);
      this._available = statusCode >= 200 && statusCode < 300;
      if (!this._available) {
        console.warn(`CloakLLM: Ollama returned HTTP ${statusCode} at ${this._baseUrl} — LLM detection disabled`);
      }
    } catch {
      console.warn(`CloakLLM: Ollama not available at ${this._baseUrl} — LLM detection disabled`);
      this._available = false;
    }
    return this._available;
  }

  _systemPrompt() {
    const cats = [...this._effectiveCategories].sort().join(', ');
    const excluded = [...this._excludedCategories].sort().join(', ');
    let prompt = (
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
    const hints = [...this._customCategories.entries()]
      .filter(([, desc]) => desc)
      .sort(([a], [b]) => a.localeCompare(b));
    if (hints.length > 0) {
      prompt += '\nCategory hints:';
      for (const [name, desc] of hints) {
        prompt += `\n- ${name}: ${desc}`;
      }
    }
    // Append locale hint if available
    const localeHint = LOCALE_HINTS[this._locale];
    if (localeHint) {
      prompt += `\n${localeHint}`;
    }
    return prompt;
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
    if (this._cache.has(LlmDetector._cacheKey(text))) {
      entities = this._cache.get(LlmDetector._cacheKey(text));
    } else {
      entities = this._queryOllama(text);
      this._cache.set(LlmDetector._cacheKey(text), entities);
    }

    // Sort by value length desc (longer matches first) — copy to avoid mutating cached array
    entities = [...entities].sort((a, b) => (b.value?.length ?? 0) - (a.value?.length ?? 0));

    const detections = [];
    for (const ent of entities) {
      const value = ent.value ?? '';
      const category = (ent.category ?? '').toUpperCase();

      if (value.length < 2) continue;
      if (!this._effectiveCategories.has(category)) continue;

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

module.exports = { LlmDetector, BoundedCache };
