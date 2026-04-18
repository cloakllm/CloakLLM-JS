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

// v0.6.3 H2: SSRF hardening — IP-literal protections.
//
// The JS constructor stays synchronous (no breaking API change), so the
// hostname-rebinding mitigation that the Python SDK does at fetch time via
// re-resolution doesn't apply here — Node has no synchronous DNS. The
// realistic attack we DO close is an operator pasting a literal cloud
// metadata IP (or its IPv4-mapped IPv6 form) into config. Hostname-based
// rebinding (where the user's DNS server flips an answer between validation
// and curl spawn) is documented as a residual gap; if you set
// `llmAllowRemote: true`, point it at a hostname YOU control.

/**
 * v0.6.3 H2: Unwrap an IPv4-mapped IPv6 address (`::ffff:x.y.z.w`) to its
 * IPv4 form so range checks against IPv4 deny lists still apply. Returns
 * `null` if the input isn't an IPv4-mapped IPv6.
 */
function _unwrapIpv4MappedIpv6(ip) {
  if (typeof ip !== 'string') return null;
  // Normalize: lowercase, strip brackets if any
  const lower = ip.replace(/^\[|\]$/g, '').toLowerCase();
  // Match ::ffff:x.y.z.w
  const dotted = lower.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) return dotted[1];
  // Match ::ffff:hhhh:hhhh (hex form)
  const hex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const high = parseInt(hex[1], 16);
    const low = parseInt(hex[2], 16);
    return `${(high >> 8) & 0xff}.${high & 0xff}.${(low >> 8) & 0xff}.${low & 0xff}`;
  }
  return null;
}

/** v0.6.3 H2: Decimal IPv4 → integer (returns NaN on bad input). */
function _ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return NaN;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return NaN;
    n = n * 256 + v;
  }
  return n;
}

/**
 * v0.6.3 H2: True if the given IPv4 address falls in any of the always-deny
 * ranges (cloud metadata, multicast, etc.) regardless of allowRemote.
 *
 * NB: uses numeric range comparison rather than bitwise AND because JS
 * bitwise operators coerce to signed 32-bit, and any address > 2^31 comes
 * out negative — `(n & 0xffff0000) === 0xa9fe0000` evaluates to false even
 * when the bits match.
 */
function _isAlwaysDenyIpv4(ip) {
  const n = _ipv4ToInt(ip);
  if (Number.isNaN(n)) return false;
  // Always-deny ranges (mirror Python ALWAYS_DENY_NETWORKS):
  //   0.0.0.0/8        0x00000000 .. 0x00ffffff   "this network", aliases to localhost on Linux
  //   100.64.0.0/10    0x64400000 .. 0x647fffff   carrier-grade NAT (cloud metadata)
  //   169.254.0.0/16   0xa9fe0000 .. 0xa9feffff   link-local + AWS/GCP/Azure IMDS
  //   224.0.0.0/4      0xe0000000 .. 0xefffffff   multicast
  //   240.0.0.0/4      0xf0000000 .. 0xffffffff   reserved
  if (n <= 0x00ffffff) return true;
  if (n >= 0x64400000 && n <= 0x647fffff) return true;
  if (n >= 0xa9fe0000 && n <= 0xa9feffff) return true;
  if (n >= 0xe0000000) return true;  // covers 224.0.0.0/4 + 240.0.0.0/4 (everything from 224 up)
  return false;
}

/**
 * v0.6.3 H2: True if the given IPv4 address is in a permitted private range
 * (loopback, RFC1918). Accepted regardless of allowRemote.
 *
 * Same numeric-range approach as _isAlwaysDenyIpv4 to dodge the JS signed
 * bitwise trap.
 */
function _isPrivateIpv4(ip) {
  const n = _ipv4ToInt(ip);
  if (Number.isNaN(n)) return false;
  //   10.0.0.0/8       0x0a000000 .. 0x0affffff
  //   127.0.0.0/8      0x7f000000 .. 0x7fffffff
  //   172.16.0.0/12    0xac100000 .. 0xac1fffff
  //   192.168.0.0/16   0xc0a80000 .. 0xc0a8ffff
  if (n >= 0x0a000000 && n <= 0x0affffff) return true;
  if (n >= 0x7f000000 && n <= 0x7fffffff) return true;
  if (n >= 0xac100000 && n <= 0xac1fffff) return true;
  if (n >= 0xc0a80000 && n <= 0xc0a8ffff) return true;
  return false;
}

/** v0.6.3 H2: Permitted IPv6 ranges (loopback, ULA, link-local). */
function _isPrivateIpv6(ip) {
  if (typeof ip !== 'string') return false;
  const lower = ip.replace(/^\[|\]$/g, '').toLowerCase();
  if (lower === '::1') return true;                            // loopback
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;  // fc00::/7 ULA
  if (lower.startsWith('fe8') || lower.startsWith('fe9')
      || lower.startsWith('fea') || lower.startsWith('feb')) return true;  // fe80::/10
  return false;
}

/** v0.6.3 H2: Always-deny IPv6 ranges (multicast, unspecified). */
function _isAlwaysDenyIpv6(ip) {
  if (typeof ip !== 'string') return false;
  const lower = ip.replace(/^\[|\]$/g, '').toLowerCase();
  if (lower === '::') return true;                             // unspecified
  if (lower.startsWith('ff')) return true;                     // ff00::/8 multicast
  return false;
}

/**
 * v0.6.3 H2: Single source of truth for IP allow/deny.
 * Mirrors `_check_ip_allowed` in the Python SDK.
 */
function _checkIpAllowed(ip, allowRemote) {
  if (!ip || typeof ip !== 'string') return false;
  // Strip brackets (IPv6 hostnames from URL parsing arrive as `[::1]` on some
  // Node versions). Both the unwrapper and net.isIP need the bare form.
  const stripped = ip.replace(/^\[|\]$/g, '');
  // Unwrap IPv4-mapped IPv6 first so deny/private checks on the IPv4 form apply.
  const unwrapped = _unwrapIpv4MappedIpv6(stripped);
  const target = unwrapped !== null ? unwrapped : stripped;
  const ipKind = net.isIP(target);
  if (ipKind === 4) {
    if (_isAlwaysDenyIpv4(target)) return false;
    if (_isPrivateIpv4(target)) return true;
    return !!allowRemote;
  }
  if (ipKind === 6) {
    if (_isAlwaysDenyIpv6(target)) return false;
    if (_isPrivateIpv6(target)) return true;
    return !!allowRemote;
  }
  // Non-IP literal (hostname): syntactic check can't decide. Fall through to
  // the constructor's hostname handling (allowed iff allowRemote).
  return null;
}

// v0.6.3 H2: RFC 6761 §6.3 mandates that `localhost` and any `*.localhost`
// name MUST resolve to loopback. We trust the OS resolver to honour that —
// it's the same trust model Python's getaddrinfo()-based validator uses,
// just made explicit because Node lacks synchronous DNS.
const _LOOPBACK_HOSTNAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost']);
function _isCanonicalLoopbackHostname(host) {
  const lower = host.toLowerCase();
  if (_LOOPBACK_HOSTNAMES.has(lower)) return true;
  if (lower.endsWith('.localhost')) return true;  // *.localhost per RFC 6761
  return false;
}

function _validateOllamaUrl(url, allowRemote) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`CloakLLM: Invalid Ollama URL '${url}'.`);
  }
  const hostname = parsed.hostname;
  if (!hostname) {
    throw new Error(`CloakLLM: Ollama URL '${url}' has no hostname.`);
  }

  // v0.6.3 H2: RFC 6761 reserved loopback names trusted (regardless of allowRemote).
  if (_isCanonicalLoopbackHostname(hostname)) {
    return url;
  }

  // v0.6.3 H2: All IP literals — including IPv4-mapped IPv6, integer/octal
  // forms (rejected by net.isIP), and bracketed IPv6 — go through one filter.
  const decision = _checkIpAllowed(hostname, allowRemote);
  if (decision === false) {
    throw new Error(
      `CloakLLM: Ollama URL '${url}' resolves to a denied IP (cloud metadata ` +
      `service, multicast, or non-private address without llmAllowRemote: true). ` +
      `This protects against SSRF to cloud metadata endpoints (169.254.169.254 etc.) ` +
      `even when remote Ollama is enabled.`
    );
  }
  if (decision === true) {
    return url;
  }

  // decision === null → hostname is not an IP literal. JS has no synchronous
  // DNS, so we can't resolve here without breaking the synchronous constructor
  // contract. Allowed iff allowRemote — and we warn so the operator knows
  // hostname-rebinding mitigation is the operator's responsibility (point at
  // a hostname you control).
  if (allowRemote) {
    console.warn(
      `CloakLLM: Ollama URL '${url}' uses a hostname rather than an IP literal. ` +
      `JS cannot resolve at validation time; ensure the hostname's DNS is under ` +
      `your control to mitigate DNS-rebinding SSRF. Cloud metadata IP literals ` +
      `(169.254.169.254 etc.) are still blocked at the IP-literal level.`
    );
    return url;
  }

  throw new Error(
    `CloakLLM: Ollama URL '${url}' uses a non-IP hostname; cannot validate it ` +
    `as private at construction time. Use a private IP literal (127.0.0.1, ` +
    `10.x.x.x, etc.) or set llmAllowRemote: true. ` +
    `WARNING: when allowRemote is set, PII data will be sent to the remote server.`
  );
}

class LlmDetector {
  /**
   * @param {import('./config').ShieldConfig} config
   */
  constructor(config) {
    this._model = config.llmModel;
    // v0.6.3 H2: SSRF hardening landed for IP literals (cloud metadata, multicast,
    // IPv4-mapped IPv6 unwrap). The hostname-rebinding gap remains because Node
    // has no synchronous DNS — see _validateOllamaUrl for the hostname caveat.
    // We still warn on allowRemote=true so the operational risk of off-host PII
    // is visible.
    if (config && config.llmAllowRemote === true) {
      // eslint-disable-next-line no-console
      console.warn(
        '[cloakllm] llmAllowRemote: true — PII data will be transmitted to a ' +
        'non-local Ollama instance. Cloud metadata addresses (169.254.169.254 ' +
        'etc.) and other always-deny ranges are still blocked at the IP-literal ' +
        'level, but if you point at a hostname, ensure its DNS is under your ' +
        'control to mitigate DNS-rebinding SSRF. Prefer running Ollama locally.'
      );
    }
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

module.exports = {
  LlmDetector,
  BoundedCache,
  // v0.6.3 H2: exported for unit testing only — not part of the public API.
  _checkIpAllowed,
  _unwrapIpv4MappedIpv6,
  _isAlwaysDenyIpv4,
  _isPrivateIpv4,
  _validateOllamaUrl,
};
