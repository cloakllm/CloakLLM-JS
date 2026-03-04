# CloakLLM

**PII cloaking and tamper-evident audit logs for LLM API calls.**

CloakLLM intercepts your LLM API calls, detects and cloaks PII before it reaches the provider, and logs every event to a tamper-evident audit chain designed for EU AI Act Article 12 compliance.

> **Also available for Python:** `pip install cloakllm` — includes spaCy NER for name/org/location detection. See [CloakLLM Python](https://github.com/cloakllm/CloakLLM-PY).

## Install

```bash
npm install cloakllm
```

## Quick Start

### With OpenAI SDK (one line)

```javascript
const cloakllm = require('cloakllm');
const OpenAI = require('openai');

const client = new OpenAI();
cloakllm.enable(client);  // That's it. All calls are now cloaked.

const response = await client.chat.completions.create({
  model: 'gpt-4o-mini',
  messages: [{
    role: 'user',
    content: 'Write a reminder for sarah.j@techcorp.io about the Q3 audit'
  }]
});
// Provider never saw "sarah.j@techcorp.io"
// Response has the real email restored automatically
```

### With Vercel AI SDK

```javascript
const { createCloakLLMMiddleware } = require('cloakllm');
const { generateText, wrapLanguageModel } = require('ai');
const { openai } = require('@ai-sdk/openai');

const middleware = createCloakLLMMiddleware();
const model = wrapLanguageModel({ model: openai('gpt-4o'), middleware });

const { text } = await generateText({
  model,
  prompt: 'Write a reminder for sarah.j@techcorp.io about the Q3 audit'
});
// Provider never saw "sarah.j@techcorp.io"
// Response has the real email restored automatically
```

Works with any AI SDK provider (OpenAI, Anthropic, Google, Mistral, etc.) and supports both `generateText` and `streamText`.

### Standalone

```javascript
const { Shield } = require('cloakllm');

const shield = new Shield();
const [sanitized, tokenMap] = shield.sanitize(
  'Send report to john@acme.com, SSN 123-45-6789'
);
// sanitized: "Send report to [EMAIL_0], SSN [SSN_0]"

// ... send sanitized text to any LLM ...

const restored = shield.desanitize(llmResponse, tokenMap);
// Original values restored
```

### Redaction Mode (irreversible)

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

const shield = new Shield(new ShieldConfig({ mode: 'redact' }));
const [redacted] = shield.sanitize('Email john@acme.com about Sarah Johnson');
// redacted: "Email [EMAIL_REDACTED] about [PERSON_REDACTED]"
// No token map stored — cannot be reversed
```

## What It Detects

| Category | Examples | Method |
|----------|----------|--------|
| `EMAIL` | `john@acme.com` | Regex |
| `SSN` | `123-45-6789` | Regex |
| `CREDIT_CARD` | `4111111111111111` | Regex |
| `PHONE` | `+1-555-0142` | Regex |
| `IP_ADDRESS` | `192.168.1.1` | Regex |
| `API_KEY` | `sk_live_abc123...` | Regex |
| `AWS_KEY` | `AKIAIOSFODNN7EXAMPLE` | Regex |
| `JWT` | `eyJhbG...` | Regex |
| `IBAN` | `DE89370400440532013000` | Regex |
| `PERSON` | John Smith | LLM (Local) |
| `ORG` | Acme Corp, Google | LLM (Local) |
| `GPE` | New York, Israel | LLM (Local) |
| `ADDRESS` | 742 Evergreen Terrace | LLM (Local) |
| `DATE_OF_BIRTH` | 1990-01-15 | LLM (Local) |
| `MEDICAL` | diabetes mellitus | LLM (Local) |
| `FINANCIAL` | account 4521-XXX | LLM (Local) |
| `NATIONAL_ID` | TZ 12345678 | LLM (Local) |
| `BIOMETRIC` | fingerprint hash | LLM (Local) |
| `USERNAME` | @johndoe42 | LLM (Local) |
| `PASSWORD` | P@ssw0rd123 | LLM (Local) |
| `VEHICLE` | plate ABC-1234 | LLM (Local) |

> **LLM categories** require opt-in (`llmDetection: true`) and a local [Ollama](https://ollama.com) instance. Data never leaves your machine.

## How It Works

```
Your app:      "Email sarah.j@techcorp.io about Project Falcon"
Provider sees: "Email [EMAIL_0] about Project Falcon"
You receive:   Original email restored in the response
```

1. **Detect** — Regex patterns find structured PII (emails, SSNs, credit cards, etc.)
2. **Cloak** — Replace with deterministic tokens: `[EMAIL_0]`, `[SSN_0]`
3. **Log** — Write to hash-chained audit trail (each entry includes previous entry's SHA-256 hash)
4. **Uncloak** — Restore original values in the LLM response

## Tamper-Evident Audit Chain

Every event is logged to JSONL files with hash chaining:

```json
{
  "seq": 42,
  "event_type": "sanitize",
  "entity_count": 3,
  "categories": {"EMAIL": 1, "SSN": 1, "PHONE": 1},
  "prompt_hash": "sha256:9f86d0...",
  "prev_hash": "sha256:7c4d2e...",
  "entry_hash": "sha256:b5e8f3..."
}
```

Modify any entry and every subsequent hash breaks. Verify with:

```bash
npx cloakllm verify ./cloakllm_audit/
```

## CLI

```bash
# Scan text for PII
npx cloakllm scan "Email john@test.com, SSN 123-45-6789"

# Verify audit chain integrity
npx cloakllm verify ./cloakllm_audit/

# Show audit statistics
npx cloakllm stats ./cloakllm_audit/
```

## Configuration

```javascript
const { Shield, ShieldConfig } = require('cloakllm');

const shield = new Shield(new ShieldConfig({
  detectEmails: true,        // default: true
  detectPhones: true,
  detectSsns: true,
  detectCreditCards: true,
  detectApiKeys: true,
  detectIpAddresses: true,
  detectIban: true,
  logDir: './my-audit-logs', // default: ./cloakllm_audit
  auditEnabled: true,        // default: true
  skipModels: ['ollama/'],   // skip local models
  customPatterns: [
    { name: 'EMPLOYEE_ID', pattern: 'EMP-\\d{6}' }
  ],

  // LLM Detection (opt-in, requires Ollama)
  llmDetection: true,                         // Enable LLM-based detection
  llmModel: 'llama3.2',                       // Ollama model
  llmOllamaUrl: 'http://localhost:11434',      // Ollama endpoint
  llmTimeout: 10000,                           // Timeout in ms
  llmConfidence: 0.85,                         // Confidence score
}));
```

## EU AI Act Compliance

Article 12 of the EU AI Act requires tamper-evident audit logs for AI systems. Enforcement begins **August 2, 2026**. CloakLLM provides:

- **Hash-chained logs** — cryptographically linked, any modification breaks the chain
- **O(n) verification** — `cloakllm verify` audits the entire chain
- **No PII in logs** — only hashes and token counts are logged (original values never stored)
- **Event-level detail** — every sanitize/desanitize event is recorded

## Roadmap

- [x] NER-based detection (names, orgs, locations) via local LLM
- [x] Local LLM detection (opt-in, via Ollama)
- [x] Streaming response support
- [x] Vercel AI SDK middleware
- [x] Redaction / scrubbing mode
- [ ] LangChain.js integration
- [ ] OpenTelemetry span emission
- [ ] RFC 3161 trusted timestamping

## License

MIT — See [LICENSE](LICENSE).

## See Also

- **[CloakLLM Python](https://github.com/cloakllm/CloakLLM-PY)** — Python version with spaCy NER + LiteLLM integration
