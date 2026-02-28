# CloakLLM

**PII cloaking and tamper-evident audit logs for LLM API calls.**

CloakLLM intercepts your LLM API calls, detects and cloaks PII before it reaches the provider, and logs every event to a tamper-evident audit chain designed for EU AI Act Article 12 compliance.

> **Also available for Python:** `pip install cloakllm` — includes spaCy NER for name/org/location detection. See [CloakLLM Python](https://github.com/cloakllm/CloakLLM).

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

> **NER (names, orgs, locations)** is available in the [Python version](https://github.com/cloakllm/CloakLLM) via spaCy. JS NER support is on the roadmap.

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
}));
```

## EU AI Act Compliance

Article 12 of the EU AI Act requires tamper-evident audit logs for AI systems. Enforcement begins **August 2, 2026**. CloakLLM provides:

- **Hash-chained logs** — cryptographically linked, any modification breaks the chain
- **O(n) verification** — `cloakllm verify` audits the entire chain
- **No PII in logs** — only hashes and token counts are logged (original values never stored)
- **Event-level detail** — every sanitize/desanitize event is recorded

## Roadmap

- [ ] NER-based detection (names, orgs, locations) via compromise.js or similar
- [ ] Streaming response support
- [ ] Vercel AI SDK middleware
- [ ] LangChain.js integration
- [ ] OpenTelemetry span emission
- [ ] RFC 3161 trusted timestamping

## License

MIT — See [LICENSE](LICENSE).

## See Also

- **[CloakLLM Python](https://github.com/cloakllm/CloakLLM)** — Python version with spaCy NER + LiteLLM integration
