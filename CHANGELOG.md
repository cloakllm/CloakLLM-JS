# Changelog

All notable changes to CloakLLM (JavaScript) will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-27

### Added

- PII detection engine with regex patterns (emails, SSNs, credit cards, phones, IPs, API keys, AWS keys, JWTs, IBANs)
- Deterministic tokenizer with reversible `[CATEGORY_N]` tokens
- Tamper-evident hash-chained audit logger (EU AI Act Article 12 compliance)
- Shield engine tying detection, tokenization, and audit into a single interface
- OpenAI SDK middleware integration (`cloakllm.enable(client)` / `cloakllm.disable(client)`)
- Vercel AI SDK middleware integration
- Multi-turn conversation support via reusable token maps
- Custom regex pattern support via `ShieldConfig.customPatterns`
- CLI commands: `scan`, `verify`, `stats`
- Full TypeScript type declarations (`index.d.ts`)
- Zero runtime dependencies — uses only Node.js builtins
- Test suite with 50 tests covering detection, tokenization, audit chain, and end-to-end flows
