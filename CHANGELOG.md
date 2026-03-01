# Changelog

All notable changes to CloakLLM (JavaScript) will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-03-02

### Fixed

- Custom regex patterns now take priority over built-in patterns during detection, so user-defined patterns correctly match before built-ins claim overlapping spans

## [0.1.2] - 2026-03-01

### Changed

- Chore: added `package-lock.json` to `.gitignore`

## [0.1.1] - 2026-03-01

### Added

- Local LLM detection (opt-in, via Ollama) for semantic PII: names, orgs, locations, addresses, medical info, financial data, national IDs, biometrics, usernames, passwords, vehicle info
- LLM detection config: `llmDetection`, `llmModel`, `llmOllamaUrl`, `llmTimeout`, `llmConfidence`
- TypeScript definitions for LLM detection config fields
- Vercel AI SDK middleware integration

### Fixed

- Strengthened ReDoS safety check for custom regex patterns (longer test input, stricter threshold)
- API_KEY regex now uses optional separator `[-_]?` to match Python SDK behavior

## [0.1.0] - 2026-02-27

### Added

- PII detection engine with regex patterns (emails, SSNs, credit cards, phones, IPs, API keys, AWS keys, JWTs, IBANs)
- Deterministic tokenizer with reversible `[CATEGORY_N]` tokens
- Tamper-evident hash-chained audit logger (EU AI Act Article 12 compliance)
- Shield engine tying detection, tokenization, and audit into a single interface
- OpenAI SDK middleware integration (`cloakllm.enable(client)` / `cloakllm.disable(client)`)
- Multi-turn conversation support via reusable token maps
- Custom regex pattern support via `ShieldConfig.customPatterns`
- CLI commands: `scan`, `verify`, `stats`
- Full TypeScript type declarations (`index.d.ts`)
- Zero runtime dependencies — uses only Node.js builtins
- Test suite with 50 tests covering detection, tokenization, audit chain, and end-to-end flows

[0.1.3]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.3
[0.1.2]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.2
[0.1.1]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.1
[0.1.0]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.0
