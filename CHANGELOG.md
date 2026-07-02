# Changelog

All notable changes to CloakLLM (JavaScript) will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.0] - 2026-07-01

**Headline: Independent Verifiability.** A separate, zero-dependency package — [`cloakllm-verifier`](https://github.com/cloakllm/cloakllm-verifier) (`npm install cloakllm-verifier`) — lets an auditor verify every CloakLLM artifact (hash chain, RFC 3161 timestamps, KeyManifest provenance + revocation) and re-validate a compliance report **without trusting CloakLLM's code**. It reuses this package's own verify functions (single source of truth, no drift) and adds no runtime deps beyond `cloakllm`.

### Added
- **Per-article coverage matrix** in every compliance report — a machine-readable `coverage` block (report schema `1.0` -> `1.1`, additive) stating, per EU AI Act article, what CloakLLM provides and what remains the deployer's responsibility, plus an `out_of_scope` list. Byte-identical with the Python SDK. Rendered as a `## Coverage matrix` table in the Markdown report.
- **`verifyTimestampToken` and `requestTimestamp` are now exported** from the package entrypoint (previously reachable only via `src/timestamping`), with `index.d.ts` type declarations. Enables the standalone verifier to reuse them.

## [0.11.5] - 2026-06-23

### Fixed
- **StreamDesanitizer fidelity** (LOW — cosmetic, no PII leak): streamed desanitize now byte-equals batch desanitize for every chunking. When the user's text contained a literal `[CATEGORY_N]`-style token, sanitize escaped it to fullwidth brackets and the stream emitted the escaped sequence in fragments, so it leaked through fullwidth instead of being restored to `[…]`. The stream now buffers fullwidth brackets (`U+FF3B`/`U+FF3D`) across chunk boundaries. Token-injection prevention was unaffected. Regression-guarded by a streaming-vs-batch fuzz (`test/test_stream_fuzz.js`). Rides the next version bump.

## [0.11.4] - 2026-06-23

Mirror of cloakllm-py 0.11.4. **Headline: SECURITY — sanitize PII in tool-call arguments (outbound leak fix).**

### Fixed (no-PII-to-provider leak — HIGH)
- **OpenAI middleware**: tool-call arguments (`tool_calls[].function.arguments` / legacy `function_call.arguments`) are now sanitized outbound and restored inbound (all choices). Previously only message `content` was sanitized, so PII in tool calls reached the provider raw in tool-use history.
- **Vercel middleware**: tool-call `args` and tool-result `result` (JSON-serializable objects) are sanitized via a JSON round-trip outbound and restored inbound. Previously tool-call/tool-result parts were passed through unsanitized.
- **`enable()` / `disable()` banners are ASCII-only** — the `🛡️` emoji `console.log` crashed nothing in Node, but parity with Python + safety on exotic terminals.

### Tests
- New tool-call middleware regression tests (outbound stripped, inbound restored per choice, ASCII banner). 757 → **759**.

### Note
Re-aligned to 0.11.4 (py = js = mcp).

## [0.11.3] - 2026-06-23

Mirror of cloakllm-py 0.11.3. **Headline: NER `nerRequired` knob for cross-SDK parity.** The JS NER backend already degraded to regex-only when compromise was unavailable (fail-open); this adds the opt-in fail-closed switch so deployments that depend on NER can hard-fail instead.

### Added
- `ShieldConfig.nerRequired` (env `CLOAKLLM_NER_REQUIRED`, default `false`) — when `true`, an unavailable NER backend throws instead of degrading. Mirrors Python's `ner_required`. `NerBackend` now reads config; default behavior (degrade + warn) unchanged.
- Regression tests for the degrade + hard-fail paths.

### Note
Re-aligned to 0.11.3 (py = js = mcp). `index.d.ts` updated.

## [0.11.2] - 2026-06-23

Mirror of cloakllm-py 0.11.2. **Headline: detection hardening — close real PII leaks found by an honest benchmark.**

### Fixed (no-PII-invariant leaks — HIGH)
- **Spaced / dashed credit cards** partially leaked + were mistyped as PHONE (`"4111 1111 1111 1111"` → `"[PHONE_0] 1111"`). CC regex now matches space/dash-grouped Visa/MC/Amex(4-6-5)/Discover via a back-referenced separator and claims the full span before PHONE.
- **Spaced IBANs** leaked fragments because IBAN was ordered after PHONE; IBAN now precedes PHONE and captures the whole span.
- **IPv6 addresses** were entirely undetected and leaked verbatim; `IP_ADDRESS` now matches IPv6 (ReDoS-safe) + IPv4.

### Added
- 18 detection regression tests (`test/test_detection_v0112.js`) asserting the fixes on `sanitize()` output. 735 → **753** tests.

### Known limitations
- Non-US national phone formats without an intl prefix need locale config; obfuscated PII is out of scope; PHONE still over-redacts some long digit runs (safe direction). Re-aligned to 0.11.2.

## [0.11.1] - 2026-06-23

Mirror of cloakllm-py 0.11.1. **Headline: trusted-timestamping crypto hardening — OpenSSL-differential verification + DER fuzzing.**

### Added
- **OpenSSL-differential test suite** — the zero-dep verifier MUST reach the same verdict as `openssl ts -verify` across a committed token corpus (valid + four single-defect negatives + a real freetsa.org token). Independent-implementation corroboration. Runs in CI (openssl ships on the runners).
- **DER-parser fuzz harness** — random/truncated inputs never throw and are rejected; bit-flipped real tokens never throw. Crash/DoS resistance for the hand-rolled DER parser.

### Fixed (hardening)
- **ESS `SigningCertificateV2` attribute now required and verified** (RFC 3161 §2.4.1 / RFC 5035). The differential surfaced that the v0.11.0 verifier accepted a token lacking the ESS signing-certificate binding OpenSSL requires (a cert-substitution surface). Missing or mismatched ESS is now rejected. Real TSAs always include it, so real checkpoints are unaffected.

### Tests
- JavaScript 729 → **735** (+6). Re-aligned to 0.11.1 (py = js = mcp). Also backfilled `index.d.ts` config fields for v0.7.1 / v0.8.1 / v0.9.0.

## [0.11.0] - 2026-06-22

Mirror of cloakllm-py 0.11.0. **Headline: RFC 3161 trusted timestamping (checkpoint-level)** -- an external clock proving "every entry up to seq N existed no later than T", closing the backdating gap KeyManifest can't.

### Added
- **`chain_checkpoint` event** + `checkpoint_context` validation (TS-1): closed whitelists, https-only TSA URL, hex/base64 caps, coupling check. No PII / no content -- a hash, a URL, an opaque token only.
- **RFC 3161 client** (TS-2): `requestTimestamp()` -- **zero runtime dependencies**. A minimal hand-rolled DER builder/parser handles the fixed RFC 3161 structure; Node's built-in `crypto.X509Certificate` + `crypto.verify` do the signature math.
- **`shield.checkpoint()`** (TS-3, async) + opt-in auto-cadence (`timestampIntervalEntries`, default 0). Best-effort -- a TSA outage never breaks the writer.
- **Offline verifier** (TS-4): `verifyTimestampToken()` -- messageImprint + CMS signature (reads the digest algorithm from the token; SHA-256 **and** SHA-512) + optional cert-chain; extracts genTime. Validated against real freetsa.org tokens and byte-compatible with the Python verifier.
- **Report rollup** (TS-5): `timestamped_checkpoints` / `checkpoints_verified` / `earliest_provable_time` / `checkpoint_tsa_distribution`; failed-token verification -> NON_COMPLIANT (verify-don't-assert).

### Compatibility
- **Drop-in safe from 0.10.x.** Opt-in; no TSA configured -> no new behavior, no network. Zero new runtime deps (the doctrine holds). All v0.6.1+ chains verify.

## [0.10.3] - 2026-06-18

Mirror of cloakllm-py 0.10.3 — **compliance-report integrity release** (six bugs found by a deep audit + security review, all fixed + regression-guarded). No public API change.

### Fixed
- **CRITICAL-1** — `generateComplianceReport()` now actually runs `verifyChain()` and reports `NON_COMPLIANT` / `chain_integrity: broken` on a tampered log (was presumed-valid → false "verified / COMPLIANT").
- **CRITICAL-2** — removed the dead `signaturesValid < entriesWithCerts` verdict guard that falsely implied per-signature verification (the log stores only a cert hash). Attestation verdict now comes from KeyManifest provenance.
- **HIGH-3** — `buildReport` no longer corrupts aggregates on malformed `categories` (non-object, or non-integer counts are skipped).
- **HIGH-4** — `context-analyzer` `token_density`/`risk_score` now use a shared int-when-whole 3dp helper, byte-identical with Python in the audit hash chain (was `Math.round` half-up + int `0`/`1` vs Python float `0.0`/`1.0`).
- **HIGH-5** — `canonicalJson` now **rejects** `__proto__`/`constructor`/`prototype` keys (was silently dropping them, which diverged from Python and hid the key from the hash).
- **MEDIUM-6** — an `articles` filter can no longer hide a `pii_in_log=true` violation; the invariant is evaluated globally.

JS 687 → 719 tests (+32, incl. `test_v0103_audit_fixes.js`). Drop-in safe from 0.10.x.

## [0.10.2] - 2026-06-18

Mirror of cloakllm-py 0.10.2 (there was no JS 0.10.1 — that was a Python-only dev-dependency patch). **Two correctness fixes in the v0.10.0 Article 50 report logic, found by a post-release adversarial review.** No API or schema change.

### Fixed
- **C1 (cross-SDK report divergence):** `label_coverage_pct` could differ from the Python SDK on a `.xx5` rounding boundary (JS `Math.round` rounds half up; Python `round()` uses banker's rounding) — e.g. 1 labeled of 800 → JS `0.13` vs Python `0.12`, breaking the byte-identical report guarantee. `_pct` now uses **exact integer arithmetic** (`Math.floor((10000*n + Math.floor(d/2))/d)`), identical to Python. Other coverage values unchanged.
- **H1 (false NON_COMPLIANT on non-synthetic content):** the Article 50 rollup + verdict now count **synthetic events only** (`synthetic === true`). A `content_generation` event with `synthetic:false, labeled:false` no longer flips the verdict to NON_COMPLIANT — Article 50 labeling applies to AI-generated content only. Default usage (`synthetic:true`) is unchanged.

Regression-guarded (+6 tests). Drop-in safe from 0.10.0.

## [0.10.0] - 2026-06-17

Mirror of cloakllm-py 0.10.0. **Headline: EU AI Act Article 50 content-labeling compliance record-keeping.** Cross-SDK byte-equivalent: the `EU_AI_Act_Art_50` rollup and `label_coverage_pct` (int when whole, 2dp on fractions) match Python exactly.

### Added
- **`content_generation` audit event** + `content_context` validation (A50-1): closed whitelists for `modality` (text|image|audio|video) and `disclosure_method` (c2pa|watermark|metadata|visible_notice|none), bool/hash typing, NUL/oversize rejection, the no-content-in-logs invariant (a `content`/`text`/`output`/etc. key is a hard rejection), and event_type coupling (the field may ONLY appear on `content_generation` events).
- **`Shield.recordContentGeneration({...})`** (A50-2). The asset never reaches CloakLLM; pass a caller-computed `contentHash`. `article_ref=[Art_12,Art_19,Art_50]` in compliance mode.
- **Article 50 report rollup** (A50-3): `generation_events`, `labeled_events`, `label_coverage_pct`, `deepfake_events`, `modality_distribution` -- attached ONLY to the Art_50 row (the Art_4a-only invariant, applied to Article 50). Merge-not-replace fill.
- **Verdict extension** (A50-4): any unlabeled synthetic-content event flips the report to NON_COMPLIANT.
- **TypeScript declarations** for `recordContentGeneration` (and the previously-undeclared `recordKeyRevocation`).

### Compatibility
- **Drop-in safe from v0.9.0.** Additive only; pre-v0.10.0 chains have no Art_50 row. All v0.6.1+ chains verify.
- 640 -> 687 tests (+47).

## [0.9.0] - 2026-06-10

Mirror of cloakllm-py 0.9.0. **Headline: Key Revocation.** Cross-SDK byte-equivalent `list_hash` verified (`ead04756...` matches Py for fixed-input test).

**BREAKING (the scheduled one):** `verifyAudit({legacyCanonical: true})` now throws (sunset phase 2). Pre-v0.6.1 chains must be re-archived under v0.6.1..v0.8.x first.

### Added

- **`RevocationList` + `deriveRevocationList()`** (RV-1) -- root-signed out-of-band artifact; permanent entries; order-sensitive hash; valid empty list.
- **`verifyKeyProvenance` check #6** (RV-2) -- `revocationList` option; 5 status values; REVOKED + LIST_INVALID fail; X.509/OCSP cert-predates semantics; runs standalone without manifest.
- **`shield.recordKeyRevocation()`** advisory event + **`ShieldConfig.revocationListPath`** with own-key fail-hard at construction (RV-3, full Py parity per locked Open Q3).
- **`provenance_summary` revocation rollup** (RV-4, additive) + `revocationListPath` option on `generateComplianceReport()`. KM-9 fill switched to `Object.assign` merge (same replace-bug fix as Py).

### Removed

- **`legacyCanonical` encoder path** (LC-1 phase 2). `_legacyCanonicalJson` deleted from `_canonical.js`; `computeHash` options removed; `verifyChain({legacyCanonical: true})` throws an actionable Error for one more cycle; hard-delete in v1.0.

### Tests

- 622 -> 640 tests (+18 net): new `test/test_revocation_list.js` (+22 covering RV-1/2/3/4 + LC-1), minus 5 removed legacy-shim tests, plus 1 removal guard.

### Compatibility

- All v0.6.1+ chains verify unchanged. Revocation surface opt-in additive. Cross-SDK canonical parity preserved.

## [0.8.2] - 2026-05-31

**No JS-side changes.** Version bump for lockstep with cloakllm-py 0.8.2 (Ed25519-backend-missing hardening, Python-only). JS uses Node's built-in `crypto` module for Ed25519 — zero runtime dependencies, no install footgun. The v0.8.1 KeyManifest surface in JS is unaffected.

## [0.8.1] - 2026-05-31

Mirror of cloakllm-py 0.8.1. **Headline: KeyManifest -- externally-verifiable key provenance.** Drop-in safe from v0.8.0.

### Added

- **`KeyManifest` class + `deriveKeyManifest()`** (KM-1) -- binds a signing key to a deployer identity + validity window. Cross-SDK byte-equivalent `manifest_hash` (verified vs Python: `5b8e0fd8...` matches in both for fixed-input test).
- **`verifyKeyProvenance()` + `ProvenanceReport`** (KM-2) -- 5 independent checks + `clockSkewSeconds` opt-in tolerance. Backward-compat `manifest=null` falls through to signature-only.
- **`key_registered` audit event** (KM-3) -- Shield emits on init when `deployerId` set. Allow-duplicate emission, verifier dedups by `manifest_hash`. B3 schema + `_validateKeyManifest()` extended.
- **`shield.generateComplianceReport()` aggregator** (KM-9) -- fills the v0.8.0-reserved `attestation.provenance_summary` slot. Pre-v0.8.1 chains stay all-null. **Numeric parity fix**: whole-number percentages emitted as int in both SDKs (the `100.0` vs `100` divergence class flagged in v0.7.0 lessons).
- **`ShieldConfig.deployerId` + `keyValidFrom` + `keyValidUntil`** (and `CLOAKLLM_DEPLOYER_ID` / `CLOAKLLM_KEY_VALID_FROM` / `CLOAKLLM_KEY_VALID_UNTIL` env).
- **AUDIT-3 hardening from day 1** -- `_validateIso8601Utc`, `_validateKeyManifest`, `_parseIso8601Safe` reject malformed inputs. JS-specific: `_isPrototypePollutionKey` check on the new `key_manifest` allow-list keys.

### Tests

- 595 -> 622 tests (+27). New `test/test_key_manifest.js` covers KM-1 (11 tests), KM-2 (8 tests), KM-3 (3 tests), AUDIT-3 (1 test), KM-7 (2 tests). `test/test_compliance_report.js` adds 2 KM-9 tests. Full v0.6.x / v0.7.x / v0.8.0 audit-chain verify continues green.

### Compatibility

- All v0.6.x / v0.7.x / v0.8.0 audit chains verify under v0.8.1 unchanged.
- `SanitizationCertificate.verify(publicKey)` v0.6.x API unchanged. KeyManifest is opt-in additive.
- New `key_manifest` field on audit entries is null-by-default. Cross-SDK canonical-JSON parity preserved (900-byte byte-equivalent v0.8.1 report verified).

## [0.8.0] - 2026-05-31

Mirror of cloakllm-py 0.8.0. **Headline: `shield.generateComplianceReport()` -- end-to-end EU AI Act audit reports** (JSON + Markdown; PDF is Python-only because `reportlab` is a Python-native lib). Drop-in safe from v0.7.1. All v0.7.x audit chains verify under v0.8.0.

### Added

- **`shield.generateComplianceReport({periodFrom, periodTo, articles, format, outPath, includeDecisions})`** -- new method. Reads the audit chain from `config.logDir`, aggregates per-article (Article 12 / Article 19 / Article 4a / GDPR 5+25), computes verdict, returns the structured report dict (`format: 'json'`) or rendered Markdown string (`format: 'markdown'`). PDF rejected at API layer with a clear error pointing to the Python SDK / CLI.
- **`src/compliance-report.js`** -- pure-function `buildReport()` engine and `renderMarkdown()`. Cross-SDK JSON output is byte-equivalent to the Python output, including the v0.8.1 forward-compat `attestation.provenance_summary` slot with all-null KeyManifest fields.
- **`compliance_summary()` v0.8.0 fields** (CR8-9) -- `config_snapshot` now surfaces `decision_id_enabled` (always `true` since v0.7.1), `system_version_pin_configured` (`true` iff both `deploymentVersion` and `instructionVersion` are set), and `compliance_reporting_available` (`true`).
- **TypeScript declarations** -- new `ComplianceReportV080` interface and `generateComplianceReport` method on `Shield`. Forward-compat `attestation.provenance_summary` slot typed with nullable fields.

### Tests

- 574 -> 595 tests (+21): `test/test_compliance_report.js` covers per-article rollup (3 incl. **bias-stats-only-on-Art_4a correctness invariant**), `decision_id` reconciliation (3), schema contract (2), verdict (2), Markdown output (2 incl. ASCII-only assertion), format validation (2 -- PDF rejected with helpful error, unknown format rejected), attestation forward-compat (1), `compliance_summary` v0.8.0 fields (3), **AUDIT-3 adversarial-input hardening** (3 -- malformed entries, includeDecisions safety, string article_ref).

### Security

- **AUDIT-3 hardening**: `buildReport()` now coerces non-array `article_ref` to `[]` and skips non-string `timestamp` from sortable comparisons. Pre-fix, a hand-crafted audit entry with `timestamp=42` or `article_ref="EU_AI_Act_Art_12"` (string instead of array) would crash the reducer or silently corrupt per-article counts. Cross-SDK parity preserved (same hardening in Python).

### Compatibility

- All v0.6.x / v0.7.x audit chains verify under v0.8.0. New report-output schema is additive only. Cross-SDK byte-for-byte JSON parity preserved.

## [0.7.1] - 2026-05-19

Mirror of cloakllm-py 0.7.1. Drop-in safe from v0.7.0. All v0.7.0 audit chains verify under v0.7.1.

### Added

- **`AuditEntry.decision_id`** (optional, default `null`) -- per-inference audit anchor. ULID by default (auto-generated via `src/_ulid.js`, zero new deps). New `decisionId` option on `shield.sanitize/desanitize/sanitizeBatch/desanitizeBatch`. Propagates from sanitize to the matching desanitize via `tokenMap.decisionId`. C7.1-1.
- **`AuditEntry.system_version_pin`** (optional, default `null`) -- composed `<model>@<deploymentVersion>/<instructionVersion>` string. Deployer supplies `deploymentVersion` + `instructionVersion` via `ShieldConfig`. All three components required. B3 validator caps at 256 chars. C7.1-2.

### Security

- **AWS IPv6 IMDS gap closed (`_normalizeIpv6` + `fd00:ec2::/64` deny).** The v0.6.3 JS SSRF defense had a known residual: `fd00:ec2::254` lives inside the `fc00::/7` ULA range that `_isPrivateIpv6` permits. v0.7.1 adds an IPv6 normalizer that handles the three textual forms (compressed `::`, leading-zero `0ec2`, fully-expanded `0:0:0:0:0:0:254`) and now denies any address whose first two normalized groups are `fd00:0ec2:`. Cross-SDK parity with Python's v0.6.3 close. C7.1-3.

### Tests

- 538 -> 574 tests (+36): consolidated `test/test_v071_extensions.js` covering ULID generator (12 incl. parameterized accept/reject), decision_id end-to-end (8), system_version_pin (5), IPv6 SSRF defense incl. AWS IMDS deny (11). Cross-SDK fixtures regenerated.

### Compatibility

- **Backward compat:** all v0.7.0 audit chains verify under v0.7.1.

## [0.7.0] - 2026-05-19

**Headline: EU AI Act Article 4a Bias Detection Workflow.**

Mirror of cloakllm-py 0.7.0. Article 4a (May 7 2026 Digital Omnibus) permits processing GDPR Article 9 special-category data for bias detection / correction in AI systems under six safeguards; `BiasDetectionSession` operationalises all six.

### Added

- **`BiasDetectionSession`** (require: `purpose`, `necessityJustification` ≤ 2000 chars, `categoriesAllowed` subset of `SPECIAL_CATEGORY_CATEGORIES`, `maxLifetimeSeconds` 1..604800). No language-level `with` block in JS — use the static `BiasDetectionSession.run({...}, async (session) => {...})` helper which guarantees `.end()` runs on success or throw, or `.start()` / `.end()` explicitly inside try/finally.
- **8 new special-category PII categories** in `SPECIAL_CATEGORY_CATEGORIES` and `BUILTIN_CATEGORIES`: `RACE`, `ETHNICITY`, `RELIGION`, `POLITICAL_OPINION`, `HEALTH_BIOMETRIC`, `SEXUAL_ORIENTATION`, `TRADE_UNION`, `GENETIC`. Not auto-detected — introduced only via `session.pseudonymise(text, { forceCategories: [[start, end, category], ...] })`.
- **4 new audit event types** in the hash chain: `bias_session_start`, `bias_pseudonymise`, `bias_finding`, `bias_session_end`. Strict-validated `bias_context` field on each (per-key allow-list, per-key length caps, PII-forbidden-key list). When `complianceMode: 'eu_ai_act_article12'` is set, `EU_AI_Act_Art_4a` is appended to `article_ref`.
- **Typed exceptions**: `BiasDetectionError`, `BiasDetectionScopeError`, `BiasDetectionTimeoutError`, `BiasDetectionStateError`. All extend `Error`.
- **Full TypeScript declarations** for the new API in `src/index.d.ts`.
- **Cross-SDK fixture `audit_chain_bias_js.jsonl`** + I7 test that the chain Python writes verifies under JS `verifyChain` and vice versa.

### Notes

- `canonicalJson` documents the cross-SDK numeric invariant: Python's `json.dumps(0.0)` → `"0.0"`, JS's `JSON.stringify(0.0)` → `"0"`. New Python audit-log call sites must pass int 0 for zero-valued numeric fields. JS handles this automatically.

### Test suite growth

488 → 536 tests (added bias-detection suite + cross-SDK bias-chain verification).

## [0.6.5] - 2026-04-24

Drop-in safe from v0.6.4. Mirror of cloakllm-py 0.6.5 + cloakllm-mcp 0.6.5
— adds a CI install-smoke step learned from the v0.6.4.post1 FastMCP
hotfix postmortem.

### CI / supply-chain hardening

- **New pack-smoke step in `ci.yml`.** Runs `npm pack` to produce the
  publishable tarball, then installs it into a fresh directory (no
  `npm install` shortcut over the local checkout) and runs a round-trip
  sanitize/desanitize via `require('cloakllm')`. Catches broken `files`
  field, missing dist files, or package.json metadata that would only
  surface on `npm install` from the registry. Runs on Node 22 only
  (the matrix above already covers test-suite breadth across 18/20/22).

## [0.6.4] - 2026-04-20

Polish release — v0.6.4 round-up of items the v0.6.3 review pass parked.
Safe drop-in upgrade.

### Hardening

- **G8 — Timing-safe hash comparison in `verifyChain`.** `storedHash !== recomputed`
  short-circuits character-by-character; replaced with
  `crypto.timingSafeEqual` (with length pre-check, since the API throws
  on length mismatch). Defense-in-depth on `verifyChain` timing channel.

### Correctness

- **G9 — `Object.create(null)` accumulator in `_legacyCanonicalJson`.** The
  filter at line 115 already strips `__proto__`/`constructor`/`prototype`
  before any assignment, so functional behaviour is unchanged. `Object.create(null)`
  is the maximally strict accumulator — even if a future change drops
  the filter, the prototype-less base means `o['__proto__'] = X` creates
  an own property rather than triggering `Object.prototype`'s setter.

### Ergonomics

- **G10 — JSDoc for `verifyChain.legacyCanonical`.** Documents the v0.6.0
  Python-vs-JS canonicalizer asymmetry (Python escaped non-ASCII as
  `\uXXXX`; JS preserved UTF-8) and points to
  `CloakLLM/COMPLIANCE.md` § Cross-Language Compatibility for the
  per-SDK flag table. Same content was already in `Shield.verifyAudit`'s
  JSDoc; the lower-level `AuditLogger.verifyChain` was missed.
- **G12 — JS middleware idle TTL.** `_activeMaps` now stores `lastAccessed`
  (refreshed on retrieval via `_getActiveMap`) instead of `created`.
  Aligns with the MCP server's idle-refresh pattern. The current
  middleware's single-use-per-call semantics make this defense-in-depth
  rather than bug-fix, but it removes a future footgun and clarifies
  the eviction semantic ("untouched for 5 min" vs "5 min since first
  request").

### TypeScript types

- `auditStrictChain` and `auditStrictPaths` (added in v0.6.3 but missing
  from `index.d.ts`) declared on both `ShieldConfigOptions` (input) and
  `ShieldConfig` (runtime) shapes.
- `AuditLogger.verifyChain.options.legacyCanonical?: boolean` now
  documented in the type signature.

## [0.6.3] - 2026-04-19

JS mirror of the cloakllm-py v0.6.3 security release. See
`CloakLLM/COMPLIANCE.md` § "v0.6.3 Hardening Summary" for the full
audit-reviewer overview.

### Phase 0 — streaming audit

- **NEW-3** — OpenAI streaming wrapper writes a `desanitize_stream`
  audit entry per stream lifecycle (normal completion, errors,
  consumer-break). Mirrors Python wrappers.
- **P1-1** — `finish_reason` preserved at token boundaries (was
  swallowed when `delta.content` produced empty output).
- **P1-2** — `_safeErrorTypeName` handles `throw null`, `throw "string"`,
  primitives, etc. without crashing the streaming error handler.
- **P2-1** — `bytesProcessed` → `charsProcessed` rename (deprecated
  alias preserved with `console.warn`).

### Security — high severity

- **H2** — Ollama SSRF blocklist with numeric range arithmetic
  (avoiding the JS signed-32-bit bitwise trap that broke the obvious
  `(n & 0xffff0000) === 0xa9fe0000` pattern). RFC 6761 canonical
  loopback names trusted (`localhost`, `*.localhost`,
  `localhost.localdomain`, `ip6-localhost`). IPv4-mapped IPv6 unwrap
  for both dotted and hex forms. `192.0.0.0/24` covers Oracle Cloud
  IMDS. Known gap: `fd00:ec2::254` (AWS IPv6 IMDS in ULA range)
  deferred to v0.7.0 — Node lacks a synchronous IPv6 normalizer.
- **SEC-1** — `--max-redirs 0` on both curl call sites refuses HTTP
  3xx redirects. A malicious Ollama at a permitted IP could 301-redirect
  to cloud metadata, bypassing the H2 blocklist.
- **H3** — Desanitize `tokens_used` / `entity_details` filtered to
  present-only subset; `latency_ms` / `timing.*` bucketed to 10ms.
- **G2** — Desanitize `sanitized_hash` PII oracle closed
  (mirror of Python G2). `sanitized_hash == prompt_hash` on desanitize
  entries; restored PII never hashed.
- **H4** — Backward-scan audit chain recovery; `auditStrictChain` opt-in
  refuses silent GENESIS restart on full corruption; partial-write
  tail detection prepends `\n` on next write.
- **H5** — `logDir` and `attestationKeyPath` reject NUL bytes and
  symlinks at construction time. `auditStrictPaths` opt-in promotes
  outside-CWD warning to error.
- **SEC-3** — `Shield.exportComplianceConfig(outPath)` validates the
  runtime path through `_validatePath` (now exported from `config.js`).
  Opens with `O_NOFOLLOW` + `0o600` on POSIX; ELOOP raised as a clear
  TOCTOU error.
- **G7** — Audit dir mode `0o700`, audit log files mode `0o600` on
  POSIX. Windows path runs unchanged.
- **H9** — Prototype pollution defenses: `audit.js` metadata validators
  REJECT `__proto__`/`constructor`/`prototype` keys (was: silent
  `continue`). `customPatterns` name validation parity with
  `customLlmCategories`. `_legacyCanonicalJson` filters prototype
  keys before reduce. `Shield._accumulate` skips prototype-vector
  metric keys + uses `hasOwnProperty.call` for existence checks.

### Security — informational / observability

- **I3** — JS `verifyAudit()` JSDoc documents the v0.6.0 cross-SDK
  canonical-JSON asymmetry. Missing `legacyCanonical` JSDoc param
  added.
- **I5 / G3** — `Tokenizer.detokenize` AND `StreamDesanitizer.feed`
  fire a one-time `console.warn` per process when the LLM produces
  a case-variant of a canonical token. Shared module-level gate
  (`_caseVariantWarned`) so streaming + batched paths share the warn
  quota.
- **I6.1** — npm OIDC trusted publishing (auto-provenance) replaces
  long-lived NPM_TOKEN. Node 24 in publish workflow for npm CLI ≥ 11.5.
- **I7** — Cross-SDK round-trip fixtures (`audit_chain_js.jsonl`,
  `certificate_js.json`, mirrored `*_py.json`). Each SDK's tests
  verify the OTHER SDK's output.

### Audit-log shape changes (mostly informational)

- Desanitize entries: `entityCount` now means "tokens present in this
  call" (was: total in map). `tokensUsed` and `entityDetails` filtered
  to present-only subset. `sanitized_hash` equals `prompt_hash` (both
  hash the tokenized input). Reconstruct full map from the matching
  `sanitize` entry.

### Breaking changes

- External tools matching `sanitized_hash` against restored PII text on
  desanitize entries will no longer find matches — that capability
  WAS the G2 oracle. Switch to matching `prompt_hash` against
  tokenized text.

## [0.6.2] - 2026-04-17

### Added (hotfix release for v0.6.1 audit findings)

- **I2 — `test/test_audit_schema.js`.** The v0.6.1 plan committed to a JS mirror of the Python audit schema test (B3.5) but the JS file was never written. The `_validateAuditEntrySchema` function in `audit.js` is correct but had zero dedicated test coverage; this release adds the missing tests covering the 9-key allow-list, the legacy denylist, metadata length/depth bounds, and the always-on enforcement.

### Notes

- This is a **patch release**, not the second-tier security cleanup (deferred to v0.6.3).
- Version bumped to `0.6.2` (not `0.6.1.1`) because npm semver does not support 4-digit versions and we maintain version parity across all SDKs.

## [0.6.1] - 2026-04-16

### Security (blocker fixes from internal audit)

- **B1 — Cross-language canonical JSON.** Replaces the v0.6.0 replacer-based `JSON.stringify` with a hand-rolled canonical serializer (`src/_canonical.js::canonicalJson`) that produces byte-identical output to the Python SDK, including for non-ASCII keys/values, numeric-string keys, nested arrays, and prototype-pollution vectors (`__proto__` / `constructor` / `prototype` keys are skipped). Cross-SDK certificate / audit-chain verification now works for non-ASCII data.
- **B3 — Always-on allow-list audit schema validator.** Replaces v0.6.0's compliance-mode-gated denylist. Every audit write enforces:
  - top-level keys must be in the allow-list;
  - `entity_details` elements may only contain the 9 verified-allowed keys (`category, start, end, length, confidence, source, token, entity_hash, text_index`);
  - `metadata` values must be strict-typed and bounded (256-char value cap, depth 3, scalar/list/dict only).
- **B4 — MCP defaults to compliance mode** (Python `cloakllm-mcp` change; documented for cross-SDK awareness).

### Security (high-severity fixes)

- **H1 — ReDoS hardening.** Built-in regex patterns now go through the `_testRegexSafety` harness. `PHONE` and `IBAN` rewritten to eliminate ambiguity. New `_canonical.js` is prototype-pollution-safe (H9).
- **H1.4 — Input length cap.** New `ShieldConfig({ maxInputLength: ... })` (default 1MB). Raises on oversize input.
- **F1 — API_KEY pattern bound to `{20,512}`** with body allowing `-` and `_` so multi-segment keys (Anthropic, GitHub fine-grained PAT) are detected.
- **H6 — Dependency hygiene.** `npm audit` added to CI (non-fatal until v0.7). Dependabot config added.
- **H7 — CI/CD hardening.** All workflows now have explicit `permissions:` and `concurrency:` groups.
- **F5 — `legacyCanonical` shim.** Verify v0.5.x/v0.6.0 chains with `shield.verifyAudit({ legacyCanonical: true })` or `auditLogger.verifyChain({ legacyCanonical: true })`. Sunset in v0.7.0.

### Deprecations

- **F4 — `shield.analyze()` default `redactValues: false`.** v0.7.0 flips to `true`. Calling without explicit value emits a console warning.

### Known issues

- **`llmAllowRemote: true` SSRF bypass paths (H2).** Same gaps as the Python SDK. Runtime warning fires at `LlmDetector` init. Do not use in production until v0.6.2.
- **Cross-SDK verification of v0.6.0 legacy chains containing non-ASCII data.** JS v0.6.0 preserved UTF-8 in canonical JSON while Python v0.6.0 escaped non-ASCII as `\uXXXX`. Audit chains written by JS v0.6.0 containing non-ASCII data cannot be verified by the Python SDK with `legacy_canonical=True`, and vice versa. Re-write the chain by replaying through v0.6.1+ to get fully cross-SDK verifiable entries. ASCII-only legacy chains verify correctly across both SDKs. See `CloakLLM/COMPLIANCE.md` § Cross-Language Compatibility.

## [0.6.0] - 2026-04-16

### Added

- **Article 12 Compliance Mode** — formal EU AI Act compliance profile
  - `new ShieldConfig({ complianceMode: 'eu_ai_act_article12' })` enforces compliant audit log structure
  - Audit entries gain four new fields: `compliance_version`, `article_ref`, `retention_hint_days`, `pii_in_log`
  - Compliance fields are part of the SHA-256 hash chain (tamper-detectable)
  - Configurable retention hint via `ShieldConfig({ retentionHintDays: N })` — defaults to 180
- **`shield.complianceSummary()`** — structured coverage map of EU AI Act and GDPR articles
- **`shield.exportComplianceConfig(path)`** — exports a JSON snapshot for auditors
- **`shield.verifyAudit({ outputFormat: 'compliance_report' })`** — structured report with `verdict: 'COMPLIANT' | 'NON_COMPLIANT'`
- **`AuditLogger.verifyChain({ outputFormat })`** — same compliance report shape at the lower level
- **`_assertNoPiiInEntry` runtime guard** in `audit.js` — refuses entries with forbidden PII fields in `entity_details`

### Notes

- All changes backward-compatible. Default behavior unchanged when `complianceMode` is `null`.
- `shield.verifyAudit()` without arguments returns the existing `{valid, errors, finalSeq}` shape.
- KMS-backed signing keys are Python-only in v0.6 — JS continues to use local Ed25519 keys.

## [0.5.2] - 2026-04-06

### Added

- **Pluggable Detection Backends** — `DetectorBackend` base class for custom detection pipelines
  - New `backends/` module: `DetectorBackend`, `RegexBackend`, `NerBackend`, `LlmBackend`
  - `DetectionEngine` accepts optional `backends` parameter to replace the default pipeline
  - `Shield` accepts optional `{ backends }` option, forwarded to `DetectionEngine`
  - Custom backends implement `get name()` + `detect(text, coveredSpans)` method
  - TypeScript declarations for all backend classes
  - All backend classes exported from top-level `cloakllm` package

### Changed

- `DetectionEngine` refactored from inline 3-pass detection to backend pipeline orchestrator
- Metrics timing keys are now dynamic (`{backend.name}_ms`) instead of hardcoded `regex_ms`/`ner_ms`/`llm_ms`
- Attestation `detection_passes` derived from active backends instead of config introspection
- `_emptyMetrics()` changed from static to instance method (reads backend names)
- `_accumulate()` handles dynamic timing keys from custom backends
- PATTERNS single source of truth in `detector.js` (backends/regex.js imports from there)

### Removed

- Redundant final regex safety-check sweep in pattern compilation
- Duplicated `_testRegexSafety` in `DetectionEngine` (now delegates to `RegexBackend`)
- Unused `LOCALE_PATTERNS` and `NerDetector` imports from `detector.js`

## [0.5.1] - 2026-03-31

### Added

- **Normalized Token Standard** — formal specification for CloakLLM token format
  - New `token-spec.js` module: canonical regex, category registry, validation utilities
  - `validateToken()`, `parseToken()`, `isRedactedToken()`, `validateCategoryName()`
  - `BUILTIN_CATEGORIES`, `CLOAKLLM_TOKEN_PATTERN`, `MAX_TOKEN_LENGTH` constants
  - TypeScript declarations for all new exports

### Changed

- Tokenizer and stream modules now import from `token-spec` (single source of truth)
- Config validation now rejects custom LLM categories that collide with built-in names
- Token regex updated from `[A-Z_]+` to `[A-Z][A-Z0-9_]*` (stricter, spec-conformant)
- `API_KEY` regex aligned with Python (removed underscore from character class)
- `LLM_CATEGORIES` aligned with Python: `PERSON`, `ORG`, `GPE` removed (NER-only)

## [0.5.0] - 2026-03-30

### Added

- **Context-based PII leakage analysis** — new `ContextAnalyzer` class (`context-analyzer.js`)
  - Three heuristic signals: token density, identifying descriptors, relationship edges
  - `shield.analyzeContextRisk(sanitizedText)` — standalone analysis method
  - `contextAnalysis` config flag for automatic analysis after `sanitize()`
  - `contextRiskThreshold` config option (default: 0.7)
  - Risk assessment attached to `tokenMap.riskAssessment` when auto-analysis enabled
  - Risk assessment included in audit log entries
  - CLI `--context-risk` flag for `scan` command
  - TypeScript declarations for `ContextAnalyzer`, `RiskAssessment`

## [0.4.0] - 2026-03-23

### Added

- **Multi-language PII detection** — 13 locales with locale-specific regex patterns
  - Supported locales: `de`, `fr`, `es`, `it`, `pt`, `nl`, `pl`, `se`, `no`, `dk`, `fi`, `gb`, `au`
  - Locale-specific patterns for SSN, phone, IBAN, tax IDs, national ID numbers
  - New `locale` config option in `ShieldConfig`
- **NER via compromise** — optional `compromise` npm package for PERSON, ORG, GPE detection
  - `NerDetector` class with character offset extraction
  - Input truncation at 100K chars for safety
- `analyze({ redactValues: true })` option to mask PII values in analysis output
- Replay-resistant attestation certificates with UUID4 `nonce` field
- `verifyChain()` / `verifyAudit()` now return `finalSeq` for truncation detection
- Middleware TTL eviction (5-min) for `_activeMaps` to prevent memory leaks

### Security

- **Ollama SSRF prevention** — URL validation restricts to localhost/private IPs by default (`llmAllowRemote` opt-in)
- **LLM cache PII protection** — cache keys hashed with SHA-256 instead of raw text
- **CLI PII protection** — `--show-pii` flag required to display raw PII values (redacted by default)
- **StreamDesanitizer** now unescapes fullwidth brackets on output
- **ReDoS hardening** — 5 adversarial test inputs, 20ms threshold, built-in patterns tested at construction
- **Token pattern** extended to match `[CATEGORY_REDACTED]` tokens for consistent handling
- Removed unused `logOriginalValues` config option
- Path validation warnings for `logDir` and `attestationKeyPath` outside CWD
- Windows permission warning in `DeploymentKeyPair.save()`
- Full TypeScript declarations updated for all new APIs

## [0.3.2] - 2026-03-15

### Added

- **Cryptographic attestation** — Ed25519 digital signatures for sanitization certificates
  - `DeploymentKeyPair` — generate, save, load Ed25519 signing keys (Node.js built-in crypto, zero deps)
  - `SanitizationCertificate` — signed proof that a sanitization operation occurred
  - `MerkleTree` — binary Merkle tree for batch attestation with proof generation and verification
  - `deriveEntityHashKey()` — HKDF-SHA256 key derivation
  - `shield.verifyCertificate()` — verify a certificate's signature
  - `Shield.generateAttestationKey()` — convenience static method
- Attestation config: `attestationKey`, `attestationKeyPath`, `CLOAKLLM_SIGNING_KEY_PATH` env var
- Certificate attached to `tokenMap.certificate` after `sanitize()` and `sanitizeBatch()`
- Batch certificates include Merkle roots (`tokenMap.merkleTree`)
- Audit log entries include `certificate_hash` and `key_id` fields
- Full TypeScript declarations for all attestation types
- Cross-language compatible: certificates signed in Python verify in JS and vice versa

## [0.3.1] - 2026-03-15

### Added

- Detection benchmark suite: 108-sample labeled PII corpus (`benchmarks/corpus.json`)
- Benchmark harness measuring recall/precision/F1 per detection category (`benchmarks/evaluate.js`)
- CI-integrated threshold tests: overall recall >= 95%, precision >= 80%, per-category recall >= 80%
- CLI: `node benchmarks/evaluate.js [--json]` for standalone benchmark runs

## [0.3.0] - 2026-03-15

### Added

- `StreamDesanitizer` — incremental streaming desanitization state machine (`cloakllm/stream.js`)
- TypeScript types for `StreamDesanitizer` class
- Integration tests for OpenAI middleware (n>1 choices, streaming, edge cases)

### Changed

- OpenAI middleware streaming: replaced full-buffer approach with incremental `StreamDesanitizer`
- Vercel AI SDK middleware streaming: replaced buffered TransformStream with `StreamDesanitizer`
- All middleware paths now emit desanitized text as chunks arrive instead of buffering entire response

## [0.2.5] - 2026-03-15

### Changed

- Version bump to keep all packages in sync (no code changes)

## [0.2.4] - 2026-03-15

### Fixed

- LLM detector unbounded cache — replaced plain `Map` with `BoundedCache` (LRU, maxSize=1024) to prevent memory leaks in long-running services

## [0.2.3] - 2026-03-13

### Fixed

- Vercel AI SDK middleware token map fragility — replaced `WeakMap` (breaks when params object is spread/copied) with `Symbol.for('cloakllm.tokenMap')` property that survives object spread

## [0.2.2] - 2026-03-10

### Fixed

- **[SECURITY]** Multi-choice desanitization in OpenAI middleware — `_activeMaps.delete()` on first choice caused remaining choices to skip desanitization
- `enable()` silently ignoring new config on second call — now warns to call `disable()` first
- LLM detector `_checkAvailable()` not validating HTTP status code — curl exit 0 on 404/500 caused false availability
- LLM detector hardcoded `/dev/null` — now uses `NUL` on Windows for cross-platform support
- LLM detector `.sort()` mutating cached entities array — now copies before sorting
- PHONE filter not stripping `+` from digit count — `+` now excluded from minimum length check
- `_patchedClients` Set preventing garbage collection of discarded clients — changed to WeakSet

## [0.2.1] - 2026-03-10

### Added

- Per-entity HMAC hashing: `new ShieldConfig({ entityHashing: true, entityHashKey: "..." })` generates deterministic HMAC-SHA256 hashes per detected entity
- Hash included in `entityDetails` as `entity_hash` field
- Auto-generates random 32-byte hex key if enabled but no key provided
- TypeScript types updated: `entityHashing`, `entityHashKey` in config, `entity_hash` in `EntityDetail`
- Works with both `tokenize` and `redact` modes, and with `sanitizeBatch`
- 10 new tests for entity hashing (total: 130 tests)

## [0.2.0] - 2026-03-09

### Added

- Custom LLM detection categories: `new ShieldConfig({ customLlmCategories: [{ name: 'PATIENT_ID', description: 'Hospital patient ID' }] })` — define domain-specific semantic PII types for Ollama-based detection
- Excluded category conflict detection with console warnings
- Category description hints injected into Ollama system prompt
- TypeScript type: `customLlmCategories` in `ShieldConfigOptions`
- New tests for custom LLM categories (total: 120 tests)

## [0.1.9] - 2026-03-08

### Added

- Per-pass timing breakdown in audit log entries: `timing` object with `total_ms`, `detection_ms`, `regex_ms`, `llm_ms`, `tokenization_ms`
- `shield.metrics()` — accumulated performance metrics (call counts, total/avg latency, per-pass detection timing, entity counts by category)
- `shield.resetMetrics()` — clear accumulated metrics
- `DetectionEngine.detect()` now returns `{ detections, timing }` with per-pass millisecond breakdowns
- TypeScript types: `Timing`, `DetectorTiming`, `Metrics`
- 9 new tests for metrics and timing (total: 81 tests)

## [0.1.8] - 2026-03-07

### Added

- Batch processing API: `shield.sanitizeBatch(texts)` / `shield.desanitizeBatch(texts, tokenMap)` — shared token map, single audit entry
- `BatchEntityDetail` TypeScript interface (extends `EntityDetail` with `text_index`)
- `sanitizeBatch` / `desanitizeBatch` type declarations
- 9 new tests for batch operations (total: 72 tests)

## [0.1.7] - 2026-03-06

### Added

- `TokenMap.entityDetails` getter — per-entity metadata (PII-safe)
- `TokenMap.toReport()` — extended summary with entity details and mode
- `entity_details` field in audit log entries (included in hash chain)
- `EntityDetail` TypeScript interface
- 7 new tests for entity details

## [0.1.6] - 2026-03-04

### Added

- Redaction mode: `new ShieldConfig({ mode: 'redact' })` for irreversible PII removal — replaces entities with `[CATEGORY_REDACTED]`
- No token map stored in redact mode — desanitize() is a no-op
- `mode` field in audit log entries
- TypeScript type support for mode option
- 8 new tests for redaction mode (total: 88 tests)

## [0.1.5] - 2026-03-04

### Changed

- Version bump to stay in sync with cloakllm 0.1.5 (Python OpenAI SDK middleware)

## [0.1.4] - 2026-03-04

### Fixed

- OpenAI SDK streaming responses are now desanitized: chunks are buffered until completion, then the full text is desanitized and yielded as a single final chunk

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

[0.2.2]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.2.2
[0.2.1]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.2.1
[0.2.0]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.2.0
[0.1.9]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.9
[0.1.8]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.8
[0.1.7]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.7
[0.1.6]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.6
[0.1.5]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.5
[0.1.4]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.4
[0.1.3]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.3
[0.1.2]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.2
[0.1.1]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.1
[0.1.0]: https://github.com/cloakllm/CloakLLM-JS/releases/tag/v0.1.0
