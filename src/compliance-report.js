/**
 * v0.8.0 CR8: compliance reporting (JS mirror of cloakllm-py/cloakllm/compliance_report.py).
 *
 * Outputs JSON + Markdown. PDF is Python-only (reportlab is a Python-native lib).
 * For PDF, users go through the Python SDK or the CLI.
 *
 * The JSON output shape is byte-equivalent to the Python output, including the
 * v0.8.1 forward-compat attestation `provenance_summary` slot with null-filled
 * KeyManifest fields. This is how the I7 cross-SDK fixture parity continues.
 */

'use strict';

const SCHEMA_VERSION = '1.0';
const ATTESTATION_SCHEMA_VERSION = '1.0';

const _BIAS_EVENT_TYPES = new Set([
  'bias_session_start', 'bias_pseudonymise', 'bias_finding', 'bias_session_end',
]);

// v0.10.0 A50-3: Article 50 content-labeling event type + the article whose
// row the content-labeling stats attach to (and ONLY that row).
const _CONTENT_GENERATION_EVENT_TYPE = 'content_generation';
const _ART_50 = 'EU_AI_Act_Art_50';

/**
 * Percentage rounded to 2 dp (round half up), emitted as int when whole.
 *
 * v0.10.2 C1 fix: computed in EXACT INTEGER arithmetic. The old
 * `Math.round(10000*n/d)/100` rounds half toward +Inf, while Python's
 * `round(x,2)` uses banker's rounding (round-half-to-even) -- so the two
 * diverged on any `.xx5` boundary (1 labeled of 800 -> JS 0.13 vs Py 0.12),
 * silently breaking the cross-SDK byte-identical report guarantee. The
 * integer form `(10000*n + floor(d/2)) idiv d` is deterministic and matches
 * Python's `(10000*n + d//2)//d` exactly (Number is exact for these
 * magnitudes). JS stringifies whole numbers without a decimal, so the
 * int-when-whole behaviour is automatic. Returns 0 when denominator is 0.
 */
function _pct(numerator, denominator) {
  if (!denominator) return 0;
  const centi = Math.floor((10000 * numerator + Math.floor(denominator / 2)) / denominator);
  return centi / 100;
}

function _inPeriod(ts, periodFrom, periodTo) {
  if (!ts) return false;
  if (periodFrom && ts < periodFrom) return false;
  if (periodTo && ts > periodTo) return false;
  return true;
}

function _emptyAttestation() {
  // Shape-compatible with v0.8.1 KeyManifest extensions (manifest fields null).
  return {
    schema_version: ATTESTATION_SCHEMA_VERSION,
    entries_with_certificates: 0,
    signatures_valid: 0,
    key_ids: [],
    provenance_summary: {
      manifests_found: null,
      manifests_valid: null,
      within_validity_window_pct: null,
      root_signature_status_distribution: null,
      // v0.9.0 RV-4 (additive): revocation rollup. false/null when no
      // revocation list was supplied to the report.
      revocation_checked: false,
      revoked_keys_found: null,
      certs_after_revocation: null,
    },
  };
}

/**
 * v0.9.0 RV-4: fill the revocation rollup. Mirror of cloakllm-py
 * _fill_revocation_summary. No-op when revocationList is null.
 */
function _fillRevocationSummary({ auditEntries, periodFrom, periodTo, attestation, revocationList }) {
  if (revocationList == null) return;

  const revokedKeysSeen = new Set();
  let certsAfter = 0;
  for (const entry of auditEntries) {
    if (!entry.certificate_hash) continue;
    if (!_inPeriod(entry.timestamp, periodFrom, periodTo)) continue;
    const kid = entry.key_id;
    if (typeof kid !== 'string' || kid.length === 0) continue;
    const revEntry = revocationList.findEntry(kid);
    if (revEntry === null) continue;
    revokedKeysSeen.add(kid);
    const ts = entry.timestamp;
    if (typeof ts === 'string' && ts >= revEntry.revoked_at) {
      certsAfter += 1;
    }
  }

  attestation.provenance_summary.revocation_checked = true;
  attestation.provenance_summary.revoked_keys_found = revokedKeysSeen.size;
  attestation.provenance_summary.certs_after_revocation = certsAfter;
}

/**
 * v0.8.1 KM-9: aggregate ProvenanceReports into attestation.provenance_summary.
 *
 * Mirror of cloakllm-py _fill_provenance_summary. Walks the chain for
 * key_registered events, dedups by manifest_hash, runs verifyKeyProvenance
 * for each certified entry, populates the four aggregate fields.
 *
 * Pre-v0.8.1 chains (no key_registered events) -> all fields stay null.
 */
function _fillProvenanceSummary({ auditEntries, periodFrom, periodTo, attestation }) {
  const {
    KeyManifest, verifyKeyProvenance, SanitizationCertificate,
  } = require('./attestation');

  // Resolve KeyManifests, dedup by manifest_hash.
  const manifestsByKeyId = {};
  const seenHashes = new Set();
  for (const entry of auditEntries) {
    if (entry.event_type !== 'key_registered') continue;
    if (!_inPeriod(entry.timestamp, periodFrom, periodTo)) continue;
    const kmDict = entry.key_manifest;
    if (!kmDict || typeof kmDict !== 'object' || Array.isArray(kmDict)) continue;
    const h = kmDict.manifest_hash;
    if (typeof h !== 'string' || seenHashes.has(h)) continue;
    let km;
    try {
      km = KeyManifest.fromDict(kmDict);
    } catch (_) {
      continue;  // malformed -- defensive skip
    }
    seenHashes.add(h);
    manifestsByKeyId[km.key_id] = km;
  }

  if (Object.keys(manifestsByKeyId).length === 0) {
    // No key_registered events -- leave all-null (back-compat with v0.8.0).
    return;
  }

  let manifestsValid = 0;
  let withinWindowN = 0;
  let withinWindowTotal = 0;
  const rootDistribution = {
    VALID: 0, INVALID: 0, NOT_REQUESTED: 0, UNVERIFIED_NO_KEY: 0,
  };

  // Evaluate each manifest once for structural validity.
  for (const km of Object.values(manifestsByKeyId)) {
    const placeholder = new SanitizationCertificate({
      timestamp: km.valid_from,
      key_id: km.key_id,
      public_key: km.public_key,
    });
    const r = verifyKeyProvenance(placeholder, km);
    const manifestIsValid = r.manifest_hash_consistent
      && r.root_signature_status !== 'INVALID';
    if (manifestIsValid) manifestsValid += 1;
    rootDistribution[r.root_signature_status] =
      (rootDistribution[r.root_signature_status] || 0) + 1;
  }

  // Per-cert window membership.
  for (const entry of auditEntries) {
    if (entry.event_type === 'key_registered') continue;
    if (!entry.certificate_hash) continue;
    if (!_inPeriod(entry.timestamp, periodFrom, periodTo)) continue;
    const kid = entry.key_id;
    if (!kid || !(kid in manifestsByKeyId)) continue;
    withinWindowTotal += 1;
    const km = manifestsByKeyId[kid];
    const synth = new SanitizationCertificate({
      timestamp: entry.timestamp || '',
      key_id: kid,
      public_key: km.public_key,
    });
    const r = verifyKeyProvenance(synth, km);
    if (r.within_validity_window) withinWindowN += 1;
  }

  // v0.9.0: assign (not replace) so the RV-4 revocation keys -- and any
  // future additive keys -- survive this fill (same merge-fix as Py).
  Object.assign(attestation.provenance_summary, {
    manifests_found: Object.keys(manifestsByKeyId).length,
    manifests_valid: manifestsValid,
    // v0.10.3 C1-class fix: _pct (exact integer arithmetic) instead of
    // Math.round half-up, so it is byte-identical with Python's _pct on
    // .xx5 boundaries. Returns 0 for a zero denominator (matches the old
    // `=== 0 ? 0.0` branch, which serialized as 0).
    within_validity_window_pct: _pct(withinWindowN, withinWindowTotal),
    root_signature_status_distribution: rootDistribution,
  });
}

/**
 * Pure-function rollup engine. Mirror of build_report() in Python.
 *
 * @param {Object} opts
 * @param {Iterable<Object>} opts.auditEntries
 * @param {string|null} opts.periodFrom  ISO 8601 UTC inclusive
 * @param {string|null} opts.periodTo    ISO 8601 UTC inclusive
 * @param {string[]|null} opts.articles  optional whitelist
 * @param {string} opts.cloakllmVersion
 * @param {string} [opts.auditDir]
 * @param {boolean} [opts.includeDecisions]
 * @returns {Object} the report dict (matches examples/compliance_report_schema.json)
 */
function buildReport({
  auditEntries,
  periodFrom = null,
  periodTo = null,
  articles = null,
  cloakllmVersion,
  auditDir = null,
  includeDecisions = false,
  revocationList = null,
  chainValid = true,
  chainAnomalies: chainAnomaliesArg = null,
}) {
  // v0.8.1 KM-9: materialise once so we can rewalk for provenance_summary
  // without forcing callers to buffer themselves.
  const auditEntriesBuffered = Array.from(auditEntries);
  auditEntries = auditEntriesBuffered;

  const articleStats = {};
  const decisionStats = {};
  // v0.10.3 CRITICAL-1 fix: chainValid + chainAnomalies are threaded in from
  // the caller (Shield.generateComplianceReport runs verifyChain). The
  // default true keeps the pure-function path usable by unit tests with
  // synthetic fixed-hash fixtures, but the PUBLIC API always passes the real
  // verifyChain result so a tampered log reports broken / NON_COMPLIANT.
  const chainAnomalies = Array.isArray(chainAnomaliesArg) ? [...chainAnomaliesArg] : [];

  let firstTs = null;
  let lastTs = null;
  let totalEntries = 0;
  // v0.10.3 MEDIUM-6: set when ANY in-period entry has pii_in_log=true,
  // independent of the article filter (the invariant is global).
  let globalPiiViolation = false;

  let entriesWithCerts = 0;
  let signaturesValid = 0;
  const keyIds = new Set();

  const ensureArticle = (name) => {
    if (!(name in articleStats)) {
      articleStats[name] = {
        evidence_event_count: 0,
        decision_count: 0,
        categories_detected: {},
        pii_in_log: false,
      };
    }
    return articleStats[name];
  };

  const biasSessionCounts = {};
  const biasFindingCounts = {};
  const biasEndCounts = {};
  const biasEndWiped = {};
  // v0.10.0 A50-3: content-generation bookkeeping (Article 50). Accumulated
  // per-article like bias, wired ONLY onto the Art_50 row below (same
  // correctness invariant -- content stats must not appear on Art_12/19).
  const contentGenCounts = {};       // article -> count of content_generation
  const contentLabeledCounts = {};   // article -> count labeled=true
  const contentDeepfakeCounts = {};  // article -> count deepfake=true
  const contentModalityCounts = {};  // article -> {modality: count}
  const articleDecisions = {};  // article -> Set<decisionId>

  for (const entry of auditEntries) {
    const ts = entry.timestamp;
    // v0.8.0 AUDIT-3: only treat ts as a sortable timestamp when it's a
    // non-empty string. Hand-crafted malformed entries (ts=number, ts=null,
    // ts=object) must not crash the reducer -- they're skipped from period
    // tracking but still counted if they pass the period filter and have a
    // usable article_ref.
    const tsIsString = typeof ts === 'string' && ts.length > 0;
    if (!_inPeriod(tsIsString ? ts : null, periodFrom, periodTo)) continue;

    if (tsIsString) {
      if (firstTs === null || ts < firstTs) firstTs = ts;
      if (lastTs === null || ts > lastTs) lastTs = ts;
    }

    // v0.8.0 AUDIT-3: coerce to array -- a non-array article_ref must not
    // make .some()/.includes() crash on hand-crafted malformed entries.
    const entryArticles = Array.isArray(entry.article_ref) ? entry.article_ref : [];

    // v0.10.3 MEDIUM-6: the no-PII-in-logs invariant is GLOBAL -- check it on
    // every in-period entry BEFORE the article filter, so scoping a report to
    // one article can't hide a pii_in_log=true violation in an out-of-scope
    // entry (false COMPLIANT).
    if (entry.pii_in_log === true) {
      globalPiiViolation = true;
      chainAnomalies.push(`seq=${entry.seq}: COMPLIANCE VIOLATION pii_in_log=true`);
    }

    if (articles && !entryArticles.some(a => articles.includes(a))) continue;

    totalEntries += 1;

    // Per-article pii_in_log flag (in-scope rows only).
    if (entry.pii_in_log === true) {
      for (const a of entryArticles) ensureArticle(a).pii_in_log = true;
    }

    for (const art of entryArticles) {
      const stats = ensureArticle(art);
      stats.evidence_event_count += 1;

      // v0.10.3 HIGH-3: AUDIT-3 hardening -- malformed categories (non-object,
      // or non-integer counts) must not corrupt aggregates or crash.
      const cats = (entry.categories && typeof entry.categories === 'object'
        && !Array.isArray(entry.categories)) ? entry.categories : {};
      for (const [cat, cnt] of Object.entries(cats)) {
        if (typeof cnt !== 'number' || !Number.isInteger(cnt)) continue;
        stats.categories_detected[cat] = (stats.categories_detected[cat] || 0) + cnt;
      }

      const did = entry.decision_id;
      if (did) {
        if (!articleDecisions[art]) articleDecisions[art] = new Set();
        articleDecisions[art].add(did);
      }

      const evType = entry.event_type || '';
      if (_BIAS_EVENT_TYPES.has(evType)) {
        if (evType === 'bias_session_start') {
          biasSessionCounts[art] = (biasSessionCounts[art] || 0) + 1;
        } else if (evType === 'bias_finding') {
          biasFindingCounts[art] = (biasFindingCounts[art] || 0) + 1;
        } else if (evType === 'bias_session_end') {
          biasEndCounts[art] = (biasEndCounts[art] || 0) + 1;
          if ((entry.bias_context || {}).wipe_confirmed === true) {
            biasEndWiped[art] = (biasEndWiped[art] || 0) + 1;
          }
        }
      } else if (evType === _CONTENT_GENERATION_EVENT_TYPE) {
        // v0.10.0 A50-3: content_generation bookkeeping (Article 50).
        // v0.10.2 H1 fix: the Article 50 labeling obligation applies to
        // SYNTHETIC / AI-generated content only (Art 50(2)). A non-synthetic
        // record (synthetic=false) carries no labeling duty, so it must NOT
        // count toward the coverage stats or verdict -- otherwise an honest
        // deployer logging non-AI provenance gets a false NON_COMPLIANT.
        // Mirror of the Python gate.
        const cc = entry.content_context || {};
        if (cc.synthetic === true) {
          contentGenCounts[art] = (contentGenCounts[art] || 0) + 1;
          if (cc.labeled === true) {
            contentLabeledCounts[art] = (contentLabeledCounts[art] || 0) + 1;
          }
          if (cc.deepfake === true) {
            contentDeepfakeCounts[art] = (contentDeepfakeCounts[art] || 0) + 1;
          }
          const modality = cc.modality;
          // AUDIT-3: only count a string modality (malformed entries skipped).
          if (typeof modality === 'string' && modality) {
            if (!contentModalityCounts[art]) contentModalityCounts[art] = {};
            contentModalityCounts[art][modality] =
              (contentModalityCounts[art][modality] || 0) + 1;
          }
        }
      }
    }

    const did = entry.decision_id;
    if (includeDecisions && did) {
      if (!(did in decisionStats)) {
        decisionStats[did] = {
          entry_count: 0,
          articles_touched: new Set(),
          categories: {},
          first_timestamp: ts,
          last_timestamp: ts,
        };
      }
      const d = decisionStats[did];
      d.entry_count += 1;
      for (const art of entryArticles) d.articles_touched.add(art);
      // v0.10.3 HIGH-3: same categories hardening as the per-article loop.
      const cats = (entry.categories && typeof entry.categories === 'object'
        && !Array.isArray(entry.categories)) ? entry.categories : {};
      for (const [cat, cnt] of Object.entries(cats)) {
        if (typeof cnt !== 'number' || !Number.isInteger(cnt)) continue;
        d.categories[cat] = (d.categories[cat] || 0) + cnt;
      }
      if (ts) {
        if (ts < d.first_timestamp) d.first_timestamp = ts;
        if (ts > d.last_timestamp) d.last_timestamp = ts;
      }
    }

    if (entry.certificate_hash) {
      entriesWithCerts += 1;
      signaturesValid += 1;
      if (entry.key_id) keyIds.add(entry.key_id);
    }
  }

  // Article filter -- include requested articles even with zero events
  let finalArticleStats = articleStats;
  if (articles) {
    for (const a of articles) ensureArticle(a);
    finalArticleStats = {};
    for (const a of articles) {
      if (a in articleStats) finalArticleStats[a] = articleStats[a];
    }
  }

  for (const [art, dids] of Object.entries(articleDecisions)) {
    if (art in finalArticleStats) {
      finalArticleStats[art].decision_count = dids.size;
    }
  }

  // Article 4a-only bias stats (see Python module for rationale)
  const ART_4A = 'EU_AI_Act_Art_4a';
  if (ART_4A in finalArticleStats && ART_4A in biasSessionCounts) {
    finalArticleStats[ART_4A].bias_sessions = biasSessionCounts[ART_4A];
    finalArticleStats[ART_4A].findings_recorded = biasFindingCounts[ART_4A] || 0;
    const ends = biasEndCounts[ART_4A] || 0;
    const wiped = biasEndWiped[ART_4A] || 0;
    // v0.10.3 C1-class fix: _pct (exact integer 2dp) instead of
    // Math.round(1000*w/e)/10 (HALF-UP + only 1dp) -- the old path diverged
    // from Python's round(...,2) on both precision and rounding mode. Now
    // byte-identical via the shared _pct helper.
    finalArticleStats[ART_4A].wipe_confirmed_pct = _pct(wiped, ends);
  }

  // v0.10.0 A50-3: wire content-labeling fields ONLY onto the Article 50 row.
  // content_generation events carry article_ref=[Art_12,Art_19,Art_50], so the
  // naive "attach to every article that saw the event" would mislead an
  // auditor reading the Article 12 section into thinking Article 12 mandates
  // content labeling. It mandates LOGGING; content labeling is one event type
  // logged. The rollup belongs on Art_50's row alone (the bias/Art_4a
  // correctness invariant, applied to Article 50).
  if (_ART_50 in finalArticleStats && _ART_50 in contentGenCounts) {
    const gen = contentGenCounts[_ART_50];
    const labeled = contentLabeledCounts[_ART_50] || 0;
    const modalities = contentModalityCounts[_ART_50] || {};
    // Object.assign (merge, not replace) -- never clobber evidence_event_count
    // / decision_count already on the row (the KM-9 / RV-4 fix discipline).
    Object.assign(finalArticleStats[_ART_50], {
      generation_events: gen,
      labeled_events: labeled,
      label_coverage_pct: _pct(labeled, gen),
      deepfake_events: contentDeepfakeCounts[_ART_50] || 0,
      // sorted keys so canonical JSON is byte-equivalent with Python's
      // dict(sorted(...)) ordering.
      modality_distribution: Object.fromEntries(
        Object.keys(modalities).sort().map(k => [k, modalities[k]])
      ),
    });
  }

  // --- Verdict (part 1: chain + PII + Article 50) ---
  const verdictReasons = [];
  if (!chainValid) {
    verdictReasons.push(`chain_integrity: broken (${chainAnomalies.length} anomalies)`);
  }
  // In-scope per-article PII rows (existing reason format).
  const piiRows = Object.entries(finalArticleStats)
    .filter(([, s]) => s.pii_in_log === true).map(([a]) => a);
  for (const a of piiRows) verdictReasons.push(`per_article.${a}: pii_in_log=true`);
  // v0.10.3 MEDIUM-6: a pii_in_log=true entry FILTERED OUT by the article
  // scope (no per_article row) must still flip the verdict -- global invariant.
  if (globalPiiViolation && piiRows.length === 0) {
    verdictReasons.push(
      'no_pii_in_logs: pii_in_log=true on an out-of-scope in-period entry'
    );
  }
  // v0.10.0 A50-4: Article 50 unlabeled-content check (strict).
  const art50 = finalArticleStats[_ART_50];
  if (art50 && 'generation_events' in art50) {
    const gen = art50.generation_events;
    const labeled = art50.labeled_events;
    if (gen && labeled < gen) {
      verdictReasons.push(
        `per_article.${_ART_50}: ${gen - labeled} of ${gen} generation events unlabeled`
      );
    }
  }

  // Attestation block, built BEFORE finalising the verdict so the verdict can
  // use the REAL, checkable attestation signal (KeyManifest provenance).
  const attestation = _emptyAttestation();
  attestation.entries_with_certificates = entriesWithCerts;
  // v0.10.3 CRITICAL-2: `signatures_valid` is a COUNT of cert-bearing entries,
  // NOT a per-signature verification. The log stores only a hash of each
  // certificate, never the certificate, so signatures are not re-verifiable
  // from the log alone. The old `signaturesValid < entriesWithCerts` verdict
  // guard was dead code that falsely implied crypto verification; removed.
  // The verifiable attestation signal is KeyManifest provenance (below).
  attestation.signatures_valid = signaturesValid;
  attestation.key_ids = [...keyIds].sort();

  // v0.8.1 KM-9: fill provenance_summary from key_registered events.
  _fillProvenanceSummary({
    auditEntries: auditEntriesBuffered,
    periodFrom, periodTo,
    attestation,
  });
  // v0.9.0 RV-4: fill revocation rollup when a list was supplied.
  _fillRevocationSummary({
    auditEntries: auditEntriesBuffered,
    periodFrom, periodTo,
    attestation,
    revocationList,
  });

  // --- Verdict (part 2: real attestation check) ---
  // v0.10.3 CRITICAL-2: a KeyManifest that failed provenance verification IS a
  // real, checkable NON_COMPLIANT condition (verifyKeyProvenance ran above).
  const ps = attestation.provenance_summary || {};
  if (Number.isInteger(ps.manifests_found) && Number.isInteger(ps.manifests_valid)
      && ps.manifests_found > 0 && ps.manifests_valid < ps.manifests_found) {
    verdictReasons.push(
      `attestation: ${ps.manifests_valid}/${ps.manifests_found} key manifests passed provenance verification`
    );
  }

  const verdict = verdictReasons.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT';

  const report = {
    report_metadata: {
      generated_at: new Date().toISOString().replace('Z', '+00:00'),
      cloakllm_version: cloakllmVersion,
      schema_version: SCHEMA_VERSION,
    },
    period: {
      from: periodFrom || firstTs,
      to: periodTo || lastTs,
    },
    articles_in_scope: articles,
    chain_integrity: {
      verdict: chainValid ? 'verified' : 'broken',
      total_entries: totalEntries,
      anomalies: chainAnomalies,
    },
    per_article: finalArticleStats,
    attestation,
    verdict,
    verdict_reasons: verdictReasons,
  };
  if (auditDir !== null) {
    report.report_metadata.audit_dir = auditDir;
  }

  if (includeDecisions) {
    report.decisions = {};
    for (const [did, d] of Object.entries(decisionStats)) {
      report.decisions[did] = {
        ...d,
        articles_touched: [...d.articles_touched].sort(),
      };
    }
  }

  return report;
}

/**
 * Render a compliance report as Markdown (mirror of Python render_markdown).
 */
function renderMarkdown(report) {
  const lines = [];
  const meta = report.report_metadata;
  lines.push('# CloakLLM Compliance Report');
  lines.push('');
  lines.push(`**Verdict:** **${report.verdict}**`);
  if (report.verdict_reasons && report.verdict_reasons.length > 0) {
    lines.push('');
    lines.push('**Reasons (NON_COMPLIANT only):**');
    for (const r of report.verdict_reasons) lines.push(`  * ${r}`);
  }
  lines.push('');
  lines.push(`- Generated: \`${meta.generated_at}\``);
  lines.push(`- CloakLLM version: \`${meta.cloakllm_version}\``);
  lines.push(`- Schema version: \`${meta.schema_version}\``);
  if (meta.audit_dir) lines.push(`- Audit dir: \`${meta.audit_dir}\``);
  const p = report.period;
  lines.push(`- Period: \`${p.from || 'unbounded'}\` -> \`${p.to || 'unbounded'}\``);
  if (report.articles_in_scope) {
    lines.push(`- Articles in scope: ${report.articles_in_scope.join(', ')}`);
  }
  lines.push('');

  const ci = report.chain_integrity;
  lines.push('## Chain integrity');
  lines.push('');
  lines.push(`- Verdict: **${ci.verdict}**`);
  lines.push(`- Total entries in scope: **${ci.total_entries}**`);
  if (ci.anomalies && ci.anomalies.length > 0) {
    lines.push('- Anomalies:');
    for (const a of ci.anomalies) lines.push(`  * \`${a}\``);
  } else {
    lines.push('- Anomalies: none');
  }
  lines.push('');

  lines.push('## Per-article rollup');
  lines.push('');
  const arts = Object.keys(report.per_article).sort();
  if (arts.length === 0) {
    lines.push('_No in-scope entries._');
    lines.push('');
  } else {
    for (const art of arts) {
      const stats = report.per_article[art];
      lines.push(`### ${art}`);
      lines.push('');
      lines.push(`- Evidence event count: **${stats.evidence_event_count}**`);
      lines.push(`- Decision count: **${stats.decision_count || 0}**`);
      lines.push(`- pii_in_log: **${stats.pii_in_log || false}**`);
      const cats = stats.categories_detected || {};
      if (Object.keys(cats).length > 0) {
        const catStr = Object.entries(cats).sort()
          .map(([c, n]) => `${c}=${n}`).join(', ');
        lines.push(`- PII categories detected: ${catStr}`);
      }
      if ('bias_sessions' in stats) {
        lines.push(`- Article 4a bias sessions: **${stats.bias_sessions}**`);
        lines.push(`- Bias findings recorded: **${stats.findings_recorded || 0}**`);
        lines.push(`- Token-map wipe confirmed: **${stats.wipe_confirmed_pct || 0}%**`);
      }
      // v0.10.0 A50-3: Article 50 content-labeling rollup.
      if ('generation_events' in stats) {
        lines.push(`- Article 50 generation events: **${stats.generation_events}**`);
        lines.push(`- Labeled events: **${stats.labeled_events || 0}**`);
        lines.push(`- Label coverage: **${stats.label_coverage_pct || 0}%**`);
        lines.push(`- Deep-fake disclosures: **${stats.deepfake_events || 0}**`);
        const md = stats.modality_distribution || {};
        if (Object.keys(md).length > 0) {
          const mdStr = Object.entries(md).sort()
            .map(([m, n]) => `${m}=${n}`).join(', ');
          lines.push(`- Modality distribution: ${mdStr}`);
        }
      }
      lines.push('');
    }
  }

  const att = report.attestation;
  lines.push('## Attestation');
  lines.push('');
  lines.push(`- Entries with certificates: **${att.entries_with_certificates}**`);
  lines.push(`- Signatures valid: **${att.signatures_valid}**`);
  if (att.key_ids && att.key_ids.length > 0) {
    lines.push(`- Signing key_ids: ${att.key_ids.map(k => `\`${k}\``).join(', ')}`);
  }
  if (att.schema_version === '1.0') {
    lines.push('');
    lines.push(
      '_KeyManifest-based external provenance verification is not yet ' +
      'enabled. Ship v0.8.1+ to fill in the `provenance_summary` fields._'
    );
  }
  lines.push('');

  if (report.decisions) {
    lines.push('## Per-decision rollup');
    lines.push('');
    lines.push(`_${Object.keys(report.decisions).length} distinct decisions in scope._`);
    lines.push('');
  }

  return lines.join('\n') + '\n';
}

module.exports = {
  buildReport, renderMarkdown,
  SCHEMA_VERSION, ATTESTATION_SCHEMA_VERSION,
};
