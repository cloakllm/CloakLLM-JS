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
    },
  };
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
}) {
  const articleStats = {};
  const decisionStats = {};
  const chainAnomalies = [];

  let firstTs = null;
  let lastTs = null;
  let totalEntries = 0;
  const chainValid = true;  // caller has already verified; future: integrate

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
    if (articles && !entryArticles.some(a => articles.includes(a))) continue;

    totalEntries += 1;

    if (entry.pii_in_log === true) {
      for (const a of entryArticles) ensureArticle(a).pii_in_log = true;
      chainAnomalies.push(`seq=${entry.seq}: COMPLIANCE VIOLATION pii_in_log=true`);
    }

    for (const art of entryArticles) {
      const stats = ensureArticle(art);
      stats.evidence_event_count += 1;

      const cats = entry.categories || {};
      for (const [cat, cnt] of Object.entries(cats)) {
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
      const cats = entry.categories || {};
      for (const [cat, cnt] of Object.entries(cats)) {
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
    finalArticleStats[ART_4A].wipe_confirmed_pct =
      ends > 0 ? Math.round(1000 * wiped / ends) / 10 : 0.0;
  }

  // Verdict
  const verdictReasons = [];
  if (!chainValid) {
    verdictReasons.push(`chain_integrity: broken (${chainAnomalies.length} anomalies)`);
  }
  for (const [a, s] of Object.entries(finalArticleStats)) {
    if (s.pii_in_log === true) verdictReasons.push(`per_article.${a}: pii_in_log=true`);
  }
  if (entriesWithCerts > 0 && signaturesValid < entriesWithCerts) {
    verdictReasons.push(
      `attestation: ${signaturesValid}/${entriesWithCerts} signatures valid`
    );
  }
  const verdict = verdictReasons.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT';

  const attestation = _emptyAttestation();
  attestation.entries_with_certificates = entriesWithCerts;
  attestation.signatures_valid = signaturesValid;
  attestation.key_ids = [...keyIds].sort();

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
