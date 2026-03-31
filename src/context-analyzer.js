/**
 * Context-Based PII Leakage Risk Analyzer.
 *
 * Analyzes sanitized text to detect when surrounding context could
 * re-identify a person even after tokenization. For example:
 * "The CEO of [ORG_0], who founded it in 2003, lives in [GPE_0]"
 * could be de-anonymized via public records.
 *
 * Three heuristic signals:
 * 1. Token density — ratio of tokens to total words
 * 2. Identifying descriptors — words like "CEO", "founder" near tokens
 * 3. Relationship edges — phrases like "works at" connecting two tokens
 */

'use strict';

const TOKEN_RE = /\[[A-Z][A-Z0-9_]*_(?:\d+|REDACTED)\]/gi;

const IDENTIFYING_DESCRIPTORS = new Set([
    'ceo', 'president', 'founder', 'director', 'chairman', 'chairwoman',
    'wife', 'husband', 'daughter', 'son', 'mother', 'father',
    'only', 'tallest', 'youngest', 'oldest', 'first', 'last',
    'sole', 'chief', 'head', 'lead', 'senior', 'junior',
]);

const RELATIONSHIP_WORDS = [
    'married', 'divorced', 'works at', 'employed by', 'lives in',
    'born in', 'graduated from', 'founded', 'owns', 'manages',
    'reports to', 'hired by', 'sister of', 'brother of',
    'daughter of', 'son of', 'wife of', 'husband of',
];

class ContextAnalyzer {
    /**
     * Analyze sanitized text for context-based PII leakage risk.
     * @param {string} sanitizedText - Text containing [CATEGORY_N] tokens
     * @returns {object} RiskAssessment with token_density, identifying_descriptors,
     *   relationship_edges, risk_score, risk_level, warnings
     */
    analyze(sanitizedText) {
        if (!sanitizedText || !sanitizedText.trim()) {
            return {
                token_density: 0,
                identifying_descriptors: 0,
                relationship_edges: 0,
                risk_score: 0,
                risk_level: 'low',
                warnings: [],
            };
        }

        const words = sanitizedText.toLowerCase().split(/\s+/);
        const totalWords = Math.max(words.length, 1);
        TOKEN_RE.lastIndex = 0;
        const tokens = sanitizedText.match(TOKEN_RE) || [];
        const tokenDensity = tokens.length / totalWords;

        // Signal 1: Identifying descriptors near tokens (5-word window)
        let descriptorCount = 0;
        const warnings = [];
        for (let i = 0; i < words.length; i++) {
            const cleanWord = words[i].replace(/[.,;:!?"'()\[\]]/g, '');
            if (IDENTIFYING_DESCRIPTORS.has(cleanWord)) {
                const windowStart = Math.max(0, i - 5);
                const windowEnd = Math.min(words.length, i + 6);
                const window = words.slice(windowStart, windowEnd).join(' ');
                TOKEN_RE.lastIndex = 0;
                if (TOKEN_RE.test(window)) {
                    descriptorCount++;
                    warnings.push(`Identifying descriptor '${cleanWord}' near a token`);
                }
            }
        }

        // Signal 2: Relationship phrases connecting two tokens (50-char window)
        let relationshipCount = 0;
        const textLower = sanitizedText.toLowerCase();
        for (const rel of RELATIONSHIP_WORDS) {
            let searchStart = 0;
            let idx;
            while ((idx = textLower.indexOf(rel, searchStart)) !== -1) {
                const before = textLower.substring(Math.max(0, idx - 50), idx);
                const after = textLower.substring(idx + rel.length, idx + rel.length + 50);
                TOKEN_RE.lastIndex = 0;
                const hasBefore = TOKEN_RE.test(before);
                TOKEN_RE.lastIndex = 0;
                const hasAfter = TOKEN_RE.test(after);
                if (hasBefore && hasAfter) {
                    relationshipCount++;
                    warnings.push(`Relationship '${rel}' connects tokens`);
                }
                searchStart = idx + 1;
            }
        }

        // Composite score
        const riskScore = Math.min(1.0, tokenDensity * 1.5 + descriptorCount * 0.15 + relationshipCount * 0.2);
        const riskLevel = riskScore > 0.7 ? 'high' : riskScore > 0.3 ? 'medium' : 'low';

        return {
            token_density: Math.round(tokenDensity * 1000) / 1000,
            identifying_descriptors: descriptorCount,
            relationship_edges: relationshipCount,
            risk_score: Math.round(riskScore * 1000) / 1000,
            risk_level: riskLevel,
            warnings: warnings.slice(0, 5),
        };
    }
}

module.exports = { ContextAnalyzer, IDENTIFYING_DESCRIPTORS, RELATIONSHIP_WORDS };
