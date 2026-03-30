/**
 * Tests for Context-Based PII Leakage Risk Analyzer.
 *
 * Tests the ContextAnalyzer class directly and its integration with Shield.
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { ContextAnalyzer } = require('../src/context-analyzer');
const { Shield, ShieldConfig } = require('../src');
const fs = require('fs');
const os = require('os');
const path = require('path');

describe('ContextAnalyzer — direct', () => {
    const analyzer = new ContextAnalyzer();

    it('empty text → low risk', () => {
        const r = analyzer.analyze('');
        assert.equal(r.risk_level, 'low');
        assert.equal(r.risk_score, 0);
        assert.equal(r.token_density, 0);
        assert.equal(r.identifying_descriptors, 0);
        assert.equal(r.relationship_edges, 0);
        assert.deepEqual(r.warnings, []);
    });

    it('whitespace only → low risk', () => {
        const r = analyzer.analyze('   \n\t  ');
        assert.equal(r.risk_level, 'low');
        assert.equal(r.risk_score, 0);
    });

    it('no tokens → low risk', () => {
        const r = analyzer.analyze('The weather is nice today and everything is fine.');
        assert.equal(r.risk_level, 'low');
        assert.equal(r.risk_score, 0);
        assert.equal(r.token_density, 0);
    });

    it('token density calculation', () => {
        // 2 tokens in 4 words = 0.5
        const r = analyzer.analyze('[EMAIL_0] [PERSON_0] hello world');
        assert.equal(r.token_density, 0.5);
    });

    it('single token density', () => {
        // 1 token in 3 words = 0.333
        const r = analyzer.analyze('Contact [EMAIL_0] please');
        assert.ok(Math.abs(r.token_density - 0.333) < 0.002);
    });

    it('identifying descriptor — CEO', () => {
        const r = analyzer.analyze('The CEO of [ORG_0] announced the merger');
        assert.ok(r.identifying_descriptors >= 1);
        assert.ok(r.warnings.some(w => w.toLowerCase().includes('ceo')));
    });

    it('identifying descriptor — founder', () => {
        const r = analyzer.analyze('[PERSON_0] is the founder of [ORG_0]');
        assert.ok(r.identifying_descriptors >= 1);
    });

    it('identifying descriptor — wife', () => {
        const r = analyzer.analyze('The wife of [PERSON_0] was also present');
        assert.ok(r.identifying_descriptors >= 1);
    });

    it('relationship — works at', () => {
        const r = analyzer.analyze('[PERSON_0] works at [ORG_0] in the marketing department');
        assert.ok(r.relationship_edges >= 1);
        assert.ok(r.warnings.some(w => w.includes('works at')));
    });

    it('relationship — lives in', () => {
        const r = analyzer.analyze('[PERSON_0] lives in [GPE_0] with their family');
        assert.ok(r.relationship_edges >= 1);
    });

    it('relationship — married', () => {
        const r = analyzer.analyze('[PERSON_0] married [PERSON_1] in 2015');
        assert.ok(r.relationship_edges >= 1);
    });

    it('no relationship without two tokens', () => {
        const r = analyzer.analyze('Someone works at Acme Corp in marketing');
        assert.equal(r.relationship_edges, 0);
    });

    it('high risk text', () => {
        const text = 'The CEO of [ORG_0], who founded [ORG_1] in 2003, lives in [GPE_0] and is married to [PERSON_0]';
        const r = analyzer.analyze(text);
        assert.ok(r.risk_score > 0.3);
        assert.ok(['medium', 'high'].includes(r.risk_level));
        assert.ok(r.warnings.length > 0);
    });

    it('low risk simple tokens', () => {
        const r = analyzer.analyze('Please process this email from [EMAIL_0] regarding the invoice.');
        assert.ok(r.risk_score < 0.4);
    });

    it('REDACTED tokens detected', () => {
        const r = analyzer.analyze('[EMAIL_REDACTED] [PERSON_REDACTED] hello world');
        assert.equal(r.token_density, 0.5);
    });

    it('mixed tokens', () => {
        const r = analyzer.analyze('[EMAIL_0] contacted [PERSON_REDACTED] about [ORG_1]');
        assert.ok(r.token_density > 0);
    });

    it('warnings capped at 5', () => {
        const text = 'The CEO of [ORG_0] and president of [ORG_1] and director of [ORG_2] ' +
            'and chairman of [ORG_3] and founder of [ORG_4] ' +
            'and head of [ORG_5] and chief of [ORG_6]';
        const r = analyzer.analyze(text);
        assert.ok(r.warnings.length <= 5);
    });

    it('risk score capped at 1.0', () => {
        const tokens = Array.from({ length: 50 }, (_, i) => `[PERSON_${i}]`).join(' ');
        const r = analyzer.analyze(tokens);
        assert.ok(r.risk_score <= 1.0);
    });

    it('punctuation stripping on descriptors', () => {
        const r = analyzer.analyze('The CEO, [PERSON_0], announced the deal.');
        assert.ok(r.identifying_descriptors >= 1);
    });

    it('long text handled', () => {
        const text = 'Hello world. '.repeat(1000) + '[EMAIL_0] is here.';
        const r = analyzer.analyze(text);
        assert.ok(r.token_density < 0.01);
    });

    it('result has all expected fields', () => {
        const r = analyzer.analyze('Hello [EMAIL_0]');
        assert.ok('token_density' in r);
        assert.ok('identifying_descriptors' in r);
        assert.ok('relationship_edges' in r);
        assert.ok('risk_score' in r);
        assert.ok('risk_level' in r);
        assert.ok('warnings' in r);
        assert.ok(['low', 'medium', 'high'].includes(r.risk_level));
    });
});

describe('Shield.analyzeContextRisk()', () => {
    it('works without config flag', () => {
        const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
        const result = shield.analyzeContextRisk('[PERSON_0] works at [ORG_0]');
        assert.ok('risk_score' in result);
        assert.ok('risk_level' in result);
        assert.ok(result.relationship_edges >= 1);
    });

    it('no tokens → low risk', () => {
        const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
        const result = shield.analyzeContextRisk('Just a normal sentence.');
        assert.equal(result.risk_level, 'low');
        assert.equal(result.risk_score, 0);
    });
});

describe('Shield context auto-analysis', () => {
    it('disabled by default', () => {
        const shield = new Shield(new ShieldConfig({ auditEnabled: false }));
        const [, tokenMap] = shield.sanitize('Contact john@acme.com');
        assert.equal(tokenMap.riskAssessment, null);
    });

    it('enabled via config', () => {
        const shield = new Shield(new ShieldConfig({
            auditEnabled: false,
            contextAnalysis: true,
        }));
        const [, tokenMap] = shield.sanitize('Contact john@acme.com about the project');
        assert.notEqual(tokenMap.riskAssessment, null);
        assert.ok('risk_score' in tokenMap.riskAssessment);
        assert.ok('risk_level' in tokenMap.riskAssessment);
    });

    it('does not break roundtrip', () => {
        const shield = new Shield(new ShieldConfig({
            auditEnabled: false,
            contextAnalysis: true,
        }));
        const original = 'Contact john@acme.com about the project';
        const [sanitized, tokenMap] = shield.sanitize(original);
        const restored = shield.desanitize(sanitized, tokenMap);
        assert.equal(restored, original);
    });

    it('audit log includes risk_assessment', () => {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloak-ctx-'));
        try {
            const shield = new Shield(new ShieldConfig({
                logDir: tmpDir,
                auditEnabled: true,
                contextAnalysis: true,
            }));
            shield.sanitize('Contact john@acme.com about the project');
            const files = fs.readdirSync(tmpDir).filter(f => f.startsWith('audit_'));
            assert.equal(files.length, 1);
            const line = fs.readFileSync(path.join(tmpDir, files[0]), 'utf8').trim().split('\n')[0];
            const entry = JSON.parse(line);
            assert.ok('risk_assessment' in entry);
        } finally {
            fs.rmSync(tmpDir, { recursive: true });
        }
    });

    it('contextRiskThreshold is configurable', () => {
        const config = new ShieldConfig({
            auditEnabled: false,
            contextAnalysis: true,
            contextRiskThreshold: 0.1,
        });
        assert.equal(config.contextRiskThreshold, 0.1);
    });
});

describe('Cross-language parity', () => {
    it('same input produces same scores as Python would', () => {
        const analyzer = new ContextAnalyzer();
        // Simple density test — 2/4 = 0.5
        const r1 = analyzer.analyze('[EMAIL_0] [PERSON_0] hello world');
        assert.equal(r1.token_density, 0.5);

        // Empty → zero
        const r2 = analyzer.analyze('');
        assert.equal(r2.risk_score, 0);

        // Relationship detection
        const r3 = analyzer.analyze('[PERSON_0] works at [ORG_0]');
        assert.ok(r3.relationship_edges >= 1);
    });
});
