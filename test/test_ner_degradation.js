/**
 * v0.11.3: NER backend degrades gracefully when compromise is unavailable;
 * fail-closed via nerRequired. Mirror of the Python regression guard.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { Shield, ShieldConfig } = require('../src');
const { NerBackend } = require('../src/backends/ner');

describe('v0.11.3 NER degradation', () => {
  it('degrades to [] when NER is unavailable (default fail-open)', () => {
    const b = new NerBackend(new ShieldConfig({ auditEnabled: false }));
    if (b.available) return; // compromise installed -> nothing to degrade
    assert.deepEqual(b.detect('Contact Jane Doe at the office', []), []);
  });

  it('regex still protects when NER is unavailable', () => {
    const sh = new Shield(new ShieldConfig({ auditEnabled: false }));
    const r = sh.sanitize('email me at secret.person@example.com please');
    const out = Array.isArray(r) ? r[0] : r.sanitized;
    assert.ok(out.includes('[EMAIL_0]') && !out.includes('secret.person@example.com'), out);
  });

  it('nerRequired=true hard-fails when NER is unavailable', () => {
    const b = new NerBackend(new ShieldConfig({ auditEnabled: false, nerRequired: true }));
    if (b.available) return; // compromise installed -> would not throw
    assert.throws(() => b.detect('Contact Jane Doe', []), /NER is required/);
  });

  it('config exposes nerRequired (default false)', () => {
    assert.equal(new ShieldConfig({}).nerRequired, false);
    assert.equal(new ShieldConfig({ nerRequired: true }).nerRequired, true);
  });
});
