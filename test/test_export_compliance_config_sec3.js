/**
 * v0.6.3 SEC-3 — JS exportComplianceConfig path validation parity with Python G1.
 *
 * Pre-SEC-3, exportComplianceConfig called fs.writeFileSync(outPath, ...)
 * directly with no validation — a symlink at outPath would be followed and
 * the target overwritten (data-loss attack), and NUL bytes were unguarded.
 * SEC-3 mirrors the Python G1 fix: validate via _validatePath, then open
 * with O_NOFOLLOW + 0o600 on POSIX.
 */

'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-sec3-js-'));
}

function trySymlink(target, link) {
  try {
    fs.symlinkSync(target, link);
    return true;
  } catch {
    return false;
  }
}

const isPosix = process.platform !== 'win32';

describe('SEC-3 — JS exportComplianceConfig path validation', () => {
  let tmp, shield;
  beforeEach(() => {
    tmp = tmpDir();
    shield = new Shield(new ShieldConfig({
      logDir: path.join(tmp, 'audit'),
      auditEnabled: true,
      complianceMode: 'eu_ai_act_article12',
    }));
  });

  it('clean path succeeds and writes JSON', () => {
    const out = path.join(tmp, 'compliance.json');
    const result = shield.exportComplianceConfig(out);
    assert.equal(result, out);
    assert.ok(fs.existsSync(out));
    const data = JSON.parse(fs.readFileSync(out, 'utf-8'));
    assert.ok('note' in data);
  });

  it('NUL byte in outPath rejected', () => {
    assert.throws(
      () => shield.exportComplianceConfig(path.join(tmp, 'evil\0.json')),
      /NUL/i,
    );
  });

  it('symlink target rejected (POSIX)', () => {
    if (!isPosix) {
      // Smoke: just confirm the call doesn't crash on Windows.
      const out = path.join(tmp, 'win_smoke.json');
      shield.exportComplianceConfig(out);
      assert.ok(fs.existsSync(out));
      return;
    }
    const target = path.join(tmp, 'real_secret.txt');
    fs.writeFileSync(target, 'very sensitive');
    const link = path.join(tmp, 'compliance.json');
    if (!trySymlink(target, link)) {
      // Some CI environments don't allow symlinks; treat as skip.
      return;
    }
    assert.throws(
      () => shield.exportComplianceConfig(link),
      /symlink/i,
    );
    // Critical: target must NOT be overwritten.
    assert.equal(fs.readFileSync(target, 'utf-8'), 'very sensitive');
  });

  it('file created with mode 0o600 (POSIX)', () => {
    if (!isPosix) return;
    const out = path.join(tmp, 'compliance_perms.json');
    shield.exportComplianceConfig(out);
    const mode = fs.statSync(out).mode & 0o777;
    assert.equal(mode, 0o600,
      `expected 0o600, got 0o${mode.toString(8)}`);
  });
});
