/**
 * v0.6.3 G7 — JS audit dir/file permissions are 0o700/0o600 on POSIX.
 *
 * Mirror of cloakllm-py/tests/test_audit_permissions.py. POSIX-only.
 */

'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { Shield, ShieldConfig } = require('../src');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-g7-js-'));
}

function modeOf(p) {
  return fs.statSync(p).mode & 0o777;
}

const isPosix = process.platform !== 'win32';

describe('G7 — audit dir/file permissions (POSIX-only)', () => {
  let tmp;
  beforeEach(() => { tmp = tmpDir(); });

  it('audit dir created mode 0o700', () => {
    if (!isPosix) {
      // On Windows, just confirm the call doesn't crash on the new mode option.
      const logDir = path.join(tmp, 'win_smoke');
      const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: true }));
      shield.sanitize('a@b.com');
      assert.ok(fs.existsSync(logDir));
      return;
    }
    const logDir = path.join(tmp, 'fresh_audit_dir');
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: true }));
    shield.sanitize('a@b.com');
    assert.equal(modeOf(logDir), 0o700);
  });

  it('audit log file created mode 0o600', () => {
    if (!isPosix) {
      // On Windows, just confirm the call doesn't crash on the new mode option.
      const logDir = path.join(tmp, 'win_smoke');
      const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: true }));
      shield.sanitize('a@b.com');
      assert.ok(fs.existsSync(logDir));
      return;
    }
    const logDir = path.join(tmp, 'fresh_log_for_perms');
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: true }));
    shield.sanitize('a@b.com');
    const files = fs.readdirSync(logDir).filter(f => f.startsWith('audit_'));
    assert.equal(files.length, 1, `expected 1 audit file, found ${files.length}`);
    const mode = modeOf(path.join(logDir, files[0]));
    assert.equal(mode, 0o600,
      `expected file mode 0o600, got 0o${mode.toString(8)}`);
  });

  it('existing loose dir tightened to 0o700', () => {
    if (!isPosix) {
      // On Windows, just confirm the call doesn't crash on the new mode option.
      const logDir = path.join(tmp, 'win_smoke');
      const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: true }));
      shield.sanitize('a@b.com');
      assert.ok(fs.existsSync(logDir));
      return;
    }
    const logDir = path.join(tmp, 'existing_loose');
    fs.mkdirSync(logDir, { mode: 0o755 });
    fs.chmodSync(logDir, 0o755);
    assert.equal(modeOf(logDir), 0o755);
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: true }));
    shield.sanitize('a@b.com');
    assert.equal(modeOf(logDir), 0o700);
  });

  it('subsequent writes keep file at 0o600', () => {
    if (!isPosix) {
      // On Windows, just confirm the call doesn't crash on the new mode option.
      const logDir = path.join(tmp, 'win_smoke');
      const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: true }));
      shield.sanitize('a@b.com');
      assert.ok(fs.existsSync(logDir));
      return;
    }
    const logDir = path.join(tmp, 'multi_write');
    const shield = new Shield(new ShieldConfig({ logDir, auditEnabled: true }));
    for (let i = 0; i < 5; i++) shield.sanitize('a@b.com');
    const files = fs.readdirSync(logDir).filter(f => f.startsWith('audit_'));
    const mode = modeOf(path.join(logDir, files[0]));
    assert.equal(mode, 0o600,
      `expected file mode 0o600, got 0o${mode.toString(8)}`);
  });
});
