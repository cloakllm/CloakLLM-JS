/**
 * v0.6.3 H5 — JS path traversal / symlink / NUL-byte tests.
 *
 * Mirrors cloakllm-py/tests/test_path_traversal.py:
 *   * Symlink at logDir → throws (always-on)
 *   * NUL byte in path → throws (always-on)
 *   * Outside CWD → console.warn by default; throws when auditStrictPaths: true
 */

'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { ShieldConfig } = require('../src');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cloakllm-h5-js-'));
}

function trySymlink(target, linkPath) {
  // Returns true if symlink created, false if denied (Windows non-admin, etc.)
  try {
    fs.symlinkSync(target, linkPath, 'dir');
    return true;
  } catch {
    return false;
  }
}

function captureWarnings(fn) {
  const original = console.warn;
  const captured = [];
  console.warn = (...args) => captured.push(args.join(' '));
  try {
    fn();
  } finally {
    console.warn = original;
  }
  return captured;
}

// ─── Symlink rejection (always-on) ────────────────────────────────────────

describe('H5 — symlink at logDir is always rejected', () => {
  let tmp;
  beforeEach(() => { tmp = tmpDir(); });

  it('throws when logDir is a symlink (default mode)', () => {
    const realTarget = path.join(tmp, 'real_dir');
    fs.mkdirSync(realTarget);
    const link = path.join(tmp, 'logs');
    if (!trySymlink(realTarget, link)) {
      // Skip on platforms that don't allow symlink creation
      return;
    }
    assert.throws(
      () => new ShieldConfig({ logDir: link }),
      /symlink/i,
    );
  });

  it('throws when logDir is a symlink (strict mode too)', () => {
    const realTarget = path.join(tmp, 'real_dir');
    fs.mkdirSync(realTarget);
    const link = path.join(tmp, 'logs');
    if (!trySymlink(realTarget, link)) return;
    assert.throws(
      () => new ShieldConfig({ logDir: link, auditStrictPaths: true }),
      /symlink/i,
    );
  });

  it('regular directory at logDir is accepted', () => {
    const dir = path.join(tmp, 'regular_logs');
    fs.mkdirSync(dir);
    // Outside-CWD warning fires but doesn't throw
    captureWarnings(() => {
      const cfg = new ShieldConfig({ logDir: dir });
      assert.equal(cfg.logDir, dir);
    });
  });

  it('non-existent logDir is accepted (will be created at first write)', () => {
    const dir = path.join(tmp, 'fresh_logs');
    captureWarnings(() => {
      const cfg = new ShieldConfig({ logDir: dir });
      assert.equal(cfg.logDir, dir);
    });
  });
});

// ─── NUL byte rejection (always-on) ───────────────────────────────────────

describe('H5 — NUL byte in path is always rejected', () => {
  it('throws on NUL in logDir', () => {
    assert.throws(
      () => new ShieldConfig({ logDir: './logs\0/sneaky' }),
      /NUL byte/,
    );
  });

  it('throws on NUL in attestationKeyPath', () => {
    assert.throws(
      () => new ShieldConfig({
        logDir: './logs',
        attestationKeyPath: './key.json\0bypass',
      }),
      /NUL byte/,
    );
  });
});

// ─── Strict paths mode (opt-in) ───────────────────────────────────────────

describe('H5 — auditStrictPaths promotes outside-CWD warning to error', () => {
  let tmp;
  beforeEach(() => { tmp = tmpDir(); });

  it('default mode warns but does not throw', () => {
    const warnings = captureWarnings(() => {
      new ShieldConfig({ logDir: tmp });
    });
    assert.ok(
      warnings.some(w => w.includes('outside the current working directory')),
      `expected warning, got: ${warnings.join(' | ')}`,
    );
  });

  it('strict mode throws on outside-CWD logDir', () => {
    assert.throws(
      () => new ShieldConfig({ logDir: tmp, auditStrictPaths: true }),
      /outside the current working directory.*auditStrictPaths/i,
    );
  });

  it('strict mode + inside-CWD logDir does not throw', () => {
    const inside = path.join(process.cwd(), 'test_h5_audit_dir_js');
    try {
      const cfg = new ShieldConfig({ logDir: inside, auditStrictPaths: true });
      assert.equal(cfg.logDir, inside);
    } finally {
      if (fs.existsSync(inside)) {
        fs.rmdirSync(inside);
      }
    }
  });

  it('strict mode applies to attestationKeyPath too', () => {
    const tmpKey = path.join(tmp, 'fake_key.json');
    fs.writeFileSync(tmpKey, '{}');
    assert.throws(
      () => new ShieldConfig({
        logDir: './logs',
        attestationKeyPath: tmpKey,
        auditStrictPaths: true,
      }),
      /attestationKeyPath/,
    );
  });
});

// ─── Env var ──────────────────────────────────────────────────────────────

describe('H5 — CLOAKLLM_AUDIT_STRICT_PATHS env mirrors kwarg', () => {
  let tmp, prior;
  beforeEach(() => {
    tmp = tmpDir();
    prior = process.env.CLOAKLLM_AUDIT_STRICT_PATHS;
  });
  afterEach(() => {
    if (prior === undefined) delete process.env.CLOAKLLM_AUDIT_STRICT_PATHS;
    else process.env.CLOAKLLM_AUDIT_STRICT_PATHS = prior;
  });

  it('env=true promotes outside-CWD to error', () => {
    process.env.CLOAKLLM_AUDIT_STRICT_PATHS = 'true';
    assert.throws(
      () => new ShieldConfig({ logDir: tmp }),
      /outside the current working directory/,
    );
  });

  it('env unset (default) keeps warning behaviour', () => {
    delete process.env.CLOAKLLM_AUDIT_STRICT_PATHS;
    const warnings = captureWarnings(() => {
      new ShieldConfig({ logDir: tmp });
    });
    assert.ok(warnings.some(w => w.includes('outside the current working directory')));
  });
});
