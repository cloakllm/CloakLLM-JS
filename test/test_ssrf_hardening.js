/**
 * v0.6.3 H2 — JS SSRF hardening tests for the Ollama URL validator.
 *
 * Mirrors cloakllm-py/tests/test_ssrf_hardening.py for the IP-literal
 * protections. Hostname-rebinding tests aren't applicable to JS because
 * the constructor is synchronous and Node has no synchronous DNS — that
 * gap is documented in the validator and warned-about at construction.
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  _checkIpAllowed,
  _unwrapIpv4MappedIpv6,
  _isAlwaysDenyIpv4,
  _isPrivateIpv4,
  _validateOllamaUrl,
} = require('../src/llm-detector');

// ─── _unwrapIpv4MappedIpv6 ────────────────────────────────────────────────

describe('_unwrapIpv4MappedIpv6 (v0.6.3 H2)', () => {
  it('unwraps dotted form to IPv4', () => {
    assert.equal(_unwrapIpv4MappedIpv6('::ffff:169.254.169.254'), '169.254.169.254');
    assert.equal(_unwrapIpv4MappedIpv6('::ffff:127.0.0.1'), '127.0.0.1');
  });

  it('unwraps hex form to IPv4', () => {
    // ::ffff:a9fe:a9fe is the hex of 169.254.169.254
    assert.equal(_unwrapIpv4MappedIpv6('::ffff:a9fe:a9fe'), '169.254.169.254');
  });

  it('returns null for non-IPv4-mapped IPv6', () => {
    assert.equal(_unwrapIpv4MappedIpv6('::1'), null);
    assert.equal(_unwrapIpv4MappedIpv6('fd00::1'), null);
    assert.equal(_unwrapIpv4MappedIpv6('192.168.1.1'), null);
  });

  it('handles bracketed IPv6', () => {
    assert.equal(_unwrapIpv4MappedIpv6('[::ffff:169.254.169.254]'), '169.254.169.254');
  });

  it('returns null for non-string input', () => {
    assert.equal(_unwrapIpv4MappedIpv6(null), null);
    assert.equal(_unwrapIpv4MappedIpv6(undefined), null);
    assert.equal(_unwrapIpv4MappedIpv6(123), null);
  });
});

// ─── _isAlwaysDenyIpv4 / _isPrivateIpv4 ───────────────────────────────────

describe('IPv4 range predicates (v0.6.3 H2)', () => {
  it('169.254.0.0/16 (cloud metadata) is always-deny', () => {
    assert.equal(_isAlwaysDenyIpv4('169.254.169.254'), true);
    assert.equal(_isAlwaysDenyIpv4('169.254.0.1'), true);
    assert.equal(_isAlwaysDenyIpv4('169.254.255.254'), true);
  });

  it('100.64.0.0/10 (CGN) is always-deny', () => {
    assert.equal(_isAlwaysDenyIpv4('100.64.0.1'), true);
    assert.equal(_isAlwaysDenyIpv4('100.127.255.254'), true);
    // Boundary: 100.63.x.x is NOT in /10
    assert.equal(_isAlwaysDenyIpv4('100.63.0.1'), false);
  });

  it('0.0.0.0/8 is always-deny', () => {
    assert.equal(_isAlwaysDenyIpv4('0.0.0.0'), true);
    assert.equal(_isAlwaysDenyIpv4('0.255.255.255'), true);
  });

  it('multicast 224.0.0.0/4 is always-deny', () => {
    assert.equal(_isAlwaysDenyIpv4('224.0.0.1'), true);
    assert.equal(_isAlwaysDenyIpv4('239.255.255.250'), true);
  });

  it('reserved 240.0.0.0/4 is always-deny', () => {
    assert.equal(_isAlwaysDenyIpv4('240.0.0.1'), true);
    assert.equal(_isAlwaysDenyIpv4('255.255.255.255'), true);
  });

  it('loopback and RFC1918 are NOT always-deny', () => {
    assert.equal(_isAlwaysDenyIpv4('127.0.0.1'), false);
    assert.equal(_isAlwaysDenyIpv4('10.0.0.1'), false);
    assert.equal(_isAlwaysDenyIpv4('172.16.0.1'), false);
    assert.equal(_isAlwaysDenyIpv4('192.168.1.1'), false);
  });

  it('public addresses are NOT always-deny', () => {
    assert.equal(_isAlwaysDenyIpv4('8.8.8.8'), false);
    assert.equal(_isAlwaysDenyIpv4('1.1.1.1'), false);
  });

  it('private predicate: loopback + RFC1918 only', () => {
    assert.equal(_isPrivateIpv4('127.0.0.1'), true);
    assert.equal(_isPrivateIpv4('10.0.0.1'), true);
    assert.equal(_isPrivateIpv4('172.16.0.1'), true);
    assert.equal(_isPrivateIpv4('172.31.255.254'), true);
    assert.equal(_isPrivateIpv4('192.168.1.1'), true);
  });

  it('private predicate: 172.32.x is NOT private', () => {
    // Common bug: people forget the /12 stops at 172.31
    assert.equal(_isPrivateIpv4('172.32.0.1'), false);
    assert.equal(_isPrivateIpv4('172.15.255.254'), false);
  });
});

// ─── _checkIpAllowed ──────────────────────────────────────────────────────

describe('_checkIpAllowed (v0.6.3 H2)', () => {
  it('loopback always allowed regardless of allowRemote', () => {
    assert.equal(_checkIpAllowed('127.0.0.1', false), true);
    assert.equal(_checkIpAllowed('127.0.0.1', true), true);
  });

  it('AWS IMDS denied even with allowRemote', () => {
    assert.equal(_checkIpAllowed('169.254.169.254', false), false);
    assert.equal(_checkIpAllowed('169.254.169.254', true), false);
  });

  it('IPv4-mapped IPv6 IMDS denied (the headline bypass)', () => {
    assert.equal(_checkIpAllowed('::ffff:169.254.169.254', true), false);
    assert.equal(_checkIpAllowed('::ffff:a9fe:a9fe', true), false);
  });

  it('public address requires allowRemote', () => {
    assert.equal(_checkIpAllowed('8.8.8.8', false), false);
    assert.equal(_checkIpAllowed('8.8.8.8', true), true);
  });

  it('IPv6 loopback and ULA always allowed', () => {
    assert.equal(_checkIpAllowed('::1', false), true);
    assert.equal(_checkIpAllowed('fd00::1', false), true);
  });

  it('IPv6 multicast denied with allowRemote', () => {
    assert.equal(_checkIpAllowed('ff02::1', true), false);
  });

  it('returns null for non-IP hostnames (deferred to caller)', () => {
    assert.equal(_checkIpAllowed('ollama.example.com', false), null);
    assert.equal(_checkIpAllowed('ollama.example.com', true), null);
  });

  it('returns false for empty/garbage', () => {
    assert.equal(_checkIpAllowed('', false), false);
    assert.equal(_checkIpAllowed(null, false), false);
    assert.equal(_checkIpAllowed(undefined, false), false);
  });
});

// ─── _validateOllamaUrl ───────────────────────────────────────────────────

describe('_validateOllamaUrl (v0.6.3 H2)', () => {
  it('accepts loopback IP literal', () => {
    const url = _validateOllamaUrl('http://127.0.0.1:11434', false);
    assert.equal(url, 'http://127.0.0.1:11434');
  });

  it('accepts RFC1918 IP literal', () => {
    assert.equal(_validateOllamaUrl('http://10.0.0.5:11434', false), 'http://10.0.0.5:11434');
    assert.equal(_validateOllamaUrl('http://192.168.1.100:11434', false), 'http://192.168.1.100:11434');
  });

  it('accepts IPv6 loopback (bracketed)', () => {
    assert.equal(_validateOllamaUrl('http://[::1]:11434', false), 'http://[::1]:11434');
  });

  it('rejects AWS IMDS literal', () => {
    assert.throws(
      () => _validateOllamaUrl('http://169.254.169.254', true),
      /denied IP|metadata/i,
    );
  });

  it('rejects IPv4-mapped IPv6 IMDS literal', () => {
    assert.throws(
      () => _validateOllamaUrl('http://[::ffff:169.254.169.254]:11434', true),
      /denied IP|metadata/i,
    );
  });

  it('rejects 0.0.0.0', () => {
    assert.throws(
      () => _validateOllamaUrl('http://0.0.0.0:11434', true),
      /denied IP|metadata/i,
    );
  });

  it('rejects multicast', () => {
    assert.throws(
      () => _validateOllamaUrl('http://239.255.255.250', true),
      /denied IP|metadata/i,
    );
  });

  it('hostname requires allowRemote (no synchronous DNS)', () => {
    assert.throws(
      () => _validateOllamaUrl('http://ollama.example.com', false),
      /non-IP hostname|cannot validate/i,
    );
  });

  it('hostname accepted with allowRemote (warns at fetch boundary)', () => {
    // captures console.warn so the test isn't noisy
    const orig = console.warn;
    let warned = false;
    console.warn = () => { warned = true; };
    try {
      const url = _validateOllamaUrl('http://ollama.example.com', true);
      assert.equal(url, 'http://ollama.example.com');
      assert.ok(warned, 'should warn about hostname-rebinding gap');
    } finally {
      console.warn = orig;
    }
  });

  it('canonical localhost names trusted (RFC 6761) without allowRemote', () => {
    // RFC 6761 §6.3 mandates these resolve to loopback. We trust the OS
    // resolver — same model Python uses via getaddrinfo, made explicit
    // because Node has no synchronous DNS to verify.
    assert.equal(_validateOllamaUrl('http://localhost:11434', false), 'http://localhost:11434');
    assert.equal(_validateOllamaUrl('http://ollama.localhost:11434', false), 'http://ollama.localhost:11434');
  });


  it('public address rejected without allowRemote', () => {
    assert.throws(
      () => _validateOllamaUrl('http://8.8.8.8:11434', false),
      /denied IP|metadata/i,
    );
  });

  it('public address accepted with allowRemote', () => {
    const orig = console.warn;
    console.warn = () => {};
    try {
      const url = _validateOllamaUrl('http://8.8.8.8:11434', true);
      assert.equal(url, 'http://8.8.8.8:11434');
    } finally {
      console.warn = orig;
    }
  });

  it('rejects URL with no hostname', () => {
    assert.throws(
      () => _validateOllamaUrl('http://', true),
      /Invalid Ollama URL|no hostname/i,
    );
  });
});
