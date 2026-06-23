/**
 * RFC 3161 trusted timestamping (v0.11.0 TS-2 / TS-4) -- JS mirror.
 *
 * Checkpoint-level trusted timestamps over the audit chain's latest entry_hash.
 * The TSA only ever receives a HASH; the stored checkpoint carries a hash, a
 * URL, and an opaque signed token only. Verification is fully OFFLINE.
 *
 * Zero runtime dependencies: a minimal DER navigator parses the fixed RFC 3161
 * / CMS structure, and Node's built-in `crypto.X509Certificate` + `crypto.verify`
 * do the actual signature math (we navigate ASN.1 but never hand-roll the
 * cryptographic primitives). See SPIKE_timestamping.md and the Python
 * cloakllm/timestamping.py (byte-compatible verifier).
 */

'use strict';

const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');

// --- minimal DER (TLV) navigator ---

function _readTLV(buf, off) {
  if (off >= buf.length) throw new Error('DER: read past end');
  const tag = buf[off];
  let p = off + 1;
  if (p > buf.length) throw new Error('DER: truncated');
  let len = buf[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER: unsupported length form');
    len = 0;
    // v0.11.0 LOW-5: use *256 (not <<8) so a 4-byte length with the high bit
    // set does not become a negative 32-bit int and slip past the bounds check.
    for (let i = 0; i < n; i++) len = (len * 256) + buf[p++];
  }
  const contentStart = p;
  const end = p + len;
  if (len < 0 || end > buf.length) throw new Error('DER: length exceeds buffer');
  return { tag, headerLen: contentStart - off, length: len, start: off, contentStart, contentEnd: end, end };
}

// Children of a constructed TLV located at `off`. `depth` caps nesting work
// (v0.11.0 LOW-6 defense-in-depth) on the direct-call path where input isn't
// 16 KB-capped by the audit validator.
function _children(buf, off, depth = 0) {
  if (depth > 32) throw new Error('DER: nesting too deep');
  const t = _readTLV(buf, off);
  const out = [];
  let p = t.contentStart;
  while (p < t.contentEnd) {
    const c = _readTLV(buf, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

function _content(buf, tlv) {
  return buf.subarray(tlv.contentStart, tlv.contentEnd);
}

// Parse an ASN.1 GeneralizedTime (tag 0x18) like "20260701100000Z" -> ISO UTC.
function _parseGeneralizedTime(s) {
  // YYYYMMDDHHMMSS[.fff]Z
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s);
  if (!m) return null;
  const [, Y, Mo, D, H, Mi, S] = m;
  return `${Y}-${Mo}-${D}T${H}:${Mi}:${S}+00:00`;
}

// OIDs we care about (as dotted strings, decoded from DER on demand).
const _OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const _OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
// signerInfo digestAlgorithm OIDs -> Node hash name. The TSA chooses this
// (freetsa.org uses sha512); the messageDigest attribute AND the signature
// are computed under it, so hardcoding sha256 breaks SHA-512 TSAs.
const _DIGEST_OID_TO_HASH = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
  '1.3.14.3.2.26': 'sha1',
};

function _decodeOID(buf) {
  // buf = OID content bytes
  const parts = [];
  let v = 0;
  let first = true;
  for (const b of buf) {
    v = (v * 128) + (b & 0x7f);
    if (!(b & 0x80)) {
      if (first) { parts.push(Math.floor(v / 40), v % 40); first = false; }
      else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

// v0.11.0 MEDIUM-2: does a DER cert carry the id-kp-timeStamping EKU
// (1.3.6.1.5.5.7.3.8)? RFC 3161 sec 2.3 requires it on a TSA signing cert.
// Node's X509Certificate does not expose EKU, so we DER-parse the cert.
function _certHasTimestampingEKU(certDer) {
  try {
    const cert = _children(certDer, 0);          // [tbs, sigAlg, sigVal]
    const tbs = _children(certDer, cert[0].start);
    const extWrap = tbs.find(c => c.tag === 0xa3); // [3] EXPLICIT extensions
    if (!extWrap) return false;
    const exts = _children(certDer, extWrap.contentStart); // Extension SEQs
    for (const ext of exts) {
      const parts = _children(certDer, ext.start);
      if (_decodeOID(_content(certDer, parts[0])) !== '2.5.29.37') continue; // extKeyUsage
      const octet = parts.filter(p => p.tag === 0x04).pop();
      const kps = _children(certDer, octet.contentStart);
      return kps.some(kp => kp.tag === 0x06
        && _decodeOID(_content(certDer, kp)) === '1.3.6.1.5.5.7.3.8');
    }
    return false;
  } catch (_) { return false; }
}

// v0.11.0 MEDIUM-2: is an X509Certificate valid at the given Date?
function _certValidAt(x509, genDate) {
  if (!genDate) return true; // no genTime to compare against
  const nb = x509.validFromDate || new Date(x509.validFrom);
  const na = x509.validToDate || new Date(x509.validTo);
  return nb <= genDate && genDate <= na;
}

// v0.11.1: the ESS signing-certificate attribute (RFC 3161 sec 2.4.1 / RFC
// 5035) a conforming TSA MUST place in signerInfo, binding its signing cert by
// hash. OpenSSL enforces it; we require + verify it to close a cert-
// substitution surface and accept exactly what a conforming verifier accepts.
const _OID_ESS_SIGNING_CERT_V2 = '1.2.840.113549.1.9.16.2.47'; // SigningCertificateV2
const _OID_ESS_SIGNING_CERT_V1 = '1.2.840.113549.1.9.16.2.12'; // SigningCertificate

// Locate + decode the ESS attribute among `attrs` (signedAttrs children).
// Returns {present:false} when absent, else {present:true, hashName, certHash}.
// Throws on a malformed attribute (the caller treats that as a rejection).
function _essSigningCert(buf, attrs) {
  for (const a of attrs) {
    const ac = _children(buf, a.start);
    const oid = _decodeOID(_content(buf, ac[0]));
    const isV2 = oid === _OID_ESS_SIGNING_CERT_V2;
    if (!isV2 && oid !== _OID_ESS_SIGNING_CERT_V1) continue;
    // ac[1] = SET OF SigningCertificate(V2); first element is the structure SEQ,
    // whose first child is `certs` (SEQUENCE OF ESSCertID(v2)).
    const scv = _children(buf, ac[1].start)[0];
    const certsSeq = _children(buf, scv.start)[0];
    const fields = _children(buf, _children(buf, certsSeq.start)[0].start);
    if (isV2) {
      // ESSCertIDv2 ::= SEQ { hashAlgorithm AlgId DEFAULT sha256 (OPTIONAL),
      //                       certHash OCTET STRING, issuerSerial OPTIONAL }
      if (fields[0].tag === 0x30) { // hashAlgorithm present
        const algOid = _decodeOID(_content(buf, _children(buf, fields[0].start)[0]));
        const hashName = _DIGEST_OID_TO_HASH[algOid];
        if (!hashName) throw new Error('ess: unsupported hash algorithm');
        return { present: true, hashName, certHash: Buffer.from(_content(buf, fields[1])) };
      }
      return { present: true, hashName: 'sha256', certHash: Buffer.from(_content(buf, fields[0])) };
    }
    // ESSCertID (v1) ::= SEQ { certHash OCTET STRING (SHA-1), issuerSerial OPTIONAL }
    return { present: true, hashName: 'sha1', certHash: Buffer.from(_content(buf, fields[0])) };
  }
  return { present: false };
}

/**
 * Verify an RFC 3161 TimeStampToken offline.
 * @param {string} tstTokenB64
 * @param {string} expectedDigestHex  the stamped_entry_hash (hex)
 * @param {string[]|null} trustedCertsPem  optional TSA trust anchors (PEM)
 * @returns {{valid:boolean, gen_time:string|null, message_imprint_matches:boolean,
 *            signature_valid:boolean, chain_valid:boolean|null, reason:string}}
 */
function verifyTimestampToken(tstTokenB64, expectedDigestHex, trustedCertsPem = null) {
  const fail = (reason, extra = {}) => ({
    valid: false, gen_time: null, message_imprint_matches: false,
    signature_valid: false, chain_valid: null, reason, ...extra,
  });

  let buf;
  try { buf = Buffer.from(tstTokenB64, 'base64'); } catch (_) { return fail('token is not valid base64'); }
  if (!buf || buf.length === 0) return fail('empty token');

  let genTime = null;
  try {
    // ContentInfo ::= SEQ { contentType OID, content [0] EXPLICIT SignedData }
    const ci = _children(buf, 0);
    const ctOid = _decodeOID(_content(buf, ci[0]));
    if (ctOid !== _OID_SIGNED_DATA) return fail('token is not a CMS SignedData');
    // ci[1] is [0] EXPLICIT whose content IS the SignedData SEQUENCE, so its
    // children are the SignedData fields directly.
    const sd = _children(buf, ci[1].contentStart);
    // sd: version, digestAlgorithms SET, encapContentInfo SEQ, [optional [0] certs, [1] crls], signerInfos SET
    const encapCI = sd[2];  // encapContentInfo is always the 3rd element
    const encapChildren = _children(buf, encapCI.start);
    // eContent = [0] EXPLICIT { OCTET STRING wrapping TSTInfo (standard, real
    // TSAs) | TSTInfo SEQUENCE directly (asn1crypto's encoding) }. Handle both;
    // tstInfoDer is always the FULL TSTInfo SEQUENCE DER, which is exactly what
    // the messageDigest signed-attribute is computed over.
    const eContentExplicit = encapChildren[1];
    const inner = _children(buf, eContentExplicit.contentStart)[0];
    let tstInfoDer;
    if (inner.tag === 0x04) {           // OCTET STRING wrapper (standard)
      tstInfoDer = _content(buf, inner);
    } else {                            // TSTInfo SEQUENCE directly
      tstInfoDer = Buffer.from(buf.subarray(inner.start, inner.end));
    }

    // TSTInfo ::= SEQ { version, policy OID, messageImprint SEQ, serialNumber, genTime GeneralizedTime, ... }
    const tst = _children(tstInfoDer, 0);
    const messageImprint = tst[2];
    const miChildren = _children(tstInfoDer, messageImprint.start);
    const hashedMessage = _content(tstInfoDer, miChildren[1]); // OCTET STRING value
    // genTime is the first GeneralizedTime (tag 0x18) after serialNumber
    const gtTlv = tst.find(c => c.tag === 0x18);
    if (gtTlv) genTime = _parseGeneralizedTime(_content(tstInfoDer, gtTlv).toString('latin1'));

    // messageImprint == expected digest
    const expected = Buffer.from(expectedDigestHex, 'hex');
    if (hashedMessage.length !== expected.length ||
        !crypto.timingSafeEqual(hashedMessage, expected)) {
      return { ...fail('message imprint does not match the stamped entry hash'), gen_time: genTime };
    }

    // --- signer info ---
    const signerInfosSet = sd[sd.length - 1]; // SET OF SignerInfo (last element)
    const signerInfo = _children(buf, signerInfosSet.start)[0];
    const si = _children(buf, signerInfo.start);
    // si: version, sid, digestAlgorithm SEQ, [0] signedAttrs, sigAlgorithm SEQ, signature OCTET STRING
    // The digestAlgorithm (si[2]) drives both the messageDigest hash and the
    // signature hash -- read it rather than assuming sha256.
    const digestAlgOid = _decodeOID(_content(buf, _children(buf, si[2].start)[0]));
    const hashName = _DIGEST_OID_TO_HASH[digestAlgOid];
    if (!hashName) {
      return { ...fail(`unsupported digest algorithm ${digestAlgOid}`), gen_time: genTime, message_imprint_matches: true };
    }
    const signedAttrsTlv = si.find(c => c.tag === 0xa0);
    if (!signedAttrsTlv) {
      return { ...fail('token has no signed attributes'), gen_time: genTime, message_imprint_matches: true };
    }
    // signature = the OCTET STRING (tag 0x04) after the signatureAlgorithm
    const octets = si.filter(c => c.tag === 0x04);
    const signatureTlv = octets[octets.length - 1];
    const signature = _content(buf, signatureTlv);

    // messageDigest signed attr == sha256(TSTInfo DER)
    const attrs = _children(buf, signedAttrsTlv.start);
    let mdAttrVal = null;
    for (const a of attrs) {
      const ac = _children(buf, a.start);
      const aoid = _decodeOID(_content(buf, ac[0]));
      if (aoid === _OID_MESSAGE_DIGEST) {
        const valSet = _children(buf, ac[1].start)[0]; // OCTET STRING inside the SET
        mdAttrVal = _content(buf, valSet);
        break;
      }
    }
    const eHash = crypto.createHash(hashName).update(tstInfoDer).digest();
    if (!mdAttrVal || mdAttrVal.length !== eHash.length || !crypto.timingSafeEqual(mdAttrVal, eHash)) {
      return { ...fail('messageDigest attribute does not match eContent'), gen_time: genTime, message_imprint_matches: true };
    }

    // signer certificate: SignedData certificates [0] IMPLICIT (tag 0xa0)
    const certsTlv = sd.find(c => c.tag === 0xa0);
    if (!certsTlv) {
      return { ...fail('no certificate in token (request certReq=true)'), gen_time: genTime, message_imprint_matches: true };
    }
    const certTlvs = _children(buf, certsTlv.start).filter(c => c.tag === 0x30);
    // Use the signer cert. We confirm by checking the signature verifies under
    // its key. Keep all token certs (as {x509, der}) for intermediate chaining.
    const tokenCerts = [];
    for (const ct of certTlvs) {
      const certDer = buf.subarray(ct.start, ct.end);
      try { tokenCerts.push({ x509: new crypto.X509Certificate(certDer), der: certDer }); }
      catch (_) { /* skip unparseable */ }
    }
    let signerCert = null, signerCertDer = null, signatureValid = false;
    const signedAttrsDer = Buffer.from(buf.subarray(signedAttrsTlv.start, signedAttrsTlv.end));
    signedAttrsDer[0] = 0x31; // re-encode signedAttrs with the universal SET tag (RFC 5652 5.4)
    for (const { x509, der } of tokenCerts) {
      try {
        if (crypto.verify(hashName, signedAttrsDer, x509.publicKey, signature)) {
          signerCert = x509; signerCertDer = der; signatureValid = true; break;
        }
      } catch (_) { /* try next cert */ }
    }
    if (!signatureValid) {
      return { ...fail('CMS signature verification failed'), gen_time: genTime, message_imprint_matches: true };
    }

    // v0.11.1: ESS signing-certificate attribute MUST be present and bind the
    // signer cert (RFC 3161 sec 2.4.1 / RFC 5035 / RFC 5816). Require + verify.
    let ess;
    try { ess = _essSigningCert(buf, attrs); }
    catch (_) {
      return { ...fail('malformed ESS signing-certificate attribute'), gen_time: genTime, message_imprint_matches: true, signature_valid: true };
    }
    if (!ess.present) {
      return { ...fail('token lacks the ESS signing-certificate attribute (RFC 3161 sec 2.4.1)'), gen_time: genTime, message_imprint_matches: true, signature_valid: true };
    }
    const essGot = crypto.createHash(ess.hashName).update(signerCertDer).digest();
    if (essGot.length !== ess.certHash.length || !crypto.timingSafeEqual(essGot, ess.certHash)) {
      return { ...fail('ESS signing-certificate hash does not match the signer cert'), gen_time: genTime, message_imprint_matches: true, signature_valid: true };
    }

    // v0.11.0 MEDIUM-2: intrinsic signer-cert checks (independent of any anchor)
    // -- must carry id-kp-timeStamping EKU (RFC 3161 2.3) and be valid at genTime.
    const genDate = genTime ? new Date(genTime) : null;
    if (!_certHasTimestampingEKU(signerCertDer)) {
      return { ...fail('signer cert lacks the id-kp-timeStamping EKU'), gen_time: genTime, message_imprint_matches: true, signature_valid: true };
    }
    if (!_certValidAt(signerCert, genDate)) {
      return { ...fail('signer cert is not valid at genTime'), gen_time: genTime, message_imprint_matches: true, signature_valid: true };
    }

    // chain to a trusted anchor (MEDIUM-3: allow ONE intermediate from the
    // token's own certificates: signer <- intermediate <- anchor).
    let chainValid = null;
    if (trustedCertsPem && trustedCertsPem.length) {
      const anchors = [];
      for (const pem of trustedCertsPem) {
        try { anchors.push(new crypto.X509Certificate(pem)); } catch (_) { /* skip */ }
      }
      const signedBy = (child, issuer) => { try { return child.verify(issuer.publicKey); } catch (_) { return false; } };
      chainValid = anchors.some(a => signedBy(signerCert, a));
      if (!chainValid) {
        for (const { x509: inter } of tokenCerts) {
          if (inter.fingerprint256 === signerCert.fingerprint256) continue;
          if (signedBy(signerCert, inter) && _certValidAt(inter, genDate)
              && anchors.some(a => signedBy(inter, a))) { chainValid = true; break; }
        }
      }
      if (!chainValid) {
        return {
          valid: false, gen_time: genTime, message_imprint_matches: true,
          signature_valid: true, chain_valid: false,
          reason: 'signer cert does not chain to a trusted anchor',
        };
      }
    }

    return {
      valid: true, gen_time: genTime, message_imprint_matches: true,
      signature_valid: true, chain_valid: chainValid, reason: 'ok',
    };
  } catch (e) {
    return { ...fail(`malformed token: ${e.message}`), gen_time: genTime };
  }
}

// --- TS-2 client: request build + network ---

function _encodeLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function _tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), _encodeLen(content.length), content]);
}
// OID encoder for the two digest algorithms we support.
const _DIGEST_OID_DER = {
  // sha256 = 2.16.840.1.101.3.4.2.1 ; sha512 = 2.16.840.1.101.3.4.2.3
  sha256: Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
  sha512: Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]),
};

/** DER-encode an RFC 3161 TimeStampReq for a digest. certReq=TRUE. */
function buildTimestampRequest(digest, hashAlgorithm = 'sha256', nonce = null) {
  const oid = _DIGEST_OID_DER[hashAlgorithm];
  if (!oid) throw new Error(`hash_algorithm must be sha256 or sha512`);
  const algId = _tlv(0x30, Buffer.concat([_tlv(0x06, oid), _tlv(0x05, Buffer.alloc(0))])); // AlgorithmIdentifier (NULL params)
  const messageImprint = _tlv(0x30, Buffer.concat([algId, _tlv(0x04, Buffer.from(digest))]));
  const version = _tlv(0x02, Buffer.from([1]));
  let nonceDer = Buffer.alloc(0);
  if (nonce == null) nonce = crypto.randomBytes(8);
  // INTEGER (positive): prepend 0x00 if high bit set
  let nb = Buffer.isBuffer(nonce) ? nonce : Buffer.from([nonce]);
  if (nb[0] & 0x80) nb = Buffer.concat([Buffer.from([0]), nb]);
  nonceDer = _tlv(0x02, nb);
  const certReq = _tlv(0x01, Buffer.from([0xff])); // BOOLEAN TRUE
  return _tlv(0x30, Buffer.concat([version, messageImprint, nonceDer, certReq]));
}

/** Parse a TimeStampResp; throw unless granted; return the TimeStampToken DER. */
function parseTimestampResponse(der) {
  const buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  const resp = _children(buf, 0); // SEQ { PKIStatusInfo, TimeStampToken OPTIONAL }
  const statusInfo = _children(buf, resp[0].start);
  const statusInt = _content(buf, statusInfo[0]); // INTEGER
  const status = statusInt.length ? statusInt[statusInt.length - 1] : 1;
  if (status !== 0 && status !== 1) {
    throw new Error(`TSA did not grant the timestamp (status=${status}).`);
  }
  if (resp.length < 2) throw new Error('TSA response granted but carried no token.');
  return buf.subarray(resp[1].start, resp[1].end);
}

/** POST a TimeStampReq to a TSA over https (SSRF-guarded). Returns token base64. */
async function requestTimestamp(tsaUrl, digest, hashAlgorithm = 'sha256', timeoutMs = 10000) {
  let u;
  try { u = new URL(tsaUrl); } catch (_) { throw new Error('tsa_url is not a valid URL'); }
  if (u.protocol !== 'https:') throw new Error('tsa_url must be an https:// URL');

  // v0.11.0 HIGH-1 fix (SSRF parity with Python): resolve the host and reject
  // any address in the always-deny set (cloud metadata, multicast, IPv4-mapped
  // forms). Reuses the llm-detector _checkIpAllowed defense. allow_remote=true
  // (TSAs are remote): metadata-exfil is blocked, but private ranges + loopback
  // are NOT (a deployer may run an internal TSA -- same posture as Python). We
  // connect to a pinned, validated IP to resist DNS rebinding.
  const dns = require('dns').promises;
  const net = require('net');
  const { _checkIpAllowed } = require('./llm-detector');
  let pinnedIp;
  const host = u.hostname;
  const family = net.isIP(host);
  if (family) {
    if (!_checkIpAllowed(host, true)) {
      throw new Error(`tsa_url host ${host} is a disallowed address.`);
    }
    pinnedIp = host;
  } else {
    let addrs;
    try { addrs = await dns.lookup(host, { all: true }); }
    catch (e) { throw new Error(`tsa_url host ${host} did not resolve (${e.message}).`); }
    for (const a of addrs) {
      if (!_checkIpAllowed(a.address, true)) {
        throw new Error(`tsa_url host ${host} resolves to a disallowed address (${a.address}).`);
      }
    }
    pinnedIp = addrs[0].address;
  }

  const body = buildTimestampRequest(digest, hashAlgorithm);
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: pinnedIp,                 // connect to the validated IP (anti-rebind)
      servername: host,               // SNI/cert validation still uses the hostname
      headers: { 'Content-Type': 'application/timestamp-query', 'Content-Length': body.length, Host: host },
      port: u.port || 443, path: u.pathname + u.search,
      method: 'POST',
      timeout: timeoutMs,
    }, (res) => {
      // Reject redirects (SSRF) -- TSAs answer directly.
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.resume(); return reject(new Error(`TSA returned a redirect (${res.statusCode}); refused.`));
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const token = parseTimestampResponse(Buffer.concat(chunks));
          resolve(token.toString('base64'));
        } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('TSA request timed out')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

module.exports = {
  verifyTimestampToken, buildTimestampRequest, parseTimestampResponse, requestTimestamp,
};
