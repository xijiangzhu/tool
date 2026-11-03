/* 极简 TLS 客户端：只握手到「拿到服务端证书」这一步就断开。
 *
 * 为什么需要它：无论本地还是云端，都不能依赖运行时自带的 TLS 栈拿证书
 * （Workers 的 fetch 不暴露对端证书，Node 的 tls 又是本地专用的），
 * 于是自己发 ClientHello、读 ServerHello + Certificate，再自己解 DER。
 * 本地 Node（node:net）与云端 Workers（cloudflare:sockets）走同一份代码，
 * 是全项目唯一的 TLS 检测实现。
 */

import { certMatches } from './ct.js';
import { platform } from '../platform/index.js';

/* ------------------------------- 通用小工具 ------------------------------- */

const concat = (a, b) => {
  if (!a.length) return b;
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
};

const hex = (b) => {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
};

function randBytes(n) {
  const out = new Uint8Array(n);
  try {
    globalThis.crypto.getRandomValues(out);
    return out;
  } catch (_) {
    for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
    return out;
  }
}

async function sha256Hex(b) {
  try {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', b);
    return hex(new Uint8Array(digest)).toUpperCase();
  } catch (_) {
    return null;
  }
}

/* --------------------------------- DER 解析 -------------------------------- */

/** 读一个 TLV，返回 { tag, start, end, next } */
function tlv(buf, off) {
  if (off + 2 > buf.length) return null;
  const tag = buf[off];
  let len = buf[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || off + 2 + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[off + 2 + i];
    hdr = 2 + n;
  }
  const start = off + hdr;
  const end = start + len;
  if (end > buf.length) return null;
  return { tag, start, end, next: end };
}

function decodeOid(b) {
  if (!b || !b.length) return '';
  const parts = [];
  const first = b[0];
  parts.push(Math.floor(first / 40), first % 40);
  let n = 0;
  let started = false;
  for (let i = 1; i < b.length; i++) {
    const byte = b[i];
    n = n * 128 + (byte & 0x7f);
    started = true;
    if (!(byte & 0x80)) {
      parts.push(n);
      n = 0;
      started = false;
    }
  }
  if (started) parts.push(n);
  return parts.join('.');
}

function stringVal(buf, t) {
  const b = buf.subarray(t.start, t.end);
  if (t.tag === 0x1e) {
    // BMPString：UTF-16BE
    let s = '';
    for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]);
    return s;
  }
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return s;
}

const NAME_OID = {
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'STREET',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'title',
  '2.5.4.42': 'GN',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '0.9.2342.19200300.100.1.25': 'DC',
  '0.9.2342.19200300.100.1.1': 'UID',
};

function parseName(buf, t) {
  const parts = [];
  let p = t.start;
  while (p < t.end) {
    const rdn = tlv(buf, p);
    if (!rdn) break;
    p = rdn.next;
    let q = rdn.start;
    while (q < rdn.end) {
      const atv = tlv(buf, q);
      if (!atv) break;
      q = atv.next;
      const oidT = tlv(buf, atv.start);
      if (!oidT) continue;
      const valT = tlv(buf, oidT.next);
      if (!valT) continue;
      const oid = decodeOid(buf.subarray(oidT.start, oidT.end));
      parts.push({ k: NAME_OID[oid] || oid, v: stringVal(buf, valT) });
    }
  }
  return parts.map((x) => `${x.k}=${x.v}`).join(', ');
}

/** UTCTime(0x17) / GeneralizedTime(0x18) → 毫秒时间戳 */
function parseTime(buf, t) {
  const b = buf.subarray(t.start, t.end);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  s = s.replace(/[^0-9]/g, '');
  let y, mo, d, h, mi, se;
  if (t.tag === 0x17) {
    if (s.length < 10) return null;
    const yy = parseInt(s.slice(0, 2), 10);
    y = yy >= 50 ? 1900 + yy : 2000 + yy;
    mo = parseInt(s.slice(2, 4), 10);
    d = parseInt(s.slice(4, 6), 10);
    h = parseInt(s.slice(6, 8), 10);
    mi = parseInt(s.slice(8, 10), 10);
    se = s.length >= 12 ? parseInt(s.slice(10, 12), 10) : 0;
  } else {
    if (s.length < 12) return null;
    y = parseInt(s.slice(0, 4), 10);
    mo = parseInt(s.slice(4, 6), 10);
    d = parseInt(s.slice(6, 8), 10);
    h = parseInt(s.slice(8, 10), 10);
    mi = parseInt(s.slice(10, 12), 10);
    se = s.length >= 14 ? parseInt(s.slice(12, 14), 10) : 0;
  }
  if (!Number.isFinite(y) || !Number.isFinite(mo) || !Number.isFinite(d)) return null;
  const ts = Date.UTC(y, mo - 1, d, h || 0, mi || 0, se || 0);
  return Number.isNaN(ts) ? null : ts;
}

function parseSAN(buf) {
  const out = [];
  const seq = tlv(buf, 0);
  if (!seq) return out;
  let p = seq.start;
  while (p < seq.end) {
    const gn = tlv(buf, p);
    if (!gn) break;
    p = gn.next;
    if (gn.tag === 0x82) out.push({ type: 'DNS', value: stringVal(buf, gn) });
    else if (gn.tag === 0x81) out.push({ type: 'email', value: stringVal(buf, gn) });
    else if (gn.tag === 0x86) out.push({ type: 'URI', value: stringVal(buf, gn) });
    else if (gn.tag === 0x87) {
      const b = buf.subarray(gn.start, gn.end);
      out.push({
        type: 'IP',
        value: b.length === 4 ? Array.from(b).join('.') : hex(b),
      });
    }
  }
  return out;
}

const KU_NAMES = [
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
];

function parseKeyUsage(buf) {
  const t = tlv(buf, 0);
  if (!t || t.end <= t.start) return null;
  const unused = buf[t.start];
  const bits = (t.end - t.start - 1) * 8 - (unused || 0);
  const out = [];
  for (let i = 0; i < bits && i < KU_NAMES.length; i++) {
    const idx = t.start + 1 + Math.floor(i / 8);
    if (idx >= t.end) break;
    if (buf[idx] & (0x80 >> (i % 8))) out.push(KU_NAMES[i]);
  }
  return out;
}

const EC_BITS = {
  '1.2.840.10045.3.1.7': 256,
  '1.3.132.0.34': 384,
  '1.3.132.0.35': 521,
  '1.3.36.3.3.2.8.1.1.7': 256,
  '1.3.132.0.33': 224,
  '1.3.132.0.10': 256,
};

const iso = (ms) => (ms == null ? null : new Date(ms).toISOString());

/** 解一张 DER 证书，字段与 Node 的 normalizeCert 保持一致 */
function parseCert(der) {
  const cert = tlv(der, 0);
  if (!cert || cert.tag !== 0x30) return null;
  const tbs = tlv(der, cert.start);
  if (!tbs) return null;

  let q = tbs.start;
  if (der[q] === 0xa0) {
    const v = tlv(der, q);
    q = v ? v.next : q;
  }

  const serialT = tlv(der, q);
  const serialNumber = serialT ? hex(der.subarray(serialT.start, serialT.end)).toUpperCase() : null;
  q = serialT ? serialT.next : q;

  const sigAlgT = tlv(der, q);
  q = sigAlgT ? sigAlgT.next : q;

  const issuerT = tlv(der, q);
  const issuer = issuerT ? parseName(der, issuerT) : null;
  q = issuerT ? issuerT.next : q;

  let validFrom = null;
  let validTo = null;
  const validT = tlv(der, q);
  if (validT) {
    let r = validT.start;
    const a = tlv(der, r);
    if (a) {
      validFrom = parseTime(der, a);
      r = a.next;
    }
    const b = tlv(der, r);
    if (b) validTo = parseTime(der, b);
  }
  q = validT ? validT.next : q;

  const subjectT = tlv(der, q);
  const subject = subjectT ? parseName(der, subjectT) : null;
  q = subjectT ? subjectT.next : q;

  let publicKey = { type: null, bits: null };
  const spkiT = tlv(der, q);
  if (spkiT) {
    const algT = tlv(der, spkiT.start);
    if (algT) {
      const oidT = tlv(der, algT.start);
      const oid = oidT ? decodeOid(der.subarray(oidT.start, oidT.end)) : '';
      let curve = null;
      if (oidT && oidT.next < algT.end) {
        const pt = tlv(der, oidT.next);
        if (pt) curve = decodeOid(der.subarray(pt.start, pt.end));
      }
      let type = null;
      if (oid === '1.2.840.113549.1.1.1') type = 'RSA';
      else if (oid === '1.2.840.113549.1.1.10') type = 'RSA-PSS';
      else if (oid === '1.2.840.10045.2.1') type = 'EC';
      else if (oid === '1.3.101.112') type = 'Ed25519';
      else if (oid === '1.3.101.113') type = 'Ed448';
      else if (oid === '1.2.840.10040.4.1') type = 'DSA';
      else type = oid || null;

      const bitsT = tlv(der, algT.next);
      let bits = null;
      if (bitsT && bitsT.end > bitsT.start) {
        const keyBytes = der.subarray(bitsT.start + 1, bitsT.end);
        if (type === 'RSA' || type === 'RSA-PSS') {
          const rsaSeq = tlv(keyBytes, 0);
          if (rsaSeq) {
            const mod = tlv(keyBytes, rsaSeq.start);
            if (mod) {
              let s = mod.start;
              while (s < mod.end && keyBytes[s] === 0) s++;
              bits = (mod.end - s) * 8;
            }
          }
        } else if (type === 'EC') {
          bits = (curve && EC_BITS[curve]) || null;
        } else if (type === 'Ed25519') bits = 256;
        else if (type === 'Ed448') bits = 448;
      }
      publicKey = { type, bits };
    }
  }
  q = spkiT ? spkiT.next : q;

  if (q < tbs.end && (der[q] === 0xa1 || der[q] === 0xa2)) {
    const t = tlv(der, q);
    q = t ? t.next : q;
  }
  if (q < tbs.end && (der[q] === 0xa1 || der[q] === 0xa2)) {
    const t = tlv(der, q);
    q = t ? t.next : q;
  }

  let subjectAltName = [];
  let keyUsage = null;

  if (q < tbs.end && der[q] === 0xa3) {
    const wrapT = tlv(der, q);
    const seq = wrapT ? tlv(der, wrapT.start) : null;
    if (seq) {
      let r = seq.start;
      while (r < seq.end) {
        const ext = tlv(der, r);
        if (!ext) break;
        r = ext.next;
        let s = ext.start;
        const oidT = tlv(der, s);
        if (!oidT) continue;
        const oid = decodeOid(der.subarray(oidT.start, oidT.end));
        s = oidT.next;
        if (der[s] === 0x01) {
          const c = tlv(der, s);
          s = c ? c.next : s;
        }
        const valT = tlv(der, s);
        if (!valT) continue;
        const payload = der.subarray(valT.start, valT.end);
        if (oid === '2.5.29.17') subjectAltName = parseSAN(payload);
        else if (oid === '2.5.29.15') keyUsage = parseKeyUsage(payload);
      }
    }
  }

  const selfSigned = !!subject && subject === issuer;
  return {
    subject,
    issuer,
    subjectAltName,
    validFrom: iso(validFrom),
    validTo: iso(validTo),
    serialNumber,
    fingerprint256: null, // 由调用方异步补齐（需要 await）
    publicKey,
    selfSigned,
    keyUsage,
    der,
  };
}

/* ------------------------------ ClientHello ------------------------------ */

const SUITES = [
  0xc02f, 0xc030, 0xcca8, 0xc02b, 0xc02c, 0xc027, 0xc023, 0xc013, 0xc014, 0xc009,
  0x009c, 0x009d, 0x002f, 0x0035, 0x003c, 0x000a,
];

const SUITE_NAMES = {
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0xc027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  0xc023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
  0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0xc009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
};

const VERSION_NAMES = {
  0x0301: 'TLSv1.0',
  0x0302: 'TLSv1.1',
  0x0303: 'TLSv1.2',
  0x0304: 'TLSv1.3',
};

function putLen(n, bytes = 2) {
  const out = [];
  for (let i = bytes - 1; i >= 0; i--) out.push((n >> (8 * i)) & 0xff);
  return out;
}

/**
 * 构造 ClientHello。
 * - 默认只声明 TLS 1.2（不送 supported_versions），服务端会回到 1.2，证书明文可读
 * - probe 场景可指定 legacyVersion / supportedVersions（探测 TLS 1.3 时需要）
 */
function buildClientHello(servername, { legacyVersion = 0x0303, supportedVersions = null, tls13Suites = false, keyShare = false } = {}) {
  const host = String(servername || '');
  const hostBytes = Array.from(new TextEncoder().encode(host));

  const ext = [];
  // server_name：ServerNameList 长度 → name_type(0) → 主机名长度 → 主机名
  const sniBody = putLen(hostBytes.length + 3, 2).concat([0x00], putLen(hostBytes.length, 2), hostBytes);
  ext.push(...[0x00, 0x00], ...putLen(sniBody.length, 2), ...sniBody);
  // extended_master_secret
  ext.push(0x00, 0x17, 0x00, 0x00);
  // renegotiation_info
  ext.push(0xff, 0x01, 0x00, 0x01, 0x00);
  // supported_groups
  const groups = [0x00, 0x1d, 0x00, 0x17, 0x00, 0x18];
  ext.push(0x00, 0x0a, ...putLen(groups.length + 2, 2), ...putLen(groups.length, 2), ...groups);
  // ec_point_formats
  ext.push(0x00, 0x0b, 0x00, 0x02, 0x01, 0x00);
  // signature_algorithms
  const sigs = [0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x02, 0x03];
  ext.push(0x00, 0x0d, ...putLen(sigs.length + 2, 2), ...putLen(sigs.length, 2), ...sigs);
  // ALPN: http/1.1
  const alpn = [0x02, ...Array.from(new TextEncoder().encode('h2')), 0x08, ...Array.from(new TextEncoder().encode('http/1.1'))];
  ext.push(0x00, 0x10, ...putLen(alpn.length + 2, 2), ...putLen(alpn.length, 2), ...alpn);
  // supported_versions：声明指定版本（探测 TLS 1.3 支持时用）
  if (supportedVersions) {
    const vers = [];
    supportedVersions.forEach((v) => vers.push((v >> 8) & 0xff, v & 0xff));
    ext.push(0x00, 0x2b, ...putLen(vers.length + 1, 2), ...putLen(vers.length, 1), ...vers);
  }
  // key_share：TLS 1.3 服务端要求 ClientHello 必带此扩展，缺了直接 fatal missing_extension。
  // 注意数据结构是「2 字节向量总长 + 条目」——条目本身不另算外层长度会报 decode_error。
  // 放一个随机 x25519 公钥（内容无所谓，选上 1.3 就立刻断开，不会真做密钥交换）
  if (keyShare) {
    const key = Array.from(randBytes(32));
    const entry = [0x00, 0x1d, 0x00, 0x20].concat(key);
    ext.push(0x00, 0x33, ...putLen(entry.length + 2, 2), ...putLen(entry.length, 2), ...entry);
  }

  const random = Array.from(randBytes(32));
  const suiteList = tls13Suites ? SUITES.concat([0x1301, 0x1302, 0x1303]) : SUITES;
  const suites = [];
  suiteList.forEach((s) => suites.push((s >> 8) & 0xff, s & 0xff));

  const body = []
    .concat([(legacyVersion >> 8) & 0xff, legacyVersion & 0xff], random, [0x00], putLen(suites.length, 2), suites, [0x01, 0x00], putLen(ext.length, 2), ext);

  const hs = [0x01].concat(putLen(body.length, 3), body);
  const rec = [0x16, 0x03, 0x01].concat(putLen(hs.length, 2), hs);
  return new Uint8Array(rec);
}

/** Certificate 报文 → 一串 DER */
function splitCertificates(body) {
  const out = [];
  let off = 3; // 跳过 3 字节总长度
  while (off + 3 <= body.length) {
    const len = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2];
    off += 3;
    if (len <= 0 || off + len > body.length) break;
    out.push(body.subarray(off, off + len));
    off += len;
  }
  return out;
}

function parseServerHello(body) {
  if (!body || body.length < 35) return null;
  const version = (body[0] << 8) | body[1];
  let off = 34;
  const sidLen = body[off] || 0;
  off += 1 + sidLen;
  if (off + 2 > body.length) return { version, suite: null, supportedVersion: null };
  const suite = (body[off] << 8) | body[off + 1];
  off += 2;
  // 压缩方法 + 扩展区；TLS 1.3 协商用 supported_versions(0x002b) 扩展回选
  let supportedVersion = null;
  if (off < body.length) {
    const compLen = body[off] || 0;
    off += 1 + compLen;
    if (off + 2 <= body.length) {
      const extLen = (body[off] << 8) | body[off + 1];
      off += 2;
      const extEnd = Math.min(body.length, off + extLen);
      while (off + 4 <= extEnd) {
        const eType = (body[off] << 8) | body[off + 1];
        const eLen = (body[off + 2] << 8) | body[off + 3];
        off += 4;
        if (eType === 0x002b && eLen >= 2 && off + 2 <= extEnd) {
          supportedVersion = (body[off] << 8) | body[off + 1];
        }
        off += eLen;
      }
    }
  }
  return { version, suite, supportedVersion };
}

/* ------------------------------- 握手主流程 ------------------------------- */

const ALERT_TEXT = {
  0: 'close_notify',
  40: 'handshake_failure（服务端不接受我们的套件）',
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  51: 'decrypt_error',
  71: 'insufficient_security',
  80: 'internal_error',
  86: 'certificate_required',
  112: 'unrecognized_name（SNI 不被接受）',
  120: 'no_application_protocol',
};

/**
 * 自己做一次 TLS 握手，返回证书链与协商结果。
 * 只握手到拿到 Certificate，随后立即断开，不做密钥交换与加密通信。
 */
export async function rawTlsInspect(host, port, servername, timeoutMs = 8000) {
  const p = await platform();
  if (typeof p.tcpOpen !== 'function') throw new Error('当前运行环境不支持裸 TCP');
  const sock = await p.tcpOpen(host, port, timeoutMs);

  let hello = null;
  let certMsg = null;
  let alert = null;
  let hs = new Uint8Array(0);
  // 证书链通常 3~5 KB，会跨多个 TCP 分片，未凑齐的记录必须留到下一片
  let pending = new Uint8Array(0);

  try {
    await sock.write(buildClientHello(servername || host));
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const chunk = await sock.read(Math.max(300, deadline - Date.now()));
      if (!chunk) break;
      let buf = concat(pending, chunk);
      pending = new Uint8Array(0);
      // 只关心握手记录（0x16），其余（alert 0x15 除外）跳过
      while (buf.length >= 5 && alert == null) {
        const type = buf[0];
        const len = (buf[3] << 8) | buf[4];
        if (buf.length < 5 + len) {
          pending = buf.slice();
          break;
        }
        const payload = buf.subarray(5, 5 + len);
        buf = buf.subarray(5 + len);
        if (type === 0x15 && payload.length >= 2) {
          alert = payload[1];
          break;
        }
        if (type !== 0x16) continue;
        hs = concat(hs, payload);
      }
      // 握手报文可能跨记录分片，逐条解析已凑齐的部分
      for (;;) {
        if (hs.length < 4) break;
        const hlen = (hs[1] << 16) | (hs[2] << 8) | hs[3];
        if (hs.length < 4 + hlen) break;
        const body = hs.subarray(4, 4 + hlen);
        const type = hs[0];
        hs = hs.subarray(4 + hlen);
        if (type === 2) hello = body;
        else if (type === 11) certMsg = body;
      }
      if (alert != null || certMsg) break;
    }
  } finally {
    try {
      sock.close();
    } catch (_) {}
  }

  if (alert != null) {
    throw new Error(`TLS 握手被拒绝：${ALERT_TEXT[alert] || `alert ${alert}`}`);
  }
  if (!certMsg) throw new Error('未完成 TLS 握手：未收到服务端证书');

  const ders = splitCertificates(certMsg);
  if (!ders.length) throw new Error('服务端未返回证书');

  const chain = [];
  for (const der of ders) {
    const c = parseCert(der);
    if (!c) continue;
    c.fingerprint256 = await sha256Hex(der);
    delete c.der;
    chain.push(c);
  }
  if (!chain.length) throw new Error('证书解析失败');

  const names = (chain[0].subjectAltName || []).filter((x) => x.type === 'DNS').map((x) => x.value);
  const sh = parseServerHello(hello) || { version: null, suite: null };
  const protocol = VERSION_NAMES[sh.version] || null;
  const suiteName = sh.suite ? SUITE_NAMES[sh.suite] || `0x${sh.suite.toString(16)}` : null;

  return {
    protocol,
    cipher: suiteName ? { name: suiteName, version: null, bits: null, standardName: null } : null,
    chain,
    hostMatch: names.length ? certMatches(host, names) : null,
    // 自解析拿不到系统信任库，信任链不做判断（本地与云端行为一致）
    authorized: null,
    authorizationError: null,
    protocols: null,
  };
}

/* --------------------------- 逐版本协议支持探测 --------------------------- */

/** 单版本探测：只声明该版本，看服务端是否愿意继续握手 */
async function probeVersion(host, port, servername, version, timeoutMs) {
  const p = await platform();
  const sock = await p.tcpOpen(host, port, timeoutMs);
  try {
    const hello =
      version === 0x0304
        ? buildClientHello(servername, {
            // 同时声明 1.3 与 1.2：支持 1.3 的服务端会用 supported_versions 扩展回选 1.3；
            // 只支持 1.2 的则忽略扩展按 1.2 走，不会误伤
            supportedVersions: [0x0304, 0x0303],
            tls13Suites: true,
            keyShare: true,
          })
        : buildClientHello(servername, { legacyVersion: version });
    await sock.write(hello);
    const deadline = Date.now() + timeoutMs;
    let pending = new Uint8Array(0);
    while (Date.now() < deadline) {
      const chunk = await sock.read(Math.max(300, deadline - Date.now()));
      if (!chunk) break;
      let buf = concat(pending, chunk);
      pending = new Uint8Array(0);
      while (buf.length >= 5) {
        const type = buf[0];
        const len = (buf[3] << 8) | buf[4];
        if (buf.length < 5 + len) {
          pending = buf.slice();
          break;
        }
        const payload = buf.subarray(5, 5 + len);
        buf = buf.subarray(5 + len);
        if (type === 0x15) return false; // alert：服务端拒绝该版本
        if (type !== 0x16) continue;
        if (payload.length >= 4 && payload[0] === 2) {
          const sh = parseServerHello(payload.subarray(4));
          if (!sh) return false;
          if (version === 0x0304) return sh.supportedVersion === 0x0304;
          return sh.version === version;
        }
      }
    }
  } catch (_) {
    // 探测失败按不支持处理
  } finally {
    try {
      sock.close();
    } catch (_) {}
  }
  return false;
}

/** 四路并行探测 TLS 1.0~1.3 支持情况，返回 { TLSv1: bool, ... }（本地云端同一实现） */
export async function rawTlsProtocols(host, port, servername, timeoutMs = 6000) {
  const t = Math.max(2000, Math.min(timeoutMs, 8000));
  const defs = [
    ['TLSv1', 0x0301],
    ['TLSv1.1', 0x0302],
    ['TLSv1.2', 0x0303],
    ['TLSv1.3', 0x0304],
  ];
  const out = {};
  await Promise.all(
    defs.map(async ([k, v]) => {
      out[k] = await probeVersion(host, port, servername || host, v, t).catch(() => false);
    })
  );
  return out;
}
