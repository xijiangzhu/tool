/* SSL 证书检测（Workers 版）：
   Workers 无法读取 TLS 握手的对端证书，改为「公共 CT 日志拿证书元数据 + 实时探测站点可用性」 */
import { clamp, isIP } from '../lib/util.js';
import { dohQuery } from '../lib/doh.js';

/** 允许传入 https://example.com/path、example.com:8443 等写法 */
function normalizeTarget(input) {
  let host = String(input.host || '').trim();
  host = host.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '');
  let portFromHost = null;
  if (!isIP(host) && host.includes(':') && host.indexOf(':') === host.lastIndexOf(':')) {
    const idx = host.indexOf(':');
    portFromHost = Number(host.slice(idx + 1));
    host = host.slice(0, idx);
  }
  const port = Number(input.port || portFromHost || 443);
  if (!host) throw new Error('请填写域名或 IP');
  if (!/^[a-zA-Z0-9.\-_]+$/.test(host)) throw new Error('域名格式不合法');
  if (!(port > 0 && port < 65536)) throw new Error('端口不合法');
  return { host: host.toLowerCase(), port };
}

/* ----------------------------- 证书来源：CT 日志 ----------------------------- */

/** 通配符匹配：*.example.com 只匹配一级子域 */
function certMatches(host, names) {
  return names.some((n) => {
    const name = String(n || '').toLowerCase();
    if (!name) return false;
    if (name === host) return true;
    if (name.startsWith('*.')) {
      const base = name.slice(2);
      if (!host.endsWith('.' + base)) return false;
      return host.slice(0, host.length - base.length - 1).indexOf('.') === -1;
    }
    return false;
  });
}

const unescapeDn = (s) => String(s || '').replace(/\\([,+="<>;#])/g, '$1');

/** CT 日志只有 SAN 列表，没有单独的 Subject：取「匹配该主机名」的那个名字作为 CN */
function bestName(host, names) {
  const exact = names.find((n) => n === host);
  if (exact) return exact;
  const wildcard = names.find((n) => n.startsWith('*.') && certMatches(host, [n]));
  return wildcard || names[0] || host;
}

async function fromCertSpotter(host) {
  const url =
    'https://api.certspotter.com/v1/issuances?domain=' +
    encodeURIComponent(host) +
    '&include_subdomains=false&expand=dns_names&expand=issuer&expand=cert';
  const res = await fetch(url, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(9000),
  });
  if (!res.ok) throw new Error(`Cert Spotter HTTP ${res.status}`);
  const list = await res.json();
  if (!Array.isArray(list) || !list.length) return null;
  const certs = list.map((c) => {
    const names = (c.dns_names || []).map((n) => String(n).toLowerCase());
    return {
      names,
      notBefore: c.not_before,
      notAfter: c.not_after,
      issuer: unescapeDn((c.issuer && c.issuer.name) || ''),
      cn: bestName(host, names),
      fingerprint: (c.cert && c.cert.sha256) || c.cert_sha256 || null,
      serial: null,
      source: 'Cert Spotter',
      total: list.length,
    };
  });
  return pickLatest(host, certs);
}

async function fromCrtSh(host) {
  const url = `https://crt.sh/?q=${encodeURIComponent(host)}&output=json&exclude=expired`;
  const res = await fetch(url, {
    headers: { accept: 'application/json', 'user-agent': 'ops-toolbox/1.0' },
    signal: AbortSignal.timeout(12000),
  });
  if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
  const text = await res.text();
  let list;
  try {
    list = JSON.parse(text);
  } catch (_) {
    throw new Error('crt.sh 返回内容无法解析（服务可能繁忙）');
  }
  if (!Array.isArray(list) || !list.length) return null;
  const certs = list.map((c) => {
    const names = String(c.name_value || '')
      .split('\n')
      .map((n) => n.trim().toLowerCase())
      .filter(Boolean);
    return {
      names,
      notBefore: c.not_before,
      notAfter: c.not_after,
      issuer: unescapeDn(c.issuer_name || ''),
      cn: c.common_name || bestName(host, names),
      fingerprint: null,
      serial: c.serial_number || null,
      source: 'crt.sh',
      total: list.length,
    };
  });
  return pickLatest(host, certs);
}

/** 优先取「确实覆盖该主机名」的证书，取到期时间最晚的一张 */
function pickLatest(host, certs) {
  const matched = certs.filter((c) => certMatches(host, c.names));
  const pool = matched.length ? matched : certs;
  pool.sort((a, b) => new Date(b.notAfter || 0) - new Date(a.notAfter || 0));
  return Object.assign({ hostMatch: matched.length > 0 }, pool[0]);
}

async function ctLookup(host) {
  const errors = [];
  for (const fn of [fromCertSpotter, fromCrtSh]) {
    try {
      const cert = await fn(host);
      if (cert) return { cert, errors };
      errors.push(`${fn.name}: 未查到公开证书记录`);
    } catch (e) {
      errors.push(e.message || String(e));
    }
  }
  return { cert: null, errors };
}

/* ------------------------------ 实时可达性探测 ------------------------------ */

async function liveProbe(host, port) {
  const t0 = Date.now();
  try {
    const res = await fetch(`https://${host}:${port}/`, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'user-agent': 'ops-toolbox/1.0', accept: '*/*' },
      signal: AbortSignal.timeout(9000),
    });
    // 读到响应头即说明 TLS 握手 + HTTP 均已成功
    try {
      await res.body?.cancel();
    } catch (_) {}
    return { ok: true, status: res.status, ms: Date.now() - t0, error: null };
  } catch (e) {
    return { ok: false, status: null, ms: Date.now() - t0, error: (e && e.message) || '连接失败' };
  }
}

/* --------------------------------- 主流程 --------------------------------- */

export default async function sslCheck(input) {
  const started = Date.now();
  const { host, port } = normalizeTarget(input);
  if (isIP(host)) {
    throw new Error('云端证书信息来自公共 CT 日志（按域名索引），请填写域名而不是 IP');
  }

  const [resolveRes, liveRes, ctRes] = await Promise.all([
    resolveHost(host),
    liveProbe(host, port),
    ctLookup(host),
  ]);

  const cert = ctRes.cert;
  const now = Date.now();
  const notBefore = cert && cert.notBefore ? new Date(cert.notBefore).toISOString() : null;
  const notAfter = cert && cert.notAfter ? new Date(cert.notAfter).toISOString() : null;
  const daysLeft = notAfter ? Math.floor((new Date(notAfter) - now) / 86400000) : null;
  const totalDays =
    notAfter && notBefore ? Math.floor((new Date(notAfter) - new Date(notBefore)) / 86400000) : null;

  let status = 'valid';
  if (!cert) status = 'unknown';
  else if (notAfter && new Date(notAfter) < now) status = 'expired';
  else if (notBefore && new Date(notBefore) > now) status = 'notyet';
  else if (daysLeft !== null && daysLeft <= 30) status = 'expiring';
  if (cert && cert.hostMatch === false) status = 'mismatch';

  const leaf = cert
    ? {
        subject: `CN=${cert.cn}`,
        issuer: cert.issuer,
        subjectAltName: cert.names.map((n) => ({ type: 'DNS', value: n })),
        validFrom: notBefore,
        validTo: notAfter,
        serialNumber: cert.serial,
        fingerprint256: cert.fingerprint ? formatFp(cert.fingerprint) : null,
        publicKey: { type: null, bits: null },
        ca: false,
        selfSigned: false,
        keyUsage: null,
        infoAccess: null,
      }
    : null;

  return {
    host,
    port,
    resolved: resolveRes.ips,
    status,
    daysLeft,
    totalDays,
    notBefore,
    notAfter,
    hostMatch: cert ? cert.hostMatch : null,
    authorized: null,
    authorizationError: null,
    protocol: null,
    cipher: null,
    chain: leaf ? [leaf] : [],
    protocols: null,
    checkedAt: new Date().toISOString(),
    mode: 'ct',
    ct: {
      source: cert ? cert.source : null,
      total: cert ? cert.total : 0,
      errors: ctRes.errors,
    },
    live: liveRes,
    elapsed: Date.now() - started,
  };
}

/** 用 DoH 解析 A / AAAA，作为「解析 IP」展示 */
async function resolveHost(host) {
  const ips = [];
  await Promise.all(
    ['A', 'AAAA'].map(async (t) => {
      try {
        const r = await dohQuery(host, t);
        if (r.status === 0) {
          for (const a of r.answer) {
            if ((t === 'A' && a.type === 1) || (t === 'AAAA' && a.type === 28)) ips.push(a.data);
          }
        }
      } catch (_) {}
    })
  );
  return { ips };
}

function formatFp(hexRaw) {
  const hex = String(hexRaw).replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  return hex.match(/.{2}/g)?.join(':') || hex;
}
