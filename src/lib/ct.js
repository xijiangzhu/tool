/* 公共 CT 日志查询：云端读不到 TLS 对端证书时，用证书透明日志补全证书元数据。
   Cert Spotter 优先，失败退到 crt.sh。 */

/** 通配符匹配：*.example.com 只匹配一级子域 */
export function certMatches(host, names) {
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

/* 部分 CT 服务会拦掉默认 UA，统一带上可识别的标识 */
const UA = { 'user-agent': 'ops-toolbox/1.0 (+https://github.com/xijiangzhu/tool)' };

/** CT 日志只有 SAN 列表：取「匹配该主机名」的那个名字作为 CN */
function bestName(host, names) {
  const exact = names.find((n) => n === host);
  if (exact) return exact;
  const wildcard = names.find((n) => n.startsWith('*.') && certMatches(host, [n]));
  return wildcard || names[0] || host;
}

/** 优先取「确实覆盖该主机名」的证书，取到期时间最晚的一张 */
function pickLatest(host, certs) {
  const matched = certs.filter((c) => certMatches(host, c.names));
  const pool = matched.length ? matched : certs;
  pool.sort((a, b) => new Date(b.notAfter || 0) - new Date(a.notAfter || 0));
  return Object.assign({ hostMatch: matched.length > 0 }, pool[0]);
}

async function fromCertSpotter(host) {
  const url =
    'https://api.certspotter.com/v1/issuances?domain=' +
    encodeURIComponent(host) +
    '&include_subdomains=false&expand=dns_names&expand=issuer&expand=cert';
  const res = await fetch(url, {
    headers: { accept: 'application/json', ...UA },
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`Cert Spotter HTTP ${res.status}`);
  if (Number(res.headers.get('content-length') || 0) > 3_000_000) {
    throw new Error('Cert Spotter 返回数据过大，已跳过');
  }
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
    headers: { accept: 'application/json', ...UA },
    signal: AbortSignal.timeout(9000),
  });
  if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
  // 大域名下 crt.sh 会返回数 MB JSON，云端实例 CPU 配额有限，解析会直接超限，先按体积挡掉
  const len = Number(res.headers.get('content-length') || 0);
  if (len > 2_000_000) throw new Error('crt.sh 返回数据过大，已跳过');
  const raw = await res.text();
  if (raw.length > 3_000_000) throw new Error('crt.sh 返回数据过大，已跳过');
  let list;
  try {
    list = JSON.parse(raw);
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

/** 并发查询多家 CT 日志，谁先给出有效证书就立即返回；返回 { cert, errors } */
export async function ctLookup(host) {
  const errors = [];
  const fns = [fromCertSpotter, fromCrtSh];
  const entries = fns.map((fn, i) =>
    fn(host).then(
      (cert) => ({ i, cert }),
      (e) => ({ i, error: `${fn.name}: ${(e && e.message) || e}` })
    )
  );
  const done = new Set();
  while (done.size < entries.length) {
    const r = await Promise.race(entries.filter((_, i) => !done.has(i)));
    done.add(r.i);
    if (r.cert) return { cert: r.cert, errors };
    errors.push(r.error || 'CT 日志: 未查到公开证书记录');
  }
  return { cert: null, errors };
}

/** SHA-256 十六进制 → AA:BB:CC 形式 */
export function formatFingerprint(hexRaw) {
  const hex = String(hexRaw).replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  return hex.match(/.{2}/g)?.join(':') || hex;
}
