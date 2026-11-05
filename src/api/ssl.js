/* SSL 证书检测（本地与云端同一条路）：
   ① 自解析 TLS 握手拿线上真实证书（rawtls，平台无关）
   ② 逐版本协议探测（rawtls，四路并行）
   ③ 握手拿不到（目标不在线 / 非 TLS 服务 / 被拦截）才退到
      「CT 日志（证书字段）+ SSL Labs（协议支持与评级）+ 实时可达探测」 */
import { ctLookup, formatFingerprint } from '../lib/ct.js';
import { rawTlsInspect, rawTlsProtocols } from '../lib/rawtls.js';
import { ssllabsInfo } from '../lib/ssllabs.js';
import { clamp, isIP, isPrivateHost } from '../lib/util.js';
import { platform } from '../platform/index.js';

/* 云端结果缓存：公共源都有速率限制，同一主机 10 分钟内直接复用，避免重复外呼与超时 */
const CACHE_TTL = 10 * 60 * 1000;
const CACHE_MAX = 200;
const remoteCache = new Map();

function cacheGet(key) {
  const hit = remoteCache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > CACHE_TTL) {
    remoteCache.delete(key);
    return null;
  }
  return hit.value;
}

function cacheSet(key, value) {
  if (remoteCache.size >= CACHE_MAX) remoteCache.delete(remoteCache.keys().next().value);
  remoteCache.set(key, { at: Date.now(), value });
}

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
  // 中文 / IDN 域名：先转成 punycode（xn-- 前缀），否则 SNI 里发的是非法的 UTF-8 原始字节，握手必然失败
  if (/[^\x20-\x7e]/.test(host)) {
    try {
      host = new URL(`https://${host}`).hostname;
    } catch (_) {}
  }
  if (!/^[a-zA-Z0-9.\-_\u4e00-\u9fa5]+$/.test(host)) throw new Error('域名格式不合法');
  if (!(port > 0 && port < 65536)) throw new Error('端口不合法');
  return { host: host.toLowerCase(), port };
}

/** 有效期 / 主机名匹配 → 结论状态 */
function computeStatus({ notBefore, notAfter, daysLeft, hostMatch, selfSigned, authorized, authorizationError, known = true }) {
  const now = Date.now();
  let status = known ? 'valid' : 'unknown';
  if (!known) return status;
  if (notAfter && notAfter < now) status = 'expired';
  else if (notBefore && notBefore > now) status = 'notyet';
  else if (daysLeft !== null && daysLeft <= 30) status = 'expiring';
  if (hostMatch === false) status = 'mismatch';
  else if (selfSigned) status = 'selfsigned';
  if (!authorized && authorizationError && status === 'valid') status = 'untrusted';
  return status;
}

function periodFields(notBefore, notAfter) {
  const now = Date.now();
  const daysLeft = notAfter ? Math.floor((notAfter - now) / 86400000) : null;
  const totalDays = notAfter && notBefore ? Math.floor((notAfter - notBefore) / 86400000) : null;
  return { daysLeft, totalDays };
}

export default async function sslCheck(input) {
  const started = Date.now();
  const p = await platform();
  const { host, port } = normalizeTarget(input);
  const timeoutMs = clamp(Number(input.timeout) || 12000, 1000, 30000);

  // 解析 IP 仅用于展示与定位，解析失败不阻断：证书信息来自公共数据源，不依赖本地解析
  let resolved = [host];
  let dnsError = null;
  if (!isIP(host)) {
    try {
      resolved = await p.lookupIps(host);
    } catch (e) {
      dnsError = `DNS 解析失败：${e.code || e.message}`;
      resolved = [];
    }
  }

  if (p.limits.blockPrivateHost && resolved.some((ip) => isPrivateHost(ip))) {
    throw new Error('云端环境禁止连接内网 / 本机地址，SSL 检测请使用公网域名');
  }

  const key = `${host}:${port}`;
  const cached = input.refresh ? null : cacheGet(key);
  if (cached) return { ...cached, resolved, elapsed: Date.now() - started, cached: true };

  // 硬截止 20 秒：Workers 单个请求有固定时长上限，不允许外部源把请求拖死
  const deadline = started + 20000;

  // ① 自己发一次 ClientHello：本地与云端同一条路，能连上就能拿到真实证书，不依赖任何第三方
  let handshake = null;
  let handshakeError = null;
  try {
    handshake = await rawTlsInspect(host, port, host, Math.min(timeoutMs, 9000));
  } catch (e) {
    handshakeError = (e && e.message) || '握手失败';
  }

  if (handshake && handshake.chain && handshake.chain.length) {
    // ② 逐版本协议探测：四路并行握手，各平台共用同一实现
    const budget = Math.min(6000, Math.max(2500, deadline - Date.now()));
    handshake.protocols = await rawTlsProtocols(host, port, host, budget).catch(() => null);

    const result = fromHandshake({ host, port, resolved, info: handshake, started });
    result.source = 'TLS 握手';
    result.dnsError = dnsError;
    result.errors = [];
    cacheSet(key, result);
    return result;
  }

  // ③ 握手拿不到（端口不通 / 非 TLS 服务 / 被拦截）：退回公共数据源
  if (isIP(host)) {
    throw new Error(
      `无法与 ${host}:${port} 完成 TLS 握手（${handshakeError}）；公共数据源只按域名索引，填 IP 时无法兜底`
    );
  }

  const result = await fromRemoteSources({
    host,
    port,
    resolved,
    started,
    deadline,
    dnsError,
    handshakeError,
  });
  if (result.status !== 'unknown') cacheSet(key, result);
  return result;
}

/** 真实握手：协议、套件、证书链、信任链、主机名匹配 */
function fromHandshake({ host, port, resolved, info, started }) {
  const leaf = info.chain[0] || null;
  const notBefore = leaf && leaf.validFrom ? new Date(leaf.validFrom).getTime() : null;
  const notAfter = leaf && leaf.validTo ? new Date(leaf.validTo).getTime() : null;
  const { daysLeft, totalDays } = periodFields(notBefore, notAfter);
  const status = computeStatus({
    notBefore,
    notAfter,
    daysLeft,
    hostMatch: info.hostMatch,
    selfSigned: leaf && leaf.selfSigned,
    authorized: info.authorized,
    authorizationError: info.authorizationError,
  });

  return {
    host,
    port,
    resolved,
    status,
    daysLeft,
    totalDays,
    notBefore: leaf ? leaf.validFrom : null,
    notAfter: leaf ? leaf.validTo : null,
    hostMatch: info.hostMatch,
    authorized: info.authorized,
    authorizationError: info.authorizationError,
    protocol: info.protocol,
    cipher: info.cipher,
    chain: info.chain,
    protocols: info.protocols,
    checkedAt: new Date().toISOString(),
    mode: 'tls',
    elapsed: Date.now() - started,
  };
}

/** 云端：CT 日志出证书字段 + SSL Labs 出协议支持与评级 + 实时可达探测 */
async function fromRemoteSources({ host, port, resolved, started, deadline, dnsError, handshakeError }) {
  const remain = () => Math.max(0, deadline - Date.now());
  const liveP = liveProbe(host, port, Math.min(9000, Math.max(2000, remain())));
  const errors = [];
  if (handshakeError) errors.push(`TLS 握手：${handshakeError}`);

  const [labs, ct] = await Promise.all([
    ssllabsInfo(host, { timeoutMs: 6000 }).catch((e) => {
      errors.push(`SSL Labs：${(e && e.message) || e}`);
      return null;
    }),
    ctLookup(host).catch((e) => {
      errors.push(`CT 日志：${(e && e.message) || e}`);
      return null;
    }),
  ]);
  if (ct && ct.errors) errors.push(...ct.errors);
  const ctData = ct && ct.cert ? ct : null;

  const live = await liveP;
  const source =
    [ctData ? `CT 日志（${ctData.cert.source}）` : null, labs ? 'SSL Labs' : null]
      .filter(Boolean)
      .join(' + ') || null;

  if (!ctData && !labs) {
    return {
      host,
      port,
      resolved,
      status: 'unknown',
      daysLeft: null,
      totalDays: null,
      notBefore: null,
      notAfter: null,
      hostMatch: null,
      authorized: null,
      authorizationError: null,
      protocol: null,
      cipher: null,
      chain: [],
      protocols: null,
      checkedAt: new Date().toISOString(),
      mode: 'remote',
      source: null,
      ct: { source: null, total: 0, errors },
      errors,
      live,
      dnsError,
      elapsed: Date.now() - started,
    };
  }

  const result = ctData
    ? buildFromCt(host, port, ctData)
    : {
        status: 'unknown',
        daysLeft: null,
        totalDays: null,
        notBefore: null,
        notAfter: null,
        hostMatch: null,
        authorized: null,
        authorizationError: null,
        chain: [],
      };
  if (labs) {
    result.protocols = labs.protocols;
    result.grade = labs.grade;
  }
  result.source = source;
  result.resolved = resolved;
  result.live = live;
  result.errors = errors;
  result.dnsError = dnsError;
  result.elapsed = Date.now() - started;
  return result;
}

/** 公共数据源结果的统一组装：日期、剩余天数、结论状态 */
function remoteResult({ host, port, meta, chain, protocols, ctErrors }) {
  const nb = meta.notBefore ? new Date(meta.notBefore) : null;
  const na = meta.notAfter ? new Date(meta.notAfter) : null;
  const { daysLeft, totalDays } = periodFields(nb ? nb.getTime() : null, na ? na.getTime() : null);
  const status = computeStatus({
    notBefore: nb ? nb.getTime() : null,
    notAfter: na ? na.getTime() : null,
    daysLeft,
    hostMatch: meta.hostMatch,
    selfSigned: false,
    authorized: null,
    authorizationError: null,
    known: !!(nb || na || (meta.names && meta.names.length)),
  });
  return {
    host,
    port,
    status,
    daysLeft,
    totalDays,
    notBefore: nb ? nb.toISOString() : null,
    notAfter: na ? na.toISOString() : null,
    hostMatch: meta.hostMatch,
    authorized: null,
    authorizationError: null,
    protocol: null,
    cipher: null,
    chain,
    protocols: protocols || null,
    grade: null,
    checkedAt: new Date().toISOString(),
    mode: 'remote',
    source: null,
    ct: { source: null, total: 0, errors: ctErrors || [] },
  };
}

/** CT 日志数据 → 统一结果（协议/评级由调用方按 SSL Labs 结果覆盖） */
function buildFromCt(host, port, ct) {
  const cert = ct.cert;
  const meta = {
    names: cert.names,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    hostMatch: cert.hostMatch,
  };
  const notBefore = cert.notBefore ? new Date(cert.notBefore).toISOString() : null;
  const notAfter = cert.notAfter ? new Date(cert.notAfter).toISOString() : null;
  const leaf = {
    subject: `CN=${cert.cn}`,
    issuer: cert.issuer,
    subjectAltName: cert.names.map((n) => ({ type: 'DNS', value: n })),
    validFrom: notBefore,
    validTo: notAfter,
    serialNumber: cert.serial,
    fingerprint256: cert.fingerprint ? formatFingerprint(cert.fingerprint) : null,
    publicKey: { type: null, bits: null },
    selfSigned: false,
    keyUsage: null,
  };
  return remoteResult({
    host,
    port,
    meta,
    chain: [leaf],
    protocols: null,
    ctErrors: ct.errors,
  });
}

/** 实时探测：能读到响应头即说明 TLS 握手 + HTTP 都成功 */
async function liveProbe(host, port, timeoutMs = 9000) {
  const t0 = Date.now();
  try {
    const res = await fetch(`https://${host}:${port}/`, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'user-agent': 'tool/1.0', accept: '*/*' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    try {
      await res.body?.cancel();
    } catch (_) {}
    return { ok: true, status: res.status, ms: Date.now() - t0, error: null };
  } catch (e) {
    return { ok: false, status: null, ms: Date.now() - t0, error: (e && e.message) || '连接失败' };
  }
}
