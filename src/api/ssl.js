/* SSL 证书检测：平台能发起真实 TLS 握手时直接读证书；
   云端拿不到对端证书，用「CT 日志（证书字段）+ SSL Labs（协议支持与评级）+ 实时可达探测」。 */
import { ctLookup, formatFingerprint } from '../lib/ct.js';
import { ssllabsInfo } from '../lib/ssllabs.js';
import { clamp, isIP } from '../lib/util.js';
import { platform } from '../platform/index.js';

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
  const probe = input.probe !== false;

  // 解析 IP 仅用于展示与报错定位，解析失败直接说明原因
  let resolved = [host];
  if (!isIP(host)) {
    try {
      resolved = await p.lookupIps(host);
    } catch (e) {
      throw new Error(`DNS 解析失败：${e.code || e.message}`);
    }
    if (!resolved.length) throw new Error(`DNS 解析失败：${host} 没有解析记录`);
  }

  if (p.caps.tls) {
    let info;
    try {
      info = await p.inspectTls(host, port, { servername: host, timeoutMs, probe });
    } catch (e) {
      throw new Error(
        `TLS 握手失败：${e.code ? `${e.code} - ` : ''}${e.message}（请确认 ${host}:${port} 提供 TLS 服务）`
      );
    }
    return fromHandshake({ host, port, resolved, info, started });
  }

  if (isIP(host)) {
    throw new Error('云端证书信息来自公共数据源（按域名索引），请填写域名而不是 IP');
  }
  return fromRemoteSources({ host, port, resolved, started, deep: !!input.deep });
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
async function fromRemoteSources({ host, port, resolved, started, deep }) {
  const liveP = liveProbe(host, port);
  const [labs, ct] = await Promise.all([
    ssllabsInfo(host).catch(() => null),
    ctLookup(host).catch(() => null),
  ]);
  let ctData = ct && ct.cert ? ct : null;
  let labsData = labs;

  // 深度检测：CT 没查到证书时等一次 SSL Labs 完整扫描（结果被缓存，下次秒回），同时重试 CT
  if (!ctData && deep) {
    const [labs2, ct2] = await Promise.all([
      labsData ? Promise.resolve(labsData) : ssllabsInfo(host, { scanBudgetMs: 60000 }).catch(() => null),
      ctLookup(host).catch(() => null),
    ]);
    labsData = labsData || labs2;
    ctData = ct2 && ct2.cert ? ct2 : null;
  }

  const live = await liveP;
  const source =
    [
      ctData ? `CT 日志（${ctData.cert.source}）` : null,
      labsData ? 'SSL Labs' : null,
    ]
      .filter(Boolean)
      .join(' + ') || null;

  if (!ctData && !labsData) {
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
      ct: { source: null, total: 0, errors: (ct && ct.errors) || ['未查到公开证书记录'] },
      live,
      elapsed: Date.now() - started,
    };
  }

  const result = ctData
    ? buildFromCt(host, port, started, ctData)
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
        leaf: null,
        ctErrors: (ct && ct.errors) || [],
      };
  if (labsData) {
    result.protocols = labsData.protocols;
    result.grade = labsData.grade;
  }
  result.source = source;
  result.resolved = resolved;
  result.live = live;
  result.elapsed = Date.now() - started;
  return result;
}

/** 公共数据源结果的统一组装：日期、剩余天数、结论状态 */
function remoteResult({ host, port, started, meta, leaf, chain, protocols, source, grade, ctErrors }) {
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
    grade: grade || null,
    checkedAt: new Date().toISOString(),
    mode: 'remote',
    source,
    ct: { source: null, total: 0, errors: ctErrors || [] },
  };
}

/** CT 日志数据 → 统一结果（协议/评级由调用方按 SSL Labs 结果覆盖） */
function buildFromCt(host, port, started, ct) {
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
    ca: false,
    selfSigned: false,
    keyUsage: null,
    infoAccess: null,
  };
  return remoteResult({
    host,
    port,
    started,
    meta,
    leaf,
    chain: [leaf],
    protocols: null,
    ctErrors: ct.errors,
  });
}

/** 实时探测：能读到响应头即说明 TLS 握手 + HTTP 都成功 */
async function liveProbe(host, port) {
  const t0 = Date.now();
  try {
    const res = await fetch(`https://${host}:${port}/`, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'user-agent': 'ops-toolbox/1.0', accept: '*/*' },
      signal: AbortSignal.timeout(9000),
    });
    try {
      await res.body?.cancel();
    } catch (_) {}
    return { ok: true, status: res.status, ms: Date.now() - t0, error: null };
  } catch (e) {
    return { ok: false, status: null, ms: Date.now() - t0, error: (e && e.message) || '连接失败' };
  }
}
