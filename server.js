/**
 * 运维工具箱 - 轻量后端
 * 1) 静态资源托管（前端页面）
 * 2) /api/ssl   SSL 证书检测（需服务端发起 TLS 握手）
 * 3) /api/http  HTTP 调试代理（突破浏览器跨域限制）
 * 4) /api/net/* DNS / 端口扫描 / IP 归属地 / 本机网卡信息
 * 不依赖数据库，不持久化任何数据。
 */
'use strict';

const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const dns = require('dns');
const crypto = require('crypto');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY = 5 * 1024 * 1024; // 5MB

/* ---------------------------------- 工具函数 --------------------------------- */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.map': 'application/json; charset=utf-8',
};

function sendJson(res, code, data) {
  const buf = Buffer.from(JSON.stringify(data));
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': buf.length,
    'Cache-Control': 'no-store',
  });
  res.end(buf);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('请求体过大（上限 5MB）'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(new Error('请求体不是合法 JSON'));
      }
    });
    req.on('error', reject);
  });
}

/* ------------------------------ SSL 证书检测 ------------------------------- */

function parseCertDate(str) {
  if (!str) return null;
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

/** 把 getPeerCertificate 返回的对象整理成前端友好的结构 */
function normalizeCert(peerCert, rawBuf) {
  const out = {
    subject: null,
    issuer: null,
    subjectAltName: [],
    validFrom: null,
    validTo: null,
    serialNumber: null,
    fingerprint256: null,
    publicKey: { type: null, bits: null },
    ca: false,
    selfSigned: false,
    keyUsage: null,
    infoAccess: null,
  };
  if (!peerCert) return out;

  let x509 = null;
  try {
    const buf = rawBuf || peerCert.raw;
    if (buf) x509 = new crypto.X509Certificate(buf);
  } catch (_) {
    x509 = null;
  }

  const src = x509 || peerCert;
  const flat = (s) =>
    typeof s === 'string' ? s.replace(/\s*\r?\n\s*/g, ', ').trim() : stringifyDN(s);
  out.subject = flat(src.subject);
  out.issuer = flat(src.issuer);

  // 有效期
  if (x509) {
    out.validFrom = parseCertDate(x509.validFrom);
    out.validTo = parseCertDate(x509.validTo);
  } else {
    out.validFrom = parseCertDate(peerCert.valid_from);
    out.validTo = parseCertDate(peerCert.valid_to);
  }

  // SAN
  let san = x509 ? safeGet(() => x509.subjectAltName) : null;
  if (!san) san = peerCert.subjectaltname;
  if (typeof san === 'string' && san) {
    out.subjectAltName = san
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => {
        const idx = s.indexOf(':');
        if (idx === -1) return { type: 'OTHER', value: s };
        return { type: s.slice(0, idx).trim(), value: s.slice(idx + 1).trim() };
      });
  }

  out.serialNumber = src.serialNumber || null;
  if (x509) {
    out.fingerprint256 = x509.fingerprint256 || null;
    try {
      const pk = x509.publicKey;
      let bits = pk ? pk.asymmetricKeySize : null;
      if (!bits && pk && pk.asymmetricKeyDetails) {
        bits =
          pk.asymmetricKeyDetails.modulusLength ||
          (pk.asymmetricKeyDetails.namedCurve ? undefined : null);
      }
      out.publicKey = {
        type: pk ? pk.asymmetricKeyType : null,
        bits: bits || null,
      };
    } catch (_) {}
    out.ca = !!safeGet(() => x509.ca);
    out.keyUsage = safeGet(() => x509.keyUsage) || null;
    out.infoAccess = safeGet(() => x509.infoAccess) || null;
  } else {
    out.fingerprint256 = peerCert.fingerprint256 || null;
    out.publicKey = {
      type: peerCert.asn1Curve ? 'ec' : peerCert.modulus ? 'rsa' : null,
      bits: peerCert.bits || null,
    };
  }

  // 自签名判断
  out.selfSigned = !!out.subject && out.subject === out.issuer;

  out.raw = x509 || rawBuf ? { _skip: true } : undefined;
  delete out.raw;

  return out;
}

function safeGet(fn) {
  try {
    return fn();
  } catch (_) {
    return undefined;
  }
}

function stringifyDN(obj) {
  if (!obj || typeof obj !== 'object') return obj || null;
  const order = ['CN', 'O', 'OU', 'C', 'ST', 'L', 'emailAddress'];
  const keys = Object.keys(obj);
  const parts = [];
  for (const k of order) {
    if (obj[k] !== undefined) parts.push(`${k}=${obj[k]}`);
  }
  for (const k of keys) {
    if (!order.includes(k) && obj[k] !== undefined) parts.push(`${k}=${obj[k]}`);
  }
  return parts.join(', ') || null;
}

function tlsConnect(host, port, servername, timeoutMs, extra = {}) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      Object.assign(
        {
          host,
          port,
          servername: servername || host,
          rejectUnauthorized: false,
          timeout: timeoutMs,
        },
        extra
      ),
      () => {
        try {
          const peer = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const result = {
            protocol: socket.getProtocol(),
            cipher: cipher
              ? { name: cipher.name, version: cipher.version, bits: cipher.bits }
              : null,
            authorized: socket.authorized,
            authorizationError: socket.authorizationError || null,
            peer,
          };
          socket.destroy();
          resolve(result);
        } catch (e) {
          socket.destroy();
          reject(e);
        }
      }
    );
    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('连接超时'));
    });
    socket.on('error', (e) => reject(e));
  });
}

/** 探测服务器支持的 TLS 版本 */
async function probeProtocols(host, port, servername, timeoutMs) {
  const versions = [
    { key: 'TLSv1', min: 'TLSv1', max: 'TLSv1' },
    { key: 'TLSv1.1', min: 'TLSv1.1', max: 'TLSv1.1' },
    { key: 'TLSv1.2', min: 'TLSv1.2', max: 'TLSv1.2' },
    { key: 'TLSv1.3', min: 'TLSv1.3', max: 'TLSv1.3' },
  ];
  const out = {};
  await Promise.all(
    versions.map(async (v) => {
      try {
        await tlsConnect(host, port, servername, Math.min(timeoutMs, 8000), {
          minVersion: v.min,
          maxVersion: v.max,
        });
        out[v.key] = true;
      } catch (e) {
        out[v.key] = false;
      }
    })
  );
  return out;
}

async function checkSsl(input) {
  let host = String(input.host || '').trim();
  // 容错：允许传入 https://example.com/path 这类完整地址
  host = host.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '');
  let portFromHost = null;
  if (!net.isIP(host) && host.includes(':') && host.indexOf(':') === host.lastIndexOf(':')) {
    const idx = host.indexOf(':');
    portFromHost = Number(host.slice(idx + 1));
    host = host.slice(0, idx);
  }
  const port = Number(input.port || portFromHost || 443);
  /* SNI 固定跟目标域名一致，不再支持单独指定 */
  const servername = host;
  const timeoutMs = Math.min(Math.max(Number(input.timeout) || 12000, 1000), 30000);
  const withProbe = input.probe !== false;

  if (!host) throw new Error('请填写域名或 IP');
  if (!/^[a-zA-Z0-9.\-_:\u4e00-\u9fa5]+$/.test(host)) throw new Error('域名格式不合法');
  if (!(port > 0 && port < 65536)) throw new Error('端口不合法');

  // 解析 DNS，便于给出清晰报错与解析结果
  let resolved = null;
  try {
    if (net.isIP(host)) resolved = [host];
    else {
      const list = await dns.promises.lookup(host, { all: true });
      resolved = list.map((x) => x.address);
    }
  } catch (e) {
    throw new Error(`DNS 解析失败：${e.code || e.message}`);
  }

  let conn;
  try {
    conn = await tlsConnect(host, port, servername, timeoutMs);
  } catch (e) {
    throw new Error(
      `TLS 握手失败：${e.code ? `${e.code} - ` : ''}${e.message}（请确认 ${host}:${port} 提供 TLS 服务）`
    );
  }

  const chain = [];
  let cur = conn.peer;
  let guard = 0;
  while (cur && Object.keys(cur).length && guard++ < 10) {
    chain.push(normalizeCert(cur));
    const next = cur.issuerCertificate;
    if (!next || next === cur || (chain[0].subject && next.subject === cur.subject && next.issuer === cur.issuer)) {
      break;
    }
    cur = next;
  }

  const leaf = chain[0] || null;
  const now = Date.now();
  let hostMatch = null;
  try {
    if (leaf && conn.peer && conn.peer.raw) {
      const x = new crypto.X509Certificate(conn.peer.raw);
      hostMatch = !!(
        x.checkHost(servername, { subject: 'default' }) ||
        x.checkHost(servername, { subject: 'always' })
      );
    }
  } catch (_) {
    hostMatch = null;
  }

  const notAfter = leaf && leaf.validTo ? new Date(leaf.validTo).getTime() : null;
  const notBefore = leaf && leaf.validFrom ? new Date(leaf.validFrom).getTime() : null;
  const daysLeft = notAfter ? Math.floor((notAfter - now) / 86400000) : null;
  const totalDays =
    notAfter && notBefore ? Math.floor((notAfter - notBefore) / 86400000) : null;

  let status = 'valid';
  if (notAfter && notAfter < now) status = 'expired';
  else if (notBefore && notBefore > now) status = 'notyet';
  else if (daysLeft !== null && daysLeft <= 30) status = 'expiring';
  if (hostMatch === false) status = 'mismatch';
  else if (leaf && leaf.selfSigned) status = 'selfsigned';
  if (!conn.authorized && conn.authorizationError && status === 'valid') {
    status = 'untrusted';
  }

  const protocols = withProbe ? await probeProtocols(host, port, servername, timeoutMs) : null;

  return {
    host,
    port,
    resolved,
    status,
    daysLeft,
    totalDays,
    notBefore: leaf ? leaf.validFrom : null,
    notAfter: leaf ? leaf.validTo : null,
    hostMatch,
    authorized: conn.authorized,
    authorizationError: conn.authorizationError,
    protocol: conn.protocol,
    cipher: conn.cipher,
    chain,
    protocols,
    checkedAt: new Date().toISOString(),
  };
}

/* ------------------------------- HTTP 调试代理 ------------------------------ */

function httpRequest(opts) {
  return new Promise((resolve) => {
    let target;
    try {
      target = new URL(opts.url);
    } catch (e) {
      return resolve({ ok: false, error: 'URL 格式不合法：' + e.message });
    }
    const isHttps = target.protocol === 'https:';
    if (!isHttps && target.protocol !== 'http:') {
      return resolve({ ok: false, error: '仅支持 http / https 协议' });
    }
    const lib = isHttps ? https : http;

    const method = (opts.method || 'GET').toUpperCase();
    const timeoutMs = Math.min(Math.max(Number(opts.timeout) || 15000, 1000), 60000);
    const maxRedirects = opts.followRedirects === false ? 0 : 10;
    const headers = Object.assign({}, opts.headers || {});
    const bodyStr = opts.body || '';

    const redirects = [];
    let currentUrl = target;
    let hops = 0;
    const startAll = Date.now();

    const doRequest = () => {
      const start = Date.now();
      const timings = { dns: null, tcp: null, tls: null, ttfb: null, total: null };
      const options = {
        method,
        hostname: currentUrl.hostname,
        port: currentUrl.port || (isHttps ? 443 : 80),
        path: (currentUrl.pathname || '/') + (currentUrl.search || ''),
        headers: Object.assign({}, headers, {
          Host: currentUrl.host,
          Connection: 'close',
          'Accept-Encoding': 'identity',
        }),
        rejectUnauthorized: false,
      };
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && bodyStr) {
        options.headers['Content-Length'] = Buffer.byteLength(bodyStr, 'utf8');
      }

      const req = lib.request(options, (res) => {
        timings.ttfb = Date.now() - start;
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          timings.total = Date.now() - start;
          const buf = Buffer.concat(chunks);
          const loc = res.headers.location;

          const isRedirect = [301, 302, 303, 307, 308].includes(res.statusCode);
          if (isRedirect && loc && hops < maxRedirects) {
            hops++;
            redirects.push({
              url: currentUrl.toString(),
              status: res.statusCode,
              location: loc,
            });
            try {
              currentUrl = new URL(loc, currentUrl);
            } catch (e) {
              return finish(res, buf, timings, currentUrl);
            }
            // 重定向后方法降级（与常见客户端一致）
            if (res.statusCode === 303 && method !== 'GET' && method !== 'HEAD') {
              options.method = 'GET';
            }
            return doRequest();
          }

          return finish(res, buf, timings, currentUrl);
        });
      });

      req.on('socket', (socket) => {
        socket.on('lookup', () => (timings.dns = Date.now() - start));
        socket.on('connect', () => (timings.tcp = Date.now() - start));
        socket.on('secureConnect', () => (timings.tls = Date.now() - start));
      });

      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error(`请求超时（${timeoutMs}ms）`));
      });

      req.on('error', (err) => {
        resolve({
          ok: false,
          error: `${err.code ? err.code + ' - ' : ''}${err.message}`,
          elapsed: Date.now() - start,
          redirects,
          finalUrl: currentUrl.toString(),
        });
      });

      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && bodyStr) {
        req.write(bodyStr);
      }
      req.end();
    };

    const finish = (res, buf, timings, finalUrl) => {
      const ctype = String(res.headers['content-type'] || '');
      const textual =
        /text|json|xml|javascript|urlencoded|graphql|html|csv|yaml/i.test(ctype) || buf.length === 0;
      resolve({
        ok: true,
        status: res.statusCode,
        statusText: res.statusMessage || '',
        httpVersion: res.httpVersion,
        headers: res.headers,
        size: buf.length,
        contentType: ctype || null,
        isBase64: !textual,
        body: textual ? buf.toString('utf8') : buf.toString('base64'),
        timings,
        elapsed: Date.now() - startAll,
        redirects,
        finalUrl: finalUrl.toString(),
        request: {
          method,
          url: opts.url,
          headers,
          body: bodyStr,
        },
      });
    };

    doRequest();
  });
}

/* ------------------------- 网络诊断 ------------------------- */


function clamp(v, min, max) {
  const n = Number(v);
  if (!isFinite(n)) return min;
  return Math.min(Math.max(n, min), max);
}

/** 域名/URL 归一化，只允许安全字符 */
function normalizeHost(raw) {
  let h = String(raw || '').trim();
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '');
  if (h.includes('@')) h = h.split('@').pop();
  h = h.replace(/^\[|\]$/g, '');
  if (!h) throw new Error('请输入域名或 IP');
  if (h.length > 253) throw new Error('域名过长');
  if (!/^[A-Za-z0-9._:-]+$/.test(h)) throw new Error('域名格式不合法（仅支持字母、数字、点、减号、下划线与冒号）');
  return h;
}

/* --------------------------------- DNS 查询 -------------------------------- */

const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'];

async function doDns(input) {
  const rawName = String(input.name || '').trim();
  if (!rawName) throw new Error('请输入域名或 IP');
  const type = String(input.type || 'A').toUpperCase();
  if (type !== 'ALL' && !DNS_TYPES.includes(type)) throw new Error('不支持的记录类型');

  const isIp = !!net.isIP(rawName);
  const name = isIp ? rawName : normalizeHost(rawName);
  const server = String(input.server || '').trim();
  if (server && !net.isIP(server)) throw new Error('自定义 DNS 服务器需填写 IP 地址');

  const queryOne = async (resolver, t) => {
    const t0 = Date.now();
    try {
      let records;
      if (t === 'PTR') {
        if (!isIp) return { type: t, records: [], error: 'PTR 查询需要输入 IP 地址' };
        records = (await resolver.reverse(name)).map((x) => ({ name: x }));
      } else if (t === 'A' || t === 'AAAA') {
        const list = t === 'A' ? await resolver.resolve4(name) : await resolver.resolve6(name);
        records = list.map((x) => ({ address: x }));
      } else if (t === 'CNAME') {
        records = (await resolver.resolveCname(name)).map((x) => ({ name: x }));
      } else if (t === 'NS') {
        records = (await resolver.resolveNs(name)).map((x) => ({ name: x }));
      } else if (t === 'MX') {
        records = (await resolver.resolveMx(name)).map((x) => ({ priority: x.priority, exchange: x.exchange }));
      } else if (t === 'TXT') {
        const list = await resolver.resolveTxt(name);
        records = list.map((chunks) => ({ text: chunks.join('') }));
      } else if (t === 'SOA') {
        const s = await resolver.resolveSoa(name);
        records = [{ nsname: s.nsname, hostmaster: s.hostmaster, serial: s.serial, refresh: s.refresh, retry: s.retry, expire: s.expire, minttl: s.minttl }];
      } else if (t === 'SRV') {
        records = (await resolver.resolveSrv(name)).map((x) => ({ priority: x.priority, weight: x.weight, port: x.port, name: x.name }));
      } else if (t === 'CAA') {
        records = (await resolver.resolveCaa(name)).map((x) => {
          const tag = x.issue ? 'issue' : x.issuewild ? 'issuewild' : x.iodef ? 'iodef' : 'unknown';
          const value = x.issue || x.issuewild || x.iodef || '';
          return { critical: !!x.critical, tag, value };
        });
      }
      return { type: t, records, elapsed: Date.now() - t0, error: null };
    } catch (e) {
      return { type: t, records: [], error: friendlyDnsError(e), code: e && e.code, elapsed: Date.now() - t0 };
    }
  };

  const runWith = async (dnsServer) => {
    const resolver = new dns.promises.Resolver({ timeout: 5000, tries: 2 });
    if (dnsServer) resolver.setServers([dnsServer]);
    let groups;
    let elapsed = 0;
    if (type === 'ALL') {
      const types = isIp ? ['PTR'] : ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA'];
      const results = await Promise.all(types.map((t) => queryOne(resolver, t)));
      groups = results.filter((r) => r.records.length);
      elapsed = results.reduce((a, r) => Math.max(a, r.elapsed || 0), 0);
      return {
        groups,
        errors: results.filter((r) => r.error),
        empty: results.filter((r) => !r.records.length && !r.error).map((r) => r.type),
        elapsed,
        server: dnsServer || resolver.getServers()[0] || '(系统默认)',
      };
    }
    const one = await queryOne(resolver, type);
    return {
      groups: one.records.length ? [one] : [],
      errors: one.error ? [one] : [],
      empty: [],
      error: one.error || null,
      code: one.code,
      elapsed: one.elapsed,
      server: dnsServer || resolver.getServers()[0] || '(系统默认)',
    };
  };

  // 系统解析器不可用时（例如本机 53 端口无服务）自动退到公共 DNS
  const candidates = [];
  if (server) candidates.push(server);
  else {
    const sys = dns.getServers().filter((s) => s && s !== '127.0.0.1' && s !== '::1');
    if (sys.length) candidates.push(null, '223.5.5.5');
    else candidates.push('223.5.5.5', '119.29.29.29', '8.8.8.8');
  }

  let last = null;
  for (const srv of candidates) {
    last = await runWith(srv);
    if (last.groups.length) return Object.assign({ name, type }, last);
    const connErr = (last.errors || []).some((e) => ['ECONNREFUSED', 'ETIMEOUT'].includes(e.code));
    if (!connErr) break;
  }
  return Object.assign({ name, type }, last);
}

function friendlyDnsError(e) {
  const code = e && e.code;
  const map = {
    ENOTFOUND: '记录不存在（NXDOMAIN）',
    ENODATA: '该域名没有此类型的记录',
    ETIMEOUT: 'DNS 查询超时',
    ESERVFAIL: 'DNS 服务器返回失败（SERVFAIL）',
    EREFUSED: 'DNS 服务器拒绝查询（REFUSED）',
    ECONNREFUSED: '无法连接该 DNS 服务器',
  };
  return map[code] || (e && e.message) || '查询失败';
}

/* --------------------------------- 端口扫描 -------------------------------- */

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 389,
  443, 445, 465, 500, 514, 515, 587, 623, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049,
  2181, 2375, 2376, 3000, 3306, 3389, 4444, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 7001,
  8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017,
];

const PORT_SERVICE = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
  80: 'HTTP', 110: 'POP3', 111: 'rpcbind', 123: 'NTP', 135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS',
  139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP Trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
  465: 'SMTPS', 500: 'ISAKMP', 514: 'Syslog', 515: 'LPD', 587: 'SMTP Submission', 623: 'IPMI',
  636: 'LDAPS', 873: 'rsync', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL',
  1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS', 2181: 'ZooKeeper', 2375: 'Docker', 2376: 'Docker TLS',
  3000: 'Node/Grafana', 3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit', 5000: 'Flask/UPnP',
  5432: 'PostgreSQL', 5601: 'Kibana', 5672: 'RabbitMQ', 5900: 'VNC', 5984: 'CouchDB',
  6379: 'Redis', 7001: 'WebLogic', 8000: 'HTTP Alt', 8008: 'HTTP Alt', 8080: 'HTTP Proxy',
  8081: 'HTTP Alt', 8088: 'HTTP Alt', 8443: 'HTTPS Alt', 8888: 'HTTP Alt', 9000: 'PHP-FPM',
  9090: 'Prometheus', 9200: 'Elasticsearch', 9300: 'Elasticsearch', 10000: 'Webmin',
  11211: 'Memcached', 27017: 'MongoDB',
};

function parsePortSpec(spec) {
  const out = new Set();
  const parts = String(spec || '').split(/[,\s]+/).filter(Boolean);
  for (const p of parts) {
    const m = /^(\d{1,5})\s*-\s*(\d{1,5})$/.exec(p);
    if (m) {
      const a = Number(m[1]), b = Number(m[2]);
      if (a < 1 || b > 65535 || a > b) throw new Error(`端口范围不合法：${p}`);
      for (let i = a; i <= b; i++) {
        out.add(i);
        if (out.size > 2000) throw new Error('单次最多扫描 2000 个端口');
      }
    } else if (/^\d{1,5}$/.test(p)) {
      const n = Number(p);
      if (n < 1 || n > 65535) throw new Error(`端口不合法：${p}`);
      out.add(n);
    } else {
      throw new Error(`端口格式不正确：${p}`);
    }
  }
  if (!out.size) throw new Error('请填写要扫描的端口');
  return [...out].sort((a, b) => a - b);
}

function tcpProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const sock = new net.Socket();
    let done = false;
    const finish = (open, reason) => {
      if (done) return;
      done = true;
      const ms = Math.round(Number(process.hrtime.bigint() - t0) / 1e6);
      sock.destroy();
      resolve({ port, open, ms, reason: reason || null });
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false, 'timeout'));
    sock.once('error', (e) => finish(false, e.code || 'error'));
    sock.connect(port, host);
  });
}

async function doPortScan(input) {
  const host = normalizeHost(input.host);
  const spec = String(input.ports || '').trim();
  const ports = parsePortSpec(spec || COMMON_PORTS.join(','));
  const timeoutMs = clamp(Number(input.timeout) || 800, 100, 5000);
  const concurrency = clamp(Number(input.concurrency) || 80, 1, 200);

  let target = host;
  if (!net.isIP(host)) {
    try {
      const list = await dns.promises.lookup(host, { all: true });
      if (list.length) target = list[0].address;
    } catch (e) {
      throw new Error(`DNS 解析失败：${e.code || e.message}`);
    }
  }

  const startedAt = Date.now();
  const results = [];
  let idx = 0;
  const workers = new Array(Math.min(concurrency, ports.length)).fill(0).map(async () => {
    while (idx < ports.length) {
      const port = ports[idx++];
      results.push(await tcpProbe(target, port, timeoutMs));
    }
  });
  await Promise.all(workers);

  results.sort((a, b) => a.port - b.port);
  const open = results.filter((r) => r.open).map((r) => ({
    port: r.port,
    service: PORT_SERVICE[r.port] || '',
    ms: r.ms,
  }));

  return {
    host,
    target,
    scanned: ports.length,
    open,
    elapsed: Date.now() - startedAt,
    timeout: timeoutMs,
  };
}

/* --------------------------------- IP 查询 --------------------------------- */

/** 判断 IP 的用途类型（内网 / 环回 / 保留 …） */
function ipScope(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return { kind: 'private', label: '内网私有' };
    if (a === 172 && b >= 16 && b <= 31) return { kind: 'private', label: '内网私有' };
    if (a === 192 && b === 168) return { kind: 'private', label: '内网私有' };
    if (a === 127) return { kind: 'loopback', label: '本机环回' };
    if (a === 169 && b === 254) return { kind: 'linklocal', label: '链路本地' };
    if (a === 100 && b >= 64 && b <= 127) return { kind: 'cgnat', label: '运营商级 NAT' };
    if (a >= 224 && a <= 239) return { kind: 'multicast', label: '组播地址' };
    if (a >= 240) return { kind: 'reserved', label: '保留地址' };
    if (a === 0) return { kind: 'reserved', label: '保留地址' };
    return { kind: 'public', label: '公网地址' };
  }
  if (v === 6) {
    const low = ip.toLowerCase();
    if (low === '::1') return { kind: 'loopback', label: '本机环回' };
    if (/^f[cd]/.test(low)) return { kind: 'private', label: 'IPv6 唯一本地' };
    if (/^fe[89ab]/.test(low)) return { kind: 'linklocal', label: '链路本地' };
    if (/^ff/.test(low)) return { kind: 'multicast', label: '组播地址' };
    return { kind: 'public', label: '公网地址' };
  }
  return { kind: 'unknown', label: '未知' };
}

/** IPv4 → 十进制整数（部分日志与防火墙规则使用） */
function ipv4ToInt(ip) {
  if (net.isIP(ip) !== 4) return null;
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/** 反向解析，本机 DNS 不可用时退回公共 DNS */
async function reverseLookup(ip) {
  if (!net.isIP(ip)) return null;
  const run = async (srv) => {
    const resolver = new dns.promises.Resolver({ timeout: 4000, tries: 2 });
    if (srv) resolver.setServers([srv]);
    const list = await resolver.reverse(ip);
    return list && list[0] ? list[0] : null;
  };
  try {
    const r = await run(null);
    if (r) return r;
  } catch (_) {}
  for (const srv of ['223.5.5.5', '119.29.29.29']) {
    try {
      const r = await run(srv);
      if (r) return r;
    } catch (_) {}
  }
  return null;
}

function fetchJson(url, ms = 6000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, {
    signal: ctrl.signal,
    headers: { 'User-Agent': 'ops-toolbox/1.0', Accept: 'application/json' },
  })
    .then((r) => r.json())
    .finally(() => clearTimeout(timer));
}

/** 归属地：依次尝试三家免密钥服务，任一成功即返回 */
async function geoLookup(ip) {
  const q = ip ? encodeURIComponent(ip) : '';
  try {
    const d = await fetchJson(
      `http://ip-api.com/json/${q}?fields=status,message,country,regionName,city,isp,org,as,timezone,lat,lon,query&lang=zh-CN`
    );
    if (d && d.status === 'success') {
      return {
        provider: 'ip-api.com',
        ip: d.query || ip || null,
        country: d.country || null,
        region: d.regionName || null,
        city: d.city || null,
        isp: d.isp || null,
        org: d.org || null,
        as: d.as || null,
        timezone: d.timezone || null,
        lat: d.lat ?? null,
        lon: d.lon ?? null,
      };
    }
  } catch (_) {}

  try {
    const d = await fetchJson(`https://ipwho.is/${q}?lang=zh-CN`);
    if (d && d.success !== false && d.ip) {
      const conn = d.connection || {};
      return {
        provider: 'ipwho.is',
        ip: d.ip,
        country: d.country || null,
        region: d.region || null,
        city: d.city || null,
        isp: conn.isp || null,
        org: conn.org || null,
        as: conn.asn ? `AS${conn.asn} ${conn.org || ''}`.trim() : null,
        timezone: (d.timezone && d.timezone.id) || null,
        lat: d.latitude ?? null,
        lon: d.longitude ?? null,
      };
    }
  } catch (_) {}

  try {
    const d = await fetchJson(`https://ipinfo.io/${q}/json`);
    if (d && d.ip) {
      const loc = String(d.loc || '').split(',');
      return {
        provider: 'ipinfo.io',
        ip: d.ip,
        country: d.country || null,
        region: d.region || null,
        city: d.city || null,
        isp: null,
        org: d.org || null,
        as: d.org && /^AS\d+/.test(d.org) ? d.org.split(' ')[0] : null,
        timezone: d.timezone || null,
        lat: loc[0] || null,
        lon: loc[1] || null,
      };
    }
  } catch (_) {}

  return null;
}

async function doIpInfo(input) {
  const started = Date.now();
  const raw = String(input.ip || '').trim();
  let host = raw
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    .replace(/[/?#].*$/, '');
  if (host.includes('@')) host = host.split('@').pop();
  host = host.replace(/^\[|\]$/g, '');

  let ip = '';
  let from = null;
  if (host) {
    if (net.isIP(host)) ip = host;
    else {
      if (!/^[A-Za-z0-9._-]+$/.test(host)) throw new Error('请输入合法的 IP 地址或域名');
      let list;
      try {
        list = await dns.promises.lookup(host, { all: true });
      } catch (e) {
        throw new Error(`域名解析失败：${e.code || e.message}`);
      }
      if (!list.length) throw new Error('该域名没有解析记录');
      ip = list[0].address;
      from = host;
    }
  }

  const geo = await geoLookup(ip).catch(() => null);
  if (!ip && geo && geo.ip) ip = geo.ip;

  const scope = ip ? ipScope(ip) : null;
  const ptr = ip ? await reverseLookup(ip).catch(() => null) : null;

  return {
    query: raw || null,
    ip: ip || null,
    from,
    version: ip ? (net.isIP(ip) === 6 ? 'IPv6' : 'IPv4') : null,
    scope,
    decimal: ipv4ToInt(ip),
    ptr,
    geo,
    elapsed: Date.now() - started,
  };
}

/** 本机网络信息：主机名 + 各网卡地址（按 IPv4 → 非内部 → 名称排序） */
function doLocalIp() {
  const list = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      const family = a.family === 6 || a.family === 'IPv6' ? 'IPv6' : 'IPv4';
      list.push({
        name,
        address: a.address,
        family,
        internal: !!a.internal,
        mac: a.mac && a.mac !== '00:00:00:00:00:00' ? a.mac : null,
        cidr: a.cidr || null,
        scope: ipScope(a.address),
      });
    }
  }
  const rank = (x) =>
    (x.internal ? 4 : 0) + (x.family === 'IPv4' ? 0 : 1) + (x.scope.kind === 'public' ? 0 : 1);
  list.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));

  return {
    hostname: os.hostname(),
    platform: process.platform,
    release: os.release(),
    addressCount: list.filter((x) => !x.internal).length,
    interfaces: list,
  };
}

/* --------------------------------- 路由层 ---------------------------------- */

/** POST 统一入口：读 body → 调处理函数 → 统一错误包装（wrap=false 时按原样返回） */
async function handlePost(req, res, fn, wrap = true) {
  try {
    const body = await readBody(req);
    const data = await fn(body);
    return sendJson(res, 200, wrap ? { ok: true, data } : data);
  } catch (e) {
    return sendJson(res, 200, { ok: false, error: e.message || String(e) });
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = decodeURIComponent(url.pathname);

  // API
  if (pathname === '/api/health') {
    return sendJson(res, 200, { ok: true, time: new Date().toISOString() });
  }

  if (pathname === '/api/ssl' && req.method === 'POST') {
    return handlePost(req, res, checkSsl);
  }

  if (pathname === '/api/http' && req.method === 'POST') {
    /* http 的返回体本身带 ok 字段，不再二次包装 */
    return handlePost(req, res, httpRequest, false);
  }

  if (pathname.startsWith('/api/net/') && req.method === 'POST') {
    const fn = { dns: doDns, portscan: doPortScan, ipinfo: doIpInfo, localip: doLocalIp }[
      pathname.slice(9)
    ];
    if (!fn) return sendJson(res, 404, { ok: false, error: '未知接口' });
    return handlePost(req, res, fn);
  }

  if (pathname.startsWith('/api/')) {
    return sendJson(res, 404, { ok: false, error: '未知接口' });
  }

  // 静态资源
  if (pathname === '/favicon.ico') {
    res.writeHead(204).end();
    return;
  }

  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403).end('Forbidden');
    return;
  }
  fs.stat(filePath, (err, st) => {
    if (err || !st.isFile()) {
      // SPA 回退
      filePath = path.join(PUBLIC_DIR, 'index.html');
    }
    fs.readFile(filePath, (err2, data) => {
      if (err2) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('404 Not Found');
        return;
      }
      const ext = path.extname(filePath).toLowerCase();
      res.writeHead(200, {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Cache-Control': 'no-cache',
      });
      res.end(data);
    });
  });
});

server.listen(PORT, () => {
  console.log(`\n  运维工具箱已启动:  http://localhost:${PORT}\n`);
});
