/* Node 平台实现：原生 DNS / TLS / TCP / 静态文件。
   只有 Node 能用到的内置模块都在这里按需动态加载，Workers 打包时不会被解析到。 */

import { friendlyDnsError } from '../lib/util.js';

const load = (name) => import('node:' + name);

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

let libsPromise = null;
function libs() {
  if (!libsPromise) {
    libsPromise = (async () => {
      const [http, https, tls, net, dns, crypto, os, fs, path] = await Promise.all([
        load('http'),
        load('https'),
        load('tls'),
        load('net'),
        load('dns'),
        load('crypto'),
        load('os'),
        load('fs'),
        load('path'),
      ]);
      return {
        http: http.default,
        https: https.default,
        tls: tls.default,
        net: net.default,
        dns: dns.default,
        crypto: crypto.default,
        os: os.default,
        fs: fs.default,
        path: path.default,
      };
    })();
  }
  return libsPromise;
}

const now = () => Date.now();

/* ------------------------------- 证书结构整理 ------------------------------- */

function parseCertDate(str) {
  if (!str) return null;
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

const safeGet = (fn) => {
  try {
    return fn();
  } catch (_) {
    return undefined;
  }
};

function stringifyDN(obj) {
  if (!obj || typeof obj !== 'object') return obj || null;
  const order = ['CN', 'O', 'OU', 'C', 'ST', 'L', 'emailAddress'];
  const parts = [];
  for (const k of order) if (obj[k] !== undefined) parts.push(`${k}=${obj[k]}`);
  for (const k of Object.keys(obj)) {
    if (!order.includes(k) && obj[k] !== undefined) parts.push(`${k}=${obj[k]}`);
  }
  return parts.join(', ') || null;
}

/** 把 getPeerCertificate 返回的对象整理成前端友好的结构 */
function normalizeCert(peerCert, crypto) {
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
    if (peerCert.raw) x509 = new crypto.X509Certificate(peerCert.raw);
  } catch (_) {
    x509 = null;
  }

  const src = x509 || peerCert;
  const flat = (s) => (typeof s === 'string' ? s.replace(/\s*\r?\n\s*/g, ', ').trim() : stringifyDN(s));
  out.subject = flat(src.subject);
  out.issuer = flat(src.issuer);

  out.validFrom = parseCertDate(x509 ? x509.validFrom : peerCert.valid_from);
  out.validTo = parseCertDate(x509 ? x509.validTo : peerCert.valid_to);

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
        bits = pk.asymmetricKeyDetails.modulusLength || (pk.asymmetricKeyDetails.namedCurve ? undefined : null);
      }
      out.publicKey = { type: pk ? pk.asymmetricKeyType : null, bits: bits || null };
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

  out.selfSigned = !!out.subject && out.subject === out.issuer;
  return out;
}

/* --------------------------------- TLS 握手 -------------------------------- */

async function tlsConnect(host, port, servername, timeoutMs, extra = {}) {
  const { tls } = await libs();
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, servername: servername || host, rejectUnauthorized: false, timeout: timeoutMs, ...extra },
      () => {
        try {
          const peer = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const result = {
            protocol: socket.getProtocol(),
            cipher: cipher ? { name: cipher.name, version: cipher.version, bits: cipher.bits } : null,
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
      } catch (_) {
        out[v.key] = false;
      }
    })
  );
  return out;
}

/* --------------------------------- 平台实现 -------------------------------- */

export default {
  name: 'node',
  caps: { tls: true, tcp: true, nics: true, httpTimings: true },
  limits: {
    maxPorts: 2000,
    portSuffix: '',
    concurrency: 80,
    minTimeout: 100,
    dnsConcurrency: 8,
    blockPrivateHost: false,
  },
  geoOrder: ['ip-api', 'ipwho', 'ipinfo'],

  /** 本机直连时没有可信的访问者 IP，交给第三方按出口 IP 识别 */
  clientIp() {
    return null;
  },

  cfGeo() {
    return null;
  },

  checkDnsServer(server) {
    return { ok: true, label: server };
  },

  /** 候选解析服务器：null 表示系统默认；系统 DNS 指向本机 stub 时直接用公共 DNS */
  async dnsCandidates(wanted) {
    if (wanted) return [wanted];
    const { dns } = await libs();
    const sys = (dns.getServers() || []).filter((s) => s && s !== '127.0.0.1' && s !== '::1');
    return sys.length ? [null, '223.5.5.5'] : ['223.5.5.5', '119.29.29.29', '8.8.8.8'];
  },

  async dnsOne(name, type, { server } = {}) {
    const { dns } = await libs();
    const t0 = now();
    const resolver = new dns.promises.Resolver({ timeout: 5000, tries: 2 });
    if (server) resolver.setServers([server]);
    const label = server || (resolver.getServers() || [])[0] || '(系统默认)';
    let records = [];
    try {
      if (type === 'PTR') {
        records = (await resolver.reverse(name)).map((x) => ({ name: x }));
      } else if (type === 'A' || type === 'AAAA') {
        const list = type === 'A' ? await resolver.resolve4(name) : await resolver.resolve6(name);
        records = list.map((x) => ({ address: x }));
      } else if (type === 'CNAME') {
        records = (await resolver.resolveCname(name)).map((x) => ({ name: x }));
      } else if (type === 'NS') {
        records = (await resolver.resolveNs(name)).map((x) => ({ name: x }));
      } else if (type === 'MX') {
        records = (await resolver.resolveMx(name)).map((x) => ({ priority: x.priority, exchange: x.exchange }));
      } else if (type === 'TXT') {
        records = (await resolver.resolveTxt(name)).map((chunks) => ({ text: chunks.join('') }));
      } else if (type === 'SOA') {
        const s = await resolver.resolveSoa(name);
        records = [
          {
            nsname: s.nsname,
            hostmaster: s.hostmaster,
            serial: s.serial,
            refresh: s.refresh,
            retry: s.retry,
            expire: s.expire,
            minttl: s.minttl,
          },
        ];
      } else if (type === 'SRV') {
        records = (await resolver.resolveSrv(name)).map((x) => ({
          priority: x.priority,
          weight: x.weight,
          port: x.port,
          name: x.name,
        }));
      } else if (type === 'CAA') {
        records = (await resolver.resolveCaa(name)).map((x) => {
          const tag = x.issue ? 'issue' : x.issuewild ? 'issuewild' : x.iodef ? 'iodef' : 'unknown';
          return { critical: !!x.critical, tag, value: x.issue || x.issuewild || x.iodef || '' };
        });
      }
      return { records, error: null, code: null, elapsed: now() - t0, server: label };
    } catch (e) {
      return { records: [], error: friendlyDnsError(e), code: e.code, elapsed: now() - t0, server: label };
    }
  },

  /** 域名 → IP 列表 */
  async lookupIps(host) {
    const { dns } = await libs();
    const list = await dns.promises.lookup(host, { all: true });
    return list.map((x) => x.address);
  },

  /** 反向解析：系统 DNS 失败时退到公共 DNS */
  async reverseLookup(ip) {
    const { dns } = await libs();
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
  },

  /** 单次 HTTP 请求（不跟随重定向），返回原始字节与分段耗时 */
  async httpSend({ url, method, headers, body, timeoutMs }) {
    const { http, https } = await libs();
    const target = new URL(url);
    const isHttps = target.protocol === 'https:';
    const lib = isHttps ? https : http;
    const t0 = now();
    const timings = { dns: null, tcp: null, tls: null, ttfb: null };
    const outHeaders = { ...headers, Host: target.host, Connection: 'close', 'Accept-Encoding': 'identity' };
    if (body && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      outHeaders['Content-Length'] = Buffer.byteLength(body, 'utf8');
    }

    return new Promise((resolve, reject) => {
      const req = lib.request(
        {
          method,
          hostname: target.hostname,
          port: target.port || (isHttps ? 443 : 80),
          path: (target.pathname || '/') + (target.search || ''),
          headers: outHeaders,
          rejectUnauthorized: false,
        },
        (res) => {
          timings.ttfb = now() - t0;
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () =>
            resolve({
              status: res.statusCode,
              statusText: res.statusMessage || '',
              httpVersion: res.httpVersion,
              headers: res.headers,
              bytes: Buffer.concat(chunks),
              timings,
            })
          );
        }
      );

      req.on('socket', (socket) => {
        socket.on('lookup', () => (timings.dns = now() - t0));
        socket.on('connect', () => (timings.tcp = now() - t0));
        socket.on('secureConnect', () => (timings.tls = now() - t0));
      });
      req.setTimeout(timeoutMs, () => req.destroy(new Error(`请求超时（${timeoutMs}ms）`)));
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
  },

  /** 单端口 TCP 连通性探测 */
  async tcpProbe(host, port, timeoutMs) {
    const { net } = await libs();
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
  },

  /** 裸 TCP 连接：给自解析 TLS 握手用（rawtls.js），接口与 Workers 保持一致 */
  async tcpOpen(host, port, timeoutMs) {
    const { net } = await libs();
    const sock = new net.Socket();
    sock.setTimeout(timeoutMs);
    await new Promise((resolve, reject) => {
      const onErr = (e) => reject(e);
      sock.once('connect', () => {
        sock.removeListener('error', onErr);
        resolve();
      });
      sock.once('timeout', () => {
        sock.removeListener('error', onErr);
        reject(new Error('连接超时'));
      });
      sock.once('error', onErr);
      sock.connect(port, host);
    });
    sock.setTimeout(0);

    let chunks = [];
    let waiters = [];
    let ended = false;
    const flush = () => {
      while (waiters.length) waiters.shift()(null);
    };
    sock.on('data', (d) => {
      const b = new Uint8Array(d);
      const w = waiters.shift();
      if (w) w(b);
      else chunks.push(b);
    });
    sock.on('end', () => {
      ended = true;
      flush();
    });
    sock.on('close', () => {
      ended = true;
      flush();
    });
    sock.on('error', () => {
      ended = true;
      flush();
    });

    return {
      write(bytes) {
        return new Promise((resolve, reject) => {
          sock.write(bytes, (err) => (err ? reject(err) : resolve()));
        });
      },
      read(ms) {
        return new Promise((resolve) => {
          if (chunks.length) return resolve(chunks.shift());
          if (ended) return resolve(null);
          const timer = setTimeout(() => {
            const i = waiters.findIndex((w) => w === waiter);
            if (i >= 0) waiters.splice(i, 1);
            resolve(null);
          }, ms);
          const waiter = (d) => {
            clearTimeout(timer);
            resolve(d);
          };
          waiters.push(waiter);
        });
      },
      close() {
        try {
          sock.destroy();
        } catch (_) {}
      },
    };
  },

  /** 真实 TLS 握手：拿协议、套件、证书链、主机名匹配 */
  async inspectTls(host, port, { servername, timeoutMs, probe }) {
    const { crypto } = await libs();
    const conn = await tlsConnect(host, port, servername, timeoutMs);

    const chain = [];
    let cur = conn.peer;
    let guard = 0;
    while (cur && Object.keys(cur).length && guard++ < 10) {
      chain.push(normalizeCert(cur, crypto));
      const next = cur.issuerCertificate;
      const leaf = chain[0];
      if (!next || next === cur || (leaf.subject && next.subject === cur.subject && next.issuer === cur.issuer)) break;
      cur = next;
    }

    let hostMatch = null;
    try {
      if (conn.peer && conn.peer.raw) {
        const x = new crypto.X509Certificate(conn.peer.raw);
        hostMatch = !!(x.checkHost(servername, { subject: 'default' }) || x.checkHost(servername, { subject: 'always' }));
      }
    } catch (_) {
      hostMatch = null;
    }

    return {
      protocol: conn.protocol,
      cipher: conn.cipher,
      authorized: conn.authorized,
      authorizationError: conn.authorizationError,
      chain,
      hostMatch,
      protocols: probe ? await probeProtocols(host, port, servername, timeoutMs) : null,
    };
  },

  /** 静态资源：读 public/ 目录，未命中回退 index.html */

  /** 静态资源：读 public/ 目录，未命中回退 index.html */
  async serveStatic(request) {
    const { fs, path } = await libs();    const url = new URL(request.url);
    let pathname;
    try {
      pathname = decodeURIComponent(url.pathname);
    } catch (_) {
      pathname = url.pathname;
    }
    if (pathname === '/favicon.ico') return new Response(null, { status: 204 });

    const base = new URL('../../public/', import.meta.url);
    const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    let fileUrl = new URL(rel, base);
    if (!fileUrl.href.startsWith(base.href)) {
      return new Response('Forbidden', { status: 403 });
    }
    try {
      const st = await fs.promises.stat(fileUrl);
      if (!st.isFile()) throw new Error('not a file');
    } catch (_) {
      fileUrl = new URL('index.html', base); // SPA 回退
    }

    try {
      const data = await fs.promises.readFile(fileUrl);
      const ext = path.extname(fileUrl.pathname).toLowerCase();
      return new Response(data, {
        status: 200,
        headers: {
          'content-type': MIME[ext] || 'application/octet-stream',
          'cache-control': 'no-cache',
          'content-length': String(data.length),
        },
      });
    } catch (_) {
      return new Response('404 Not Found', {
        status: 404,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }
  },
};
