/* Workers 平台实现：DoH 解析、cloudflare:sockets 探测、边缘信息、ASSETS 静态资源。
   云端拿不到 TLS 对端证书与本机网卡，对应能力由调用方降级处理。 */

import { connect } from 'cloudflare:sockets';
import { DOH_SERVERS, dohRecords, dohResolve, dohReverse, pickEndpoint } from '../lib/doh.js';

export default {
  name: 'workers',
  caps: { tls: false, tcp: true, nics: false, httpTimings: false },
  limits: {
    maxPorts: 150,
    portSuffix: '（云端并发受限）',
    concurrency: 6,
    minTimeout: 300,
    dnsConcurrency: 4,
    blockPrivateHost: true,
  },
  geoOrder: ['ipwho', 'ip-api', 'ipinfo'],

  clientIp(request) {
    return request.headers.get('cf-connecting-ip') || null;
  },

  /** Cloudflare 边缘自带的地理信息，用作第三方服务失败时的兜底 */
  cfGeo(request, ip) {
    const cf = request.cf;
    if (!cf || !cf.country) return null;
    return {
      provider: 'Cloudflare 边缘',
      ip: ip || null,
      country: cf.country,
      region: cf.region || null,
      city: cf.city || null,
      isp: null,
      org: cf.asOrganization || null,
      as: cf.asn ? `AS${cf.asn}` : null,
      timezone: cf.timezone || null,
      lat: cf.latitude || null,
      lon: cf.longitude || null,
    };
  },

  /** 云端只能访问已知的公共 DoH 端点 */
  checkDnsServer(server) {
    const ep = pickEndpoint(server);
    if (!ep) {
      return {
        ok: false,
        error: `云端运行不支持向 ${server} 直接发 53 端口查询，可用：${Object.keys(DOH_SERVERS).join(' / ')}（或留空自动选择）`,
      };
    }
    return { ok: true, endpoint: ep, label: ep.name };
  },

  async dnsOne(name, type, { endpoint } = {}) {
    return dohRecords(name, type, endpoint || null);
  },

  /** DoH 内部已做端点择优与回退，这里只需一轮 */
  dnsCandidates() {
    return [null];
  },

  async lookupIps(host) {
    const ip = await dohResolve(host);
    return ip ? [ip] : [];
  },

  async reverseLookup(ip) {
    return dohReverse(ip);
  },

  /** 单次 HTTP 请求（不跟随重定向） */
  async httpSend({ url, method, headers, body, timeoutMs }) {
    const init = { method, headers, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) };
    if (body && !['GET', 'HEAD'].includes(method)) init.body = body;
    const t0 = Date.now();
    const res = await fetch(url, init);
    const ttfb = Date.now() - t0;
    let bytes;
    try {
      bytes = new Uint8Array(await res.arrayBuffer());
    } catch (_) {
      bytes = new Uint8Array(0);
    }
    const out = {};
    res.headers.forEach((v, k) => {
      out[k] = out[k] ? `${out[k]}, ${v}` : v;
    });
    return {
      status: res.status,
      statusText: res.statusText || '',
      httpVersion: null, // 平台不暴露 HTTP 版本
      headers: out,
      bytes,
      timings: { dns: null, tcp: null, tls: null, ttfb },
      location: res.headers.get('location'),
    };
  },

  /** 单端口 TCP 连通性探测（受平台并发与网段限制） */
  tcpProbe(host, port, timeoutMs) {
    return new Promise((resolve) => {
      const t0 = Date.now();
      let done = false;
      let socket;
      const finish = (open, reason) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try {
          if (socket) socket.close();
        } catch (_) {}
        resolve({ port, open, ms: Date.now() - t0, reason: reason || null });
      };
      const timer = setTimeout(() => finish(false, 'timeout'), timeoutMs);
      try {
        socket = connect({ hostname: host, port });
        socket.opened.then(
          () => finish(true),
          (e) => finish(false, (e && e.message) || 'error')
        );
      } catch (e) {
        finish(false, (e && e.message) || 'error');
      }
    });
  },

  /** 云端没有本机网卡，返回运行环境信息供前端降级展示 */
  async localInfo(request) {
    const cf = request.cf || {};
    return {
      hostname: null,
      platform: 'cloudflare',
      release: null,
      addressCount: 0,
      interfaces: [],
      runtime: 'workers',
      colo: cf.colo || null,
      country: cf.country || null,
      clientIp: request.headers.get('cf-connecting-ip') || null,
    };
  },

  /** 静态资源交给 ASSETS 绑定 */
  async serveStatic(request, env) {
    if (!env || !env.ASSETS) return null;
    return env.ASSETS.fetch(request);
  },
};
