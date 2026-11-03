/* Workers 平台实现：DoH 解析、cloudflare:sockets 探测、边缘信息、ASSETS 静态资源。
   TLS 证书检测统一走 lib/rawtls.js（与本地同一份代码）。 */

import { connect } from 'cloudflare:sockets';
import { DOH_SERVERS, dohRecords, dohResolve, dohReverse, pickEndpoint } from '../lib/doh.js';

export default {
  name: 'workers',
  /** 仅保留平台固有差异；端口上限、超时范围等统一参数见各 api 模块顶部常量 */
  limits: {
    concurrency: 6, // 平台硬限制：单请求最多 6 个并发出站连接
    blockPrivateHost: true, // 平台限制：cloudflare:sockets 无法连接内网地址
  },
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

  /** 裸 TCP 连接：云端没有 TLS 对端证书 API，自解析握手（rawtls.js）要用 */
  async tcpOpen(host, port, timeoutMs) {
    const socket = connect({ hostname: host, port });
    let openedErr = null;
    const opened = socket.opened.catch((e) => {
      openedErr = e;
    });
    await Promise.race([
      opened,
      new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs)),
    ]);
    if (openedErr) throw openedErr;

    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    let closed = false;
    const close = () => {
      if (closed) return;
      closed = true;
      try {
        socket.close();
      } catch (_) {}
    };

    return {
      async write(bytes) {
        await writer.write(bytes);
      },
      async read(ms) {
        if (closed) return null;
        const pending = reader.read().catch(() => ({ done: true, value: undefined }));
        const res = await Promise.race([
          pending,
          new Promise((r) => setTimeout(() => r({ timeout: true }), ms)),
        ]);
        if (res.timeout) {
          close();
          return null;
        }
        if (res.done || !res.value) return null;
        return res.value instanceof Uint8Array ? res.value : new Uint8Array(res.value);
      },
      close,
    };
  },

  /** 静态资源交给 ASSETS 绑定 */
  async serveStatic(request, env) {
    if (!env || !env.ASSETS) return null;
    return env.ASSETS.fetch(request);
  },
};
