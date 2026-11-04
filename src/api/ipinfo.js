/* IP 地址查询：任意 IP / 域名 → 归属地、运营商、ASN、时区、反向解析；
   留空则查询调用方出口 IP（云端用 cf-connecting-ip，本地由第三方按出口识别）。 */
import { geoLookup } from '../lib/geo.js';
import { isIP, ipScope, isPrivateHost } from '../lib/util.js';
import { platform } from '../platform/index.js';

/* 仅 A / 仅 AAAA 的出口查询地址：显式按地址族探测，
   避免运营商双栈下第三方服务随机按 IPv4 / IPv6 识别，导致「我的 IP」一会儿一个版本。 */
const EGRESS_URL = {
  4: 'https://api.ipify.org',
  6: 'https://ipv6.icanhazip.com',
};

async function egressIp(family, ms = family === 4 ? 4000 : 2000) {
  try {
    const res = await fetch(EGRESS_URL[family], {
      headers: { accept: 'text/plain' },
      signal: AbortSignal.timeout(ms),
    });
    if (!res.ok) return null;
    const v = (await res.text()).trim();
    return isIP(v) === family ? v : null;
  } catch (_) {
    return null;
  }
}

export async function ipinfo(input, ctx) {
  const p = await platform();
  const started = Date.now();

  const raw = String(input.ip || '').trim();
  let host = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '');
  if (host.includes('@')) host = host.split('@').pop();
  host = host.replace(/^\[|\]$/g, '');

  let ip = '';
  let from = null;
  let altV6 = null;

  if (host) {
    if (isIP(host)) {
      ip = host;
    } else {
      if (!/^[A-Za-z0-9._-]+$/.test(host)) throw new Error('请输入合法的 IP 地址或域名');
      let ips;
      try {
        ips = await p.lookupIps(host);
      } catch (e) {
        throw new Error(`域名解析失败：${e.code || e.message}`);
      }
      if (!ips.length) throw new Error('该域名没有解析记录');
      ip = ips[0];
      from = host;
    }
  } else {
    // 留空 → 访问者出口 IP
    const ci = p.clientIp(ctx.request);
    if (ci && !isPrivateHost(ci)) {
      ip = ci;
    } else {
      // 本地运行 / 看不到真实客户端地址：服务端与浏览器同机，直接探测本机公网出口。
      // 优先 IPv4；同时拿到 IPv6 时作为附加上报，前端不会再在两个版本间跳变。
      const [v4, v6] = await Promise.all([egressIp(4), egressIp(6)]);
      ip = v4 || v6 || '';
      if (v4) altV6 = v6;
    }
  }

  let geo = null;
  if (ip && !isPrivateHost(ip)) {
    geo = await geoLookup(ip).catch(() => null);
  } else if (!ip) {
    geo = await geoLookup('').catch(() => null);
    if (geo && geo.ip) ip = geo.ip;
  }
  if (!geo) geo = p.cfGeo(ctx.request, ip || null);

  const ptr = ip && !isPrivateHost(ip) ? await p.reverseLookup(ip).catch(() => null) : null;

  return {
    query: raw || null,
    ip: ip || null,
    from,
    version: ip ? (isIP(ip) === 6 ? 'IPv6' : 'IPv4') : null,
    scope: ip ? ipScope(ip) : null,
    ptr,
    geo,
    altV6,
    elapsed: Date.now() - started,
  };
}
