/* IP 地址查询：任意 IP / 域名 → 归属地、运营商、ASN、时区、反向解析；
   留空则查询调用方出口 IP（云端用 cf-connecting-ip，本地由第三方按出口识别）。 */
import { geoLookup } from '../lib/geo.js';
import { isIP, ipScope, ipv4ToInt, isPrivateHost } from '../lib/util.js';
import { platform } from '../platform/index.js';

export async function ipinfo(input, ctx) {
  const p = await platform();
  const started = Date.now();

  const raw = String(input.ip || '').trim();
  let host = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '');
  if (host.includes('@')) host = host.split('@').pop();
  host = host.replace(/^\[|\]$/g, '');

  let ip = '';
  let from = null;

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
    // 留空 → 访问者出口 IP；本地运行时拿到的是内网地址，交给第三方按实际出口识别
    const ci = p.clientIp(ctx.request);
    if (ci && !isPrivateHost(ci)) ip = ci;
  }

  let geo = null;
  if (ip && !isPrivateHost(ip)) {
    geo = await geoLookup(ip, p.geoOrder).catch(() => null);
  } else if (!ip) {
    geo = await geoLookup('', p.geoOrder).catch(() => null);
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
    decimal: ipv4ToInt(ip),
    ptr,
    geo,
    elapsed: Date.now() - started,
  };
}

export async function localip(input, ctx) {
  const p = await platform();
  return p.localInfo(ctx.request);
}
