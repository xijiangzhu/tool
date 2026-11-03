/* IP 地址查询（Workers 版）：
   - 任意 IP / 域名 → 归属地、运营商、ASN、时区、反向解析
   - 留空 → 当前访问者出口 IP（用 cf-connecting-ip 头）
   - 「本机网卡信息」在云端无法获取，localip 返回空列表由前端降级展示 */
import { isIP, ipScope, ipv4ToInt, isPrivateHost } from '../lib/util.js';
import { dohQuery, getEndpoint } from '../lib/doh.js';

const enc = encodeURIComponent;

async function getJson(url, ms = 6000) {
  const res = await fetch(url, {
    headers: { accept: 'application/json', 'user-agent': 'ops-toolbox/1.0' },
    signal: AbortSignal.timeout(ms),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/** 归属地：ipwho.is（支持中文）→ ip-api → ipinfo.io */
async function geoLookup(ip) {
  const q = ip ? enc(ip) : '';
  try {
    const d = await getJson(`https://ipwho.is/${q}?lang=zh-CN`);
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
    const d = await getJson(
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
    const d = await getJson(`https://ipinfo.io/${q}/json`);
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

/** 用 Cloudflare 的边缘信息兜底（无第三方依赖，但只有国家代码与英文城市） */
function cfGeo(cf, ip) {
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
}

async function reverseLookup(ip) {
  if (!isIP(ip)) return null;
  const name =
    isIP(ip) === 4
      ? ip.split('.').reverse().join('.') + '.in-addr.arpa'
      : null; // IPv6 反查较少用，云端略过
  if (!name) return null;
  try {
    // 反查只是附加信息：只用已确认可用的端点，失败就放弃，不做多端点回退
    const ep = await getEndpoint();
    const r = await dohQuery(name, 'PTR', ep, 2500);
    const hit = r.answer.find((a) => a.type === 12);
    return hit ? String(hit.data).replace(/\.$/, '') : null;
  } catch (_) {
    return null;
  }
}

/** 域名 → IP（DoH），优先 IPv4 */
async function resolveHost(host) {
  for (const t of ['A', 'AAAA']) {
    try {
      const r = await dohQuery(host, t);
      const want = t === 'A' ? 1 : 28;
      const hit = r.answer.find((a) => a.type === want);
      if (hit) return hit.data;
    } catch (_) {}
  }
  return null;
}

export async function ipinfo(input, ctx) {
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
    if (isIP(host)) ip = host;
    else {
      if (!/^[A-Za-z0-9._-]+$/.test(host)) throw new Error('请输入合法的 IP 地址或域名');
      ip = await resolveHost(host);
      if (!ip) throw new Error('域名解析失败，未查询到 A / AAAA 记录');
      from = host;
    }
  } else {
    // 留空 → 访问者出口 IP
    ip = ctx.request.headers.get('cf-connecting-ip') || '';
    if (!ip) throw new Error('无法获取访问者 IP，请手动输入要查询的地址');
    if (isPrivateHost(ip)) {
      throw new Error('本地调试环境拿不到真实出口 IP（部署到 Cloudflare 后自动可用），请手动输入要查询的地址');
    }
  }

  let geo = await geoLookup(ip).catch(() => null);
  if (!geo) geo = cfGeo(ctx.request.cf, ip);

  const scope = ip ? ipScope(ip) : null;
  const ptr = isPrivateHost(ip) ? null : await reverseLookup(ip);

  return {
    query: raw || null,
    ip: ip || null,
    from,
    version: ip ? (isIP(ip) === 6 ? 'IPv6' : 'IPv4') : null,
    scope,
    decimal: ipv4ToInt(ip),
    ptr,
    geo,
    elapsed: Date.now() - started,
  };
}

export async function localip(input, ctx) {
  const cf = ctx.request.cf || {};
  return {
    hostname: null,
    platform: 'cloudflare',
    release: null,
    addressCount: 0,
    interfaces: [],
    runtime: 'workers',
    colo: cf.colo || null,
    country: cf.country || null,
    clientIp: ctx.request.headers.get('cf-connecting-ip') || null,
  };
}
