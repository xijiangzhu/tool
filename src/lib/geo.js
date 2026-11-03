/* IP 归属地：三家免密钥服务兜底，任一成功即返回。两端运行时使用同一查询顺序。 */

const enc = encodeURIComponent;

async function getJson(url, ms = 6000, accept = 'application/json') {
  const res = await fetch(url, {
    headers: { accept, 'user-agent': 'ops-toolbox/1.0' },
    signal: AbortSignal.timeout(ms),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const PROVIDERS = {
  'ip-api': {
    name: 'ip-api.com',
    url: (ip) =>
      `http://ip-api.com/json/${ip ? enc(ip) : ''}?fields=status,message,country,regionName,city,isp,org,as,timezone,lat,lon,query&lang=zh-CN`,
    map: (d, ip) => {
      if (!d || d.status !== 'success') return null;
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
    },
  },
  'ipwho': {
    name: 'ipwho.is',
    url: (ip) => `https://ipwho.is/${ip ? enc(ip) : ''}?lang=zh-CN`,
    map: (d, ip) => {
      if (!d || d.success === false || !d.ip) return null;
      const conn = d.connection || {};
      return {
        provider: 'ipwho.is',
        ip: d.ip || ip || null,
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
    },
  },
  ipinfo: {
    name: 'ipinfo.io',
    url: (ip) => `https://ipinfo.io/${ip ? enc(ip) : ''}/json`,
    map: (d, ip) => {
      if (!d || !d.ip) return null;
      const loc = String(d.loc || '').split(',');
      return {
        provider: 'ipinfo.io',
        ip: d.ip || ip || null,
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
    },
  },
};

/** 统一查询顺序：ipwho.is → ip-api.com → ipinfo.io */
const GEO_ORDER = ['ipwho', 'ip-api', 'ipinfo'];

/**
 * 查询 IP 归属地
 * @param ip 留空时由服务方按调用方出口 IP 处理（Node 本地即本机公网出口）
 */
export async function geoLookup(ip, order = GEO_ORDER) {
  for (const key of order) {
    const p = PROVIDERS[key];
    if (!p) continue;
    try {
      const d = await getJson(p.url(ip));
      const hit = p.map(d, ip);
      if (hit) return hit;
    } catch (_) {}
  }
  return null;
}
