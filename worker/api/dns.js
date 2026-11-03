/* DNS 查询：走 DoH（Workers 无法直接发 53 端口的 UDP 查询），返回结构与 Node 版一致 */
import { isIP, normalizeHost, reverseName } from '../lib/util.js';
import {
  DOH_SERVERS,
  TYPE_NUM,
  dohQuery,
  getEndpoint,
  parseTxt,
  pickEndpoint,
  stripDot,
} from '../lib/doh.js';

const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'];
const ALL_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA'];

/** 把 DoH 的 data 字段解析成前端要的字段结构 */
function toRecord(type, raw) {
  const data = String(raw || '');
  switch (type) {
    case 'A':
    case 'AAAA':
      return { address: data };
    case 'CNAME':
    case 'NS':
    case 'PTR':
      return { name: stripDot(data) };
    case 'MX': {
      const [priority, exchange] = data.split(/\s+/, 2);
      // 值为 "." 表示该域声明「不收邮件」（RFC 7505），原样展示
      return { priority: Number(priority), exchange: stripDot(exchange) || '.' };
    }
    case 'TXT':
      return { text: parseTxt(data) };
    case 'SRV': {
      const [priority, weight, port, name] = data.split(/\s+/);
      return { priority: Number(priority), weight: Number(weight), port: Number(port), name: stripDot(name) };
    }
    case 'CAA': {
      const m = /^(\d+)\s+(\S+)\s+"?([^"]*)"?$/.exec(data);
      if (!m) return { critical: false, tag: 'unknown', value: data };
      return { critical: m[1] !== '0', tag: m[2], value: m[3] };
    }
    case 'SOA': {
      const p = data.split(/\s+/);
      return {
        nsname: stripDot(p[0]),
        hostmaster: stripDot(p[1]),
        serial: unsigned(p[2]),
        refresh: Number(p[3]),
        retry: Number(p[4]),
        expire: Number(p[5]),
        minttl: Number(p[6]),
      };
    }
    default:
      return { name: data };
  }
}

/** 个别 DoH 会把 32 位 SOA 序列号当有符号整数返回，这里还原 */
function unsigned(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return v;
  return n < 0 ? n + 4294967296 : n;
}

export default async function dnsQuery(input) {
  const rawName = String(input.name || '').trim();
  if (!rawName) throw new Error('请输入域名或 IP');
  const type = String(input.type || 'A').toUpperCase();
  if (type !== 'ALL' && !DNS_TYPES.includes(type)) throw new Error('不支持的记录类型');

  const ipVersion = isIP(rawName);
  const name = ipVersion ? rawName : normalizeHost(rawName);
  if (rawName.includes('@') || /^[a-z][a-z0-9+.-]*:\/\//i.test(rawName)) {
    throw new Error('请填写域名或 IP，不要带协议与路径');
  }

  // 自定义服务器：只支持已知公共 DNS 的 DoH 端点；留空则由 dohQuery 自动挑选并回退
  const wanted = String(input.server || '').trim();
  const custom = wanted ? pickEndpoint(wanted) : null;
  if (wanted && !custom) {
    throw new Error(
      `云端运行不支持向 ${wanted} 直接发 53 端口查询，可用：${Object.keys(DOH_SERVERS).join(' / ')}（或留空自动选择）`
    );
  }
  let usedServer = custom ? custom.name : '';

  const queryOne = async (t) => {
    const t0 = Date.now();
    // PTR 需要把 IP 转成 arpa 域名
    const qname = t === 'PTR' ? reverseName(name) : name;
    if (t === 'PTR' && !qname) {
      return { type: t, records: [], error: 'PTR 查询需要输入 IP 地址', elapsed: 0 };
    }
    try {
      const r = await dohQuery(qname, t, custom);
      if (!usedServer && r.endpoint) usedServer = r.endpoint.name;
      if (r.status === 3) {
        return { type: t, records: [], error: '记录不存在（NXDOMAIN）', code: 'ENOTFOUND', elapsed: Date.now() - t0 };
      }
      if (r.status !== 0) {
        return { type: t, records: [], error: r.statusText || `DNS 返回状态 ${r.status}`, code: 'ESERVFAIL', elapsed: Date.now() - t0 };
      }
      const num = TYPE_NUM[t];
      const recs = r.answer.filter((a) => a.type === num).map((a) => toRecord(t, a.data));
      return {
        type: t,
        records: recs,
        error: recs.length ? null : '该域名没有此类型的记录',
        code: recs.length ? null : 'ENODATA',
        elapsed: Date.now() - t0,
      };
    } catch (e) {
      return { type: t, records: [], error: e.message || '查询失败', code: e.code || 'EDOH', elapsed: Date.now() - t0 };
    }
  };

  if (type === 'ALL') {
    const types = isIP(name) ? ['PTR'] : ALL_TYPES;
    // 并发压到 4：一次打 8 个 DoH 请求时本地运行时容易丢连接
    const results = [];
    for (let i = 0; i < types.length; i += 4) {
      results.push(...(await Promise.all(types.slice(i, i + 4).map((t) => queryOne(t)))));
    }
    return {
      name,
      type,
      groups: results.filter((r) => r.records.length),
      errors: results.filter((r) => r.error && r.code !== 'ENODATA'),
      empty: results.filter((r) => !r.records.length && r.code === 'ENODATA').map((r) => r.type),
      elapsed: results.reduce((a, r) => Math.max(a, r.elapsed || 0), 0),
      server: usedServer || '公共 DoH',
    };
  }

  const one = await queryOne(type);
  return {
    name,
    type,
    groups: one.records.length ? [one] : [],
    errors: one.error ? [one] : [],
    empty: [],
    error: one.error || null,
    code: one.code,
    elapsed: one.elapsed,
    server: usedServer || '公共 DoH',
  };
}
