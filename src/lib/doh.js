/* DoH（DNS over HTTPS）实现：Workers 无法直接发 53 端口的 UDP 查询，统一走 JSON API。
   端点自动择优 + 失败回退，结果按 isolate 缓存。 */

import { friendlyDnsError, isIP, reverseName } from './util.js';

/** 候选公共 DoH（均支持 application/dns-json） */
const CANDIDATES = [
  { url: 'https://cloudflare-dns.com/dns-query', name: 'Cloudflare DoH' },
  { url: 'https://doh.pub/dns-query', name: '腾讯 DoH' },
  { url: 'https://dns.google/dns-query', name: 'Google DoH' },
];

/** 常见公共 DNS → 对应的 DoH 端点（自建 / 未知服务器不支持） */
export const DOH_SERVERS = {
  '1.1.1.1': { url: 'https://cloudflare-dns.com/dns-query', name: 'Cloudflare 1.1.1.1' },
  '1.0.0.1': { url: 'https://cloudflare-dns.com/dns-query', name: 'Cloudflare 1.0.0.1' },
  '8.8.8.8': { url: 'https://dns.google/dns-query', name: 'Google 8.8.8.8' },
  '8.8.4.4': { url: 'https://dns.google/dns-query', name: 'Google 8.8.4.4' },
  '119.29.29.29': { url: 'https://doh.pub/dns-query', name: '腾讯 119.29.29.29' },
  '223.5.5.5': { url: 'https://doh.pub/dns-query', name: '腾讯 DoH（代 223.5.5.5）' },
};

export const pickEndpoint = (server) => DOH_SERVERS[String(server || '').trim()] || null;

const STATUS_TEXT = {
  1: 'DNS 报文格式错误（FORMERR）',
  2: 'DNS 服务器返回失败（SERVFAIL）',
  3: '记录不存在（NXDOMAIN）',
  4: '查询类型不支持（NOTIMP）',
  5: 'DNS 服务器拒绝查询（REFUSED）',
};

const TYPE_NUM = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, CAA: 257,
};

const stripDot = (s) => String(s || '').replace(/\.$/, '');

/** TXT 记录的数据是若干带引号的片段，拼回原文 */
function parseTxt(data) {
  const parts = String(data || '').match(/"((?:[^"\\]|\\.)*)"/g);
  if (parts) return parts.map((s) => s.slice(1, -1).replace(/\\"/g, '"')).join('');
  return String(data || '').replace(/^"|"$/g, '');
}

/** 个别 DoH 会把 32 位 SOA 序列号当有符号整数返回，这里还原 */
const unsigned = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return v;
  return n < 0 ? n + 4294967296 : n;
};

/** 把 DoH 的 data 字段解析成前端需要的字段结构 */
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

let cached = null; // 已确认可用的端点
let probing = null; // 进行中的探测（并发请求共用一次探测）
const badUntil = new Map(); // 端点 → 屏蔽到期时间，避免每次请求都重试死掉的端点

const BAD_TTL = 5 * 60 * 1000;
const isBad = (ep) => (badUntil.get(ep.url) || 0) > Date.now();
const markBad = (ep) => badUntil.set(ep.url, Date.now() + BAD_TTL);

/** 原始 DoH 查询：返回 DNS RCODE + Answer */
async function rawQuery(name, type, endpoint, ms) {
  const url = `${endpoint.url}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  let res;
  try {
    res = await fetch(url, {
      headers: { accept: 'application/dns-json' },
      signal: AbortSignal.timeout(ms),
    });
  } catch (e) {
    const err = new Error(e && e.name === 'TimeoutError' ? '连接超时' : `网络错误 ${e.message || ''}`.trim());
    err.kind = 'network';
    throw err;
  }
  if (!res.ok) {
    // 4xx/5xx 多为该端点不支持这种记录类型，只影响这一条查询，不该整段拉黑端点
    const err = new Error(`HTTP ${res.status}`);
    err.kind = 'http';
    throw err;
  }
  let data;
  try {
    data = await res.json();
  } catch (_) {
    const err = new Error('返回内容不是 JSON');
    err.kind = 'http';
    throw err;
  }
  const status = Number(data.Status || 0);
  return {
    status,
    statusText: STATUS_TEXT[status] || null,
    answer: Array.isArray(data.Answer) ? data.Answer : [],
  };
}

/** 选一个可用的 DoH 端点（首次成功后缓存） */
async function getEndpoint(force = false) {
  if (cached && !force && !isBad(cached)) return cached;
  if (probing) return probing;
  probing = (async () => {
    const errors = [];
    for (const ep of CANDIDATES) {
      if (isBad(ep)) continue;
      try {
        const r = await rawQuery('example.com', 'A', ep, 1500);
        if (r.status === 0) {
          cached = ep;
          return ep;
        }
        errors.push(`${ep.name}: RCODE ${r.status}`);
      } catch (e) {
        markBad(ep);
        errors.push(`${ep.name}: ${e.message}`);
      }
    }
    // 全部被屏蔽时清空屏蔽表，下一轮重新试
    if (!errors.length) {
      badUntil.clear();
      return getEndpoint(true);
    }
    throw new Error(`没有可用的 DoH 服务（${errors.join('；')}）`);
  })().finally(() => {
    probing = null;
  });
  return probing;
}

/** 执行一次 DoH 查询：指定端点就只用它，否则自动择优并回退 */
export async function dohQuery(name, type, endpoint = null, ms = 6000) {
  if (endpoint) {
    const result = await rawQuery(name, type, endpoint, ms);
    return Object.assign(result, { endpoint });
  }
  const first = await getEndpoint();
  const list = [first, ...CANDIDATES.filter((e) => e.url !== first.url && !isBad(e))];
  const deadline = Date.now() + ms; // 一条查询的总预算，避免多端点回退把页面拖住
  let lastErr;
  for (const ep of list) {
    const remain = deadline - Date.now();
    if (remain < 300) break;
    try {
      const result = await rawQuery(name, type, ep, Math.min(remain, 4000));
      return Object.assign(result, { endpoint: ep });
    } catch (e) {
      if (e.kind !== 'http') markBad(ep); // 网络类失败才拉黑；类型不支持只跳过本次
      lastErr = e;
    }
  }
  throw lastErr;
}

/** 单类型查询，输出与 Node 原生解析一致的记录结构 */
export async function dohRecords(name, type, endpoint = null) {
  const t0 = Date.now();
  const qname = type === 'PTR' ? reverseName(name) : name;
  if (type === 'PTR' && !qname) {
    return { records: [], error: 'PTR 查询需要输入 IP 地址', code: 'ENODATA', elapsed: 0 };
  }
  try {
    const r = await dohQuery(qname, type, endpoint);
    if (r.status === 3) {
      return { records: [], error: '记录不存在（NXDOMAIN）', code: 'ENOTFOUND', elapsed: Date.now() - t0 };
    }
    if (r.status !== 0) {
      return {
        records: [],
        error: r.statusText || `DNS 返回状态 ${r.status}`,
        code: 'ESERVFAIL',
        elapsed: Date.now() - t0,
      };
    }
    const num = TYPE_NUM[type];
    const records = r.answer.filter((a) => a.type === num).map((a) => toRecord(type, a.data));
    return {
      records,
      error: records.length ? null : '该域名没有此类型的记录',
      code: records.length ? null : 'ENODATA',
      elapsed: Date.now() - t0,
      server: r.endpoint ? r.endpoint.name : undefined,
    };
  } catch (e) {
    return {
      records: [],
      error: friendlyDnsError(e) || '查询失败',
      code: e.code || 'EDOH',
      elapsed: Date.now() - t0,
    };
  }
}

/** 域名 → IP（优先 A，退 AAAA） */
export async function dohResolve(host) {
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

/** 反查：只用已确认可用的端点，失败就放弃（附加信息，不做多端点回退） */
export async function dohReverse(ip) {
  if (!isIP(ip)) return null;
  const qname = reverseName(ip);
  if (!qname) return null;
  try {
    const ep = await getEndpoint();
    const r = await dohQuery(qname, 'PTR', ep, 2500);
    const hit = r.answer.find((a) => a.type === 12);
    return hit ? stripDot(hit.data) : null;
  } catch (_) {
    return null;
  }
}
