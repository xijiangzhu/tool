/* DoH（DNS over HTTPS）查询封装：Workers 里没有 53 端口原生 DNS，统一走 JSON API */

/** 候选公共 DoH（均支持 application/dns-json）。
    默认按顺序探测，用第一个能通的；结果按 isolate 缓存，避免每次请求都探测 */
export const CANDIDATES = [
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
};

export function pickEndpoint(server) {
  const s = String(server || '').trim();
  if (!s) return null;
  return DOH_SERVERS[s] || null;
}

let cached = null; // 已确认可用的端点
let probing = null; // 进行中的探测（并发请求共用一次探测）
const badUntil = new Map(); // 端点 → 屏蔽到期时间，避免每次请求都重试死掉的端点

const BAD_TTL = 5 * 60 * 1000;
const isBad = (ep) => (badUntil.get(ep.url) || 0) > Date.now();
const markBad = (ep) => badUntil.set(ep.url, Date.now() + BAD_TTL);

const STATUS_TEXT = {
  1: 'DNS 报文格式错误（FORMERR）',
  2: 'DNS 服务器返回失败（SERVFAIL）',
  3: '记录不存在（NXDOMAIN）',
  4: '查询类型不支持（NOTIMP）',
  5: 'DNS 服务器拒绝查询（REFUSED）',
};

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
    authority: Array.isArray(data.Authority) ? data.Authority : [],
  };
}

/** 选一个可用的 DoH 端点（首次成功后缓存） */
export async function getEndpoint(force = false) {
  if (cached && !force) return cached;
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

/**
 * 执行一次 DoH 查询
 * @param endpoint 不传则自动选一个可用的公共 DoH
 */
export async function dohQuery(name, type, endpoint = null, ms = 6000) {
  // 指定了服务器就只用它；否则先用缓存的端点，失败再依次换下一个候选
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

export const TYPE_NUM = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, CAA: 257,
};

/** TXT 记录的数据是若干带引号的片段，拼回原文 */
export function parseTxt(data) {
  const parts = String(data || '').match(/"((?:[^"\\]|\\.)*)"/g);
  if (parts) return parts.map((s) => s.slice(1, -1).replace(/\\"/g, '"')).join('');
  return String(data || '').replace(/^"|"$/g, '');
}

export const stripDot = (s) => String(s || '').replace(/\.$/, '');
