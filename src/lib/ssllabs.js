/* SSL Labs API（api.ssllabs.com）：云端拿不到 TLS 对端证书，这里的
   服务端扫描用于补全「协议支持情况」与站点评级（证书字段仍由 CT 日志提供）。
   先查缓存（最近扫描过的域名秒回），未命中再发起新扫描并轮询。 */

const API = 'https://api.ssllabs.com/api/v3';

async function apiGet(params, timeoutMs = 10000) {
  const res = await fetch(`${API}/analyze?${params}`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`SSL Labs HTTP ${res.status}`);
  return res.json();
}

/** 查缓存：最近扫描过的结果直接可用；maxAge 单位小时 */
async function cached(host, maxAge = 168) {
  const r = await apiGet(
    `host=${encodeURIComponent(host)}&all=done&fromCache=on&maxAge=${maxAge}`
  );
  return extract(r);
}

/** 发起新扫描并轮询到就绪或超时（预算用完返回 null，结果会被 SSL Labs 缓存，下次查询秒回） */
async function scan(host, budgetMs) {
  await apiGet(
    `host=${encodeURIComponent(host)}&all=done&startNew=on&ignoreMismatch=on`,
    15000
  );
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 4000));
    let r;
    try {
      r = await apiGet(`host=${encodeURIComponent(host)}&all=done`);
    } catch (_) {
      continue; // 单次轮询失败不中断
    }
    if (r.status === 'ERROR') throw new Error(`SSL Labs 扫描失败：${r.statusMessage || '未知原因'}`);
    const out = extract(r);
    if (out) return out;
  }
  return null;
}

/** 从 analyze 响应取协议支持与评级；尚无可用端点时返回 null */
function extract(r) {
  if (!r || !Array.isArray(r.endpoints)) return null;
  const ep = r.endpoints.find((e) => e.details && Array.isArray(e.details.protocols) && e.details.protocols.length);
  if (!ep) return null;
  const d = ep.details;

  /* SSL Labs 只列出服务端启用的协议（name=TLS, version=1.2 …），按版本顺序输出 */
  const enabled = new Set();
  (d.protocols || []).forEach((p) => {
    const v = String(p.version || '');
    if (/^1(\.[0-3])?$/.test(v)) enabled.add(`TLSv${v}`);
  });
  const protocols = {};
  for (const v of ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']) {
    protocols[v] = enabled.has(v);
  }

  return {
    protocols,
    grade: ep.grade || null,
    source: 'SSL Labs',
  };
}

/**
 * 取协议支持与评级：
 *   1. 先查缓存（最近 7 天内被扫描过的域名秒回）
 *   2. scanBudgetMs > 0 且缓存未命中 → 发起新扫描并轮询
 * 返回 null 表示没有拿到，由调用方决定是否降级。
 */
export async function ssllabsInfo(host, { scanBudgetMs = 0 } = {}) {
  try {
    const hit = await cached(host);
    if (hit) return hit;
  } catch (_) {
    /* 缓存查询失败继续 */
  }
  if (scanBudgetMs > 0) {
    try {
      return await scan(host, scanBudgetMs);
    } catch (_) {
      return null;
    }
  }
  return null;
}
