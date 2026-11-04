/* SSL Labs API（api.ssllabs.com）：证书字段拿不到时的兜底数据源之一，
   用于补全「协议支持情况」与站点评级。只查缓存（最近 7 天内被 SSL Labs
   扫描过的域名秒回），不发起耗时十几秒的新扫描，避免拖垮单次请求。 */

const API = 'https://api.ssllabs.com/api/v3';

const UA = 'tool/1.0 (+https://github.com/xijiangzhu/tool)';

async function apiGet(params, timeoutMs = 10000) {
  const res = await fetch(`${API}/analyze?${params}`, {
    headers: { accept: 'application/json', 'user-agent': UA },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`SSL Labs HTTP ${res.status}`);
  return res.json();
}

/** 查缓存：最近扫描过的结果直接可用；maxAge 单位小时 */
async function cached(host, maxAge = 168, timeoutMs = 8000) {
  const r = await apiGet(
    `host=${encodeURIComponent(host)}&all=done&fromCache=on&maxAge=${maxAge}`,
    timeoutMs
  );
  return extract(r);
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
 * 取协议支持与评级（仅缓存命中时返回）。
 * 返回 null 表示没有拿到，由调用方决定是否降级。
 */
export async function ssllabsInfo(host, { timeoutMs = 8000 } = {}) {
  try {
    return await cached(host, 168, timeoutMs);
  } catch (_) {
    return null;
  }
}
