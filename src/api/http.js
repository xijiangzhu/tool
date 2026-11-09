/* HTTP 调试：平台只负责发单次请求，重定向、编码与结果结构这里统一处理。 */
import { platform } from '../platform/index.js';
import { clamp, isTextualType, isPrivateHost, toBase64 } from '../lib/util.js';

const MAX_BODY = 1024 * 1024; // 响应体上限 1MB，超出截断
const MAX_BINARY = 65536; // 二进制只回传前 64KB
const TOTAL_BUDGET = 45000; // 含全部重定向的总预算，避免 10 跳 × 60s 把请求拖到平台超时
const REDIRECT_CODES = [301, 302, 303, 307, 308];
const BODY_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

/** 由运行时接管的请求头，用户传了也会被忽略 */
const DROP_HEADERS = /^(host|content-length|connection|accept-encoding|cf-|x-forwarded-)/i;

function sanitizeHeaders(raw) {
  const out = {};
  for (const [k, v] of Object.entries(raw || {})) {
    if (!k || DROP_HEADERS.test(k)) continue;
    out[k] = String(v);
  }
  return out;
}

const headerOf = (headers, name) => {
  const hit = Object.keys(headers).find((k) => k.toLowerCase() === name);
  return hit ? headers[hit] : null;
};

export default async function httpProxy(input) {
  const p = await platform();

  let target;
  try {
    target = new URL(String(input.url || '').trim());
  } catch (_) {
    return { ok: false, error: 'URL 格式不合法，请填写完整地址（含 http:// 或 https://）' };
  }
  if (!/^https?:$/.test(target.protocol)) {
    return { ok: false, error: '仅支持 http / https 协议' };
  }

  const method0 = String(input.method || 'GET').toUpperCase();
  const timeoutMs = clamp(Number(input.timeout) || 15000, 1000, 60000);
  const maxRedirects = input.followRedirects === false ? 0 : 10;
  const bodyStr = input.body == null ? '' : String(input.body);
  const headers = sanitizeHeaders(input.headers);

  const redirects = [];
  let currentUrl = target;
  let method = method0;
  let hops = 0;
  const startAll = Date.now();

  try {
    for (;;) {
      const remaining = TOTAL_BUDGET - (Date.now() - startAll);
      if (remaining < 1000) throw new Error('总耗时超出预算');
      const res = await p.httpSend({
        url: currentUrl.toString(),
        method,
        headers,
        body: BODY_METHODS.includes(method) ? bodyStr : '',
        timeoutMs: Math.min(timeoutMs, remaining), // 最后一跳不能突破总预算
        maxBytes: MAX_BODY, // 到 1MB 即断流，避免平台层无限缓冲整个响应
      });

      const loc = headerOf(res.headers, 'location');
      if (REDIRECT_CODES.includes(res.status) && loc && hops < maxRedirects) {
        hops++;
        redirects.push({ url: currentUrl.toString(), status: res.status, location: loc });
        let next;
        try {
          next = new URL(loc, currentUrl);
        } catch (_) {
          return finish(res, { startAll, currentUrl, method, redirects, headers, bodyStr, input });
        }
        // 不能跟随到非 http(s) 协议：node 平台会把任何非 https 的 URL 用 http 模块发出，
        // gopher://127.0.0.1:6379/ 这类 Location 会变成打本机端口的普通 HTTP 请求。
        // 云端还要额外挡住重定向到内网 / 本机（Node 本地允许访问内网是既有设计）。
        const h = next.hostname.replace(/^\[|\]$/g, '');
        const unsafe = !/^https?:$/.test(next.protocol)
          ? `重定向到不支持的协议（${next.protocol}）`
          : p.limits.blockPrivateHost && (/^localhost$/i.test(h) || isPrivateHost(h))
            ? `重定向到本机 / 内网地址（${h}）`
            : null;
        if (unsafe) {
          return {
            ok: false,
            error: `${unsafe}，已停止跟随`,
            elapsed: Date.now() - startAll,
            redirects,
            finalUrl: currentUrl.toString(),
          };
        }
        currentUrl = next;
        // 301/302/303 之后方法降级为 GET（307/308 保留原方法），与常见客户端一致
        if (
          res.status === 303 ||
          ((res.status === 301 || res.status === 302) && method !== 'GET' && method !== 'HEAD')
        ) {
          method = 'GET';
        }
        continue;
      }

      return finish(res, { startAll, currentUrl, method, redirects, headers, bodyStr, input });
    }
  } catch (e) {
    return {
      ok: false,
      error: friendlyError(e, timeoutMs, p.name === 'workers'),
      elapsed: Date.now() - startAll,
      redirects,
      finalUrl: currentUrl.toString(),
    };
  }
}

function finish(res, ctx) {
  const { startAll, currentUrl, method, redirects, headers, bodyStr, input } = ctx;
  const bytes = res.bytes || new Uint8Array(0);
  // 平台层已按 MAX_BODY 断流时 bytes.length 恰好等于 MAX_BODY，须用平台层返回的 truncated 标记
  const truncated = res.truncated === true || bytes.length > MAX_BODY;
  const view = truncated ? bytes.subarray(0, MAX_BODY) : bytes;
  const ctype = headerOf(res.headers, 'content-type') || '';
  const textual = isTextualType(ctype) || view.length === 0;
  const binaryTruncated = !textual && view.length > MAX_BINARY;
  const body = textual
    ? new TextDecoder('utf-8', { fatal: false }).decode(view)
    : toBase64(view.subarray(0, MAX_BINARY));

  const t = res.timings || {};
  return {
    ok: true,
    status: res.status,
    statusText: res.statusText || '',
    httpVersion: res.httpVersion || null,
    headers: res.headers,
    size: view.length,
    truncated,
    binaryTruncated, // 二进制只回传前 64KB，前端需提示而不是当成完整内容
    contentType: ctype || null,
    isBase64: !textual,
    body,
    timings: { dns: t.dns ?? null, tcp: t.tcp ?? null, tls: t.tls ?? null, ttfb: t.ttfb ?? null, total: Date.now() - startAll },
    elapsed: Date.now() - startAll,
    redirects,
    finalUrl: currentUrl.toString(),
    request: { method, url: input.url, headers, body: bodyStr },
  };
}

function friendlyError(e, timeoutMs, onCloud) {
  const msg = String((e && e.message) || e);
  if (/timed out|TimeoutError|aborted|超时/i.test(msg)) return `请求超时（${timeoutMs}ms）`;
  if (onCloud && /private|localhost|disallowed|not allowed|cannot connect|connection refused/i.test(msg)) {
    return `请求失败：${msg}（云端无法访问内网 / 本机地址）`;
  }
  const code = e && e.code ? `${e.code} - ` : '';
  return `请求失败：${code}${msg}`;
}
