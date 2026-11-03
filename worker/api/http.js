/* HTTP 调试：用 fetch 代理请求（Workers 环境），返回结构与 Node 版对齐 */
import { clamp } from '../lib/util.js';

const TEXTUAL = /text|json|xml|javascript|urlencoded|graphql|html|csv|yaml/i;
const MAX_BODY = 1024 * 1024; // 1MB，超出截断

function headersToObject(h) {
  const out = {};
  h.forEach((v, k) => {
    out[k] = out[k] ? `${out[k]}, ${v}` : v;
  });
  return out;
}

export default async function httpProxy(input) {
  let target;
  try {
    target = new URL(String(input.url || '').trim());
  } catch (e) {
    return { ok: false, error: 'URL 格式不合法，请填写完整地址（含 http:// 或 https://）' };
  }
  if (!/^https?:$/.test(target.protocol)) {
    return { ok: false, error: '仅支持 http / https 协议' };
  }

  const method0 = String(input.method || 'GET').toUpperCase();
  const timeoutMs = clamp(Number(input.timeout) || 15000, 1000, 60000);
  const maxRedirects = input.followRedirects === false ? 0 : 10;
  const bodyStr = input.body == null ? '' : String(input.body);
  const reqHeaders = Object.assign({}, input.headers || {});
  // 这些请求头由运行时接管，传了会被忽略或报错
  for (const k of Object.keys(reqHeaders)) {
    if (/^(host|content-length|connection|cf-|x-forwarded-|accept-encoding)/i.test(k)) delete reqHeaders[k];
  }

  const redirects = [];
  let currentUrl = target;
  let method = method0;
  let hops = 0;
  const startAll = Date.now();

  const send = async (url, m, body) => {
    const t0 = Date.now();
    const init = {
      method: m,
      headers: reqHeaders,
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    };
    if (body && !['GET', 'HEAD'].includes(m)) init.body = body;
    const res = await fetch(url, init);
    return { res, ttfb: Date.now() - t0 };
  };

  try {
    for (;;) {
      const { res, ttfb } = await send(currentUrl, method, bodyStr);
      const loc = res.headers.get('location');
      const isRedirect = [301, 302, 303, 307, 308].includes(res.status);
      if (isRedirect && loc && hops < maxRedirects) {
        hops++;
        redirects.push({ url: currentUrl.toString(), status: res.status, location: loc });
        try {
          currentUrl = new URL(loc, currentUrl);
        } catch (_) {
          return finish(res, ttfb, startAll, currentUrl, method, redirects, reqHeaders, bodyStr, input);
        }
        if (res.status === 303 && method !== 'GET' && method !== 'HEAD') {
          method = 'GET';
        }
        await res.body?.cancel();
        continue;
      }
      return finish(res, ttfb, startAll, currentUrl, method, redirects, reqHeaders, bodyStr, input);
    }
  } catch (e) {
    const msg = String((e && e.message) || e);
    return {
      ok: false,
      error: friendlyError(msg, timeoutMs),
      elapsed: Date.now() - startAll,
      redirects,
      finalUrl: currentUrl.toString(),
    };
  }
}

async function finish(res, ttfb, startAll, finalUrl, method, redirects, reqHeaders, bodyStr, input) {
  const t0 = Date.now();
  let buf;
  try {
    buf = new Uint8Array(await res.arrayBuffer());
  } catch (_) {
    buf = new Uint8Array(0);
  }
  const total = Date.now() - startAll;
  const ctype = res.headers.get('content-type') || '';
  const truncated = buf.length > MAX_BODY;
  const view = truncated ? buf.slice(0, MAX_BODY) : buf;
  const textual = TEXTUAL.test(ctype) || view.length === 0;
  let body;
  if (textual) {
    body = new TextDecoder('utf-8', { fatal: false }).decode(view);
  } else {
    body = toBase64(view.subarray(0, 65536));
  }

  return {
    ok: true,
    status: res.status,
    statusText: res.statusText || '',
    httpVersion: res.headers.get('x-http-version') || null,
    headers: headersToObject(res.headers),
    size: view.length,
    truncated,
    contentType: ctype || null,
    isBase64: !textual,
    body,
    timings: { dns: null, tcp: null, tls: null, ttfb, total: Date.now() - t0 },
    elapsed: total,
    redirects,
    finalUrl: finalUrl.toString(),
    request: {
      method,
      url: input.url,
      headers: reqHeaders,
      body: bodyStr,
    },
  };
}

/** 二进制内容转 base64（分块，避免 fromCharCode 参数过多爆栈） */
function toBase64(bytes) {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function friendlyError(msg, timeoutMs) {
  if (/timed out|TimeoutError|The operation was aborted|aborted/i.test(msg)) {
    return `请求超时（${timeoutMs}ms）`;
  }
  if (/private|localhost|disallowed|not allowed|cannot connect|connection refused/i.test(msg)) {
    return `请求失败：${msg}（云端无法访问内网 / 本机地址）`;
  }
  return `请求失败：${msg}`;
}
