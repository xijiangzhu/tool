/**
 * 运维工具箱 - 唯一入口
 *
 * 同一份代码同时跑在两种运行时：
 *   - Cloudflare Workers：导出 { fetch }，静态资源走 ASSETS 绑定
 *   - Node：直接 `node src/index.js` 时自建 HTTP 服务，静态资源读 public/
 *
 * 差异全部收在 src/platform/ 里，这里只做路由与错误包装。
 */
import dns from './api/dns.js';
import httpProxy from './api/http.js';
import { ipinfo } from './api/ipinfo.js';
import portscan from './api/portscan.js';
import ssl from './api/ssl.js';
import { json, readJson, textResponse } from './lib/util.js';
import { isWorkers, platform } from './platform/index.js';

/** 路由表：wrap=false 的接口自带 ok 字段，不再二次包装 */
const ROUTES = {
  '/api/ssl': { fn: ssl, wrap: true },
  '/api/http': { fn: httpProxy, wrap: false },
  '/api/net/dns': { fn: dns, wrap: true },
  '/api/net/portscan': { fn: portscan, wrap: true },
  '/api/net/ipinfo': { fn: ipinfo, wrap: true },
};

function pathOf(request) {
  const { pathname } = new URL(request.url);
  try {
    return decodeURIComponent(pathname);
  } catch (_) {
    return pathname;
  }
}

/** Web 标准请求处理：Workers 与 Node 共用 */
export async function handle(request, env = {}, ctx = {}) {
  const pathname = pathOf(request);

  if (pathname === '/api/health') {
    return json({ ok: true, runtime: isWorkers ? 'workers' : 'node', time: new Date().toISOString() });
  }

  if (pathname.startsWith('/api/')) {
    // 仅允许同源页面调用：避免任意网站借浏览器访问本机 / 云端转发接口。
    // Sec-Fetch-Site 由浏览器设置、页面无法伪造，可兜住「伪造 Host 头绕过同源比较」；
    // curl / 脚本调用不带这个头，保持可用（非浏览器请求本身不构成 CSRF）。
    const fetchSite = request.headers.get('sec-fetch-site');
    if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
      return json({ ok: false, error: '不允许跨站调用接口' }, 403);
    }
    const origin = request.headers.get('origin');
    if (origin) {
      let sameOrigin = false;
      try {
        const url = new URL(request.url);
        const host = (request.headers.get('host') || url.host).toLowerCase();
        sameOrigin = new URL(origin).host.toLowerCase() === host;
      } catch (_) {}
      if (!sameOrigin) return json({ ok: false, error: '不允许跨源调用接口' }, 403);
    }

    if (request.method === 'OPTIONS') return new Response(null, { status: 204 });

    const route = ROUTES[pathname];
    if (!route) return json({ ok: false, error: '未知接口' }, 404);
    if (request.method !== 'POST') return json({ ok: false, error: '仅支持 POST' }, 405);

    try {
      const input = await readJson(request);
      const data = await route.fn(input, { request, env, ctx });
      return json(route.wrap ? { ok: true, data } : data);
    } catch (e) {
      // 参数 / 请求体问题（HttpError）返回 4xx，真正的内部异常才返回 500
      const s = Number(e && e.status);
      const status = s >= 400 && s < 600 ? s : 500;
      return json({ ok: false, error: (e && e.message) || String(e) }, status);
    }
  }

  const p = await platform();
  const asset = await p.serveStatic(request, env);
  if (asset) return asset;
  return textResponse('404 Not Found', 404);
}

/* ------------------------------ Workers 入口 ------------------------------ */

export default { fetch: handle };

/* -------------------------------- Node 入口 ------------------------------- */

/** 判断当前模块是否被直接执行（`node src/index.js`），被 import 时不启动服务 */
function isEntryModule() {
  if (typeof import.meta.main === 'boolean') return import.meta.main;
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    const self = decodeURIComponent(new URL(import.meta.url).pathname).replace(/^\/([A-Za-z]:)/, '$1');
    return self === entry.replace(/\\/g, '/');
  } catch (_) {
    return false;
  }
}

/** 把 Node 的 http 请求转成 Web Request，响应再写回 —— 与 Workers 走完全相同的处理链 */
async function startServer() {
  const http = (await import('node:' + 'http')).default;
  const port = Number(process.env.PORT || 3000);
  const host = process.env.HOST || '127.0.0.1';

  const server = http.createServer(async (req, res) => {
    req.on('error', () => {}); // 超限/客户端中断销毁请求流时避免未处理 error 事件
    try {
      // 请求体累计上限 5MB（与 util.js readJson 的 MAX_BODY 一致），超限提前断流并返回 413
      const MAX_REQ_BYTES = 5 * 1024 * 1024;
      const chunks = [];
      let total = 0;
      let tooLarge = false;
      for await (const chunk of req) {
        total += chunk.length;
        if (total > MAX_REQ_BYTES) {
          tooLarge = true;
          break;
        }
        chunks.push(chunk);
      }
      if (tooLarge) {
        req.destroy();
        // 与 handle() 的 JSON 错误格式一致，前端 api() 才能正常解析并提示
        res.writeHead(413, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ ok: false, error: '请求体过大（上限 5MB）' }));
        return;
      }
      const raw = chunks.length ? Buffer.concat(chunks) : undefined;

      const url = `http://${req.headers.host || `localhost:${port}`}${req.url}`;
      const hasBody = !['GET', 'HEAD'].includes(req.method) && raw && raw.length > 0;
      const request = new Request(url, {
        method: req.method,
        headers: req.headers,
        body: hasBody ? raw : undefined,
      });

      const response = await handle(request, {}, {});
      const headers = {};
      response.headers.forEach((v, k) => (headers[k] = v));
      const body = Buffer.from(await response.arrayBuffer());
      res.writeHead(response.status, headers);
      res.end(body);
    } catch (e) {
      res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`500 ${(e && e.message) || 'Internal Error'}`);
    }
  });

  server.listen(port, host, () => {
    console.log(`\n  运维工具箱已启动:  http://${host}:${port}\n`);
  });
  return server;
}

if (!isWorkers && isEntryModule()) startServer();
