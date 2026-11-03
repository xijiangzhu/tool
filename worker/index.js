/* Cloudflare Worker 入口：
   /api/* 交给各工具的处理函数，其余请求由静态资源绑定（public/）直接返回 */
import { json } from './lib/util.js';
import dns from './api/dns.js';
import httpProxy from './api/http.js';
import ssl from './api/ssl.js';
import portscan from './api/portscan.js';
import { ipinfo, localip } from './api/ipinfo.js';

const ROUTES = {
  '/api/ssl': ssl,
  '/api/http': httpProxy,
  '/api/net/dns': dns,
  '/api/net/portscan': portscan,
  '/api/net/ipinfo': ipinfo,
  '/api/net/localip': localip,
};

/** 与 Node 版一致：HTTP 调试直接返回原始对象（自带 ok 字段），其余包一层 { ok, data } */
const RAW = new Set(['/api/http']);

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: CORS });
      }
      const handler = ROUTES[url.pathname];
      if (!handler) return json({ ok: false, error: '未知接口' }, 404);
      if (request.method !== 'POST') return json({ ok: false, error: '仅支持 POST' }, 405);

      let input = {};
      try {
        input = (await request.json()) || {};
      } catch (_) {
        input = {};
      }
      try {
        const data = await handler(input, { request, env, ctx });
        return json(RAW.has(url.pathname) ? data : { ok: true, data });
      } catch (e) {
        return json({ ok: false, error: (e && e.message) || String(e) });
      }
    }

    return env.ASSETS.fetch(request);
  },
};
