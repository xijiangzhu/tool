/* HTTP 调试 */
import { h, api, copy, toast, codeBox, esc, fmtBytes, remember, segGroup, setBusy } from '../ui.js';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

function statusCls(code) {
  if (code >= 500) return 'err';
  if (code >= 400) return 'warn';
  if (code >= 300) return 'info';
  if (code >= 200) return 'ok';
  return 'mute';
}

function timingsText(t) {
  const parts = [];
  if (t.dns != null) parts.push(`DNS ${t.dns}`);
  if (t.tcp != null) parts.push(`TCP ${t.tcp}`);
  if (t.tls != null) parts.push(`TLS ${t.tls}`);
  if (t.ttfb != null) parts.push(`TTFB ${t.ttfb}`);
  return parts.join(' · ') + (parts.length ? ' ms' : '');
}

export default {
  id: 'http',
  name: 'HTTP 调试',
  group: '网络工具',
  desc: '自定义方法、请求头与请求体发起请求，查看状态码、耗时与响应内容',
  keywords: 'http 请求 调试 api curl rest 接口',
  net: true,
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>请求</div>
          <div class="card-note">由服务端代理发出，无跨域限制</div>
        </div>
        <div class="card-body">
          <div class="http-url-row">
            <select id="method" class="w150">${METHODS.map((m) => `<option>${m}</option>`).join('')}</select>
            <input type="text" id="url" class="mono" placeholder="https://api.example.com/v1/health" />
            <button class="btn btn-primary" id="send">发送</button>
          </div>

          <div class="pane mt12">
            <div class="pane-head">
              <span class="pane-title">请求头</span>
              <span class="pane-note">逐行填写，留空的名称会被忽略</span>
              <span class="spacer"></span>
              <button class="btn btn-sm btn-ghost" id="addH">+ 添加</button>
            </div>
            <div class="pane-body" id="headers"></div>
          </div>

          <div class="pane mt12">
            <div class="pane-head">
              <span class="pane-title">请求体</span>
              <span class="pane-note">POST / PUT / PATCH / DELETE 时发送</span>
            </div>
            <div class="pane-body pane-body-flush" id="body"></div>
          </div>

          <div class="tool-bar mt12">
            <label class="inline-field">超时
              <input type="number" id="timeout" value="15000" min="1000" max="60000" step="1000" />
              <span>ms</span>
            </label>
            <label class="check"><input type="checkbox" id="follow" checked /> 跟随重定向</label>
            <span class="spacer"></span>
            <button class="btn" id="curl">复制 cURL</button>
            <button class="btn btn-ghost" id="clear">清空</button>
          </div>
        </div>
      </section>

      <div id="result"></div>
    `);
    root.appendChild(wrap);

    const bodyBox = codeBox({ title: 'Body', height: '104px', placeholder: '{"key":"value"} 或 a=1&b=2' });
    wrap.querySelector('#body').appendChild(bodyBox.el);

    const headersEl = wrap.querySelector('#headers');
    function addHeader(k = '', v = '') {
      const row = h(`
        <div class="kv-row">
          <input type="text" class="hk mono" placeholder="Header 名，如 Content-Type" value="${esc(k)}" />
          <input type="text" class="hv mono" placeholder="值，如 application/json" value="${esc(v)}" />
          <button class="btn btn-sm btn-ghost kv-del" title="删除">✕</button>
        </div>
      `);
      row.querySelector('.kv-del').addEventListener('click', () => row.remove());
      remember(row.querySelector('.hk'), 'http.header.name');
      headersEl.appendChild(row);
    }
    addHeader('Accept', '*/*');

    function collectHeaders() {
      const out = {};
      headersEl.querySelectorAll('.kv-row').forEach((r) => {
        const k = r.querySelector('.hk').value.trim();
        const v = r.querySelector('.hv').value.trim();
        if (k) out[k] = v;
      });
      return out;
    }
    function setHeaders(obj) {
      Object.entries(obj).forEach(([k, v]) => {
        const rows = [...headersEl.querySelectorAll('.kv-row')];
        const hit = rows.find((r) => r.querySelector('.hk').value.trim().toLowerCase() === k.toLowerCase());
        if (hit) hit.querySelector('.hv').value = v;
        else addHeader(k, v);
      });
    }

    wrap.querySelector('#addH').addEventListener('click', () => addHeader());

    const resultEl = wrap.querySelector('#result');
    const sendBtn = wrap.querySelector('#send');
    const urlEl = wrap.querySelector('#url');
    remember(urlEl, 'http.url');

    function currentReq() {
      return {
        method: wrap.querySelector('#method').value,
        url: urlEl.value.trim(),
        headers: collectHeaders(),
        body: bodyBox.getValue(),
        timeout: Number(wrap.querySelector('#timeout').value || 15000),
        followRedirects: wrap.querySelector('#follow').checked,
      };
    }

    function toCurl(req) {
      let s = `curl -X ${req.method} '${req.url}'`;
      Object.entries(req.headers).forEach(([k, v]) => {
        s += ` \\\n  -H '${k}: ${String(v).replace(/'/g, "'\\''")}'`;
      });
      if (req.body && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        s += ` \\\n  -d '${req.body.replace(/'/g, "'\\''")}'`;
      }
      if (req.followRedirects) s += ' \\\n  -L';
      s += ` \\\n  --max-time ${Math.round(req.timeout / 1000)}`;
      return s;
    }

    wrap.querySelector('#curl').addEventListener('click', () => copy(toCurl(currentReq()), '已复制 cURL'));
    wrap.querySelector('#clear').addEventListener('click', () => {
      urlEl.value = '';
      bodyBox.setValue('');
      headersEl.innerHTML = '';
      addHeader('Accept', '*/*');
      resultEl.innerHTML = '';
    });

    async function send() {
      const req = currentReq();
      if (!req.url) return toast('请输入 URL', 'err');
      if (!/^https?:\/\//i.test(req.url)) return toast('URL 需以 http:// 或 https:// 开头', 'err');
      setBusy(sendBtn, true, '请求中');
      resultEl.innerHTML = '<div class="card"><div class="card-body"><div class="empty">请求发送中…</div></div></div>';
      let res;
      try {
        res = await api('/api/http', req);
      } catch (e) {
        res = { ok: false, error: e.message };
      }
      setBusy(sendBtn, false);
      render(res, req);
    }

    sendBtn.addEventListener('click', send);
    urlEl.addEventListener('keydown', (e) => e.key === 'Enter' && send());

    function render(res, req) {
      if (!res.ok) {
        resultEl.innerHTML = `<div class="card"><div class="card-body"><div class="alert err">请求失败：${esc(res.error)}</div></div></div>`;
        return;
      }
      const cls = statusCls(res.status);
      const t = res.timings || {};
      const ctype = res.contentType || '';
      const isJson = /json/i.test(ctype);
      const redirects = res.redirects || [];

      resultEl.innerHTML = `
        <section class="card">
          <div class="card-head">
            <div class="card-title"><span class="dot"></span>响应</div>
            <div class="card-note mono">${esc(res.finalUrl)}</div>
          </div>
          <div class="card-body">
            <div class="http-metrics">
              <span class="badge ${cls} http-code">${res.status} ${esc(res.statusText || '')}</span>
              <span class="metric"><i>总耗时</i><b>${res.elapsed} ms</b></span>
              <span class="metric"><i>大小</i><b>${fmtBytes(res.size)}</b></span>
              <span class="metric"><i>协议</i><b>${res.httpVersion ? 'HTTP/' + esc(res.httpVersion) : '—'}</b></span>
              ${t.ttfb != null ? `<span class="metric"><i>分段</i><b class="fs12">${timingsText(t)}</b></span>` : ''}
              ${redirects.length ? `<span class="metric"><i>重定向</i><b>${redirects.length} 次</b></span>` : ''}
            </div>

            <div class="seg" id="rtab" style="margin:14px 0 12px">
              <button data-v="body" class="active">响应体</button>
              <button data-v="headers">响应头</button>
            </div>
            <div id="rpanel"></div>
          </div>
        </section>
      `;

      const panel = resultEl.querySelector('#rpanel');
      function showBody() {
        panel.innerHTML = '';
        let text = res.isBase64 ? `(二进制内容，共 ${fmtBytes(res.size)})` : res.body || '';
        if (isJson && !res.isBase64) {
          try {
            text = JSON.stringify(JSON.parse(text), null, 2);
          } catch (_) {}
        }
        const box = codeBox({
          lang: isJson ? 'json' : '',
          title: `响应体${ctype ? ' · ' + ctype.split(';')[0] : ''}`,
          height: '400px',
          placeholder: '（空响应）',
        });
        box.setValue(text);
        panel.appendChild(box.el);
        if (isJson) box.el.querySelector('[data-act="hl"]').click();
      }
      function showHeaders() {
        const rows = Object.entries(res.headers || {})
          .map(([k, v]) => `<tr><th style="width:260px">${esc(k)}</th><td class="mono">${esc(Array.isArray(v) ? v.join('\n') : v)}</td></tr>`)
          .join('');
        panel.innerHTML = `<table class="tbl zebra">${rows || '<tr><td class="muted">无响应头</td></tr>'}</table>`;
      }

      showBody();
      segGroup(resultEl.querySelector('#rtab'), (v) => {
        if (v === 'body') showBody();
        else showHeaders();
      });
    }
  },
};
