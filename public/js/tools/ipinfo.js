/* IP 地址查询：公网出口 / 任意 IP 归属地 */
import { h, esc, api, copy, remember, setBusy, formError } from '../ui.js';

const QUICK = [
  ['本机出口', ''],
  ['223.5.5.5', '223.5.5.5'],
  ['8.8.8.8', '8.8.8.8'],
  ['114.114.114.114', '114.114.114.114'],
];

function asnText(g) {
  if (!g) return '—';
  const num = /AS\d+/i.exec(g.as || '');
  const org = g.org || '';
  if (num) return org && org !== g.isp ? `${num[0]} · ${org}` : num[0];
  return g.org || g.as || '—';
}

function coordText(g) {
  if (!g || g.lat == null || g.lon == null) return '—';
  return `${g.lat}, ${g.lon}`;
}

/* 双栈网络下浏览器会优先用 IPv6 连到站点，服务端只能看到 IPv6 出口；
   这里由浏览器自己去问「只有 A 记录」的接口，拿到同一网络的 IPv4 出口地址。
   全部注册源都确认过只有 A 记录，且带 Access-Control-Allow-Origin，可被浏览器直连。 */
const V4_SOURCES = [
  { url: 'https://api-ipv4.ip.sb', json: false },
  { url: 'https://ipv4.icanhazip.com', json: false },
  { url: 'https://v4.ident.me', json: false },
];
const V4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const V4_CACHE_KEY = 'ops.ipv4';
const V4_CACHE_TTL = 10 * 60 * 1000;

/** 一段时间内复用上次检测到的 IPv4，避免网络双栈抖动导致地址一会儿 IPv4 一会儿 IPv6 */
function readCachedV4() {
  try {
    const raw = JSON.parse(sessionStorage.getItem(V4_CACHE_KEY) || 'null');
    if (!raw || !V4_RE.test(raw.ip || '')) return null;
    if (!raw.t || Date.now() - raw.t > V4_CACHE_TTL) return null;
    return raw.ip;
  } catch (_) {
    return null;
  }
}
function writeCachedV4(ip) {
  try {
    sessionStorage.setItem(V4_CACHE_KEY, JSON.stringify({ ip, t: Date.now() }));
  } catch (_) {}
}

/** 多源并发抢跑：谁先返回合法 IPv4 用谁，避免某个源在特定网络不可达时整体失败 */
async function detectIpv4(budget = 4000, force = false) {
  if (!force) {
    const cached = readCachedV4();
    if (cached) return cached;
  }
  const ctrls = [];
  const tasks = V4_SOURCES.map(async (s) => {
    const ctrl = new AbortController();
    ctrls.push(ctrl);
    const timer = setTimeout(() => ctrl.abort(), budget);
    try {
      const res = await fetch(s.url, { signal: ctrl.signal, cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = (await res.text()).trim();
      const v = s.json || text.startsWith('{') ? JSON.parse(text).ip || '' : text;
      if (!V4_RE.test(v)) throw new Error('not ipv4');
      return v;
    } finally {
      clearTimeout(timer);
    }
  });
  try {
    const v4 = await Promise.any(tasks);
    if (V4_RE.test(v4)) {
      writeCachedV4(v4);
      return v4;
    }
    return null;
  } catch (_) {
    return null;
  } finally {
    ctrls.forEach((c) => {
      try {
        c.abort();
      } catch (_) {}
    });
  }
}

/** 本机出口：先由浏览器自查 IPv4，服务端查询并行发起，全部就绪后一次性渲染，
 *  避免先显示 IPv6 再跳成 IPv4 的闪烁。
 *  @param {boolean} force 忽略会话缓存，强制重新探测 IPv4（用户点「刷新」时使用） */
async function myIpInfo(force = false) {
  const started = Date.now();
  const mineP = api('/api/net/ipinfo', { ip: '' });
  // 浏览器自查与服务端查询并行；服务端已经给出 IPv4 时无需等它
  const v4P = detectIpv4(4000, force);
  const mine = await mineP;
  if (!mine.ok) throw new Error(mine.error);
  let d = mine.data || {};
  const serverV6 = d.version === 'IPv6' ? d.ip : d.altV6 || null;
  if (d.ip && d.version === 'IPv4') return { ...d, altV6: serverV6 };
  const v4 = await v4P;
  if (v4 && (!d.ip || d.version !== 'IPv4')) {
    const r4 = await api('/api/net/ipinfo', { ip: v4 });
    d = r4.ok && r4.data
      ? { ...r4.data, altV6: serverV6 }
      : {
          // 二次查询失败时不能沿用 IPv6 的归属地 / PTR 等字段
          ip: v4,
          version: 'IPv4',
          scope: null,
          ptr: null,
          geo: null,
          elapsed: Date.now() - started,
          altV6: serverV6,
        };
  }
  return d;
}

export default {
  id: 'ipinfo',
  name: 'IP 地址查询',
  group: '网络工具',
  desc: '输入 IP / 域名查询归属地、运营商与反向解析，并可查看本机公网出口 IP',
  keywords: 'ip 查询 归属地 本机 出口 ip地址 运营商 asn whois',
  net: true,
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>IP 查询</div>
          <div class="card-note">支持 IPv4 / IPv6 / 域名；本机出口见下方「我的 IP 信息」</div>
        </div>
        <div class="card-body">
          <div class="ipq-search">
            <svg class="ipq-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20.5 20.5l-3.9-3.9"/></svg>
            <input type="text" id="q" class="mono" placeholder="输入 IP 或域名，如 223.5.5.5" />
            <button class="btn btn-primary" id="go">查询</button>
          </div>
          <div class="chips mt10" id="quick">
            ${QUICK.map(([n, v]) => `<span class="chip" data-v="${esc(v)}">${esc(n)}</span>`).join('')}
          </div>
          <div id="out" class="mt12">
            <div class="empty">输入 IP / 域名后点击「查询」</div>
          </div>
        </div>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>我的 IP 信息</div>
          <div class="row">
            <span class="card-note">你的公网出口 IP</span>
            <button class="btn btn-sm btn-ghost" id="reload" title="重新检测公网出口">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M20.5 12a8.5 8.5 0 1 1-2.6-6.1"/><path d="M20.5 4v5.4h-5.4"/></svg>
              刷新
            </button>
          </div>
        </div>
        <div class="card-body">
          <div id="pubOut">
            <div class="empty">正在检测本机公网出口…</div>
          </div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const qEl = remember(wrap.querySelector('#q'), 'ipinfo.ip');
    const qErr = formError(wrap.querySelector('.ipq-search'), wrap.querySelector('.ipq-search'));
    const goBtn = wrap.querySelector('#go');
    const outEl = wrap.querySelector('#out');
    const pubOutEl = wrap.querySelector('#pubOut');
    const reloadBtn = wrap.querySelector('#reload');

    /** 两张卡片共用的键值网格 */
    function kvGrid(rows) {
      return `<div class="ip-kv ipq-kv">${rows
        .map(
          ([k, v]) =>
            `<div class="ip-kv-item"><div class="ip-kv-label">${esc(k)}</div><div class="ip-kv-value mono" title="${esc(
              v
            )}">${esc(v)}</div></div>`
        )
        .join('')}</div>`;
    }

    /** 复制按钮行：复制 IP / 复制详情 */
    function copyRow(el, d, rows) {
      const row = h(`<div class="btn-row mt12">
          <button class="btn btn-sm" data-act="ip">复制 IP</button>
          <button class="btn btn-sm btn-ghost" data-act="all">复制详情</button>
        </div>`);
      el.appendChild(row);
      row.querySelector('[data-act="ip"]').addEventListener('click', () => copy(d.ip || ''));
      row.querySelector('[data-act="all"]').addEventListener('click', () =>
        copy(
          [
            `IP：${d.ip || ''}${d.from ? `（来自 ${d.from}）` : ''}`,
            ...rows.map(([k, v]) => `${k}：${v}`),
          ].join('\n'),
          '已复制查询详情'
        )
      );
    }

    /** 「我的 IP 信息」卡片：与上方 IP 查询结果同一套版式 */
    function renderPublic(d) {
      const g = d.geo;
      if (!d.ip) {
        pubOutEl.innerHTML = '<div class="empty">未检测到公网出口 IP</div>';
        return;
      }
      const loc = g ? [g.country, g.region, g.city].filter(Boolean).join(' · ') : '';
      const rows = [
        ['归属地', loc || '—'],
        ['运营商', (g && g.isp) || '—'],
        ['ASN / 组织', asnText(g)],
        ['时区', (g && g.timezone) || '—'],
        ['经纬度', coordText(g)],
        ['反向解析', d.ptr || '—'],
        ['IP 类型', d.scope ? d.scope.label : '—'],
      ];
      if (d.altV6) rows.push(['IPv6 出口', d.altV6]);
      let meta = `${(g && g.provider) || '归属地信息不可用'} · ${d.elapsed} ms`;
      if (d.altV6) meta += ' · 已优先显示 IPv4';
      else if (d.version === 'IPv6') meta += ' · 未取到 IPv4 出口，可点刷新重试';
      const badge = d.scope && d.scope.kind === 'public' ? 'ok' : 'warn';
      pubOutEl.innerHTML = `
        <div class="ipq-head">
          <span class="ipq-ip mono">${esc(d.ip)}</span>
          <span class="badge ${badge}">${esc(d.scope ? d.scope.label : '未知')}</span>
          <span class="muted">${esc(loc)}</span>
          <span class="spacer"></span>
          <span class="muted">${esc(meta)}</span>
        </div>` + kvGrid(rows);
    }

    async function loadMine(force = false) {
      reloadBtn.disabled = true;
      reloadBtn.classList.add('is-busy');
      try {
        renderPublic(await myIpInfo(force));
      } catch (e) {
        pubOutEl.innerHTML = `<div class="alert err">${esc(e.message)}</div>`;
      } finally {
        reloadBtn.disabled = false;
        reloadBtn.classList.remove('is-busy');
      }
    }

    reloadBtn.addEventListener('click', () => loadMine(true));

    /* ------------------------------- IP 查询 ------------------------------- */
    function renderIp(d) {
      const g = d.geo || null;
      const loc = g ? [g.country, g.region, g.city].filter(Boolean).join(' · ') : '';
      const kv = [
        ['归属地', loc || '—'],
        ['运营商', (g && g.isp) || '—'],
        ['ASN / 组织', asnText(g)],
        ['时区', (g && g.timezone) || '—'],
        ['经纬度', coordText(g)],
        ['反向解析', d.ptr || '—'],
        ['IP 类型', d.scope ? d.scope.label : '—'],
      ];
      if (d.version === 'IPv6') kv.push(['地址类型', 'IPv6']);
      const badge = d.scope && d.scope.kind === 'public' ? 'ok' : 'warn';
      const head = `
        <div class="ipq-head">
          <span class="ipq-ip mono">${esc(d.ip || '未知')}</span>
          <span class="badge ${badge}">${esc(d.scope ? d.scope.label : '未知')}</span>
          <span class="muted">${esc(d.from ? `来自域名 ${d.from}` : loc || '')}</span>
          ${d.altV6 ? `<span class="muted">IPv6 出口 ${esc(d.altV6)}</span>` : ''}
          <span class="spacer"></span>
          <span class="muted">${esc((g && g.provider) || '归属地信息不可用')} · ${d.elapsed} ms</span>
        </div>`;
      const extra =
        !g && d.scope && d.scope.kind !== 'public'
          ? '<div class="hint">该地址属于内网 / 保留网段，没有公网归属地信息。</div>'
          : '';
      outEl.innerHTML = head + kvGrid(kv) + extra;
    }

    let running = false;

    /** 在查询结果区展示本机出口（快捷入口「本机出口」使用） */
    async function runMine() {
      if (running) return;
      running = true;
      qErr.clear();
      setBusy(goBtn, true, '查询中');
      outEl.innerHTML = '<div class="empty">正在检测本机出口…</div>';
      try {
        renderIp(await myIpInfo());
      } catch (e) {
        outEl.innerHTML = `<div class="alert err">${esc(e.message)}</div>`;
      } finally {
        running = false;
        setBusy(goBtn, false);
      }
    }

    async function run() {
      const q = qEl.value.trim();
      if (!q) return qErr.show('请输入要查询的 IP 或域名');
      if (running) return;
      qErr.clear();
      running = true;
      setBusy(goBtn, true, '查询中');
      outEl.innerHTML = '<div class="empty">正在查询…</div>';
      try {
        const r = await api('/api/net/ipinfo', { ip: q });
        if (!r.ok) throw new Error(r.error);
        renderIp(r.data);
      } catch (e) {
        outEl.innerHTML = `<div class="alert err">${esc(e.message)}</div>`;
      } finally {
        running = false;
        setBusy(goBtn, false);
      }
    }

    goBtn.addEventListener('click', run);
    qEl.addEventListener('keydown', (e) => e.key === 'Enter' && run());
    wrap.querySelectorAll('#quick .chip').forEach((c) =>
      c.addEventListener('click', () => {
        // 「本机出口」没有具体查询值，直接复用本机检测，不再走空查询
        if (c.dataset.v === '') {
          qEl.value = '';
          runMine();
          return;
        }
        qEl.value = c.dataset.v;
        run();
      })
    );

    loadMine();
  },
};
