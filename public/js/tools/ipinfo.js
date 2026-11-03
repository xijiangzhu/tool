/* IP 地址查询：本机网卡 / 公网出口 / 任意 IP 归属地 */
import { h, esc, api, copy, remember, setBusy } from '../ui.js';

const QUICK = [
  ['本机出口', ''],
  ['223.5.5.5', '223.5.5.5'],
  ['8.8.8.8', '8.8.8.8'],
  ['114.114.114.114', '114.114.114.114'],
];

const BADGE = { public: 'ok', private: 'info', cgnat: 'info', linklocal: 'mute', loopback: 'mute' };

/* 系统代号转成常见叫法，如 win32 10.0.19045 → Windows 10.0.19045 */
const OS_NAME = { win32: 'Windows', darwin: 'macOS', linux: 'Linux', freebsd: 'FreeBSD' };

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
   这里由浏览器自己去问一个「只有 A 记录」的接口，拿到同一网络的 IPv4 出口地址。 */
const V4_SOURCES = [
  { url: 'https://v4.ident.me', json: false },
  { url: 'https://ipv4.icanhazip.com', json: false },
  { url: 'https://api.ipify.org?format=json', json: true },
];
const V4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

async function detectIpv4(budget = 3200) {
  const deadline = Date.now() + budget;
  for (const s of V4_SOURCES) {
    const left = deadline - Date.now();
    if (left <= 200) break;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), Math.min(1600, left));
    try {
      const res = await fetch(s.url, { signal: ctrl.signal, cache: 'no-store' });
      if (!res.ok) continue;
      const text = (await res.text()).trim();
      const v = s.json ? (JSON.parse(text).ip || '') : text;
      if (V4_RE.test(v)) return v;
    } catch (_) {
      /* 换下一个来源 */
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

/** 出口是 IPv6 时补一次 IPv4 查询：拿到就用 IPv4 作为主显示，IPv6 收进副行 */
async function preferIpv4(d) {
  if (!d || d.version !== 'IPv6' || !d.ip) return d;
  const v4 = await detectIpv4();
  if (!v4 || v4 === d.ip) return d;
  const r = await api('/api/net/ipinfo', { ip: v4 });
  if (!r || !r.ok || !r.data || r.data.version !== 'IPv4') return d;
  return { ...r.data, altV6: d.ip };
}

export default {
  id: 'ipinfo',
  name: 'IP 地址查询',
  group: '网络工具',
  desc: '输入 IP / 域名查询归属地、运营商与反向解析，并可查看本机网卡与公网出口 IP',
  keywords: 'ip 查询 归属地 本机 出口 ip地址 运营商 asn whois',
  net: true,
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>IP 查询</div>
          <div class="card-note">支持 IPv4 / IPv6 / 域名，留空则查询本机出口 IP</div>
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
            <span class="card-note" id="myipNote">公网出口与本机内网地址</span>
            <button class="btn btn-sm btn-ghost" id="reload" title="重新读取本机信息">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M20.5 12a8.5 8.5 0 1 1-2.6-6.1"/><path d="M20.5 4v5.4h-5.4"/></svg>
              刷新
            </button>
          </div>
        </div>
        <div class="card-body">
          <div class="myip-hero">
            <div class="myip-item">
              <div class="myip-label">公网出口 IP<span class="badge ok" id="pubBadge">公网地址</span></div>
              <div class="myip-ip mono" id="pubIp">检测中…</div>
              <div class="myip-sub" id="pubWhere">—</div>
              <div class="myip-sub dim" id="pubMeta"></div>
            </div>
            <div class="myip-item" id="lanCell">
              <div class="myip-label">本机内网 IP<span class="badge info" id="lanBadge">—</span></div>
              <div class="myip-ip mono" id="lanIp">—</div>
              <div class="myip-sub" id="lanSub">—</div>
            </div>
          </div>

          <div class="myip-facts">
            <span><i id="kHost">主机名</i><b class="mono" id="stHost">—</b></span>
            <span><i id="kOs">系统</i><b class="mono" id="stOs">—</b></span>
            <span><i id="kCount">地址数</i><b class="mono" id="stCount">—</b></span>
          </div>

          <ul class="myip-list" id="ifList">
            <li class="myip-row muted">读取中…</li>
          </ul>
          <div class="note mt8" id="ifNote" hidden></div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const qEl = remember(wrap.querySelector('#q'), 'ipinfo.ip');
    const goBtn = wrap.querySelector('#go');
    const outEl = wrap.querySelector('#out');
    const pubIpEl = wrap.querySelector('#pubIp');
    const pubBadgeEl = wrap.querySelector('#pubBadge');
    const pubWhereEl = wrap.querySelector('#pubWhere');
    const pubMetaEl = wrap.querySelector('#pubMeta');
    const lanIpEl = wrap.querySelector('#lanIp');
    const lanBadgeEl = wrap.querySelector('#lanBadge');
    const lanSubEl = wrap.querySelector('#lanSub');
    const ifList = wrap.querySelector('#ifList');
    const ifNote = wrap.querySelector('#ifNote');
    const lanCell = wrap.querySelector('#lanCell');
    const hero = wrap.querySelector('.myip-hero');
    const kHost = wrap.querySelector('#kHost');
    const kOs = wrap.querySelector('#kOs');
    const kCount = wrap.querySelector('#kCount');
    const stHost = wrap.querySelector('#stHost');
    const stOs = wrap.querySelector('#stOs');
    const stCount = wrap.querySelector('#stCount');
    const reloadBtn = wrap.querySelector('#reload');
    const myipNote = wrap.querySelector('#myipNote');

    /* --------------------------- 本机网卡 / 出口 IP --------------------------- */
    /** 取 CIDR 的掩码后缀，如 192.168.20.66/24 → /24 */
    function maskOf(x) {
      const bits = x.cidr && x.cidr.split('/')[1];
      return bits ? `/${bits}` : '';
    }

    function renderInterfaces(d) {
      const all = d.interfaces || [];
      // 云端运行（Cloudflare Workers）读不到本机网卡：保留两栏版式，内网一侧写明原因
      if (d.runtime === 'workers' || (d.platform === 'cloudflare' && !all.length)) {
        lanCell.hidden = false;
        hero.classList.remove('single');
        lanIpEl.textContent = '不可读取';
        lanIpEl.style.fontSize = '16px';
        lanIpEl.style.color = 'var(--muted)';
        lanBadgeEl.className = 'badge mute';
        lanBadgeEl.textContent = '云端限制';
        lanSubEl.textContent = '边缘节点位于你的局域网之外';
        kHost.textContent = '运行环境';
        kOs.textContent = '边缘节点';
        kCount.textContent = '本机网卡';
        stHost.textContent = 'Cloudflare Workers';
        stOs.textContent = d.colo || '—';
        stCount.textContent = '不可读取';
        stCount.classList.remove('mono');
        ifList.hidden = true;
        ifNote.hidden = false;
        ifNote.textContent =
          '线上只能拿到你的公网出口 IP：Worker 跑在 Cloudflare 边缘节点，读到的是节点网卡；浏览器也会用 mDNS 屏蔽局域网地址。需要查看本机内网 IP，请在本地运行 npm start 后访问 localhost。';
        myipNote.textContent = '公网出口 IP · 云端运行环境';
        return;
      }
      lanCell.hidden = false;
      ifList.hidden = false;
      hero.classList.remove('single');
      lanIpEl.style.fontSize = '';
      lanIpEl.style.color = '';
      myipNote.textContent = '公网出口与本机内网地址';
      kHost.textContent = '主机名';
      kOs.textContent = '系统';
      kCount.textContent = '地址数';
      stCount.classList.add('mono');
      stHost.textContent = d.hostname || '—';
      stOs.textContent =
        `${OS_NAME[d.platform] || d.platform || ''} ${d.release || ''}`.trim() || '—';


      const list = all.filter((x) => !x.internal);
      const shown = list.length ? list : all;
      stCount.textContent = `${shown.length} 个`;

      // 主内网地址：优先私有 / CGNAT 的 IPv4
      const v4 = shown.filter((x) => x.family === 'IPv4');
      const main =
        v4.find((x) => x.scope.kind === 'private' || x.scope.kind === 'cgnat') || v4[0] || shown[0] || null;
      if (main) {
        lanIpEl.textContent = main.address;
        lanBadgeEl.className = `badge ${BADGE[main.scope.kind] || 'warn'}`;
        lanBadgeEl.textContent = main.scope.label;
        lanSubEl.textContent = `${main.name} · ${main.family}`;
      } else {
        lanIpEl.textContent = '未读取到';
        lanBadgeEl.className = 'badge mute';
        lanBadgeEl.textContent = '无地址';
        lanSubEl.textContent = '—';
      }

      if (!shown.length) {
        ifList.innerHTML = '<li class="myip-row muted">未读取到网卡地址</li>';
        ifNote.hidden = true;
        return;
      }
      ifList.innerHTML = shown
        .map(
          (x) => `<li class="myip-row" data-addr="${esc(x.address)}" title="点击复制 ${esc(x.address)}">
            <span class="myip-ifname">${esc(x.name)}</span>
            <span class="myip-addr mono">${esc(x.address)}<em>${esc(maskOf(x))}</em></span>
            <span class="badge ${BADGE[x.scope.kind] || 'warn'}">${esc(x.scope.label)}</span>
          </li>`
        )
        .join('');
      ifList.querySelectorAll('.myip-row[data-addr]').forEach((li) =>
        li.addEventListener('click', () => copy(li.dataset.addr))
      );

      const hidden = all.length - shown.length;
      ifNote.hidden = !hidden;
      ifNote.textContent = hidden ? `已隐藏 ${hidden} 个本机环回地址` : '';
    }

    function renderPublic(d) {
      const g = d.geo;
      if (!d.ip) {
        pubIpEl.textContent = '未检测到';
        pubBadgeEl.className = 'badge warn';
        pubBadgeEl.textContent = '出口未知';
        pubWhereEl.textContent = '';
        pubMetaEl.textContent = '';
        return;
      }
      pubIpEl.textContent = d.ip;
      pubBadgeEl.className = 'badge ok';
      pubBadgeEl.textContent = d.altV6 ? 'IPv4' : d.scope ? d.scope.label : '公网地址';
      pubWhereEl.textContent = g ? [g.country, g.region, g.city].filter(Boolean).join(' · ') : '';
      const meta = `${(g && g.provider) || '归属地信息不可用'} · ${d.elapsed} ms`;
      pubMetaEl.textContent = d.altV6 ? `${meta} · IPv6 出口 ${d.altV6}（已优先显示 IPv4）` : meta;
    }

    async function loadLocal() {
      reloadBtn.disabled = true;
      reloadBtn.classList.add('is-busy');
      // 两个请求互不等待：网卡信息通常毫秒级返回，公网归属地要走第三方接口
      const localTask = api('/api/net/localip', {})
        .then((r) => {
          if (r.ok) renderInterfaces(r.data);
          else ifList.innerHTML = `<li class="myip-row muted">${esc(r.error)}</li>`;
        })
        .catch((e) => {
          ifList.innerHTML = `<li class="myip-row muted">${esc(e.message)}</li>`;
        });
      const pubTask = api('/api/net/ipinfo', { ip: '' })
        .then(async (r) => {
          if (!r.ok) throw new Error(r.error);
          const d = r.data;
          renderPublic(d);
          // 双栈网络下服务端先看到 IPv6：浏览器再自查一次 IPv4 出口并升级显示
          if (d && d.version === 'IPv6') {
            pubMetaEl.textContent = 'IPv6 出口，正在查找同一网络的 IPv4…';
            const better = await preferIpv4(d);
            if (better !== d) renderPublic(better);
            else if (pubMetaEl.textContent.startsWith('IPv6 出口')) renderPublic(d);
          }
        })
        .catch((e) => {
          pubIpEl.textContent = '—';
          pubBadgeEl.className = 'badge warn';
          pubBadgeEl.textContent = '出口未知';
          pubWhereEl.textContent = '';
          pubMetaEl.textContent = e.message;
        });
      await Promise.allSettled([localTask, pubTask]);
      reloadBtn.disabled = false;
      reloadBtn.classList.remove('is-busy');
    }

    reloadBtn.addEventListener('click', loadLocal);

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
        [d.version === 'IPv4' ? '十进制' : '地址类型', d.decimal != null ? String(d.decimal) : d.version || '—'],
        ['IP 类型', d.scope ? d.scope.label : '—'],
      ];
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
      const grid = `<div class="ip-kv ipq-kv">${kv
        .map(
          ([k, v]) =>
            `<div class="ip-kv-item"><div class="ip-kv-label">${esc(k)}</div><div class="ip-kv-value mono" title="${esc(
              v
            )}">${esc(v)}</div></div>`
        )
        .join('')}</div>`;
      const extra =
        !g && d.scope && d.scope.kind !== 'public'
          ? '<div class="hint">该地址属于内网 / 保留网段，没有公网归属地信息。</div>'
          : '';
      const acts = `<div class="btn-row mt12">
          <button class="btn btn-sm" data-act="ip">复制 IP</button>
          <button class="btn btn-sm btn-ghost" data-act="all">复制详情</button>
        </div>`;
      outEl.innerHTML = head + grid + extra + acts;

      outEl.querySelector('[data-act="ip"]').addEventListener('click', () => copy(d.ip || ''));
      outEl.querySelector('[data-act="all"]').addEventListener('click', () =>
        copy(
          [
            `IP：${d.ip || ''}${d.from ? `（来自 ${d.from}）` : ''}`,
            ...kv.map(([k, v]) => `${k}：${v}`),
          ].join('\n'),
          '已复制查询详情'
        )
      );
    }

    let running = false;
    async function run() {
      if (running) return;
      running = true;
      setBusy(goBtn, true, '查询中');
      outEl.innerHTML = '<div class="empty">正在查询…</div>';
      try {
        const r = await api('/api/net/ipinfo', { ip: qEl.value.trim() });
        if (!r.ok) throw new Error(r.error);
        let d = r.data;
        // 「本机出口」留空查询同样优先 IPv4
        if (!qEl.value.trim()) d = await preferIpv4(d);
        renderIp(d);
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
        qEl.value = c.dataset.v;
        run();
      })
    );

    loadLocal();
  },
};
