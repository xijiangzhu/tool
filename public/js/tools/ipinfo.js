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
            <span class="card-note">公网出口与本机内网地址</span>
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
            <div class="myip-item">
              <div class="myip-label">本机内网 IP<span class="badge info" id="lanBadge">—</span></div>
              <div class="myip-ip mono" id="lanIp">—</div>
              <div class="myip-sub" id="lanSub">—</div>
            </div>
          </div>

          <div class="myip-facts">
            <span><i>主机名</i><b class="mono" id="stHost">—</b></span>
            <span><i>系统</i><b class="mono" id="stOs">—</b></span>
            <span><i>地址数</i><b class="mono" id="stCount">—</b></span>
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
    const reloadBtn = wrap.querySelector('#reload');

    /* --------------------------- 本机网卡 / 出口 IP --------------------------- */
    /** 取 CIDR 的掩码后缀，如 192.168.20.66/24 → /24 */
    function maskOf(x) {
      const bits = x.cidr && x.cidr.split('/')[1];
      return bits ? `/${bits}` : '';
    }

    function renderInterfaces(d) {
      wrap.querySelector('#stHost').textContent = d.hostname || '—';
      wrap.querySelector('#stOs').textContent =
        `${OS_NAME[d.platform] || d.platform || ''} ${d.release || ''}`.trim() || '—';

      const all = d.interfaces || [];
      const list = all.filter((x) => !x.internal);
      const shown = list.length ? list : all;
      wrap.querySelector('#stCount').textContent = `${shown.length} 个`;

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
      pubBadgeEl.textContent = d.scope ? d.scope.label : '公网地址';
      pubWhereEl.textContent = g ? [g.country, g.region, g.city].filter(Boolean).join(' · ') : '';
      pubMetaEl.textContent = `${(g && g.provider) || '归属地信息不可用'} · ${d.elapsed} ms`;
    }

    async function loadLocal() {
      reloadBtn.disabled = true;
      reloadBtn.classList.add('is-busy');
      try {
        const [local, pub] = await Promise.allSettled([
          api('/api/net/localip', {}),
          api('/api/net/ipinfo', { ip: '' }),
        ]);
        if (local.status === 'fulfilled' && local.value.ok) renderInterfaces(local.value.data);
        else {
          ifList.innerHTML = `<li class="myip-row muted">${esc(
            local.status === 'fulfilled' ? local.value.error : local.reason.message
          )}</li>`;
        }
        if (pub.status === 'fulfilled' && pub.value.ok) renderPublic(pub.value.data);
        else {
          pubIpEl.textContent = '检测失败';
          pubBadgeEl.className = 'badge err';
          pubBadgeEl.textContent = '出口未知';
          pubWhereEl.textContent = '';
          pubMetaEl.textContent = pub.status === 'fulfilled' ? pub.value.error : pub.reason.message;
        }
      } finally {
        reloadBtn.disabled = false;
        reloadBtn.classList.remove('is-busy');
      }
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
        qEl.value = c.dataset.v;
        run();
      })
    );

    loadLocal();
  },
};
