/* DNS 记录查询 */
import { h, esc, api, remember, setBusy, formError, createGuard } from '../ui.js';

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'ALL'];

const COLS = {
  A: [['address', 'IP 地址']],
  AAAA: [['address', 'IPv6 地址']],
  CNAME: [['name', '目标主机']],
  NS: [['name', '名称服务器']],
  PTR: [['name', '主机名']],
  MX: [['priority', '优先级'], ['exchange', '邮件服务器']],
  TXT: [['text', '文本内容']],
  SRV: [['priority', '优先级'], ['weight', '权重'], ['port', '端口'], ['name', '目标地址']],
  CAA: [['critical', 'Critical'], ['tag', '标签'], ['value', '值']],
  SOA: [
    ['nsname', '主名称服务器'],
    ['hostmaster', '管理员邮箱'],
    ['serial', '序列号'],
    ['refresh', '刷新间隔'],
    ['retry', '重试间隔'],
    ['expire', '过期时间'],
    ['minttl', '最小 TTL'],
  ],
};

const QUICK = ['example.com', 'www.baidu.com', 'qq.com', '8.8.8.8'];

export default {
  id: 'dns',
  name: 'DNS 查询',
  group: '网络工具',
  desc: '查询 A / AAAA / CNAME / MX / TXT / NS / SOA 等 DNS 记录',
  keywords: 'dns 域名 解析 记录 mx txt ns cname ptr soa',
  net: true,
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>查询条件</div>
          <div class="card-note">PTR 查询请直接填写 IP</div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <input type="text" id="name" class="grow2" placeholder="域名或 IP，如 example.com" />
            <select id="type" class="w150">
              ${TYPES.map((t) => `<option value="${t}">${t === 'ALL' ? '全部记录' : t + ' 记录'}</option>`).join('')}
            </select>
            <input type="text" id="server" class="mono w280" placeholder="DNS 服务器（可选，如 223.5.5.5）" />
            <button class="btn btn-primary" id="run">查询</button>
          </div>
          <div class="chips mt12" id="quick">
            ${QUICK.map((d) => `<span class="chip" data-h="${d}">${d}</span>`).join('')}
          </div>
        </div>
      </section>

      <section class="card" id="resultCard" style="display:none">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>解析结果</div>
          <div class="card-note" id="meta"></div>
        </div>
        <div class="card-body" id="out">
          <div class="empty">输入域名后点击「查询」</div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const nameEl = wrap.querySelector('#name');
    remember(nameEl, 'dns.name');
    remember(wrap.querySelector('#server'), 'dns.server');
    const nameErr = formError(wrap.querySelector('.field-row'), nameEl);
    const outEl = wrap.querySelector('#out');
    const metaEl = wrap.querySelector('#meta');
    const resultCard = wrap.querySelector('#resultCard');
    const btn = wrap.querySelector('#run');

    wrap.querySelectorAll('#quick .chip').forEach((c) =>
      c.addEventListener('click', () => {
        nameEl.value = c.dataset.h;
        // 填的是 IP（IPv4 或 IPv6）都用 PTR 反查；查 A/AAAA 记录只会得到 NXDOMAIN
        wrap.querySelector('#type').value = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)$/.test(c.dataset.h) ? 'PTR' : 'A';
        run();
      })
    );

    function table(type, records) {
      const cols = COLS[type] || [['name', '值']];
      if (type === 'SOA') {
        const r = records[0];
        return `<table class="tbl"><tr><th style="width:180px">字段</th><td class="mono">${esc(String(r[cols[0][0]] ?? ''))}</td></tr>
          ${cols.slice(1).map(([k, label]) => `<tr><th>${label}</th><td class="mono">${esc(String(r[k] ?? ''))}</td></tr>`).join('')}
        </table>`;
      }
      return `<table class="tbl zebra">
        <tr>${cols.map(([, label]) => `<th>${label}</th>`).join('')}</tr>
        ${records
          .map((r) => `<tr>${cols.map(([k]) => `<td class="mono">${esc(r[k] === '' || r[k] == null ? '-' : String(r[k]))}</td>`).join('')}</tr>`)
          .join('')}
      </table>`;
    }

    function render(d) {
      const groups = d.groups || [];
      const errs = d.errors || [];
      metaEl.textContent = `${d.server || ''} · ${d.elapsed || 0} ms`;
      if (!groups.length) {
        const msg = errs.length ? errs.map((e) => `${e.type}：${e.error}`).join('；') : d.error || '未查询到记录';
        outEl.innerHTML = `<div class="alert warn">没有解析到 <b>${esc(d.name)}</b> 的 ${esc(d.type)} 记录：${esc(msg)}</div>`;
        return;
      }
      outEl.innerHTML = groups
        .map(
          (g) => `<div class="mt12" style="margin-top:${groups.indexOf(g) === 0 ? 0 : 16}px">
            <div class="row" style="margin-bottom:8px">
              <span class="badge info">${esc(g.type)}</span>
              <span class="note">${g.records.length} 条 · ${g.elapsed || 0} ms</span>
            </div>
            ${table(g.type, g.records)}
          </div>`
        )
        .join('') +
        (errs.length
          ? `<div class="alert warn mt12">部分类型无结果：${errs.map((e) => `${esc(e.type)}（${esc(e.error)}）`).join('、')}</div>`
          : '');
    }

    const guard = createGuard(wrap);

    async function run() {
      const name = nameEl.value.trim();
      if (!name) return nameErr.show('请输入要查询的域名或 IP');
      nameErr.clear();
      resultCard.style.display = ''; // 结果卡片只在发起查询后出现
      const task = guard.begin();
      setBusy(btn, true, '查询中');
      outEl.innerHTML = '<div class="empty">正在查询…</div>';
      metaEl.textContent = '';
      try {
        const r = await api('/api/net/dns', {
          name,
          type: wrap.querySelector('#type').value,
          server: wrap.querySelector('#server').value.trim(),
        }, { signal: task.signal });
        if (!guard.alive(task.id)) return; // 旧响应不覆盖新结果
        if (!r.ok) throw new Error(r.error);
        render(r.data);
      } catch (e) {
        if (!guard.alive(task.id)) return;
        outEl.innerHTML = `<div class="alert err">${esc(e.message)}</div>`;
      } finally {
        if (guard.alive(task.id)) setBusy(btn, false);
      }
    }

    btn.addEventListener('click', run);
    nameEl.addEventListener('keydown', (e) => e.key === 'Enter' && run());
  },
};
