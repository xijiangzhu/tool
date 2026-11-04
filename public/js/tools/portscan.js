/* TCP 端口扫描 */
import { h, esc, api, remember, setBusy, formError } from '../ui.js';

/* 端口数上限：本地与云端一致（云端并发只有 6，大范围扫描会慢，但不限数量） */
const MAX_PORTS = 2000;
const BATCH_SIZE = 6;

const COMMON =
  '21,22,23,25,53,80,110,111,123,135,139,143,161,389,443,445,465,514,587,636,873,993,995,1080,1433,1521,1723,2049,2181,2375,3000,3306,3389,5000,5432,5601,5672,5900,6379,7001,8000,8080,8081,8443,8888,9000,9090,9200,9300,11211,27017';

const PRESETS = [
  ['常见端口', COMMON],
  ['Web 服务', '80,443,8000,8008,8080,8081,8088,8443,8888'],
  ['数据库', '1433,1521,3306,5432,6379,9200,27017'],
  ['远程管理', '22,23,3389,5900,5985,5986'],
  ['1 - 1024', '1-1024'],
];

export default {
  id: 'portscan',
  name: '端口扫描',
  group: '网络工具',
  desc: 'TCP 连接探测目标主机端口开放情况，识别常见服务',
  keywords: '端口 扫描 port scan 开放 nmap tcp',
  net: true,
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>扫描目标</div>
          <div class="card-note">仅做 TCP 连接探测，请只扫描自己有权检测的主机</div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <div class="field grow">
              <label class="lb">目标主机</label>
              <input type="text" id="host" placeholder="域名或 IP，如 192.168.1.1" />
            </div>
            <div class="field w170">
              <label class="lb">单端口超时</label>
              <div class="input-suffix">
                <input type="number" id="timeout" value="2000" min="100" max="5000" step="100" />
                <span>毫秒</span>
              </div>
            </div>
          </div>

          <div class="field mt12">
            <label class="lb">端口范围</label>
            <input type="text" id="ports" class="mono" value="${COMMON}" placeholder="22,80,443 或 1-1024" />
            <div class="chips mt8">
              ${PRESETS.map(([n, v]) => `<span class="chip" data-v="${v}">${n}</span>`).join('')}
            </div>
            <div class="hint" id="portHint"></div>
          </div>

          <div class="btn-row">
            <button class="btn btn-primary" id="run">开始扫描</button>
          </div>
        </div>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>扫描结果</div>
          <div class="card-note" id="meta"></div>
        </div>
        <div class="card-body" id="out">
          <div class="empty" style="padding:16px">填写目标后点击「开始扫描」</div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const hostEl = wrap.querySelector('#host');
    const portsEl = wrap.querySelector('#ports');
    remember(hostEl, 'portscan.host');
    remember(portsEl, 'portscan.ports');
    const hostErr = formError(hostEl.closest('.field-row'), hostEl);
    const portsErr = formError(portsEl, portsEl);
    const outEl = wrap.querySelector('#out');
    const metaEl = wrap.querySelector('#meta');
    const btn = wrap.querySelector('#run');

    wrap.querySelector('#portHint').textContent =
      `单次最多 ${MAX_PORTS} 个端口，支持逗号与区间混写。超时指每个端口等待响应的最长时间，默认 2000 毫秒：内网 300 ~ 500 毫秒即可，跨公网或高丢包建议 2000 以上。注意：部分防火墙会对同源 IP 的高频连接做限速丢包，大范围扫描可能漏报开放端口，有疑问时可用小范围端口重扫验证。`;

    /** 统计端口写法覆盖的端口数：'80,443' → 2，'1-1024' → 1024；写法非法返回 NaN */
    function portCount(s) {
      const ports = new Set();
      for (const part of String(s).split(/[\s,]+/)) {
        const t = part.trim();
        if (!t) continue;
        const m = /^(\d+)-(\d+)$/.exec(t);
        if (m) {
          const a = Number(m[1]);
          const b = Number(m[2]);
          if (a < 1 || b > 65535 || a > b) return NaN;
          for (let p = a; p <= b; p++) {
            ports.add(p);
            if (ports.size > MAX_PORTS) return ports.size;
          }
        } else if (/^\d+$/.test(t)) {
          if (Number(t) < 1 || Number(t) > 65535) return NaN;
          ports.add(Number(t));
        } else return NaN;
      }
      return ports.size;
    }

    function expandPorts(s) {
      const ports = new Set();
      for (const part of String(s).split(/[\s,]+/)) {
        const t = part.trim();
        if (!t) continue;
        const m = /^(\d+)-(\d+)$/.exec(t);
        if (m) for (let p = Number(m[1]); p <= Number(m[2]); p++) ports.add(p);
        else ports.add(Number(t));
      }
      return [...ports].sort((a, b) => a - b);
    }

    wrap.querySelectorAll('.chips .chip').forEach((c) =>
      c.addEventListener('click', () => {
        const n = portCount(c.dataset.v);
        if (n > MAX_PORTS) {
          return portsErr.show(`该范围含 ${n} 个端口，超过单次上限 ${MAX_PORTS} 个，请手动缩小`);
        }
        portsErr.clear();
        portsEl.value = c.dataset.v;
      })
    );

    function render(d) {
      metaEl.textContent = `${d.scanned} 个端口 · ${(d.elapsed / 1000).toFixed(1)} s · 单端口超时 ${d.timeout} ms`;
      const stats = `
        <div class="grid grid-3">
          <div class="stat"><div class="stat-label">扫描端口数</div><div class="stat-value mono">${d.scanned}</div></div>
          <div class="stat"><div class="stat-label">开放端口</div><div class="stat-value mono" style="color:${d.open.length ? 'var(--ok)' : 'var(--muted)'}">${d.open.length}</div></div>
          <div class="stat"><div class="stat-label">耗时</div><div class="stat-value mono">${(d.elapsed / 1000).toFixed(1)} s</div></div>
        </div>`;

      const body = d.open.length
        ? `<table class="tbl zebra mt12">
            <tr><th style="width:100px">端口</th><th style="width:200px">服务</th><th style="width:120px">握手耗时</th><th>状态</th></tr>
            ${d.open
              .map(
                (p) => `<tr>
                  <td class="mono"><b>${p.port}</b></td>
                  <td>${esc(p.service || '未知服务')}</td>
                  <td class="mono">${p.ms} ms</td>
                  <td><span class="badge ok" title="端口可连接">open</span></td>
                </tr>`
              )
              .join('')}
          </table>`
        : '<div class="alert ok mt12">未发现开放端口（可能全部被防火墙过滤，或超时时间过短）</div>';

      outEl.innerHTML = `${stats}
        <div class="note mt12">目标地址：<span class="mono">${esc(d.target)}</span>${d.target !== d.host ? `（${esc(d.host)}）` : ''}</div>
        ${body}`;
    }

    async function run() {
      const host = hostEl.value.trim();
      if (!host) return hostErr.show('请输入要扫描的域名或 IP');
      const portsStr = portsEl.value.trim();
      const count = portCount(portsStr);
      if (Number.isNaN(count)) return portsErr.show('端口写法不合法，示例：22,80,443 或 1-1024');
      if (!count) return portsErr.show('请填写端口范围，如 22,80,443 或 1-1024');
      if (count > MAX_PORTS) {
        return portsErr.show(`单次最多扫描 ${MAX_PORTS} 个端口（当前 ${count} 个），请缩小范围`);
      }
      hostErr.clear();
      portsErr.clear();
      setBusy(btn, true, '扫描中');
      outEl.innerHTML = '<div class="empty">正在探测端口，请稍候…</div>';
      metaEl.textContent = '';
      const ports = expandPorts(portsStr);
      const combined = { host, target: host, scanned: 0, open: [], elapsed: 0, timeout: Number(wrap.querySelector('#timeout').value) };
      try {
        for (let i = 0; i < ports.length; i += BATCH_SIZE) {
          const batch = ports.slice(i, i + BATCH_SIZE);
          // 锁定首批解析出的 IP，避免域名轮询解析时不同批次扫到不同主机
          const r = await api('/api/net/portscan', { host: combined.target, ports: batch.join(','), timeout: combined.timeout });
          if (!r.ok) throw new Error(r.error);
          combined.target = r.data.target;
          combined.scanned += r.data.scanned;
          combined.open.push(...r.data.open);
          combined.elapsed += r.data.elapsed;
          metaEl.textContent = `已完成 ${combined.scanned} / ${ports.length} 个端口`;
          outEl.innerHTML = `<div class="empty">正在扫描：${combined.scanned} / ${ports.length} 个端口，已发现 ${combined.open.length} 个开放端口…</div>`;
        }
        combined.open.sort((a, b) => a.port - b.port);
        render(combined);
      } catch (e) {
        if (combined.scanned) {
          combined.open.sort((a, b) => a.port - b.port);
          render(combined);
          outEl.insertAdjacentHTML('afterbegin', `<div class="alert warn">扫描中断：${combined.scanned} / ${ports.length} 个端口已完成。${esc(e.message)}</div>`);
        } else outEl.innerHTML = `<div class="alert err">${esc(e.message)}</div>`;
      } finally {
        setBusy(btn, false);
      }
    }

    btn.addEventListener('click', run);
    hostEl.addEventListener('keydown', (e) => e.key === 'Enter' && run());
  },
};
