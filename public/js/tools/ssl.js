/* SSL 证书检测 */
import { h, api, copy, toast, esc, remember, setBusy, fmtDateTime } from '../ui.js';

const STATUS_MAP = {
  valid: { cls: 'ok', text: '证书有效' },
  expiring: { cls: 'warn', text: '即将过期' },
  expired: { cls: 'err', text: '证书已过期' },
  notyet: { cls: 'warn', text: '证书尚未生效' },
  mismatch: { cls: 'err', text: '证书与主机名不匹配' },
  selfsigned: { cls: 'warn', text: '自签名证书' },
  untrusted: { cls: 'err', text: '证书链不受信任' },
};

/* 空值返回 -，其余交给通用格式化 */
function fmtDT(iso) {
  return iso ? fmtDateTime(iso) : '-';
}

function cnOf(subject) {
  if (!subject) return '-';
  const m = /(?:^|,\s*)CN=([^,]+)/.exec(subject);
  return m ? m[1] : subject;
}

export default {
  id: 'ssl',
  name: 'SSL 证书检测',
  group: '网络工具',
  desc: '在线检测站点证书的颁发者、有效期、SAN、证书链与 TLS 协议支持情况',
  keywords: 'ssl tls 证书 https 过期 检测 certificate',
  net: true,
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>检测目标</div>
          <div class="card-note">由本机服务端发起 TLS 握手，结果不落库</div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <input type="text" id="host" class="grow2" placeholder="example.com 或 https://example.com" />
            <input type="number" id="port" class="w120" value="443" placeholder="端口" />
            <button class="btn btn-primary" id="go">开始检测</button>
          </div>
          <div class="row mt10">
            <span class="note">支持直接粘贴 https:// 开头的完整地址</span>
            <span class="spacer"></span>
            <label class="check"><input type="checkbox" id="probe" checked /> 探测 TLS 版本支持</label>
          </div>
        </div>
      </section>
      <div id="result"></div>
    `);
    root.appendChild(wrap);

    const resultEl = wrap.querySelector('#result');
    const goBtn = wrap.querySelector('#go');
    remember(wrap.querySelector('#host'), 'ssl.host');

    function normalizeTarget(raw) {
      let s = String(raw || '').trim();
      if (!s) throw new Error('请输入域名或 https:// 地址');
      if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
      let u;
      try {
        u = new URL(s);
      } catch (e) {
        throw new Error('地址格式不正确，请填写域名或完整 URL');
      }
      if (!u.hostname) throw new Error('地址中缺少域名');
      return { host: u.hostname, port: u.port ? Number(u.port) : null };
    }

    async function run() {
      let target;
      try {
        target = normalizeTarget(wrap.querySelector('#host').value);
      } catch (e) {
        return toast(e.message, 'err');
      }
      const host = target.host;
      const port = target.port || Number(wrap.querySelector('#port').value || 443);
      if (target.port) wrap.querySelector('#port').value = target.port;
      const probe = wrap.querySelector('#probe').checked;

      setBusy(goBtn, true, '检测中');
      resultEl.innerHTML = '<div class="card"><div class="card-body"><div class="empty">正在与 ' + esc(host) + ':' + port + ' 进行 TLS 握手…</div></div></div>';

      let res;
      try {
        res = await api('/api/ssl', { host, port, probe });
      } catch (e) {
        setBusy(goBtn, false);
        resultEl.innerHTML = `<div class="card"><div class="card-body"><div class="alert err">请求失败：${esc(e.message)}</div></div></div>`;
        return;
      }
      setBusy(goBtn, false);
      if (!res.ok) {
        resultEl.innerHTML = `<div class="card"><div class="card-body"><div class="alert err">${esc(res.error)}</div></div></div>`;
        return;
      }
      render(res.data);
    }

    goBtn.addEventListener('click', run);
    wrap.querySelector('#host').addEventListener('keydown', (e) => e.key === 'Enter' && run());

    function render(d) {
      const st = STATUS_MAP[d.status] || STATUS_MAP.valid;
      const leaf = (d.chain && d.chain[0]) || null;
      const dnsNames = (leaf && leaf.subjectAltName || []).filter((s) => s.type === 'DNS').map((s) => s.value);
      const pct = d.notBefore && d.notAfter
        ? Math.min(100, Math.max(0, ((Date.now() - new Date(d.notBefore)) / (new Date(d.notAfter) - new Date(d.notBefore))) * 100))
        : 0;

      const chainRows = (d.chain || [])
        .map(
          (c, i) => `<tr>
            <td>${i === 0 ? '<span class="badge info">叶子</span>' : i === (d.chain.length - 1) ? '<span class="badge mute">根</span>' : '<span class="badge mute">中间</span>'}</td>
            <td class="mono">${esc(cnOf(c.subject))}</td>
            <td class="mono">${esc(cnOf(c.issuer))}</td>
            <td class="mono">${fmtDT(c.validFrom)}</td>
            <td class="mono">${fmtDT(c.validTo)}</td>
            <td class="mono">${esc((c.publicKey && c.publicKey.type ? c.publicKey.type.toUpperCase() + (c.publicKey.bits ? ' ' + c.publicKey.bits : '') : '-'))}</td>
          </tr>`
        )
        .join('');

      const protoChips = d.protocols
        ? Object.entries(d.protocols)
            .map(([k, v]) => {
              const old = k === 'TLSv1' || k === 'TLSv1.1';
              const cls = v ? (old ? 'warn' : 'ok') : 'mute';
              return `<span class="badge ${cls}">${k} ${v ? (old ? '支持(不安全)' : '支持') : '不支持'}</span>`;
            })
            .join(' ')
        : '<span class="muted">未探测</span>';

      resultEl.innerHTML = `
        <section class="card">
          <div class="card-head">
            <div class="card-title"><span class="dot"></span>检测结论</div>
            <div class="card-note">${esc(d.host)}:${d.port} · ${fmtDT(d.checkedAt)}</div>
          </div>
          <div class="card-body">
            <div class="row" style="margin-bottom:14px">
              <span class="badge ${st.cls} lg">${st.text}</span>
              <span class="out-meta">${
                d.daysLeft === null
                  ? '—'
                  : d.daysLeft < 0
                  ? `已过期 ${Math.abs(d.daysLeft)} 天`
                  : `剩余 ${d.daysLeft} 天（总有效期 ${d.totalDays} 天）`
              }</span>
              <span class="spacer"></span>
              <span class="out-meta">解析 IP：${esc((d.resolved || []).join(', ') || '-')}</span>
            </div>
            <div class="progress ${st.cls === 'ok' ? '' : st.cls}" style="margin-bottom:6px"><i style="width:${pct.toFixed(1)}%"></i></div>
            <div class="row" style="justify-content:space-between;font-size:12px;color:var(--muted)">
              <span>生效 ${fmtDT(d.notBefore)}</span><span>到期 ${fmtDT(d.notAfter)}</span>
            </div>
            <div class="grid grid-4 mt12">
              <div class="stat"><div class="stat-label">通用名 CN</div><div class="stat-value mono sm">${esc(cnOf(leaf && leaf.subject))}</div></div>
              <div class="stat"><div class="stat-label">颁发者 O</div><div class="stat-value mono sm">${esc((/O=([^,]+)/.exec((leaf && leaf.issuer) || '') || [])[1] || '-')}</div></div>
              <div class="stat"><div class="stat-label">密钥</div><div class="stat-value mono sm">${esc(`${(leaf && leaf.publicKey && leaf.publicKey.type) || '-'} ${(leaf && leaf.publicKey && leaf.publicKey.bits) || ''}`)}</div></div>
              <div class="stat"><div class="stat-label">协商协议</div><div class="stat-value mono sm">${esc(d.protocol || '-')}</div></div>
            </div>
          </div>
        </section>

        <section class="card">
          <div class="card-head"><div class="card-title"><span class="dot"></span>证书详情</div></div>
          <div class="card-body">
            <table class="tbl zebra">
              <tr><th style="width:150px">主题 Subject</th><td class="mono">${esc(leaf && leaf.subject)}</td></tr>
              <tr><th>颁发者 Issuer</th><td class="mono">${esc(leaf && leaf.issuer)}</td></tr>
              <tr><th>有效期</th><td class="mono">${fmtDT(d.notBefore)} ~ ${fmtDT(d.notAfter)}</td></tr>
              <tr><th>序列号</th><td class="mono">${esc((leaf && leaf.serialNumber) || '-')}</td></tr>
              <tr><th>SHA-256 指纹</th><td class="mono">${esc((leaf && leaf.fingerprint256) || '-')}</td></tr>
              <tr><th>公钥</th><td class="mono">${esc(`${(leaf && leaf.publicKey && leaf.publicKey.type) || '-'} ${(leaf && leaf.publicKey && leaf.publicKey.bits) || ''} 位`)}</td></tr>
              <tr><th>密钥用法</th><td class="mono">${esc((leaf && leaf.keyUsage && leaf.keyUsage.join(', ')) || '-')}</td></tr>
              <tr><th>主机名校验</th><td>${d.hostMatch === null ? '<span class="muted">未知</span>' : d.hostMatch ? '<span class="badge ok">匹配</span>' : `<span class="badge err">不匹配（证书 CN/SAN 未包含 ${esc(d.host)}）</span>`}</td></tr>
              <tr><th>信任链校验</th><td>${d.authorized ? '<span class="badge ok">通过</span>' : `<span class="badge err">未通过${d.authorizationError ? '：' + esc(d.authorizationError) : ''}</span>`}</td></tr>
              <tr><th>加密套件</th><td class="mono">${esc((d.cipher && d.cipher.name) || '-')} ${d.cipher && d.cipher.bits ? '(' + d.cipher.bits + ' bit)' : ''}</td></tr>
            </table>
            <div class="note mt12">备用名称 SAN（${dnsNames.length} 项）</div>
            <div class="chips mt8">${
              dnsNames.length
                ? dnsNames.map((n) => `<span class="chip">${esc(n)}</span>`).join('')
                : '<span class="muted">无</span>'
            }</div>
            <div class="btn-row mt12">
              <button class="btn btn-sm" id="copyFp">复制指纹</button>
              <button class="btn btn-sm" id="copySan">复制 SAN</button>
            </div>
          </div>
        </section>

        <section class="card">
          <div class="card-head"><div class="card-title"><span class="dot"></span>证书链（${(d.chain || []).length} 层）</div></div>
          <div class="card-body">
            <table class="tbl">
              <tr><th style="width:70px">角色</th><th>主题</th><th>颁发者</th><th>生效</th><th>到期</th><th>密钥</th></tr>
              ${chainRows || '<tr><td colspan="6" class="muted">无</td></tr>'}
            </table>
          </div>
        </section>

        <section class="card">
          <div class="card-head"><div class="card-title"><span class="dot"></span>TLS 协议支持</div></div>
          <div class="card-body">
            <div class="chips">${protoChips}</div>
            <div class="mt8 out-meta">本次连接使用：${esc(d.protocol || '-')} · 套件 ${esc((d.cipher && d.cipher.name) || '-')}</div>
          </div>
        </section>
      `;

      const fpBtn = resultEl.querySelector('#copyFp');
      if (fpBtn) fpBtn.addEventListener('click', () => copy((leaf && leaf.fingerprint256) || ''));
      const sanBtn = resultEl.querySelector('#copySan');
      if (sanBtn) sanBtn.addEventListener('click', () => copy(dnsNames.join('\n')));
    }
  },
};
