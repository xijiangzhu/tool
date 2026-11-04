/* IP 子网计算器 */
import { h, copy, esc, fmtNum, remember, formError } from '../ui.js';

const QUICK = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12', '192.168.10.5/26'];

function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) throw new Error('IPv4 地址需为 4 段，如 192.168.1.1');
  let v = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) throw new Error(`非法 IPv4 段：${p}`);
    const n = Number(p);
    if (n > 255) throw new Error(`IPv4 段超出范围：${p}`);
    v = (v << 8) | n;
  }
  return v >>> 0;
}
function intToIp(v) {
  return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.');
}
function maskOf(p) {
  return p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
}
function typeOf(intIp) {
  const eq = (base, prefix) => (intIp & maskOf(prefix)) >>> 0 === (ipToInt(base) & maskOf(prefix)) >>> 0;
  if (eq('10.0.0.0', 8) || eq('172.16.0.0', 12) || eq('192.168.0.0', 16)) return ['私有地址', 'info'];
  if (eq('100.64.0.0', 10)) return ['运营商级 NAT', 'info'];
  if (eq('127.0.0.0', 8)) return ['回环地址', 'mute'];
  if (eq('169.254.0.0', 16)) return ['链路本地', 'warn'];
  if (eq('224.0.0.0', 4)) return ['组播地址', 'mute'];
  return ['公网地址', 'ok'];
}

/* IPv6 基础计算 */
function v6ToBigInt(str) {
  const seg = str.replace(/%[^%]*$/, '').split('::');
  if (seg.length > 2) throw new Error('IPv6 地址中 :: 只能出现一次');
  const head = seg[0] ? seg[0].split(':').filter(Boolean) : [];
  const tail = seg.length > 1 && seg[1] ? seg[1].split(':').filter(Boolean) : [];
  const missing = 8 - head.length - tail.length;
  if (seg.length === 1 && head.length !== 8) throw new Error('IPv6 地址需为 8 段或使用 :: 缩写');
  const groups = [...head, ...Array(Math.max(0, missing)).fill('0'), ...tail];
  if (groups.length !== 8) throw new Error('IPv6 地址段数不正确');
  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) throw new Error(`非法 IPv6 段：${g}`);
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  return v;
}
function v6Groups(v) {
  const out = [];
  for (let i = 7; i >= 0; i--) out.push(Number((v >> BigInt(i * 16)) & 0xffffn).toString(16));
  return out;
}
function v6Compress(groups) {
  const g = groups.map((x) => x.replace(/^0+/, '') || '0');
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  g.forEach((x, i) => {
    if (x === '0') {
      if (curStart === -1) { curStart = i; curLen = 1; } else curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  });
  if (bestLen < 2) return g.join(':');
  return `${g.slice(0, bestStart).join(':')}::${g.slice(bestStart + bestLen).join(':')}`;
}

const kv = (label, value) => `
  <div class="ip-kv-item">
    <div class="ip-kv-label">${esc(label)}</div>
    <div class="ip-kv-value mono">${value}</div>
  </div>`;

export default {
  id: 'ipcalc',
  name: 'IP 子网计算器',
  group: '网络工具',
  desc: 'IPv4 / IPv6 网段计算：网络地址、可用范围、子网划分',
  keywords: 'ip 子网 cidr 掩码 网段 ipv4 ipv6 netmask',
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <div class="ip-page">
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>网段</div>
          <div class="card-note">支持 192.168.1.0/24、10.0.0.5 255.255.0.0、2001:db8::/32</div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <input type="text" id="cidr" class="mono" placeholder="192.168.1.0/24" />
            <button class="btn btn-primary" id="calc">计算</button>
          </div>
          <div class="chips mt10">
            ${QUICK.map((q) => `<span class="chip" data-v="${esc(q)}">${esc(q)}</span>`).join('')}
          </div>
        </div>
      </section>
      <div id="out"></div>
      </div>
    `);
    root.appendChild(wrap);

    const outEl = wrap.querySelector('#out');
    const input = wrap.querySelector('#cidr');
    remember(input, 'ipcalc.cidr');
    /* 与其他页面统一的内联错误（紧贴字段、标红聚焦、重新输入自动清除） */
    const cidrErr = formError(wrap.querySelector('.field-row'), input);

    wrap.querySelectorAll('.chips .chip').forEach((c) =>
      c.addEventListener('click', () => {
        input.value = c.dataset.v;
        calc();
      })
    );
    wrap.querySelector('#calc').addEventListener('click', calc);
    input.addEventListener('keydown', (e) => e.key === 'Enter' && calc());
    input.value = '192.168.1.0/24';
    setTimeout(calc, 0);

    function calc() {
      cidrErr.clear();
      outEl.innerHTML = '';
      const raw = input.value.trim();
      if (!raw) return cidrErr.show('请输入网段');
      try {
        if (raw.includes(':')) calcV6(raw);
        else calcV4(raw);
      } catch (e) {
        cidrErr.show(e.message);
      }
    }

    /* ------------------------------ IPv4 ------------------------------ */
    function calcV4(raw) {
      const text = raw.replace(/\s+/g, ' ').trim();
      let ipStr, prefix;
      if (text.includes('/')) {
        const [a, b] = text.split('/');
        ipStr = a.trim();
        prefix = Number(b.trim());
      } else if (text.includes(' ')) {
        const [a, b] = text.split(' ');
        ipStr = a.trim();
        const mm = ipToInt(b.trim()) >>> 0;
        const inv = ~mm >>> 0;
        if ((inv & (inv + 1)) >>> 0 !== 0) throw new Error('子网掩码不是连续掩码（如 255.255.255.0）');
        let cnt = 0;
        let x = mm;
        while (x) {
          cnt += x & 1;
          x >>>= 1;
        }
        prefix = cnt;
      } else {
        ipStr = text;
        prefix = 32;
      }
      if (!(prefix >= 0 && prefix <= 32)) throw new Error('前缀长度需在 0 - 32 之间');

      const ip = ipToInt(ipStr);
      const mask = maskOf(prefix);
      const network = (ip & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      const total = Math.pow(2, 32 - prefix);
      const usable = prefix >= 31 ? total : total - 2;
      const first = prefix <= 30 ? (network + 1) >>> 0 : network;
      const last = prefix <= 30 ? (broadcast - 1) >>> 0 : broadcast;
      const [typeTxt, typeCls] = typeOf(network);
      const usableTxt = prefix === 32 ? '1' : prefix === 31 ? '2' : fmtNum(usable);
      const role = prefix === 32 ? '主机地址' : ip === network ? '网络地址' : ip === broadcast ? '广播地址' : '可用主机地址';

      const summary = [
        `网络地址: ${intToIp(network)}/${prefix}`,
        `子网掩码: ${intToIp(mask)}`,
        `广播地址: ${prefix >= 31 ? '—' : intToIp(broadcast)}`,
        `可用范围: ${intToIp(first)} ~ ${intToIp(last)}`,
        `可用主机: ${usableTxt}`,
        `地址总数: ${fmtNum(total)}`,
      ].join('\n');

      outEl.innerHTML = `
        <section class="card">
          <div class="card-head">
            <div class="card-title"><span class="dot"></span>计算结果</div>
            <div class="card-note">${esc(ipStr)} → ${esc(intToIp(network))}/${prefix}</div>
          </div>
          <div class="card-body">
            <div class="ip-hero">
              <div>
                <div class="ip-hero-label">网络地址</div>
                <div class="ip-cidr">${intToIp(network)}<span>/${prefix}</span></div>
              </div>
              <span class="badge ${typeCls} ml-auto">${typeTxt}</span>
              <button class="btn btn-sm" id="copyAll">复制摘要</button>
            </div>

            <div class="ip-kv">
              ${kv('子网掩码', intToIp(mask))}
              ${kv('可用主机数', usableTxt)}
              ${kv('可用范围', `${intToIp(first)} ~ ${intToIp(last)}`)}
              ${kv('广播地址', prefix >= 31 ? '—' : intToIp(broadcast))}
              ${kv('地址总数', fmtNum(total))}
              ${kv('输入地址角色', role)}
            </div>

            <div class="pane mt12">
              <div class="pane-head">
                <span class="pane-title">包含判断</span>
                <span class="pane-note">检查某个 IP 是否落在该网段内</span>
              </div>
              <div class="pane-body">
                <div class="ip-check-row">
                  <input type="text" id="chk" class="mono" placeholder="如 192.168.1.100" />
                  <button class="btn" id="chkBtn">判断</button>
                  <span id="chkOut" class="ip-check-out"></span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section class="card">
          <div class="card-head">
            <div class="card-title"><span class="dot"></span>子网划分</div>
            <div class="card-note">把 /${prefix} 再切成更小的网段</div>
          </div>
          <div class="card-body">
            <div class="ip-split-row">
              <label class="inline-field">目标前缀 <span class="mono">/${prefix} →</span>
                <input type="number" id="sval" value="${Math.min(32, prefix + 2)}" min="${prefix + 1}" max="32" />
              </label>
              <button class="btn btn-primary" id="split">划分</button>
            </div>
            <div id="splitOut" class="mt12"></div>
          </div>
        </section>
      `;

      outEl.querySelector('#copyAll').addEventListener('click', () => copy(summary, '已复制摘要'));

      outEl.querySelector('#split').addEventListener('click', () => {
        const target = outEl.querySelector('#splitOut');
        const newPrefix = Number(outEl.querySelector('#sval').value);
        if (!(newPrefix > prefix && newPrefix <= 32))
          return (target.innerHTML = `<div class="alert err">目标前缀需大于 ${prefix} 且不超过 32</div>`);
        const step = Math.pow(2, 32 - newPrefix);
        const count = Math.pow(2, newPrefix - prefix);
        const show = Math.min(count, 128);
        const rows = [];
        for (let i = 0; i < show; i++) {
          const net = (network + i * step) >>> 0;
          const bc = (net + step - 1) >>> 0;
          const f = newPrefix >= 31 ? net : (net + 1) >>> 0;
          const l = newPrefix >= 31 ? bc : (bc - 1) >>> 0;
          rows.push(`<tr>
            <td class="mono">${intToIp(net)}/${newPrefix}</td>
            <td class="mono">${intToIp(f)} ~ ${intToIp(l)}</td>
            <td class="mono">${newPrefix >= 31 ? '—' : intToIp(bc)}</td>
            <td class="mono">${fmtNum(newPrefix >= 32 ? 1 : newPrefix === 31 ? 2 : step - 2)}</td>
          </tr>`);
        }
        target.innerHTML = `
          <div class="alert info" style="margin-top:0">共 ${fmtNum(count)} 个子网，每个 /${newPrefix}${count > show ? `（仅展示前 ${show} 个）` : ''}</div>
          <div class="tbl-scroll">
            <table class="tbl">
              <tr><th>子网</th><th>可用范围</th><th>广播地址</th><th>可用主机</th></tr>
              ${rows.join('')}
            </table>
          </div>
        `;
      });

      outEl.querySelector('#chkBtn').addEventListener('click', () => {
        const v = outEl.querySelector('#chk').value.trim();
        const box = outEl.querySelector('#chkOut');
        if (!v) return (box.innerHTML = '<span class="result-tag err">请输入 IP</span>');
        let n;
        try {
          n = ipToInt(v);
        } catch (e) {
          return (box.innerHTML = `<span class="result-tag err">地址不合法</span>`);
        }
        const inside = (n & mask) >>> 0 === network;
        box.innerHTML = inside
          ? `<span class="result-tag ok">属于</span>${esc(v)} 在 ${intToIp(network)}/${prefix} 内`
          : `<span class="result-tag err">不属于</span>${esc(v)} 不在 ${intToIp(network)}/${prefix} 内`;
      });
      remember(outEl.querySelector('#chk'), 'ipcalc.chk');
      outEl.querySelector('#chk').addEventListener('keydown', (e) => e.key === 'Enter' && outEl.querySelector('#chkBtn').click());
    }

    /* ------------------------------ IPv6 ------------------------------ */
    function calcV6(raw) {
      const [addr, pfx] = raw.split('/');
      const prefix = pfx === undefined ? 128 : Number(pfx);
      if (!(prefix >= 0 && prefix <= 128)) throw new Error('IPv6 前缀长度需在 0 - 128 之间');
      const v = v6ToBigInt(addr.trim());
      const bits = BigInt(prefix);
      const all = (1n << 128n) - 1n;
      const mask = bits === 0n ? 0n : (all << (128n - bits)) & all;
      const network = v & mask;
      const last = network | ((1n << (128n - bits)) - 1n);
      const total = 1n << (128n - bits);
      const first = Number(v >> 112n);
      let typeTxt = '公网单播';
      let typeCls = 'ok';
      if (v === 1n) { typeTxt = '回环地址'; typeCls = 'mute'; }
      else if ((first & 0xfe) === 0xfc) { typeTxt = '唯一本地地址'; typeCls = 'info'; }
      else if ((first & 0xff) === 0xfe && ((Number(v >> 104n) & 0xc0) === 0x80)) { typeTxt = '链路本地'; typeCls = 'warn'; }
      else if ((first & 0xff) === 0xff) { typeTxt = '组播地址'; typeCls = 'mute'; }

      outEl.innerHTML = `
        <section class="card">
          <div class="card-head">
            <div class="card-title"><span class="dot"></span>计算结果</div>
            <div class="card-note">IPv6 前缀划分需手工计算</div>
          </div>
          <div class="card-body">
            <div class="ip-hero">
              <div>
                <div class="ip-hero-label">网络地址</div>
                <div class="ip-cidr">${v6Compress(v6Groups(network))}<span>/${prefix}</span></div>
              </div>
              <span class="badge ${typeCls} ml-auto">${typeTxt}</span>
            </div>
            <div class="ip-kv">
              ${kv('地址范围', `${v6Compress(v6Groups(network))} ~ ${v6Compress(v6Groups(last))}`)}
              ${kv('地址数量', total > 1000000n ? `${total}（约 2^${128 - prefix}）` : total.toString())}
            </div>
          </div>
        </section>
      `;
    }
  },
};
