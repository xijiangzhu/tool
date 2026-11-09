/* 时间戳转换（仅本地时区） */
import { h, copy, esc, remember, pad2, WEEKDAYS, fmtDateTime, formError, onDispose } from '../ui.js';

const WEEK = WEEKDAYS;

function fmtCustom(ts, format) {
  const d = new Date(ts);
  const map = {
    YYYY: d.getFullYear(),
    YY: String(d.getFullYear()).slice(-2),
    MM: pad2(d.getMonth() + 1),
    M: d.getMonth() + 1,
    DD: pad2(d.getDate()),
    D: d.getDate(),
    HH: pad2(d.getHours()),
    H: d.getHours(),
    mm: pad2(d.getMinutes()),
    m: d.getMinutes(),
    ss: pad2(d.getSeconds()),
    s: d.getSeconds(),
    W: WEEK[d.getDay()],
    A: d.getHours() < 12 ? 'AM' : 'PM',
  };
  return format.replace(/YYYY|YY|MM|M|DD|D|HH|H|mm|m|ss|s|W|A/g, (t) => String(map[t]));
}

function relative(ts) {
  const diff = Date.now() - ts;
  const abs = Math.abs(diff);
  const min = 60000, hour = 3600000, day = 86400000;
  let txt;
  if (abs < 10000) txt = '刚刚';
  else if (abs < min) txt = `${Math.floor(abs / 1000)} 秒`;
  else if (abs < hour) txt = `${Math.floor(abs / min)} 分钟`;
  else if (abs < day) txt = `${Math.floor(abs / hour)} 小时`;
  else if (abs < day * 30) txt = `${Math.floor(abs / day)} 天`;
  else if (abs < day * 365) txt = `${Math.floor(abs / (day * 30))} 个月`;
  else txt = `${Math.floor(abs / (day * 365))} 年`;
  return diff >= 0 ? `${txt}前` : `${txt}后`;
}

export default {
  id: 'timestamp',
  name: '时间戳转换',
  group: '时间与调度',
  desc: 'Unix 时间戳与本地日期时间互转，支持自定义格式与相对时间',
  keywords: 'timestamp 时间戳 unix 本地时间',
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>当前时间</div>
          <div class="card-note"><label class="check"><input type="checkbox" id="ticking" checked /> 每秒刷新</label></div>
        </div>
        <div class="card-body">
          <div class="grid grid-3">
            <div class="stat"><div class="stat-label">秒级时间戳 (10 位)</div><div class="stat-value mono" id="tsS">-</div></div>
            <div class="stat"><div class="stat-label">本地时间</div><div class="stat-value mono sm" id="tsLocal">-</div></div>
            <div class="stat"><div class="stat-label">ISO 8601 (UTC)</div><div class="stat-value mono sm" id="tsIso">-</div></div>
          </div>
          <div class="btn-row mt12">
            <button class="btn btn-sm" id="copyS">复制秒级</button>
          </div>
        </div>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>时间戳 → 本地时间</div>
          <div class="card-note">自动识别秒 / 毫秒</div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <input type="text" id="tsIn" class="mono" placeholder="例如 1735689600 或 1735689600000" />
            <select id="tsUnit" class="w150">
              <option value="auto">自动识别</option>
              <option value="s">秒 (s)</option>
              <option value="ms">毫秒 (ms)</option>
            </select>
            <button class="btn btn-primary" id="tsNow">填入当前</button>
            <button class="btn" id="tsConv">转换</button>
          </div>
          <div id="tsOut" class="mt12"><div class="empty">转换结果将显示在这里</div></div>
        </div>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>本地时间 → 时间戳</div>
          <div class="card-note">按浏览器所在时区解释输入</div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <input type="datetime-local" id="dtIn" step="1" />
            <button class="btn btn-primary" id="dtConv">转换</button>
            <button class="btn" id="dtNow">现在</button>
          </div>
          <div class="grid grid-2 mt12">
            <div class="stat"><div class="stat-label">秒级时间戳</div><div class="stat-value mono" id="dtOutS">-</div></div>
            <div class="stat"><div class="stat-label">毫秒时间戳</div><div class="stat-value mono" id="dtOutMs">-</div></div>
          </div>
          <div class="field-row mt12">
            <input type="text" id="fmtIn" class="mono" value="YYYY-MM-DD HH:mm:ss" />
            <button class="btn btn-sm" id="fmtBtn">按格式输出</button>
          </div>
          <div id="fmtOut"></div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    /* 当前时间 */
    let timer = null;
    function tick() {
      const now = Date.now();
      wrap.querySelector('#tsS').textContent = Math.floor(now / 1000);
      wrap.querySelector('#tsLocal').textContent = fmtDateTime(now) + ' ' + WEEK[new Date(now).getDay()];
      wrap.querySelector('#tsIso').textContent = new Date(now).toISOString();
    }
    function loop() {
      return setInterval(() => {
        if (!document.body.contains(wrap)) return clearInterval(timer);
        tick();
      }, 1000);
    }
    tick();
    timer = loop();
    // 切换工具时立刻停表，而不是等下一次 tick 才发现 DOM 已移除
    onDispose(wrap, () => clearInterval(timer));
    wrap.querySelector('#ticking').addEventListener('change', (e) => {
      clearInterval(timer);
      if (e.target.checked) timer = loop();
    });
    wrap.querySelector('#copyS').addEventListener('click', () => copy(wrap.querySelector('#tsS').textContent));
    remember(wrap.querySelector('#tsIn'), 'timestamp.ts');

    /* 时间戳 → 本地时间 */
    function convertTs() {
      const raw = wrap.querySelector('#tsIn').value.trim();
      const unit = wrap.querySelector('#tsUnit').value;
      const out = wrap.querySelector('#tsOut');
      if (!raw) return (out.innerHTML = '<div class="empty">请输入时间戳</div>');
      if (!/^-?\d+$/.test(raw)) return (out.innerHTML = '<div class="alert err">时间戳只能由数字组成</div>');
      const n = Number(raw);
      let ts;
      let unitTxt;
      let altMs = null;
      if (unit === 's') {
        ts = n * 1000;
        unitTxt = '秒';
      } else if (unit === 'ms') {
        ts = n;
        unitTxt = '毫秒';
      } else {
        // 位数只能区分「13 位毫秒」与「10 位秒」。10~11 位其实也可能是 1970~1973 年的毫秒戳，
        // 当按秒换算已远超常用范围时，额外给出另一种解读，避免默默显示一个离谱的年份。
        const asMs = String(Math.abs(n)).length > 11;
        ts = asMs ? n : n * 1000;
        unitTxt = asMs ? '毫秒' : '秒';
        if (!asMs && n * 1000 > Date.UTC(2100, 0, 1)) {
          const d = new Date(n);
          if (!Number.isNaN(d.getTime())) altMs = d;
        }
      }
      const date = new Date(ts);
      if (Number.isNaN(date.getTime())) {
        return (out.innerHTML = '<div class="alert err">时间戳超出可表示范围（无法转换为日期）</div>');
      }
      out.innerHTML = `
        <table class="tbl zebra">
          <tr><th style="width:150px">识别单位</th><td>${unitTxt}</td></tr>
          <tr><th>本地时间</th><td class="mono">${fmtDateTime(ts)} ${WEEKDAYS[date.getDay()]}</td></tr>
          <tr><th>ISO 8601</th><td class="mono">${date.toISOString()}</td></tr>
          <tr><th>相对现在</th><td>${relative(ts)}</td></tr>
        </table>
        ${altMs
          ? `<div class="alert warn mt8">此数值也可能是毫秒时间戳（对应 ${fmtDateTime(n)}）；如需按毫秒解读，请在单位下拉中选择「毫秒」。</div>`
          : ''}
        <div class="btn-row mt8">
          <button class="btn btn-sm" id="copyLocal">复制本地时间</button>
        </div>
      `;
      out.querySelector('#copyLocal').addEventListener('click', () => copy(fmtDateTime(ts)));
    }
    wrap.querySelector('#tsConv').addEventListener('click', convertTs);
    wrap.querySelector('#tsNow').addEventListener('click', () => {
      wrap.querySelector('#tsIn').value = Math.floor(Date.now() / 1000);
      convertTs();
    });
    wrap.querySelector('#tsIn').addEventListener('keydown', (e) => e.key === 'Enter' && convertTs());

    /* 本地时间 → 时间戳 */
    const dtIn = wrap.querySelector('#dtIn');
    const dtErr = formError(dtIn.closest('.field-row'), dtIn);

    function currentTs() {
      const v = dtIn.value;
      if (!v) return null;
      const d = new Date(v);
      return isNaN(d.getTime()) ? null : d.getTime();
    }
    function renderCustom(ts) {
      const fmt = wrap.querySelector('#fmtIn').value || 'YYYY-MM-DD HH:mm:ss';
      wrap.querySelector('#fmtOut').innerHTML = `<div class="alert ok mono">${esc(fmtCustom(ts, fmt))}</div>`;
    }
    function convertDt() {
      const ts = currentTs();
      if (ts === null) return dtErr.show('请选择日期时间');
      dtErr.clear();
      wrap.querySelector('#dtOutS').textContent = Math.floor(ts / 1000);
      wrap.querySelector('#dtOutMs').textContent = ts;
      renderCustom(ts);
    }
    wrap.querySelector('#dtConv').addEventListener('click', convertDt);
    wrap.querySelector('#dtNow').addEventListener('click', () => {
      const d = new Date();
      dtIn.value = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
      convertDt();
    });
    wrap.querySelector('#fmtBtn').addEventListener('click', () => {
      const ts = currentTs();
      if (ts === null) return dtErr.show('请选择日期时间');
      dtErr.clear();
      renderCustom(ts);
    });
  },
};
