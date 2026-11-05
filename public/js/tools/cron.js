/* Cron 表达式生成器 */
import { h, copy, toast, esc, remember, segGroup, pad2, WEEKDAYS, fmtDateTime, formError } from '../ui.js';

const MONTH_LABELS = ['1月', '2月', '3月', '4月', '5月', '6月', '7月', '8月', '9月', '10月', '11月', '12月'];

const FIELDS = [
  { key: 'minute', name: '分钟', min: 0, max: 59 },
  { key: 'hour', name: '小时', min: 0, max: 23 },
  { key: 'dom', name: '日', min: 1, max: 31 },
  { key: 'month', name: '月', min: 1, max: 12, labels: MONTH_LABELS },
  { key: 'dow', name: '星期', min: 0, max: 6, labels: WEEKDAYS },
];

const PRESETS = [
  ['每分钟', '* * * * *'],
  ['每 5 分钟', '*/5 * * * *'],
  ['每 15 分钟', '*/15 * * * *'],
  ['每 30 分钟', '*/30 * * * *'],
  ['每小时整点', '0 * * * *'],
  ['每天 00:00', '0 0 * * *'],
  ['每天 02:30', '30 2 * * *'],
  ['每天 08:00、20:00', '0 8,20 * * *'],
  ['工作日 09:00', '0 9 * * 1-5'],
  ['每周一 03:00', '0 3 * * 1'],
  ['每月 1 号 00:00', '0 0 1 * *'],
  ['每年 1 月 1 日', '0 0 1 1 *'],
];

function compileField(str, min, max) {
  if (!str || str === '*' || str === '?') return () => true;
  const tests = str.split(',').map((part) => {
    if (part === 'L') return () => false;
    const [range, stepRaw] = part.split('/');
    const step = stepRaw ? parseInt(stepRaw, 10) : 1;
    if (range === '*') return (v) => (v - min) % step === 0;
    const m = /^(\d+)-(\d+)$/.exec(range);
    if (m) {
      const a = +m[1], b = +m[2];
      return (v) => v >= a && v <= b && (v - a) % step === 0;
    }
    const n = parseInt(range, 10);
    return (v) => v === n;
  });
  return (v) => tests.some((t) => t(v));
}

function nextRuns(expr, count = 5, from = new Date()) {
  const parts = expr.trim().split(/\s+/).filter(Boolean);
  if (parts.length !== 5) return [];
  const [min, hour, dom, mon, dow] = parts;
  const fMin = compileField(min, 0, 59);
  const fHour = compileField(hour, 0, 23);
  const fDom = compileField(dom, 1, 31);
  const fMon = compileField(mon, 1, 12);
  const fDow = compileField(dow, 0, 6);
  const domRestricted = dom !== '*' && dom !== '?';
  const dowRestricted = dow !== '*' && dow !== '?';

  const d = new Date(from.getTime());
  d.setMilliseconds(0);
  d.setSeconds(0);
  d.setMinutes(d.getMinutes() + 1);

  const out = [];
  const maxIter = 366 * 24 * 60;
  let iter = 0;
  while (out.length < count && iter++ < maxIter) {
    if (!fMon(d.getMonth() + 1)) {
      // 直接跳到下个月 1 日 00:00；用 setHours(24) 会在「当月 1 日 / 2 日」之间循环
      d.setMonth(d.getMonth() + 1, 1);
      d.setHours(0, 0, 0, 0);
      continue;
    }
    const domOk = fDom(d.getDate());
    const dowOk = fDow(d.getDay());
    const dayOk = domRestricted && dowRestricted ? domOk || dowOk : domRestricted ? domOk : dowRestricted ? dowOk : true;
    if (!dayOk || !fHour(d.getHours()) || !fMin(d.getMinutes())) {
      d.setMinutes(d.getMinutes() + 1);
      continue;
    }
    out.push(new Date(d.getTime()));
    d.setMinutes(d.getMinutes() + 1);
  }
  return out;
}

function fmtShort(d) {
  return `${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}
function relText(d) {
  const diff = Math.max(0, d.getTime() - Date.now());
  const m = Math.round(diff / 60000);
  if (m < 1) return '不到 1 分钟';
  if (m < 60) return `${m} 分钟后`;
  const hh = Math.floor(m / 60), mm = m % 60;
  if (hh < 24) return mm ? `${hh} 小时 ${mm} 分钟后` : `${hh} 小时后`;
  const dd = Math.floor(hh / 24), rh = hh % 24;
  return rh ? `${dd} 天 ${rh} 小时后` : `${dd} 天后`;
}

export default {
  id: 'cron',
  name: 'Cron 生成器',
  group: '时间与调度',
  desc: '可视化生成 Linux Cron 表达式，实时预览下次执行时间',
  keywords: 'cron 定时任务 调度 表达式 crontab',
  mount(root) {
    root.innerHTML = '';
    const state = {};
    FIELDS.forEach((f) => {
      state[f.key] = { mode: 'every', each: 1, spec: [], from: f.min, to: f.max };
    });
    let selected = 'minute';

    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>生成的 Cron 表达式</div>
          <div class="cron-hero-parse">
            <input type="text" id="exprIn" class="mono" placeholder="粘贴表达式解析，如 */5 * * * *" />
            <button class="btn btn-sm" id="parse">解析</button>
          </div>
        </div>
        <div class="card-body">
          <div class="cx-hero" id="exprView"></div>
          <div class="cron-desc" id="desc"></div>
          <div class="cron-hero-foot">
            <button class="btn btn-primary" id="copy">复制表达式</button>
            <button class="btn" id="copyCmd">复制 crontab 行</button>
            <div class="cron-next-now" id="nextNow"></div>
          </div>
        </div>
        <div class="cron-presets" id="presets"></div>
      </section>

      <div class="cron-cols">
        <section class="card">
          <div class="card-head">
            <div class="card-title"><span class="dot"></span>字段设置<span class="card-tag" id="editTag">分钟</span></div>
            <div class="card-note">点击上方任一段切换编辑对象</div>
          </div>
          <div class="card-body" id="editor"></div>
        </section>

        <section class="card">
          <div class="card-head">
            <div class="card-title"><span class="dot"></span>下次执行时间</div>
            <div class="card-note">本机时区 · 最近 5 次</div>
          </div>
          <div class="card-body flush" id="next"></div>
        </section>
      </div>
    `);
    root.appendChild(wrap);
    remember(wrap.querySelector('#exprIn'), 'cron.expr');

    const exprView = wrap.querySelector('#exprView');
    const exprIn = wrap.querySelector('#exprIn');
    const exprErr = formError(exprView, exprIn, { before: true });
    const editorEl = wrap.querySelector('#editor');
    const nextEl = wrap.querySelector('#next');
    const nextNowEl = wrap.querySelector('#nextNow');
    const editTagEl = wrap.querySelector('#editTag');

    const fieldOf = (key) => FIELDS.find((f) => f.key === key);
    const label = (v, f) => (f.labels ? f.labels[v - f.min] : String(v));

    function fieldValue(f) {
      const s = state[f.key];
      if (s.mode === 'every') return '*';
      if (s.mode === 'each') return `*/${Math.max(1, s.each)}`;
      if (s.mode === 'spec') {
        if (!s.spec.length) return '*';
        return [...s.spec].sort((a, b) => a - b).join(',');
      }
      return `${Math.min(s.from, s.to)}-${Math.max(s.from, s.to)}`;
    }

    function expression() {
      return FIELDS.map(fieldValue).join(' ');
    }

    /* --------------------------- 表达式概览 --------------------------- */
    function renderExpr() {
      exprView.innerHTML = FIELDS.map(
        (f) => `
        <div class="cx-seg ${selected === f.key ? 'active' : ''}" data-k="${f.key}">
          <span class="cx-val">${esc(fieldValue(f))}</span>
          <span class="cx-name">${f.name}</span>
        </div>`
      ).join('');
      exprView.querySelectorAll('.cx-seg').forEach((el) =>
        el.addEventListener('click', () => {
          selected = el.dataset.k;
          renderExpr();
          renderEditor();
        })
      );
      editTagEl.textContent = fieldOf(selected).name;
      wrap.querySelector('#desc').textContent = describe();
    }

    function listText(v, f, suffix) {
      return v.includes(',')
        ? v.split(',').map((x) => label(Number(x), f)).join('、') + suffix
        : v.includes('-')
        ? label(Number(v.split('-')[0]), f) + ' 至 ' + label(Number(v.split('-')[1]), f) + suffix
        : label(Number(v), f) + suffix;
    }

    function describe() {
      const min = fieldValue(FIELDS[0]);
      const hour = fieldValue(FIELDS[1]);
      const dom = fieldValue(FIELDS[2]);
      const mon = fieldValue(FIELDS[3]);
      const dow = fieldValue(FIELDS[4]);

      let dayTxt = '';
      if (dom !== '*') dayTxt = listText(dom, FIELDS[2], '号');
      if (dow !== '*') {
        const wt = dow.startsWith('*/')
          ? `星期字段每隔 ${dow.slice(2)} 个取值（${Array.from({ length: 7 }, (_, i) => i)
              .filter((i) => i % Number(dow.slice(2)) === 0)
              .map((i) => WEEKDAYS[i])
              .join('、')}）`
          : dow.includes(',')
          ? dow.split(',').map((x) => WEEKDAYS[Number(x) % 7]).join('、')
          : dow.includes('-')
          ? `${WEEKDAYS[Number(dow.split('-')[0]) % 7]} 至 ${WEEKDAYS[Number(dow.split('-')[1]) % 7]}`
          : WEEKDAYS[Number(dow) % 7];
        // 标准 cron 语义：日、星期同时被限定时为「或」（满足其一即执行）
        dayTxt = dayTxt ? `${dayTxt} 或 ${wt}` : wt;
      }
      if (mon !== '*') dayTxt += (dayTxt ? '（' : '') + listText(mon, FIELDS[3], '') + (dayTxt ? '）' : '');

      let timeTxt;
      if (min === '*' && hour === '*') timeTxt = '每分钟';
      else if (hour === '*') timeTxt = min.startsWith('*/') ? `每 ${min.slice(2)} 分钟` : `每小时的第 ${min.includes(',') ? min.split(',').join('、') : min} 分`;
      else if (min === '*') timeTxt = `${hour} 点的每分钟`;
      else if (min.startsWith('*/')) {
        const hours = hour.split(',').map(Number);
        const hourTxt = hours.map((v) => `${pad2(v)} 点`).join('、');
        const invalidHour = hours.some((v) => v < 0 || v > 23);
        timeTxt = `${hourTxt}每隔 ${min.slice(2)} 分钟${invalidHour ? '（小时值超出 0–23）' : ''}`;
      }
      else {
        const hv = hour.includes(',') ? hour.split(',').map((x) => pad2(x)).join('、') : hour;
        timeTxt = `${hv}:${pad2(min)}`;
      }
      return `${dayTxt ? dayTxt + ' 的 ' : ''}${timeTxt}${/[0-9:]$/.test(timeTxt) ? ' ' : ''}执行一次`;
    }

    /* ---------------------------- 字段编辑 ---------------------------- */
    function renderEditor() {
      const f = fieldOf(selected);
      const s = state[selected];
      editorEl.innerHTML = `
        <div class="cron-editor-head">
          <div>
            <span class="fname">${f.name}</span>
            <span class="frange">取值范围 ${f.min} - ${f.max}</span>
          </div>
          <div class="seg" data-role="mode">
            <button data-v="every" class="${s.mode === 'every' ? 'active' : ''}">全部 *</button>
            <button data-v="each" class="${s.mode === 'each' ? 'active' : ''}">间隔 */n</button>
            <button data-v="spec" class="${s.mode === 'spec' ? 'active' : ''}">指定</button>
            <button data-v="range" class="${s.mode === 'range' ? 'active' : ''}">范围</button>
          </div>
        </div>
        <div data-role="body"></div>
      `;
      const body = editorEl.querySelector('[data-role="body"]');

      if (s.mode === 'every') {
        body.innerHTML = `<div class="muted" style="font-size:13px">不限制「${f.name}」，在表达式中记为 <span class="mono" style="color:var(--accent-2)">*</span></div>`;
      } else if (s.mode === 'each') {
        body.innerHTML = `
          <div class="row">
            <span>每隔</span>
            <input type="number" min="1" max="${f.max}" value="${s.each}" data-role="each" class="w96" />
            <span>个${f.name}</span>
            <span class="mono note">= ${fieldValue(f)}</span>
          </div>`;
      } else if (s.mode === 'spec') {
        const cells = [];
        for (let v = f.min; v <= f.max; v++) {
          cells.push(`<div class="cron-cell ${s.spec.includes(v) ? 'active' : ''}" data-v="${v}">${label(v, f)}</div>`);
        }
        body.innerHTML = `
          <div class="cron-grid">${cells.join('')}</div>
          <div class="btn-row mt12">
            <button class="btn btn-sm btn-ghost" data-role="all">全选</button>
            <button class="btn btn-sm btn-ghost" data-role="none">清空</button>
            <span class="note">已选 ${s.spec.length} 项，未选时按 * 处理</span>
          </div>`;
      } else {
        body.innerHTML = `
          <div class="row">
            <span>从</span>
            <input type="number" min="${f.min}" max="${f.max}" value="${s.from}" data-role="from" class="w96" />
            <span>到</span>
            <input type="number" min="${f.min}" max="${f.max}" value="${s.to}" data-role="to" class="w96" />
            <span class="muted">（包含两端）</span>
            <span class="mono note">= ${fieldValue(f)}</span>
          </div>`;
      }

      segGroup(editorEl.querySelector('[data-role="mode"]'), (v) => {
        s.mode = v;
        renderEditor();
        renderExpr();
        renderNext();
      });
      editorEl.querySelectorAll('.cron-cell').forEach((c) =>
        c.addEventListener('click', () => {
          const v = Number(c.dataset.v);
          const i = s.spec.indexOf(v);
          if (i >= 0) s.spec.splice(i, 1);
          else s.spec.push(v);
          renderEditor();
          renderExpr();
          renderNext();
        })
      );
      const eachIpt = editorEl.querySelector('[data-role="each"]');
      if (eachIpt)
        eachIpt.addEventListener('input', () => {
          s.each = Math.max(1, parseInt(eachIpt.value || '1', 10));
          renderExpr();
          renderNext();
        });
      const fromIpt = editorEl.querySelector('[data-role="from"]');
      if (fromIpt)
        fromIpt.addEventListener('input', () => {
          s.from = Number(fromIpt.value);
          renderExpr();
          renderNext();
        });
      const toIpt = editorEl.querySelector('[data-role="to"]');
      if (toIpt)
        toIpt.addEventListener('input', () => {
          s.to = Number(toIpt.value);
          renderExpr();
          renderNext();
        });
      const allBtn = editorEl.querySelector('[data-role="all"]');
      if (allBtn)
        allBtn.addEventListener('click', () => {
          s.spec = [];
          for (let v = f.min; v <= f.max; v++) s.spec.push(v);
          renderEditor();
          renderExpr();
          renderNext();
        });
      const noneBtn = editorEl.querySelector('[data-role="none"]');
      if (noneBtn)
        noneBtn.addEventListener('click', () => {
          s.spec = [];
          renderEditor();
          renderExpr();
          renderNext();
        });
    }

    /* ---------------------------- 执行时间 ---------------------------- */
    function renderNext() {
      const runs = nextRuns(expression(), 5);
      if (!runs.length) {
        nextNowEl.innerHTML = '';
        nextEl.innerHTML = '<div class="alert warn" style="margin:14px">无法计算下次执行时间，请检查各字段取值</div>';
        return;
      }
      nextNowEl.innerHTML = `下次执行 <b>${fmtShort(runs[0])}</b><span class="rel">${relText(runs[0])}</span>`;
      nextEl.innerHTML = `<div class="run-list">${runs
        .map(
          (d, i) => `
          <div class="run-item ${i === 0 ? 'is-next' : ''}">
            <span class="run-idx">${i + 1}</span>
            <span class="run-time">${fmtDateTime(d, { week: true })}</span>
            <span class="run-in">${relText(d)}</span>
          </div>`
        )
        .join('')}</div>`;
    }

    /* ------------------------------ 预设 ------------------------------ */
    wrap.querySelector('#presets').innerHTML =
      '<span class="lbl">常用预设</span>' +
      PRESETS.map(([n, v]) => `<span class="chip" data-v="${v}">${esc(n)}</span>`).join('');
    wrap.querySelectorAll('#presets .chip').forEach((c) =>
      c.addEventListener('click', () => {
        wrap.querySelector('#exprIn').value = c.dataset.v;
        parseExpr(c.dataset.v);
      })
    );

    function parseExpr(text) {
      const parts = text.trim().split(/\s+/);
      if (parts.length !== 5) {
        return exprErr.show('Cron 表达式需为 5 位，如 */5 * * * *');
      }
      for (let i = 0; i < FIELDS.length; i++) {
        const field = FIELDS[i];
        // 标准 crontab 的星期字段允许 0-7（7 = 周日），这里放行 7 并在下方归一化为 0-6
        const hi = field.key === 'dow' ? 7 : field.max;
        for (const item of parts[i].split(',')) {
          if (item === '*' || item === '?') continue;
          const base = item.split('/')[0];
          const values = /^\d+-\d+$/.test(base) ? base.split('-').map(Number) : /^\d+$/.test(base) ? [Number(base)] : [];
          const invalid = values.find((value) => value < field.min || value > hi);
          if (invalid !== undefined) {
            return exprErr.show(`${field.name}字段的值 ${invalid} 超出有效范围（${field.min}–${hi}）`);
          }
        }
      }
      exprErr.clear();
      FIELDS.forEach((f, i) => {
        let v = parts[i];
        if (f.key === 'dow') v = normalizeDow(v);
        const s = state[f.key];
        s.spec = [];
        if (v === '*' || v === '?') s.mode = 'every';
        else if (/^\*\/(\d+)$/.test(v)) {
          s.mode = 'each';
          s.each = parseInt(v.slice(2), 10);
        } else if (/^\d+$/.test(v)) {
          s.mode = 'spec';
          s.spec = [Number(v)];
        } else if (/^\d+(,\d+)+$/.test(v)) {
          s.mode = 'spec';
          s.spec = v.split(',').map(Number);
        } else if (/^(\d+)-(\d+)$/.test(v)) {
          s.mode = 'range';
          s.from = Number(v.split('-')[0]);
          s.to = Number(v.split('-')[1]);
        } else {
          s.mode = 'every';
          toast(`${f.name} 字段含特殊语法（${v}），已按“全部”处理`);
        }
      });
      renderExpr();
      renderEditor();
      renderNext();
    }

    /** 星期字段归一化：7 按周日处理；范围含 7 时展开成具体取值列表（如 1-7 → 0,1,2,3,4,5,6） */
    function normalizeDow(v) {
      return v
        .split(',')
        .map((item) => {
          if (item === '7') return '0';
          const m = /^(\d+)-(\d+)$/.exec(item);
          if (m) {
            const a = Number(m[1]);
            const b = Number(m[2]);
            if (b === 7) {
              if (a === 0) return '0-6';
              const values = [];
              for (let x = a; x <= 7; x++) values.push(x % 7);
              return [...new Set(values)].sort((x, y) => x - y).join(',');
            }
          }
          return item;
        })
        .join(',');
    }

    wrap.querySelector('#parse').addEventListener('click', () => {
      const v = wrap.querySelector('#exprIn').value.trim();
      if (!v) return exprErr.show('请输入 Cron 表达式');
      parseExpr(v);
    });
    wrap.querySelector('#exprIn').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const v = wrap.querySelector('#exprIn').value.trim();
        if (v) parseExpr(v);
        else exprErr.show('请输入 Cron 表达式');
      }
    });

    wrap.querySelector('#copy').addEventListener('click', () => copy(expression(), '已复制表达式'));
    wrap.querySelector('#copyCmd').addEventListener('click', () =>
      copy(`${expression()} /path/to/script.sh >> /var/log/job.log 2>&1`, '已复制 crontab 行')
    );

    renderExpr();
    renderEditor();
    renderNext();
  },
};
