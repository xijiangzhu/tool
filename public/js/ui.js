/* 通用 UI 组件与工具函数 */

/** 由 HTML 字符串创建 DOM 元素（支持多根节点，会用一个 div 包裹） */
export function h(html) {
  const tpl = document.createElement('template');
  tpl.innerHTML = html.trim();
  const kids = [...tpl.content.children];
  if (kids.length === 1) return kids[0];
  const box = document.createElement('div');
  kids.forEach((k) => box.appendChild(k));
  return box;
}

/** 转义 HTML */
export function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** 轻提示 */
export function toast(msg, type = 'ok') {
  const wrap = document.getElementById('toasts');
  const el = h(`<div class="toast ${type}">${esc(msg)}</div>`);
  wrap.appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .2s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 220);
  }, 2200);
}

/**
 * 表单内联错误：紧贴字段显示，样式与结果区的 .alert.err 保持一致。
 * 用户重新输入时会自动清除，并把出错控件标红、聚焦。
 * @param {HTMLElement} anchor 错误条插入位置（默认插在 anchor 后面）
 * @param {HTMLElement} field 出错的输入框或其外层容器（用于标红与监听输入）
 * @param {{ before?: boolean }} [opts] before=true 时插到 anchor 前面
 */
export function formError(anchor, field, opts = {}) {
  const el = h('<div class="field-error" hidden></div>');
  if (anchor) {
    if (opts.before) anchor.insertAdjacentElement('beforebegin', el);
    else anchor.insertAdjacentElement('afterend', el);
  }
  const clear = () => {
    el.hidden = true;
    el.textContent = '';
    if (field) field.classList.remove('is-invalid');
  };
  if (field) field.addEventListener('input', clear);
  return {
    el,
    show(msg) {
      el.textContent = msg;
      el.hidden = false;
      if (!field) return;
      field.classList.add('is-invalid');
      const target = field.matches('input, select, textarea')
        ? field
        : field.querySelector('input, select, textarea');
      if (target) {
        // 聚焦报错控件，但抑制 remember() 在 focus 时弹出的历史下拉
        target._histSuppress = true;
        target.focus();
        setTimeout(() => (target._histSuppress = false), 0);
      }
    },
    clear,
  };
}

/** 复制文本 */
export async function copy(text, tip = '已复制到剪贴板') {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast(tip);
}

/** 下载文件 */
export function download(filename, content, mime = 'text/plain;charset=utf-8') {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function debounce(fn, ms = 200) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

export function fmtBytes(n) {
  if (n == null) return '-';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
}

export function fmtNum(n) {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export const WEEKDAYS = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];

export function pad2(n) {
  return String(n).padStart(2, '0');
}

/** 统一的日期时间格式：YYYY-MM-DD HH:mm:ss，opts.week 追加星期 */
export function fmtDateTime(value, opts = {}) {
  const d = value instanceof Date ? value : new Date(value);
  const s = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(
    d.getHours()
  )}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  return opts.week ? `${s} ${WEEKDAYS[d.getDay()]}` : s;
}

/**
 * 分段选择器（.seg 内的 button[data-v]）：事件委托绑定，按钮重建后依然有效。
 * @param {HTMLElement} el .seg 容器
 * @param {(value: string, btn: HTMLButtonElement) => void} onChange
 */
export function segGroup(el, onChange) {
  const buttons = () => el.querySelectorAll('button[data-v]');
  const set = (v) => buttons().forEach((b) => b.classList.toggle('active', b.dataset.v === v));
  el.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-v]');
    if (!btn || !el.contains(btn)) return;
    set(btn.dataset.v);
    onChange(btn.dataset.v, btn);
  });
  return { set, get: () => (el.querySelector('button[data-v].active') || {}).dataset?.v || '' };
}

/** 按钮忙碌态：首次进入时记住原文案，结束后自动还原，避免各页重复写 spinner */
export function setBusy(btn, busy, label) {
  if (busy) {
    if (!btn.dataset.idleLabel) btn.dataset.idleLabel = btn.textContent.trim();
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> ${esc(label || '处理中')}`;
  } else {
    btn.disabled = false;
    btn.textContent = btn.dataset.idleLabel || btn.textContent;
  }
}

/* ------------------------- 输入历史（仅存本机浏览器） ------------------------ */

const HIST_PREFIX = 'ops.hist.';
const HIST_MAX = 8;

function histRead(key) {
  try {
    const raw = JSON.parse(localStorage.getItem(HIST_PREFIX + key) || '[]');
    return Array.isArray(raw) ? raw.filter((x) => typeof x === 'string' && x) : [];
  } catch (_) {
    return [];
  }
}
function histWrite(key, list) {
  try {
    localStorage.setItem(HIST_PREFIX + key, JSON.stringify(list.slice(0, HIST_MAX)));
  } catch (_) {}
}
function historyAdd(key, value) {
  const v = String(value == null ? '' : value).trim();
  if (!v || v.length > 500) return;
  const list = histRead(key).filter((x) => x !== v);
  list.unshift(v);
  histWrite(key, list);
}
function historyClear(key) {
  try {
    localStorage.removeItem(HIST_PREFIX + key);
  } catch (_) {}
}

const hpState = { input: null, key: '', items: [], active: -1 };
let hpEl = null;

function histPanel() {
  if (hpEl) return hpEl;
  hpEl = h(`
    <div class="hist-pop" hidden>
      <div class="hist-head"><span>最近使用</span><span class="hist-count"></span></div>
      <div class="hist-list"></div>
      <div class="hist-foot"><button type="button" class="hist-clear">清空该字段记录</button></div>
    </div>
  `);
  document.body.appendChild(hpEl);
  hpEl.addEventListener('mousedown', (e) => e.preventDefault());
  hpEl.querySelector('.hist-foot').addEventListener('click', () => {
    historyClear(hpState.key);
    histHide();
  });
  hpEl.querySelector('.hist-list').addEventListener('click', (e) => {
    const item = e.target.closest('.hist-item');
    if (item) histPick(Number(item.dataset.i));
  });
  return hpEl;
}

function histHide() {
  if (!hpEl) return;
  hpEl.hidden = true;
  hpState.input = null;
  hpState.items = [];
  hpState.active = -1;
}

function histRender() {
  const p = histPanel();
  p.querySelector('.hist-count').textContent = `${hpState.items.length} 条`;
  p.querySelector('.hist-list').innerHTML = hpState.items
    .map(
      (v, i) =>
        `<div class="hist-item${i === hpState.active ? ' active' : ''}" data-i="${i}" title="${esc(v)}">${esc(v)}</div>`
    )
    .join('');
}

function histShow(input, key, items) {
  if (!items.length || !input.isConnected) return histHide();
  const p = histPanel();
  hpState.input = input;
  hpState.key = key;
  hpState.items = items;
  hpState.active = -1;
  histRender();
  const r = input.getBoundingClientRect();
  const width = Math.min(Math.max(r.width, 210), 620);
  p.style.width = `${Math.round(width)}px`;
  p.hidden = false;
  const ph = p.offsetHeight;
  let top = r.bottom + 6;
  if (top + ph > window.innerHeight - 10) {
    const up = r.top - ph - 6;
    top = up > 10 ? up : Math.max(10, window.innerHeight - ph - 10);
  }
  const left = Math.min(Math.max(8, r.left), window.innerWidth - width - 10);
  p.style.top = `${Math.round(top)}px`;
  p.style.left = `${Math.round(left)}px`;
}

function histPick(i) {
  const v = hpState.items[i];
  const input = hpState.input;
  if (!v || !input) return;
  input.value = v;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  historyAdd(hpState.key, v);
  histHide();
}

/* 面板打开时用捕获阶段拦下方向键 / 回车，避免同时触发工具本身的动作 */
document.addEventListener(
  'keydown',
  (e) => {
    if (!hpEl || hpEl.hidden || !hpState.items.length) return;
    if (!hpState.input || !hpState.input.isConnected) return histHide();
    if (e.key === 'Escape') {
      histHide();
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      e.stopPropagation();
      const n = hpState.items.length;
      hpState.active =
        e.key === 'ArrowDown' ? (hpState.active + 1) % n : (hpState.active - 1 + n) % n;
      histRender();
      const el = hpEl.querySelector('.hist-item.active');
      if (el) el.scrollIntoView({ block: 'nearest' });
      return;
    }
    if (e.key === 'Enter') {
      if (hpState.active >= 0) {
        // 选中了历史项：回车即回填，拦下不让工具同时提交
        e.preventDefault();
        e.stopPropagation();
        histPick(hpState.active);
      } else {
        // 未选中历史项：用户在提交表单，收起面板，提交动作照常进行
        histHide();
      }
    }
  },
  true
);

document.addEventListener(
  'mousedown',
  (e) => {
    if (!hpEl || hpEl.hidden) return;
    if (e.target === hpState.input || hpEl.contains(e.target)) return;
    histHide();
  },
  true
);
document.addEventListener('scroll', () => hpEl && !hpEl.hidden && histHide(), true);
window.addEventListener('resize', () => histHide());
window.addEventListener('hashchange', () => histHide());

/**
 * 给单行输入框挂上「最近使用」下拉：值存 localStorage，点击即可回填。
 * @param {HTMLInputElement} input
 * @param {string} key 存储键（按工具 + 字段区分）
 */
export function remember(input, key) {
  if (!input) return input;
  const own = () => hpState.input === input;

  function show() {
    // 程序化聚焦（如表单报错时聚焦出错控件）不应顺带弹出「最近使用」
    if (input._histSuppress) return;
    const q = input.value.trim().toLowerCase();
    const list = histRead(key)
      .filter((v) => !q || v.toLowerCase().includes(q))
      .slice(0, HIST_MAX);
    if (!list.length) return histHide();
    histShow(input, key, list);
  }

  input.setAttribute('autocomplete', 'off');
  input.addEventListener('focus', show);
  input.addEventListener('click', show);
  input.addEventListener('input', () => {
    if (own()) show();
  });
  input.addEventListener('change', () => historyAdd(key, input.value));
  input.addEventListener('blur', () => {
    setTimeout(() => {
      if (own()) histHide();
    }, 120);
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') historyAdd(key, input.value);
  });
  return input;
}

/** 代码块组件：标题栏（标题 + 字数 + 高亮/复制）+ 可编辑文本框 */
export function codeBox(opts = {}) {
  const lang = opts.lang || '';
  const el = h(`
    <div class="out-box">
      <div class="out-bar">
        <span class="out-title"${opts.title ? '' : ' style="display:none"'}>${esc(opts.title || '')}</span>
        <span class="out-meta"></span>
        <span class="out-actions">
          ${lang && window.Prism && window.Prism.languages[lang] ? '<button class="btn btn-sm btn-ghost" data-act="hl" title="语法高亮开关">高亮</button>' : ''}
          <button class="btn btn-sm btn-ghost" data-act="copy">复制</button>
          ${opts.download ? '<button class="btn btn-sm btn-ghost" data-act="dl">下载</button>' : ''}
        </span>
      </div>
      <div class="out-body">
        <textarea class="mono" spellcheck="false" placeholder="${esc(opts.placeholder || '')}">${esc(opts.value || '')}</textarea>
        <pre class="code" style="display:none"><code></code></pre>
      </div>
    </div>
  `);
  const ta = el.querySelector('textarea');
  const pre = el.querySelector('pre');
  const code = el.querySelector('code');
  const meta = el.querySelector('.out-meta');
  const body = el.querySelector('.out-body');
  if (opts.height) {
    /* 滚动交给外层 .out-body（滚动条光标为手型），文本框只负责随内容增高 */
    body.style.height = opts.height;
    pre.style.minHeight = opts.height;
  }
  function fit() {
    ta.style.height = 'auto';
    ta.style.height = ta.scrollHeight + 'px';
  }
  /* overscroll-behavior:contain 会在框内无可滚内容时连页面滚轮一起吞掉，
     因此只在框内真正可滚（scrollHeight 超出）时才启用，其余时候放行滚动链 */
  function syncContain() {
    body.style.overscrollBehavior = body.scrollHeight > body.clientHeight + 1 ? 'contain' : 'auto';
  }
  if (typeof ResizeObserver === 'function') {
    const ro = new ResizeObserver(syncContain);
    ro.observe(body);
    ro.observe(ta);
  }
  let currentLang = lang;
  let highlighted = false;
  const hlBtn = el.querySelector('[data-act="hl"]');

  function syncMeta() {
    const v = ta.value;
    meta.textContent = v
      ? `${v.length} 字符 · ${fmtBytes(new Blob([v]).size)}`
      : '0 字符';
  }
  function renderHighlight() {
    const v = ta.value;
    code.textContent = v;
    code.className = currentLang ? `language-${currentLang}` : '';
    if (window.Prism && currentLang && window.Prism.languages[currentLang]) {
      try {
        window.Prism.highlightElement(code);
      } catch (_) {}
    }
  }
  /** 高亮视图开关：开 = 隐藏可编辑文本框、显示 Prism 高亮的只读 <pre> */
  function setHighlight(on) {
    const canHl = !!(currentLang && window.Prism && window.Prism.languages[currentLang]);
    highlighted = !!on && canHl;
    if (hlBtn) hlBtn.classList.toggle('active', highlighted);
    ta.style.display = highlighted ? 'none' : '';
    pre.style.display = highlighted ? '' : 'none';
    if (highlighted) {
      renderHighlight();
      pre.scrollTop = ta.scrollTop;
      pre.scrollLeft = ta.scrollLeft;
    }
  }
  el.querySelector('[data-act="copy"]').addEventListener('click', () => copy(ta.value));
  if (hlBtn) hlBtn.addEventListener('click', () => setHighlight(!highlighted));
  const dlBtn = el.querySelector('[data-act="dl"]');
  if (dlBtn) {
    dlBtn.addEventListener('click', () =>
      download(opts.download.name || 'output.txt', ta.value, opts.download.mime)
    );
  }
  ta.addEventListener('input', () => {
    fit();
    syncContain();
    syncMeta();
    if (highlighted) renderHighlight();
  });

  fit();
  syncContain();
  syncMeta();

  return {
    el,
    ta,
    getValue: () => ta.value,
    setValue(v) {
      ta.value = v;
      fit();
      syncContain();
      syncMeta();
      if (highlighted) renderHighlight();
    },
    setLang(l) {
      currentLang = l;
      const canHl = !!(currentLang && window.Prism && window.Prism.languages[currentLang]);
      if (hlBtn) hlBtn.style.display = canHl ? '' : 'none';
      if (highlighted && !canHl) setHighlight(false);
      else if (highlighted) renderHighlight();
    },
    setHighlight,
    setTitle(t) {
      const el2 = el.querySelector('.out-title');
      el2.textContent = t;
      el2.style.display = t ? '' : 'none';
    },
    onChange(fn) {
      ta.addEventListener('input', () => fn(ta.value));
    },
  };
}

export function api(path, data) {
  return fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data || {}),
  }).then((r) => r.json());
}
