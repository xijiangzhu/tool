/* 应用入口：工具注册、导航、路由、主题 */

import { h, esc, toast } from './ui.js';

import base64 from './tools/base64.js';
import json from './tools/json.js';
import cron from './tools/cron.js';
import timestamp from './tools/timestamp.js';
import urlTool from './tools/url.js';
import yamljson from './tools/yamljson.js';
import markdown from './tools/markdown.js';
import diffTool from './tools/diff.js';
import ssl from './tools/ssl.js';
import httpTool from './tools/http.js';
import ipcalc from './tools/ipcalc.js';
import dnsTool from './tools/dns.js';
import portscan from './tools/portscan.js';
import ipinfo from './tools/ipinfo.js';

const svg = (inner) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;

const ICONS = {
  dns: svg('<rect x="3" y="4" width="18" height="6.2" rx="2"/><rect x="3" y="13.8" width="18" height="6.2" rx="2"/><path d="M6.8 7.1h.01M6.8 16.9h.01"/>'),
  portscan: svg('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 12l6.4-4.6"/>'),
  ipinfo: svg('<path d="M20 10.2c0 5.2-8 11.8-8 11.8S4 15.4 4 10.2a8 8 0 1 1 16 0z"/><circle cx="12" cy="10" r="2.9"/>'),
  base64: svg('<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>'),
  json: svg('<path d="M8 3H7a2 2 0 0 0-2 2v4a2 2 0 0 1-2 2 2 2 0 0 1 2 2v4a2 2 0 0 0 2 2h1"/><path d="M16 3h1a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2 2 2 0 0 0-2 2v4a2 2 0 0 1-2 2h-1"/>'),
  cron: svg('<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/>'),
  timestamp: svg('<rect x="3" y="4" width="18" height="17" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/><path d="M9 15l2 2 4-4"/>'),
  url: svg('<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.5 1.5"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.5-1.5"/>'),
  yamljson: svg('<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>'),
  markdown: svg('<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M6 15V9l2.5 3L11 9v6M15 9v6M15 12l2.5-3L20 12v3"/>'),
  diff: svg('<rect x="3" y="4" width="7.2" height="16" rx="1.8"/><rect x="13.8" y="4" width="7.2" height="16" rx="1.8"/><path d="M5.4 9.5h2.4M5.4 13h2.4M16.2 9.5h2.4M16.2 13h2.4M16.2 16.5h2.4"/>'),
  ssl: svg('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>'),
  http: svg('<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18"/>'),
  ipcalc: svg('<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-4h14v4M12 8v8"/>'),
};

const TOOLS = [
  httpTool,
  ssl,
  dnsTool,
  ipcalc,
  portscan,
  ipinfo,
  cron,
  timestamp,
  json,
  markdown,
  diffTool,
  base64,
  urlTool,
  yamljson,
];
TOOLS.forEach((t) => (t.icon = ICONS[t.id] || ICONS.json));

const GROUPS = ['网络工具', '时间与调度', '格式化与预览', '编码转换'];

const navEl = document.getElementById('nav');
const viewEl = document.getElementById('view');
const titleEl = document.getElementById('toolTitle');
const descEl = document.getElementById('toolDesc');
const groupEl = document.getElementById('toolGroup');
const iconEl = document.getElementById('pageIcon');
const modeEl = document.getElementById('toolMode');
const searchEl = document.getElementById('navSearch');
const clockEl = document.getElementById('clockNow');
const themeBtn = document.getElementById('themeToggle');

/* ------------------------------ 主题 ------------------------------ */
const ICON_MOON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.9A8.6 8.6 0 1 1 11.1 3a6.7 6.7 0 0 0 9.9 9.9z"/></svg>`;
const ICON_SUN = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.1"/><path d="M12 2.6v2.1M12 19.3v2.1M2.6 12h2.1M19.3 12h2.1M5.3 5.3l1.5 1.5M17.2 17.2l1.5 1.5M18.7 5.3l-1.5 1.5M6.8 17.2l-1.5 1.5"/></svg>`;

function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('ops-theme', t);
  themeBtn.innerHTML = t === 'dark' ? `${ICON_SUN}<span>浅色</span>` : `${ICON_MOON}<span>深色</span>`;
}
applyTheme(localStorage.getItem('ops-theme') || 'light');
themeBtn.addEventListener('click', () => {
  applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
});

/* ------------------------------ 导航 ------------------------------ */
const NAV_KEY = 'ops-nav-collapsed';
let collapsedGroups = new Set();
try {
  collapsedGroups = new Set(JSON.parse(localStorage.getItem(NAV_KEY) || '[]'));
} catch (_) {}
const saveCollapsed = () => localStorage.setItem(NAV_KEY, JSON.stringify([...collapsedGroups]));

function buildNav() {
  navEl.innerHTML = '';
  GROUPS.forEach((g) => {
    const items = TOOLS.filter((t) => t.group === g);
    if (!items.length) return;

    const group = h(`
      <div class="nav-group ${collapsedGroups.has(g) ? 'closed' : 'open'}" data-group="${esc(g)}">
        <button type="button" class="nav-group-head" aria-expanded="${!collapsedGroups.has(g)}">
          <span class="nav-group-name">${esc(g)}</span>
          <svg class="nav-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
        </button>
        <div class="nav-group-body"><div class="nav-group-inner"></div></div>
      </div>
    `);

    const inner = group.querySelector('.nav-group-inner');
    items.forEach((t) => {
      const item = h(
        `<div class="nav-item" data-id="${t.id}">
           <span class="ico">${t.icon}</span>
           <span>${esc(t.name)}</span>
         </div>`
      );
      item.addEventListener('click', () => {
        location.hash = '#/' + t.id;
      });
      inner.appendChild(item);
    });

    group.querySelector('.nav-group-head').addEventListener('click', () => {
      const closed = group.classList.toggle('closed');
      group.classList.toggle('open', !closed);
      group.querySelector('.nav-group-head').setAttribute('aria-expanded', String(!closed));
      if (closed) collapsedGroups.add(g);
      else collapsedGroups.delete(g);
      saveCollapsed();
    });

    navEl.appendChild(group);
  });
}

function setActive(id) {
  navEl.querySelectorAll('.nav-item').forEach((el) => {
    el.classList.toggle('active', el.dataset.id === id);
  });
  const activeItem = navEl.querySelector('.nav-item.active');
  if (activeItem) {
    const group = activeItem.closest('.nav-group');
    if (group && group.classList.contains('closed')) {
      group.classList.remove('closed');
      group.classList.add('open');
      group.querySelector('.nav-group-head').setAttribute('aria-expanded', 'true');
      collapsedGroups.delete(group.dataset.group);
      saveCollapsed();
    }
  }
}

searchEl.addEventListener('input', () => {
  const q = searchEl.value.trim().toLowerCase();
  navEl.querySelectorAll('.nav-group').forEach((group) => {
    let visible = 0;
    group.querySelectorAll('.nav-item').forEach((el) => {
      const t = TOOLS.find((x) => x.id === el.dataset.id);
      const match = !q || t.name.toLowerCase().includes(q) || t.desc.toLowerCase().includes(q) ||
        (t.keywords || '').toLowerCase().includes(q);
      el.classList.toggle('hidden', !match);
      if (match) visible++;
    });
    group.classList.toggle('force-open', !!q && visible > 0);
    group.classList.toggle('hidden', visible === 0);
  });
});

/* ---------------------------- 移动端抽屉菜单 ---------------------------- */
const navToggle = document.getElementById('navToggle');
const navClose = document.getElementById('navClose');
const scrimEl = document.getElementById('scrim');

function setNav(open) {
  document.body.classList.toggle('nav-open', open);
  navToggle.setAttribute('aria-expanded', String(open));
}
navToggle.addEventListener('click', () =>
  setNav(!document.body.classList.contains('nav-open'))
);
navClose.addEventListener('click', () => setNav(false));
scrimEl.addEventListener('click', () => setNav(false));
window.addEventListener('hashchange', () => setNav(false));
window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') setNav(false);
});
const wideQuery = window.matchMedia('(min-width: 861px)');
const onWide = (e) => e.matches && setNav(false);
if (wideQuery.addEventListener) wideQuery.addEventListener('change', onWide);
else wideQuery.addListener(onWide);

/* ------------------------------ 路由 ------------------------------ */
let current = null;

const MODES = {
  local: { cls: 'page-mode', text: '纯本地运算', tip: '全部计算在浏览器内完成，数据不会离开本机' },
  net: { cls: 'page-mode net', text: '经本机服务转发', tip: '请求由本地 Node 服务代发，浏览器不直连第三方' },
};

async function route() {
  const id = (location.hash || '').replace('#/', '') || TOOLS[0].id;
  const tool = TOOLS.find((t) => t.id === id) || TOOLS[0];
  if (current === tool.id) return;
  current = tool.id;

  titleEl.textContent = tool.name;
  descEl.textContent = tool.desc;
  groupEl.textContent = tool.group;
  iconEl.innerHTML = tool.icon;
  const mode = tool.net ? MODES.net : MODES.local;
  modeEl.className = mode.cls;
  modeEl.title = mode.tip;
  modeEl.innerHTML = `<span class="dot"></span>${mode.text}`;
  document.title = `${tool.name} · 运维工具箱`;

  setActive(tool.id);
  viewEl.innerHTML = '';
  viewEl.scrollTop = 0;
  document.querySelector('.content').scrollTop = 0;
  try {
    tool.mount(viewEl);
  } catch (e) {
    viewEl.appendChild(
      h(`<div class="alert err">工具加载失败：${esc(e.message)}</div>`)
    );
    console.error(e);
  }
}

window.addEventListener('hashchange', route);

/* ------------------------------ 时钟 ------------------------------ */
setInterval(() => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  clockEl.textContent = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}, 1000);

/* 全局错误提示 */
window.addEventListener('unhandledrejection', (e) => {
  console.error(e.reason);
});

buildNav();
if (!location.hash) location.hash = '#/' + TOOLS[0].id;
route();

