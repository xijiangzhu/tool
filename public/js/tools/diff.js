/* 文件差异对比：逐行 diff（Myers），支持并排 / 统一视图 */
import { h, debounce, copy, download, toast } from '../ui.js';

const SAMPLE_A = [
  'server:',
  '  host: 0.0.0.0',
  '  port: 8080',
  '  workers: 4',
  '  log_level: info',
  '',
  'cache:',
  '  enabled: false',
  '  ttl: 300',
  '',
  'upstream:',
  '  - 10.0.0.11:8080',
  '  - 10.0.0.12:8080',
].join('\n');

const SAMPLE_B = [
  'server:',
  '  host: 0.0.0.0',
  '  port: 8081',
  '  workers: 8',
  '  log_level: debug',
  '  timeout: 30s',
  '',
  'cache:',
  '  enabled: true',
  '  ttl: 600',
  '',
  'upstream:',
  '  - 10.0.0.11:8080',
  '  - 10.0.0.12:8080',
  '  - 10.0.0.13:8080',
].join('\n');

/* #region engine */

const MYERS_CAP = 1500; /* 编辑步数上限，超过则以 DP / 整段替换兜底 */
const MAX_CELLS = 12_000_000; /* DP 兜底的最大格数，防止内存爆掉 */

/** 文本 → 行数组（兼容 CRLF，忽略末尾换行） */
function splitLines(text) {
  const t = String(text || '').replace(/\r\n?/g, '\n');
  if (!t) return [];
  const arr = t.split('\n');
  if (arr[arr.length - 1] === '') arr.pop();
  return arr;
}

function normalize(line, opts) {
  let s = line;
  if (opts.ignoreWs) s = s.replace(/[ \t]+/g, ' ').trim();
  if (opts.ignoreCase) s = s.toLowerCase();
  return s;
}

/** Myers O(ND) 差分，返回 {t,x,y} 序列；超出步数上限返回 null */
function myers(a, b, cap) {
  const n = a.length;
  const m = b.length;
  const max = n + m;
  const off = max;
  const v = new Int32Array(2 * max + 1);
  const trace = [];
  let hit = -1;

  for (let d = 0; d <= max; d++) {
    if (d > cap) break;
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) x = v[off + k + 1];
      else x = v[off + k - 1] + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= n && y >= m) {
        hit = d;
        break;
      }
    }
    trace.push(v.slice(off - d, off + d + 1));
    if (hit >= 0) break;
  }
  if (hit < 0) return null;

  const out = [];
  let x = n;
  let y = m;
  for (let d = hit; d > 0; d--) {
    const prev = trace[d - 1];
    const pOff = d - 1;
    const k = x - y;
    let prevK;
    if (k === -d || (k !== d && prev[k - 1 + pOff] < prev[k + 1 + pOff])) prevK = k + 1;
    else prevK = k - 1;
    const prevX = prev[prevK + pOff];
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      out.push({ t: 'eq', x: x - 1, y: y - 1 });
      x--;
      y--;
    }
    if (x === prevX) {
      out.push({ t: 'ins', y: y - 1 });
      y--;
    } else {
      out.push({ t: 'del', x: x - 1 });
      x--;
    }
  }
  while (x > 0 && y > 0) {
    out.push({ t: 'eq', x: x - 1, y: y - 1 });
    x--;
    y--;
  }
  while (x > 0) {
    out.push({ t: 'del', x: x - 1 });
    x--;
  }
  while (y > 0) {
    out.push({ t: 'ins', y: y - 1 });
    y--;
  }
  return out.reverse();
}

/** LCS 动态规划兜底 */
function dpDiff(a, b) {
  const n = a.length;
  const m = b.length;
  const W = m + 1;
  const dp = new Int32Array((n + 1) * W);
  for (let i = n - 1; i >= 0; i--) {
    const rb = i * W;
    const nb = (i + 1) * W;
    for (let j = m - 1; j >= 0; j--) {
      dp[rb + j] = a[i] === b[j] ? dp[nb + j + 1] + 1 : Math.max(dp[nb + j], dp[rb + j + 1]);
    }
  }
  const out = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ t: 'eq', x: i, y: j });
      i++;
      j++;
    } else if (dp[(i + 1) * W + j] >= dp[i * W + j + 1]) {
      out.push({ t: 'del', x: i });
      i++;
    } else {
      out.push({ t: 'ins', y: j });
      j++;
    }
  }
  while (i < n) {
    out.push({ t: 'del', x: i });
    i++;
  }
  while (j < m) {
    out.push({ t: 'ins', y: j });
    j++;
  }
  return out;
}

/**
 * 逐行比较，返回 ops 数组：
 * { t: 'eq' | 'del' | 'ins', s: 左文本, s2: 右文本(eq), an: 左侧行号, bn: 右侧行号 }
 */
function diffLines(a, b, opts = {}) {
  const n = a.length;
  const m = b.length;
  const A = a.map((x) => normalize(x, opts));
  const B = b.map((x) => normalize(x, opts));

  let p = 0;
  while (p < n && p < m && A[p] === B[p]) p++;
  let s = 0;
  while (s < n - p && s < m - p && A[n - 1 - s] === B[m - 1 - s]) s++;

  const ops = [];
  for (let i = 0; i < p; i++) ops.push({ t: 'eq', s: a[i], s2: b[i], an: i + 1, bn: i + 1 });

  const rn = n - p - s;
  const rm = m - p - s;
  let coarse = false;

  if (rn > 0 && rm > 0) {
    const Na = A.slice(p, p + rn);
    const Nb = B.slice(p, p + rm);
    const Oa = a.slice(p, p + rn);
    const Ob = b.slice(p, p + rm);
    let local = myers(Na, Nb, MYERS_CAP);
    if (!local && rn * rm <= MAX_CELLS) local = dpDiff(Na, Nb);

    if (!local) {
      /* 超大且差异过于零散：退化为整段替换，避免浏览器卡死 */
      coarse = true;
      for (let i = 0; i < rn; i++) ops.push({ t: 'del', s: Oa[i], an: p + i + 1, bn: null });
      for (let j = 0; j < rm; j++) ops.push({ t: 'ins', s: Ob[j], an: null, bn: p + j + 1 });
    } else {
      for (const o of local) {
        if (o.t === 'eq') {
          ops.push({ t: 'eq', s: Oa[o.x], s2: Ob[o.y], an: p + o.x + 1, bn: p + o.y + 1 });
        } else if (o.t === 'del') {
          ops.push({ t: 'del', s: Oa[o.x], an: p + o.x + 1, bn: null });
        } else {
          ops.push({ t: 'ins', s: Ob[o.y], an: null, bn: p + o.y + 1 });
        }
      }
    }
  } else if (rn > 0) {
    for (let i = 0; i < rn; i++) ops.push({ t: 'del', s: a[p + i], an: p + i + 1, bn: null });
  } else if (rm > 0) {
    for (let j = 0; j < rm; j++) ops.push({ t: 'ins', s: b[p + j], an: null, bn: p + j + 1 });
  }

  for (let k = 0; k < s; k++) {
    ops.push({
      t: 'eq',
      s: a[n - s + k],
      s2: b[m - s + k],
      an: n - s + k + 1,
      bn: m - s + k + 1,
    });
  }
  return { ops, coarse };
}

/** 统计 */
function summarize(ops) {
  let ins = 0;
  let del = 0;
  let eq = 0;
  let blocks = 0;
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i];
    if (o.t === 'ins') ins++;
    else if (o.t === 'del') del++;
    else eq++;
    if (o.t !== 'eq' && (i === 0 || ops[i - 1].t === 'eq')) blocks++;
  }
  return { ins, del, eq, blocks };
}

/** 按上下文行数切分 hunk */
function buildHunks(ops, ctx = 3) {
  const marks = [];
  for (let i = 0; i < ops.length; i++) if (ops[i].t !== 'eq') marks.push(i);
  if (!marks.length) return [];
  const ranges = [];
  let start = Math.max(0, marks[0] - ctx);
  let end = Math.min(ops.length - 1, marks[0] + ctx);
  for (let k = 1; k < marks.length; k++) {
    const i = marks[k];
    if (i - ctx <= end) {
      end = Math.min(ops.length - 1, i + ctx);
    } else {
      ranges.push([start, end]);
      start = Math.max(0, i - ctx);
      end = Math.min(ops.length - 1, i + ctx);
    }
  }
  ranges.push([start, end]);
  return ranges.map(([st, en]) => ops.slice(st, en + 1));
}

function hunkHeader(hunk) {
  let aStart = 0;
  let bStart = 0;
  let aCount = 0;
  let bCount = 0;
  for (const o of hunk) {
    if (o.an != null) {
      if (!aCount) aStart = o.an;
      aCount++;
    }
    if (o.bn != null) {
      if (!bCount) bStart = o.bn;
      bCount++;
    }
  }
  return `@@ -${aStart},${aCount} +${bStart},${bCount} @@`;
}

/** 把改动块整理成「上一处 / 下一处」可跳转的锚点 */
function buildBlocks(ops) {
  const blocks = [];
  let cur = null;
  let prevAn = 0;
  let prevBn = 0;
  for (const o of ops) {
    if (o.t === 'eq') {
      if (cur) {
        blocks.push(cur);
        cur = null;
      }
      prevAn = o.an;
      prevBn = o.bn;
      continue;
    }
    if (!cur) cur = { a: null, b: null, aTo: prevAn + 1, bTo: prevBn + 1 };
    if (o.t === 'del' && cur.a == null) cur.a = o.an;
    if (o.t === 'ins' && cur.b == null) cur.b = o.bn;
  }
  if (cur) blocks.push(cur);
  return blocks.map((b) => ({ a: b.a == null ? b.aTo : b.a, b: b.b == null ? b.bTo : b.b }));
}
/* #endregion engine */

const LH = 20; /* 与 CSS 变量 --diff-lh 保持一致 */
const PAD = 10; /* 与 .diff-ta 的 padding 保持一致 */
const GUTTER = 50; /* 与 .diff-code 的行号列宽保持一致 */

export default {
  id: 'diff',
  name: '文件差异对比',
  group: '格式化与预览',
  desc: '逐行比较两份文本，差异直接标在原文件与新文件的行上，两侧共用一条滚动条',
  keywords: 'diff 差异 对比 比较 patch 文件 git 合并',
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>待比较的两份内容</div>
          <div class="row">
            <span class="card-note">红色为删除行，绿色为新增行 · 全部在浏览器内计算</span>
            <button type="button" class="btn btn-sm" id="copyDiff">复制 diff</button>
            <button type="button" class="btn btn-sm" id="dlDiff">下载 .diff</button>
          </div>
        </div>
        <div class="card-body">
          <div class="tool-bar">
            <label class="check"><input type="checkbox" id="igWs" /> 忽略空白</label>
            <label class="check"><input type="checkbox" id="igCase" /> 忽略大小写</label>
            <div class="diff-nav">
              <button type="button" class="btn btn-sm" id="prev">↑ 上一处</button>
              <button type="button" class="btn btn-sm" id="next">↓ 下一处</button>
              <span class="muted" id="navInfo">共 0 处</span>
            </div>
            <span class="spacer"></span>
            <button type="button" class="btn btn-sm" id="swap">交换左右</button>
            <button type="button" class="btn btn-sm" id="sample">示例</button>
            <button type="button" class="btn btn-sm btn-ghost" id="clear">清空</button>
          </div>

          <div class="diff-scroll" id="scroll">
            <div class="diff-inputs">
              <div class="diff-pane">
                <div class="diff-pane-head">
                  <span class="diff-pane-title">原文件<span class="pane-tag">A</span></span>
                  <span class="diff-pane-meta" id="metaA">0 行</span>
                  <span class="out-actions">
                    <button type="button" class="btn btn-sm btn-ghost" data-load="a">载入文件</button>
                    <button type="button" class="btn btn-sm btn-ghost" data-clear="a">清空</button>
                  </span>
                </div>
                <div class="diff-code">
                  <div class="diff-nums"><div class="diff-nums-in" id="numA"></div></div>
                  <div class="diff-codewrap">
                    <div class="diff-lines" id="linesA"></div>
                    <textarea class="diff-ta" id="taA" wrap="off" spellcheck="false" placeholder="粘贴原文件内容，也可拖入文件…"></textarea>
                  </div>
                </div>
                <input type="file" id="fileA" hidden />
              </div>

              <div class="diff-pane">
                <div class="diff-pane-head">
                  <span class="diff-pane-title">新文件<span class="pane-tag">B</span></span>
                  <span class="diff-pane-meta" id="metaB">0 行</span>
                  <span class="out-actions">
                    <button type="button" class="btn btn-sm btn-ghost" data-load="b">载入文件</button>
                    <button type="button" class="btn btn-sm btn-ghost" data-clear="b">清空</button>
                  </span>
                </div>
                <div class="diff-code">
                  <div class="diff-nums"><div class="diff-nums-in" id="numB"></div></div>
                  <div class="diff-codewrap">
                    <div class="diff-lines" id="linesB"></div>
                    <textarea class="diff-ta" id="taB" wrap="off" spellcheck="false" placeholder="粘贴新文件内容，也可拖入文件…"></textarea>
                  </div>
                </div>
                <input type="file" id="fileB" hidden />
              </div>
            </div>
          </div>

          <div class="diff-hbar" id="hbar" hidden><div class="diff-hbar-in" id="hbarIn"></div></div>

          <div class="result-strip mt12" id="statBar" style="display:none"></div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const scrollEl = wrap.querySelector('#scroll');
    const taA = wrap.querySelector('#taA');
    const taB = wrap.querySelector('#taB');
    const linesA = wrap.querySelector('#linesA');
    const linesB = wrap.querySelector('#linesB');
    const numA = wrap.querySelector('#numA');
    const numB = wrap.querySelector('#numB');
    const metaA = wrap.querySelector('#metaA');
    const metaB = wrap.querySelector('#metaB');
    const hbar = wrap.querySelector('#hbar');
    const hbarIn = wrap.querySelector('#hbarIn');
    const statBar = wrap.querySelector('#statBar');
    const navInfo = wrap.querySelector('#navInfo');
    const igWs = wrap.querySelector('#igWs');
    const igCase = wrap.querySelector('#igCase');

    let fileA = '';
    let fileB = '';
    let patch = '';
    let delMap = new Map();
    let insMap = new Map();
    let blocks = [];
    let navIdx = -1;

    function meta(ta, file) {
      const v = ta.value;
      const lines = v ? splitLines(v).length : 0;
      return `${file ? file + ' · ' : ''}${lines} 行 · ${v.length} 字符`;
    }
    function updateMeta() {
      metaA.textContent = meta(taA, fileA);
      metaB.textContent = meta(taB, fileB);
    }

    /* 每侧内容高度 = 行数 × 行高 + 上下内边距，由外层容器统一滚动 */
    function renderPane(side) {
      const ta = side === 'a' ? taA : taB;
      const linesEl = side === 'a' ? linesA : linesB;
      const numsEl = side === 'a' ? numA : numB;
      const marks = side === 'a' ? delMap : insMap;
      const value = ta.value;
      const count = value === '' ? 1 : value.split('\n').length;
      const lb = [];
      const nb = [];
      for (let i = 1; i <= count; i++) {
        const t = marks.get(i);
        const cls = t === 'del' ? ' del' : t === 'ins' ? ' add' : '';
        lb.push(`<div class="dl${cls}"></div>`);
        nb.push(
          `<div class="dn${cls}" data-sign="${
            t === 'del' ? '-' : t === 'ins' ? '+' : ''
          }">${i}</div>`
        );
      }
      linesEl.innerHTML = lb.join('');
      numsEl.innerHTML = nb.join('');
      ta.dataset.contentH = String(count * LH + PAD * 2);
    }

    /* 内容较少时把可编辑区撑满容器，点击任意位置都能直接输入 */
    function fitHeights() {
      const headEl = wrap.querySelector('.diff-pane-head');
      const headH = headEl ? headEl.offsetHeight : 38;
      const base = Math.max(160, scrollEl.clientHeight - headH);
      [taA, taB].forEach((ta) => {
        const own = Number(ta.dataset.contentH) || 0;
        ta.style.height = `${Math.max(own, base)}px`;
      });
    }

    /* 按字符宽度估算是否需要横向平移（两栏等宽，平移由下方共用横条驱动） */
    let charW = 0;
    function measureChar() {
      if (charW) return charW;
      const ctx = document.createElement('canvas').getContext('2d');
      const cs = getComputedStyle(taA);
      ctx.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
      charW = ctx.measureText('0'.repeat(40)).width / 40;
      return charW;
    }
    function maxCols(text) {
      let m = 0;
      for (const line of text.split('\n')) {
        let n = 0;
        for (const ch of line) n += ch === '\t' ? 4 : 1;
        if (n > m) m = n;
      }
      return m;
    }
    /* 两栏始终各占一半宽度；超长行不再把网格撑宽（否则左栏会占满可视区），
       改为把两侧文本按同一个横向偏移平移，由下方一条共用滚动条驱动 */
    const codeA = taA.parentElement;
    const codeB = taB.parentElement;
    function setDx(x) {
      const v = String(Math.round(x));
      codeA.style.setProperty('--dx', v);
      codeB.style.setProperty('--dx', v);
    }
    function maxDx() {
      return hbar.hidden ? 0 : Math.max(0, hbarIn.offsetWidth - hbar.clientWidth);
    }
    function fitWidth() {
      const cols = Math.max(maxCols(taA.value), maxCols(taB.value));
      const need = GUTTER + 26 + cols * measureChar();
      const half = scrollEl.clientWidth / 2;
      const over = need > half + 1;
      const taW = over ? Math.round(need - GUTTER) : 0;
      [taA, taB].forEach((ta) => {
        ta.style.width = over ? `${taW}px` : '100%';
      });
      [linesA, linesB].forEach((el) => {
        el.style.width = over ? `${taW}px` : '100%';
      });
      hbar.hidden = !over;
      if (!over) {
        hbar.scrollLeft = 0;
        hbarIn.style.width = '100%';
        setDx(0);
        return;
      }
      const barW = hbar.clientWidth || scrollEl.clientWidth;
      hbarIn.style.width = `${Math.round(barW + (need - half))}px`;
      setDx(Math.min(hbar.scrollLeft, maxDx()));
    }

    hbar.addEventListener('scroll', () => setDx(Math.min(hbar.scrollLeft, maxDx())));
    /* Shift + 滚轮在编辑区上也能横向平移 */
    scrollEl.addEventListener(
      'wheel',
      (e) => {
        if (!e.shiftKey || hbar.hidden) return;
        const d = e.deltaY || e.deltaX;
        if (!d) return;
        hbar.scrollLeft = Math.max(0, Math.min(maxDx(), hbar.scrollLeft + d));
        e.preventDefault();
      },
      { passive: false }
    );

    function toPatch(ops) {
      const out = ['--- a/原文件', '+++ b/新文件'];
      for (const hk of buildHunks(ops, 3)) {
        out.push(hunkHeader(hk));
        for (const o of hk) {
          out.push((o.t === 'del' ? '-' : o.t === 'ins' ? '+' : ' ') + o.s);
        }
      }
      return out.join('\n') + '\n';
    }

    function gotoBlock(i) {
      if (!blocks.length) return;
      navIdx = (i + blocks.length) % blocks.length;
      const blk = blocks[navIdx];
      const headH = wrap.querySelector('.diff-pane-head').offsetHeight || 38;
      const ln = blk.a || blk.b || 1;
      scrollEl.scrollTop = Math.max(0, PAD + (ln - 1) * LH - headH - 4);
      navInfo.textContent = `第 ${navIdx + 1} / ${blocks.length} 处`;
    }

    function run() {
      updateMeta();
      const a = splitLines(taA.value);
      const b = splitLines(taB.value);

      if (!a.length && !b.length) {
        delMap = new Map();
        insMap = new Map();
        blocks = [];
        navIdx = -1;
        patch = '';
        renderPane('a');
        renderPane('b');
        statBar.style.display = 'none';
        navInfo.textContent = '共 0 处';
        fitWidth();
        fitHeights();
        return;
      }

      const t0 = performance.now();
      const { ops, coarse } = diffLines(a, b, {
        ignoreWs: igWs.checked,
        ignoreCase: igCase.checked,
      });
      const st = summarize(ops);
      const used = Math.max(0.1, performance.now() - t0);
      patch = toPatch(ops);

      delMap = new Map();
      insMap = new Map();
      for (const o of ops) {
        if (o.t === 'del') delMap.set(o.an, 'del');
        else if (o.t === 'ins') insMap.set(o.bn, 'ins');
      }
      blocks = buildBlocks(ops);
      navIdx = -1;

      renderPane('a');
      renderPane('b');
      fitWidth();
      fitHeights();

      if (!st.blocks) {
        navInfo.textContent = '共 0 处';
        statBar.style.display = '';
        statBar.innerHTML = `<span class="badge ok">内容一致</span><span class="muted">共 ${st.eq} 行，没有发现差异</span>`;
        return;
      }

      navInfo.textContent = `共 ${blocks.length} 处`;
      statBar.style.display = '';
      statBar.innerHTML =
        `<span class="badge ok">新增 ${st.ins} 行</span>` +
        `<span class="badge err">删除 ${st.del} 行</span>` +
        `<span class="badge mute">相同 ${st.eq} 行</span>` +
        `<span class="muted">${st.blocks} 处差异 · 用时 ${used.toFixed(0)} ms${
          coarse ? ' · 文件过大，已按整段替换计算' : ''
        }</span>`;
    }

    const runDebounced = debounce(run, 160);
    [taA, taB].forEach((ta) => {
      ta.addEventListener('input', () => {
        updateMeta();
        runDebounced();
      });
    });

    let rt = null;
    window.addEventListener('resize', () => {
      clearTimeout(rt);
      rt = setTimeout(() => {
        charW = 0;
        fitWidth();
        fitHeights();
      }, 120);
    });

    [igWs, igCase].forEach((cb) => cb.addEventListener('change', run));
    wrap.querySelector('#prev').addEventListener('click', () =>
      gotoBlock(navIdx <= 0 ? blocks.length - 1 : navIdx - 1)
    );
    wrap.querySelector('#next').addEventListener('click', () =>
      gotoBlock(navIdx < 0 ? 0 : navIdx + 1)
    );

    wrap.querySelector('#swap').addEventListener('click', () => {
      const va = taA.value;
      taA.value = taB.value;
      taB.value = va;
      const fa = fileA;
      fileA = fileB;
      fileB = fa;
      run();
    });
    wrap.querySelector('#sample').addEventListener('click', () => {
      fileA = '';
      fileB = '';
      taA.value = SAMPLE_A;
      taB.value = SAMPLE_B;
      run();
    });
    wrap.querySelector('#clear').addEventListener('click', () => {
      fileA = '';
      fileB = '';
      taA.value = '';
      taB.value = '';
      run();
    });

    wrap.querySelector('#copyDiff').addEventListener('click', () => {
      if (!patch) return toast('暂无可复制的差异内容', 'err');
      copy(patch, '已复制 diff 文本');
    });
    wrap.querySelector('#dlDiff').addEventListener('click', () => {
      if (!patch) return toast('暂无可下载的差异内容', 'err');
      download('diff.patch', patch, 'text/x-patch;charset=utf-8');
    });

    /* 载入本地文件 */
    const fileInputs = { a: wrap.querySelector('#fileA'), b: wrap.querySelector('#fileB') };
    function applyFile(side, text, name) {
      if (side === 'a') {
        taA.value = text;
        fileA = name;
      } else {
        taB.value = text;
        fileB = name;
      }
      run();
      if (text.length > 2 * 1024 * 1024) toast('文件较大，对比结果可能需要几秒', 'err');
    }
    function readInto(side, file) {
      const reader = new FileReader();
      reader.onload = () => applyFile(side, String(reader.result || ''), file.name);
      reader.onerror = () => toast('文件读取失败', 'err');
      reader.readAsText(file);
    }
    wrap.querySelectorAll('[data-load]').forEach((btn) =>
      btn.addEventListener('click', () => fileInputs[btn.dataset.load].click())
    );
    Object.entries(fileInputs).forEach(([side, inp]) => {
      inp.addEventListener('change', () => {
        const f = inp.files[0];
        inp.value = '';
        if (f) readInto(side, f);
      });
    });
    wrap.querySelectorAll('[data-clear]').forEach((btn) =>
      btn.addEventListener('click', () => {
        const side = btn.dataset.clear;
        if (side === 'a') {
          taA.value = '';
          fileA = '';
        } else {
          taB.value = '';
          fileB = '';
        }
        run();
      })
    );

    /* 拖拽文件 */
    [
      [taA, 'a'],
      [taB, 'b'],
    ].forEach(([ta, side]) => {
      ta.addEventListener('dragover', (e) => {
        e.preventDefault();
        ta.classList.add('drop');
      });
      ta.addEventListener('dragleave', () => ta.classList.remove('drop'));
      ta.addEventListener('drop', (e) => {
        e.preventDefault();
        ta.classList.remove('drop');
        const f = e.dataTransfer.files && e.dataTransfer.files[0];
        if (f) readInto(side, f);
      });
    });

    updateMeta();
    run();
  },
};
