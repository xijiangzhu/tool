/* JSON 格式化 / 压缩 / 校验 */
import { h, codeBox, fmtBytes, esc } from '../ui.js';

const SAMPLE = `{"name":"tool","version":1.2,"enabled":true,"tags":["json","format","yaml"],"owner":{"team":"sre","members":[{"name":"张三","role":"admin"},{"name":"李四","role":"viewer"}]},"note":"支持中文与转义"}`;

function parseWithPos(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (e) {
    const msg = e.message || String(e);
    let line = null, col = null, pos = null;
    const m1 = /line (\d+) column (\d+)/.exec(msg);
    const m2 = /position (\d+)/.exec(msg);
    if (m1) {
      line = +m1[1];
      col = +m1[2];
    } else if (m2) {
      pos = +m2[1];
      const before = text.slice(0, pos);
      line = before.split('\n').length;
      col = pos - before.lastIndexOf('\n');
    }
    return { ok: false, msg, line, col, pos };
  }
}

function stats(value) {
  let keys = 0, maxDepth = 0, nodes = 0;
  const walk = (v, d) => {
    nodes++;
    maxDepth = Math.max(maxDepth, d);
    if (Array.isArray(v)) v.forEach((x) => walk(x, d + 1));
    else if (v && typeof v === 'object') {
      Object.keys(v).forEach((k) => {
        keys++;
        walk(v[k], d + 1);
      });
    }
  };
  walk(value, 1);
  return { keys, maxDepth, nodes };
}

export default {
  id: 'json',
  name: 'JSON 格式化',
  group: '格式化与预览',
  desc: 'JSON 美化、压缩与校验，语法错误精确定位到行列',
  keywords: 'json 格式化 压缩 校验 pretty',
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>JSON 处理</div>
          <div class="card-note">支持格式化 / 压缩 / 校验，错误提示到第几行第几列</div>
        </div>
        <div class="card-body">
          <div class="tool-bar">
            <button class="btn btn-primary" id="fmt">格式化</button>
            <button class="btn" id="min">压缩</button>
            <button class="btn" id="check">校验</button>
            <select id="indent" class="w150">
              <option value="2">缩进 2 空格</option>
              <option value="4">缩进 4 空格</option>
              <option value="tab">缩进 Tab</option>
            </select>
            <span class="spacer"></span>
            <button class="btn btn-sm" id="sample">示例</button>
            <button class="btn btn-sm btn-ghost" id="clear">清空</button>
          </div>

          <div class="split">
            <div id="in"></div>
            <div id="out"></div>
          </div>

          <div class="result-strip mt12" id="statBar" style="display:none">
            <span class="result-tag" id="validity"></span>
            <span id="stat"></span>
          </div>
          <div id="msg"></div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const inBox = codeBox({ lang: 'json', title: '输入 JSON', height: 'var(--json-h)', placeholder: '粘贴 JSON 内容，或点右上角「示例」…' });
    const outBox = codeBox({ lang: 'json', title: '输出结果', height: 'var(--json-h)', placeholder: '处理结果会显示在这里' });
    wrap.querySelector('#in').appendChild(inBox.el);
    wrap.querySelector('#out').appendChild(outBox.el);

    const msgEl = wrap.querySelector('#msg');
    const statBar = wrap.querySelector('#statBar');
    const statEl = wrap.querySelector('#stat');
    const validityEl = wrap.querySelector('#validity');

    function indentStr() {
      const v = wrap.querySelector('#indent').value;
      return v === 'tab' ? '\t' : Number(v);
    }

    function showStats(v) {
      const s = stats(v);
      const bytes = new Blob([outBox.getValue()]).size;
      statBar.style.display = '';
      validityEl.className = 'result-tag ok';
      validityEl.textContent = '合法 JSON';
      statEl.textContent = `键 ${s.keys} 个 · 节点 ${s.nodes} 个 · 最大深度 ${s.maxDepth} · 输出 ${fmtBytes(bytes)}`;
    }

    function showError(e) {
      statBar.style.display = 'none';
      let html = `<div class="alert err">JSON 解析失败：${esc(e.msg)}`;
      if (e.line) {
        html += `\n位置：第 ${e.line} 行第 ${e.col} 列`;
        const lines = inBox.getValue().split('\n');
        const l = lines[e.line - 1] || '';
        const caret = ' '.repeat(Math.max(0, Math.min(e.col - 1, l.length))) + '^';
        html += `\n\n${e.line} | ${esc(l)}\n${' '.repeat(String(e.line).length + 3)}${caret}`;
      }
      html += '</div>';
      msgEl.innerHTML = html.replace(/\n/g, '<br>').replace(/ /g, '&nbsp;');
    }

    function transform(kind) {
      msgEl.innerHTML = '';
      const raw = inBox.getValue();
      if (!raw.trim()) {
        outBox.setValue('');
        statBar.style.display = 'none';
        return;
      }
      const p = parseWithPos(raw);
      if (!p.ok) return showError(p);

      if (kind === 'min') outBox.setValue(JSON.stringify(p.value));
      else outBox.setValue(JSON.stringify(p.value, null, indentStr()));

      showStats(p.value);
    }

    wrap.querySelector('#fmt').addEventListener('click', () => transform('fmt'));
    wrap.querySelector('#min').addEventListener('click', () => transform('min'));
    wrap.querySelector('#check').addEventListener('click', () => transform('check'));
    wrap.querySelector('#indent').addEventListener('change', () => {
      if (inBox.getValue().trim()) transform('fmt');
    });
    wrap.querySelector('#sample').addEventListener('click', () => {
      inBox.setValue(SAMPLE);
      transform('fmt');
    });
    wrap.querySelector('#clear').addEventListener('click', () => {
      inBox.setValue('');
      outBox.setValue('');
      msgEl.innerHTML = '';
      statBar.style.display = 'none';
    });

    inBox.onChange(() => {
      msgEl.innerHTML = '';
      const raw = inBox.getValue();
      if (!raw.trim()) {
        statBar.style.display = 'none';
        return;
      }
      const p = parseWithPos(raw);
      if (p.ok) {
        const s = stats(p.value);
        statBar.style.display = '';
        validityEl.className = 'result-tag ok';
        validityEl.textContent = '合法 JSON';
        statEl.textContent = `键 ${s.keys} 个 · 节点 ${s.nodes} 个 · 最大深度 ${s.maxDepth}（尚未生成输出）`;
      } else {
        statBar.style.display = '';
        validityEl.className = 'result-tag err';
        validityEl.textContent = '语法错误';
        statEl.textContent = p.line ? `第 ${p.line} 行第 ${p.col} 列附近` : '请检查括号与逗号';
      }
    });
  },
};
