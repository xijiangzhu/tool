/* YAML 格式化 / 校验 / YAML 与 JSON 互转 */
import { h, esc, codeBox, fmtBytes } from '../ui.js';

const SAMPLE = `service:
  name: ops-toolbox
  replicas: 2
  labels:
    env: prod
    team: 运维组
  ports: [80, 443]
  healthcheck:
    interval: 30s
    retries: 3
    commands:
      - echo ready
      - curl -fsS localhost/health
disabled: false
ratio: 0.35
notes: '单引号内 # 不算注释'`;

/** 从 js-yaml 异常里解出行/列（它的消息自带 at line X, column Y，已是 1 基） */
function yamlErrorInfo(e, text) {
  const msg = String((e && e.reason) || e.message || e);
  const m = /line (\d+), column (\d+)/.exec(String(e && e.message) || '');
  let line = null;
  let col = null;
  if (e && e.mark) {
    line = e.mark.line + 1;
    col = e.mark.column + 1;
  } else if (m) {
    line = Number(m[1]);
    col = Number(m[2]);
  }
  return { msg, line, col };
}

export default {
  id: 'yaml',
  name: 'YAML 格式化',
  group: '格式化与预览',
  desc: 'YAML 格式化、语法校验与 YAML/JSON 互转，错误定位到行列',
  keywords: 'yaml 格式化 校验 k8s docker-compose ini 转换',
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>YAML 处理</div>
          <div class="card-note">格式化缩进 2/4 空格；校验错误定位行列；与 JSON 双向转换</div>
        </div>
        <div class="card-body">
          <div class="tool-bar">
            <button class="btn btn-primary" id="fmt">格式化</button>
            <button class="btn" id="y2j">YAML → JSON</button>
            <button class="btn" id="j2y">JSON → YAML</button>
            <button class="btn" id="check">校验</button>
            <select id="indent" class="w150">
              <option value="2">缩进 2 空格</option>
              <option value="4">缩进 4 空格</option>
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

    const inBox = codeBox({ title: '输入（YAML 或 JSON）', height: 'var(--json-h)', placeholder: '粘贴 YAML 内容，或点右上角「示例」…' });
    const outBox = codeBox({ title: '输出结果', height: 'var(--json-h)', placeholder: '处理结果会显示在这里' });
    wrap.querySelector('#in').appendChild(inBox.el);
    wrap.querySelector('#out').appendChild(outBox.el);

    const msgEl = wrap.querySelector('#msg');
    const statBar = wrap.querySelector('#statBar');
    const statEl = wrap.querySelector('#stat');
    const validityEl = wrap.querySelector('#validity');

    function yamlLib() {
      if (!window.jsyaml) throw new Error('YAML 解析库尚未加载，请刷新页面重试');
      return window.jsyaml;
    }

    function indentOf() {
      return Number(wrap.querySelector('#indent').value) || 2;
    }

    function showOk(value, extra = '') {
      statBar.style.display = '';
      validityEl.className = 'result-tag ok';
      validityEl.textContent = '合法 YAML';
      const bytes = new Blob([outBox.getValue()]).size;
      let keys = 0;
      const walk = (v) => {
        if (Array.isArray(v)) v.forEach(walk);
        else if (v && typeof v === 'object') {
          Object.keys(v).forEach((k) => {
            keys++;
            walk(v[k]);
          });
        }
      };
      walk(value);
      statEl.textContent = `键 ${keys} 个 · 输出 ${fmtBytes(bytes)}${extra}`;
    }

    function showError(e) {
      statBar.style.display = 'none';
      const { msg, line, col } = yamlErrorInfo(e, inBox.getValue());
      // white-space:pre-wrap 保留换行与缩进空格，避免替换 class 属性里的空格
      let html = `<div class="alert err" style="white-space:pre-wrap">YAML 解析失败：${esc(msg)}`;
      if (line) {
        html += `\n位置：第 ${line} 行第 ${col} 列`;
        const lines = inBox.getValue().split('\n');
        const l = lines[line - 1] || '';
        const caret = ' '.repeat(Math.max(0, Math.min(col - 1, l.length))) + '^';
        html += `\n\n${line} | ${esc(l)}\n${' '.repeat(String(line).length + 3)}${caret}`;
      }
      html += '</div>';
      msgEl.innerHTML = html;
    }

    function transform(kind) {
      msgEl.innerHTML = '';
      const raw = inBox.getValue();
      if (!raw.trim()) {
        outBox.setValue('');
        statBar.style.display = 'none';
        return;
      }
      try {
        const y = yamlLib();
        let value = null;
        let out = '';
        if (kind === 'j2y') {
          try {
            value = JSON.parse(raw);
          } catch (e) {
            showError({ message: '输入不是合法 JSON：' + (e.message || e) });
            return;
          }
          out = y.dump(value, { indent: indentOf(), lineWidth: 120, noRefs: true });
        } else {
          value = y.load(raw);
          if (kind === 'fmt') out = y.dump(value, { indent: indentOf(), lineWidth: 120, noRefs: true });
          else if (kind === 'y2j') out = JSON.stringify(value, null, indentOf());
          else out = '';
        }
        if (kind === 'check') {
          outBox.setValue('');
          showOk(value, '（校验通过，未生成输出）');
          return;
        }
        outBox.setValue(out);
        showOk(value);
      } catch (e) {
        showError(e);
      }
    }

    wrap.querySelector('#fmt').addEventListener('click', () => transform('fmt'));
    wrap.querySelector('#y2j').addEventListener('click', () => transform('y2j'));
    wrap.querySelector('#j2y').addEventListener('click', () => transform('j2y'));
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

    // 实时校验（不打扰输出）
    inBox.onChange(() => {
      msgEl.innerHTML = '';
      const raw = inBox.getValue();
      if (!raw.trim()) {
        statBar.style.display = 'none';
        return;
      }
      try {
        const value = yamlLib().load(raw);
        statBar.style.display = '';
        validityEl.className = 'result-tag ok';
        validityEl.textContent = '合法 YAML（尚未生成输出）';
        statEl.textContent = '';
        void value;
      } catch (e) {
        statBar.style.display = '';
        validityEl.className = 'result-tag err';
        validityEl.textContent = '语法错误';
        const { line, col, msg } = yamlErrorInfo(e, raw);
        statEl.textContent = line ? `第 ${line} 行第 ${col} 列附近 · ${msg}` : msg;
      }
    });
  },
};
