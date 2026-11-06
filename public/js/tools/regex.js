/* 正则测试器：实时匹配 / 高亮 / 捕获组明细 */
import { h, esc, codeBox, remember } from '../ui.js';

const MAX_TEXT = 500 * 1024; // 测试文本上限，超限截断并提示
const MAX_HITS = 1000; // 明细条数上限，防止超大列表卡页面

const SAMPLES = [
  {
    label: 'IPv4 地址',
    re: '(?<!\\d)(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?!\\d)',
    flags: 'gm',
    text:
      'upstream 10.0.0.12:6379, backup 192.168.7.200\nbad line: 256.1.1.9 / 300.5.5.5 / 8.8.8.888\ngood public: 114.114.114.114',
  },
  {
    label: 'Nginx 日志行',
    re: '^(?<ip>\\S+) \\S+ \\S+ \\[(?<time>[^\\]]+)\\] "(?<method>\\w+) (?<path>[^" ]+)[^"]*" (?<status>\\d{3}) (?<bytes>\\d+|-)',
    flags: 'gm',
    text:
      '1.2.3.4 - - [06/Nov/2026:10:00:01 +0800] "GET /api/status HTTP/1.1" 200 512\n5.6.7.8 - - [06/Nov/2026:10:00:02 +0800] "POST /login HTTP/1.1" 401 89\ninvalid line without brackets',
  },
  {
    label: '邮箱',
    re: '[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+',
    flags: 'g',
    text: '联系 admin@example.com 或运维组 ops-team@corp.internal，无效地址: a@@x、plain@no',
  },
];

const FLAGS = [
  ['g', '全局', 'global：查找全部匹配'],
  ['i', '忽略大小', 'ignoreCase：忽略字母大小写'],
  ['m', '多行', 'multiline：^ $ 按行各自匹配'],
  ['s', '点含换行', 'dotAll：. 也可以匹配换行符'],
  ['u', '码点', 'unicode：按 Unicode 码点解释 \\u 序列'],
];

/* 常用语法速查：点击「语法」列追加到正则输入框 */
const CHEAT = [
  ['字符与通配', [
    ['.', '任意单个字符（默认不含换行）', 'a.c  → abc、a1c'],
    ['\\d', '数字 0-9', '\\d{3}  → 137'],
    ['\\D', '非数字', '\\D+  → abc'],
    ['\\w', '字母、数字、下划线', '\\w+@\\w+\\.[a-z]+'],
    ['\\W', '非单词字符', ''],
    ['\\s', '空白（空格 / Tab / 换行）', 'a\\sb  → a b'],
    ['\\S', '非空白', ''],
    ['[abc]', '方括号内任一字符', '[0-9a-f]{2}'],
    ['[^abc]', '不在方括号内的字符', ''],
  ]],
  ['量词', [
    ['*', '前一项 0 次或多次', 'ab*c  → ac、abbc'],
    ['+', '前一项 1 次或多次', 'a\\d+'],
    ['?', '前一项 0 次或 1 次', 'colou?r  → color、colour'],
    ['{n}', '恰好 n 次', '\\d{4}  → 2026'],
    ['{n,}', '至少 n 次', '\\d{3,}'],
    ['{n,m}', 'n 到 m 次', 'a{2,4}'],
    ['? (跟在量词后)', '懒惰模式：尽量少匹配', '.*? 与 [.]+?'],
  ]],
  ['位置与锚点', [
    ['^', '行首（勾选 m 时每行生效）', '^#'],
    ['$', '行尾（勾选 m 时每行生效）', ';\\s*$'],
    ['\\b', '单词边界', '\\berror\\b'],
    ['\\B', '非单词边界', ''],
  ]],
  ['分组与分支', [
    ['(…)', '捕获分组，可提取子串', '(\\d+)\\.(\\d+)'],
    ['(?:…)', '只分组不捕获', '(?:error|warn)'],
    ['(?<名字>…)', '命名捕获组，结果表按名显示', '(?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)'],
    ['\\1 \\2', '反向引用第 1、2 个分组', '(\\w)\\1  → aa、zz'],
    ['|', '或：多选一，从左到右', 'http|https'],
  ]],
  ['断言（不消耗字符）', [
    ['(?=…)', '后面跟着指定内容', 'log(?=\\.txt)'],
    ['(?!…)', '后面没跟指定内容', '\\d{4}(?!-)'],
    ['(?<=…)', '前面是指定内容', '(?<=:\\d{2,4}) '],
    ['(?<!…)', '前面不是指定内容', '(?<!-)\\d+'],
  ]],
  ['转义', [
    ['\\.', '匹配符号本身：. * + ? ( ) [ ] { } | ^ $ \\ / 都要用 \\ 转义', '\\.  匹配小数点'],
  ]],
];

/** 行:列 换算（1 基） */
function lineCol(text, index) {
  const before = text.slice(0, index);
  const line = before.split('\n').length;
  const col = index - before.lastIndexOf('\n');
  return `${line}:${col}`;
}

export default {
  id: 'regex',
  name: '正则测试器',
  group: '格式化与预览',
  desc: '正则实时匹配测试，高亮命中位置，列出捕获组与行列信息',
  keywords: '正则 regex 测试 匹配 捕获组 grep pattern',
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>正则表达式</div>
          <div class="card-head-right">
            <span class="card-note">实时匹配；粘贴 /pattern/flags 形式会自动拆出内容与标志</span>
            <button class="btn btn-sm" id="cheat">常用语法</button>
          </div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <input type="text" id="pattern" class="mono grow" placeholder="如 (?<!\\d)\\d{1,3}(\\.\\d{1,3}){3}" spellcheck="false" />
          </div>
          <div class="row mt8">
            ${FLAGS.map(([f, zh, title]) => `<label class="check"><input type="checkbox" data-f="${f}" ${f === 'g' ? 'checked' : ''} title="${title}" /> <b>${f}</b>${zh}</label>`).join('')}
            <span class="muted" id="regexMeta"></span>
          </div>
          <div class="mt12" id="text"></div>
          <div class="chips mt8" id="quick">
            ${SAMPLES.map((s, i) => `<span class="chip" data-i="${i}">${s.label}</span>`).join('')}
          </div>
        </div>
      </section>

      <!-- 默认隐藏：输入正则后才显示，避免空卡片占位 -->
      <section class="card" id="resultCard" style="display:none">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>匹配结果</div>
          <div class="card-note" id="meta"></div>
        </div>
        <div class="card-body">
          <div class="rx-view mono" id="view" style="display:none"></div>
          <div id="list"></div>
          <div id="msg"></div>
        </div>
      </section>

      <div class="modal-mask" id="cheatMask" style="display:none">
        <div class="modal-box cheat" role="dialog" aria-modal="true" aria-label="常用正则语法">
          <div class="modal-head">
            <div class="card-title"><span class="dot"></span>常用语法<span class="card-note" style="font-weight:400">点击插入不关窗，插错可撤销</span></div>
            <button class="btn btn-sm btn-ghost" id="cheatClose">关闭</button>
          </div>
          <div class="modal-body">
            <table class="tbl zebra">
              ${CHEAT.map(
                ([title, rows]) => `
                <tr class="grp"><td colspan="3">${title}</td></tr>
                ${rows
                  .map(
                    ([syn, desc, example]) => `<tr>
                    <td class="mono syn" data-syn="${esc(syn)}" title="点击插入到正则输入框">${esc(syn)}</td>
                    <td>${esc(desc)}</td>
                    <td class="mono ex">${esc(example)}</td>
                  </tr>`
                  )
                  .join('')}`
              ).join('')}
            </table>
          </div>
          <div style="border-top:1px solid var(--border); padding:9px 16px; display:flex; gap:8px; align-items:center;">
            <span class="card-note">当前正则</span>
            <code class="mono" id="cheatEcho" style="flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:12.5px;">（空）</code>
            <button class="btn btn-sm btn-ghost" id="cheatUndo" title="删掉上一次插入的语法">撤销</button>
            <button class="btn btn-sm btn-ghost" id="cheatClear" title="清空正则输入框">清空</button>
          </div>
        </div>
      </div>
    `);
    root.appendChild(wrap);

    const patternEl = wrap.querySelector('#pattern');
    remember(patternEl, 'regex.pattern');
    const resultCard = wrap.querySelector('#resultCard');
    const cheatEcho = wrap.querySelector('#cheatEcho');
    const textBox = codeBox({ title: '测试文本', height: '200px', placeholder: '粘贴要匹配的文本…' });
    wrap.querySelector('#text').appendChild(textBox.el);
    const viewEl = wrap.querySelector('#view');
    const listEl = wrap.querySelector('#list');
    const metaEl = wrap.querySelector('#meta');
    const msgEl = wrap.querySelector('#msg');
    const regexMeta = wrap.querySelector('#regexMeta');

    /** 取复选框里的 flags */
    function readFlags() {
      let f = '';
      wrap.querySelectorAll('input[type="checkbox"][data-f]').forEach((cb) => {
        if (cb.checked) f += cb.dataset.f;
      });
      return f;
    }

    /** 支持粘贴 /pattern/flags 整串：拆出 pattern 与 flags 并同步复选框 */
    function normalizeInput(v) {
      let source = v;
      const m = /^\/([\s\S]+)\/([a-z]*)$/.exec(v.trim());
      if (m && m[1].indexOf('/') !== 0) {
        source = m[1];
        // 同步复选框状态
        wrap.querySelectorAll('input[type="checkbox"][data-f]').forEach((cb) => {
          cb.checked = m[2].includes(cb.dataset.f);
        });
      }
      return { source, flags: readFlags() };
    }

    function build() {
      const { source, flags } = normalizeInput(patternEl.value);
      if (!source.trim()) return null;
      try {
        const re = new RegExp(source, flags);
        regexMeta.textContent = `${source.length} 字符 · flags: ${flags || '(无)'}`;
        msgEl.innerHTML = '';
        return re;
      } catch (e) {
        regexMeta.textContent = '';
        msgEl.innerHTML = `<div class="alert err">正则表达式不合法：${esc(e.message)}</div>`;
        return null;
      }
    }

    /** 高亮片段（全部 HTML 已转义） */
    function highlightView(text, re) {
      let html = '';
      let last = 0;
      let count = 0;
      let truncated = false;
      re.lastIndex = 0;
      for (;;) {
        const m = re.exec(text);
        if (!m) break;
        // 零宽匹配：前进 1 字符防空转
        if (m[0] === '') {
          re.lastIndex++;
          continue;
        }
        html += esc(text.slice(last, m.index)) + `<mark class="rx-hit">${esc(m[0])}</mark>`;
        last = m.index + m[0].length;
        count++;
        if (count >= MAX_HITS) {
          truncated = true;
          break;
        }
      }
      html += esc(text.slice(last));
      return { html, count, truncated };
    }

    /** 捕获组列表文案：编号组 + 命名组 */
    function groupsText(m, re) {
      const out = [];
      for (let i = 1; i < m.length; i++) {
        if (m[i] === undefined) continue;
        out.push(`$${i}=${m[i].length > 40 ? m[i].slice(0, 40) + '…' : m[i]}`);
      }
      if (m.groups) {
        for (const [k, v] of Object.entries(m.groups)) {
          const sv = String(v);
          out.push(`${k}=${sv.length > 40 ? sv.slice(0, 40) + '…' : sv}`);
        }
      }
      return out.length ? esc(out.join(' · ')) : '(捕获为空)';
    }

    function run() {
      let text = textBox.getValue();
      msgEl.innerHTML = '';
      // 速查弹窗底部的回显：插入语法时弹窗不关，靠它确认当前拼出的正则
      cheatEcho.textContent = patternEl.value || '（空）';
      // 正则为空时整个「匹配结果」卡片都不显示；一旦有输入（含报错）即出现
      const hasPattern = normalizeInput(patternEl.value).source.trim() !== '';
      resultCard.style.display = hasPattern ? '' : 'none';
      const re = build();
      if (!re) {
        viewEl.style.display = 'none';
        listEl.innerHTML = '';
        metaEl.textContent = '';
        return;
      }
      if (text.length > MAX_TEXT) {
        msgEl.innerHTML = `<div class="alert warn">文本超过 ${Math.round(MAX_TEXT / 1024)}KB，已截断只测试前 ${Math.round(MAX_TEXT / 1024)}KB</div>`;
        text = text.slice(0, MAX_TEXT);
      }
      re.lastIndex = 0;
      // 明细收集
      const rows = [];
      let count = 0;
      let truncated = false;
      for (;;) {
        const m = re.exec(text);
        if (!m) break;
        if (m[0] === '') {
          re.lastIndex++;
          continue;
        }
        rows.push(m);
        count++;
        if (count >= MAX_HITS) {
          truncated = true;
          break;
        }
      }
      // 高亮视图（重新 exec，避免 lastIndex 交叉）
      const view = highlightView(text, re);
      metaEl.textContent =
        (count ? `${count} 处匹配` : '无匹配') +
        (truncated ? `（明细只列出前 ${MAX_HITS} 条）` : '');
      if (!count) {
        viewEl.style.display = 'none';
        listEl.innerHTML = '<div class="empty">没有匹配到内容，试试调整正则或开启忽略大小写</div>';
        return;
      }
      viewEl.innerHTML = view.html;
      viewEl.style.display = '';
      listEl.innerHTML = `
        <table class="tbl zebra mt12">
          <tr><th style="width:56px">#</th><th style="width:92px">位置(行:列)</th><th style="width:34%">匹配内容</th><th>捕获组</th></tr>
          ${rows
            .map(
              (m, i) => `<tr>
                <td class="mono">${i + 1}</td>
                <td class="mono">${lineCol(text, m.index)}</td>
                <td class="mono" style="word-break:break-all">${esc(m[0].length > 120 ? m[0].slice(0, 120) + '…' : m[0])}</td>
                <td class="mono" style="word-break:break-all">${groupsText(m, re)}</td>
              </tr>`
            )
            .join('')}
        </table>`;
    }

    wrap.querySelectorAll('#quick .chip').forEach((c) =>
      c.addEventListener('click', () => {
        const s = SAMPLES[Number(c.dataset.i)];
        patternEl.value = s.re;
        // 重置复选框为示例 flags
        wrap.querySelectorAll('input[type="checkbox"][data-f]').forEach((cb) => {
          cb.checked = s.flags.includes(cb.dataset.f);
        });
        textBox.setValue(s.text);
        run();
      })
    );

    patternEl.addEventListener('input', run);
    textBox.onChange(run);
    wrap.querySelectorAll('input[type="checkbox"][data-f]').forEach((cb) => cb.addEventListener('change', run));

    // 常用语法：弹窗 + 点击插入到正则输入框的光标位置
    const cheatMask = wrap.querySelector('#cheatMask');
    const openCheat = () => { cheatMask.style.display = ''; };
    const closeCheat = () => { cheatMask.style.display = 'none'; };
    wrap.querySelector('#cheat').addEventListener('click', openCheat);
    wrap.querySelector('#cheatClose').addEventListener('click', closeCheat);
    cheatMask.addEventListener('click', (e) => {
      if (e.target === cheatMask) closeCheat(); // 点遮罩关闭
    });
    document.addEventListener('keydown', (e) => {
      // 该工具卸载后（hash 跳走）此监听自然失效，避免残留
      if (!wrap.isConnected) return;
      if (e.key === 'Escape' && cheatMask.style.display !== 'none') closeCheat();
    });
    // 本弹窗内的插入记录：用于「撤销」逐步回退（弹窗遮挡输入框，只能在这里纠错）
    const insertStack = [];
    cheatMask.querySelectorAll('td.syn').forEach((td) =>
      td.addEventListener('click', () => {
        const s = td.dataset.syn;
        const start = patternEl.selectionStart ?? patternEl.value.length;
        const end = patternEl.selectionEnd ?? start;
        patternEl.value = patternEl.value.slice(0, start) + s + patternEl.value.slice(end);
        const caret = start + s.length;
        // 保持弹窗打开：连续插入多个语法时不必反复开关；光标停在插入位置之后
        insertStack.push({ at: start, text: s });
        patternEl.setSelectionRange(caret, caret);
        patternEl.dispatchEvent(new Event('input', { bubbles: true }));
      })
    );

    /** 撤销上一次插入：只在插入内容仍原样留在原位时才删，避免误伤后续修改 */
    wrap.querySelector('#cheatUndo').addEventListener('click', () => {
      const last = insertStack.pop();
      if (!last) return;
      const v = patternEl.value;
      if (v.slice(last.at, last.at + last.text.length) !== last.text) {
        insertStack.length = 0;
        return;
      }
      patternEl.value = v.slice(0, last.at) + v.slice(last.at + last.text.length);
      patternEl.setSelectionRange(last.at, last.at);
      patternEl.dispatchEvent(new Event('input', { bubbles: true }));
    });

    wrap.querySelector('#cheatClear').addEventListener('click', () => {
      insertStack.length = 0;
      patternEl.value = '';
      patternEl.setSelectionRange(0, 0);
      patternEl.dispatchEvent(new Event('input', { bubbles: true }));
    });

    // 初始跑一次（可能有恢复的正则）
    run();
  },
};
