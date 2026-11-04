/* Markdown 预览器 */
import { h, copy, download, codeBox, esc, segGroup } from '../ui.js';

const SAMPLE = `# 运维工具箱

> 支持 **GitHub Flavored Markdown**，可实时预览、导出 HTML。

## 功能清单

- [x] Markdown 实时预览
- [x] 代码高亮（Prism）
- [ ] 导出 PDF（后续支持）

## 表格

| 工具 | 说明 | 状态 |
| --- | --- | --- |
| Base64 | 编解码 | ✅ |
| Cron | 表达式生成 | ✅ |
| SSL | 证书检测 | ✅ |

## 代码

\`\`\`bash
kubectl get pods -n prod | grep -v Running
\`\`\`

\`\`\`json
{"status":"ok","replicas":3}
\`\`\`

## 引用与链接

参考 [WorkBuddy](https://www.workbuddy.cn) 文档。

---

*运维同学的好帮手*
`;

const TOOLBAR = [
  ['加粗', '**', '**'],
  ['斜体', '*', '*'],
  ['删除线', '~~', '~~'],
  ['行内代码', '`', '`'],
  ['标题', '\n## ', ''],
  ['链接', '[文本](https://', ')'],
  ['代码块', '\n```bash\n', '\n```\n'],
  ['引用', '\n> ', ''],
  ['无序列表', '\n- ', ''],
  ['任务', '\n- [ ] ', ''],
  ['表格', '\n| 列1 | 列2 |\n| --- | --- |\n| 值 | 值 |\n', ''],
  ['分割线', '\n---\n', ''],
];

export default {
  id: 'markdown',
  name: 'Markdown 预览器',
  group: '格式化与预览',
  desc: '实时预览 Markdown，支持 GFM、代码高亮、HTML 导出与大纲',
  keywords: 'markdown 预览 md 文档 html',
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>Markdown 编辑器</div>
          <div class="row">
            <span class="card-note">左侧编辑，右侧实时预览</span>
            <button class="btn btn-sm" id="sample">示例</button>
            <button class="btn btn-sm" id="clear">清空</button>
            <button class="btn btn-sm" id="copyHtml">复制 HTML</button>
            <button class="btn btn-sm" id="dlMd">下载 .md</button>
            <button class="btn btn-sm btn-primary" id="dlHtml">下载 .html</button>
          </div>
        </div>
        <div class="card-body tight">
          <div class="btn-row" style="padding:0 6px 10px" id="toolbar">
            ${TOOLBAR.map(([n], i) => `<button class="btn btn-sm" data-i="${i}">${esc(n)}</button>`).join('')}
          </div>
          <div class="split">
            <div id="editor" style="padding:0 6px"></div>
            <div style="padding:0 6px">
              <div class="out-box">
                <div class="out-bar">
                  <span class="out-title" id="viewTitle">预览</span>
                  <span class="out-actions">
                    <div class="seg" id="tab">
                      <button data-v="preview" class="active">预览</button>
                      <button data-v="html">HTML</button>
                    </div>
                  </span>
                </div>
                <div class="out-body" id="viewer" style="height:var(--md-h);resize:none"></div>
              </div>
            </div>
          </div>
          <div class="row" style="padding:10px 6px 0">
            <span class="out-meta" id="stats"></span>
          </div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const editor = codeBox({ height: 'var(--md-h)', placeholder: '在此输入 Markdown…' });
    wrap.querySelector('#editor').appendChild(editor.el);
    const viewer = wrap.querySelector('#viewer');
    const statsEl = wrap.querySelector('#stats');

    let currentHtml = '';
    let tab = 'preview';

    function highlightBlocks(container) {
      if (!window.Prism) return;
      container.querySelectorAll('pre code').forEach((code) => {
        const cls = [...code.classList].find((c) => c.startsWith('language-') || c === 'lang');
        let lang = cls ? cls.replace(/^language-/, '') : '';
        if (!lang) {
          const parent = code.parentElement;
          const m = parent && /language-(\w+)/.exec(parent.className || '');
          lang = m ? m[1] : '';
        }
        if (lang && window.Prism.languages[lang]) {
          try {
            window.Prism.highlightElement(code);
          } catch (_) {}
        }
      });
    }

    function render() {
      const md = editor.getValue();
      let html = '';
      try {
        html = window.marked.parse(md, { gfm: true, breaks: false });
      } catch (e) {
        html = `<p style="color:var(--err)">解析失败：${esc(e.message)}</p>`;
      }
      if (window.DOMPurify) html = window.DOMPurify.sanitize(html, { ADD_ATTR: ['target'] });
      currentHtml = html;

      const words = md.replace(/\s+/g, '').length;
      const lines = md ? md.split('\n').length : 0;
      statsEl.textContent = words
        ? `${words} 字 · ${lines} 行 · 阅读约 ${Math.max(1, Math.round(words / 350))} 分钟`
        : '0 字 · 0 行';

      if (tab === 'preview') {
        wrap.querySelector('#viewTitle').textContent = '预览';
        viewer.innerHTML = md.trim()
          ? '<div class="md-body" style="padding:14px 16px;min-height:100%"></div>'
          : '<div class="md-empty" style="min-height:100%">点击左侧输入框，直接开始写 Markdown</div>';
        if (md.trim()) viewer.querySelector('.md-body').innerHTML = html;
        highlightBlocks(viewer);
      } else if (tab === 'html') {
        wrap.querySelector('#viewTitle').textContent = 'HTML 源码';
        const pre = document.createElement('pre');
        pre.className = 'code language-markup';
        pre.style.cssText = 'height:100%;margin:0;border:0;border-radius:0;background:transparent';
        const code = document.createElement('code');
        code.className = 'language-markup';
        code.textContent = html;
        pre.appendChild(code);
        viewer.innerHTML = '';
        viewer.appendChild(pre);
        if (window.Prism && window.Prism.languages.markup) {
          try {
            window.Prism.highlightElement(code);
          } catch (_) {}
        }
      }
    }

    let timer = null;
    editor.ta.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(render, 180);
    });

    segGroup(wrap.querySelector('#tab'), (v) => {
      tab = v;
      render();
    });

    wrap.querySelectorAll('#toolbar button[data-i]').forEach((b) =>
      b.addEventListener('click', () => {
        const [, pre, post] = TOOLBAR[Number(b.dataset.i)];
        const ta = editor.ta;
        const start = ta.selectionStart;
        const end = ta.selectionEnd;
        const sel = ta.value.slice(start, end) || '文本';
        ta.value = ta.value.slice(0, start) + pre + sel + post + ta.value.slice(end);
        ta.focus();
        ta.selectionStart = start + pre.length;
        ta.selectionEnd = start + pre.length + sel.length;
        ta.dispatchEvent(new Event('input'));
        render();
      })
    );

    wrap.querySelector('#sample').addEventListener('click', () => {
      editor.setValue(SAMPLE);
      render();
    });
    wrap.querySelector('#clear').addEventListener('click', () => {
      editor.setValue('');
      render();
    });
    wrap.querySelector('#copyHtml').addEventListener('click', () => {
      render();
      copy(currentHtml, '已复制 HTML');
    });
    wrap.querySelector('#dlMd').addEventListener('click', () =>
      download('document.md', editor.getValue(), 'text/markdown;charset=utf-8')
    );
    wrap.querySelector('#dlHtml').addEventListener('click', () => {
      render();
      const doc = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>Document</title>
<style>
body{max-width:820px;margin:40px auto;padding:0 20px;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;line-height:1.75;color:#172033}
pre{background:#f7f9fc;padding:14px;border-radius:8px;overflow:auto}
code{font-family:Consolas,monospace}
blockquote{border-left:3px solid #2563eb;padding:6px 14px;background:#eef4ff;margin:12px 0}
table{border-collapse:collapse}th,td{border:1px solid #ddd;padding:7px 11px}th{background:#fafbfd}
</style></head><body>${currentHtml}</body></html>`;
      download('document.html', doc, 'text/html;charset=utf-8');
    });

    render();
  },
};
