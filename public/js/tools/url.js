/* URL 编码 / 解码 与 URL 解析 */
import { h, copy, codeBox, esc, remember, segGroup, formError } from '../ui.js';

export default {
  id: 'url',
  name: 'URL 编码解码',
  group: '编码转换',
  desc: 'URL 百分号编码 / 解码，支持分量与整串两种口径，附带 URL 拆解与查询参数编辑',
  keywords: 'url 编码 解码 encodeURIComponent percent query',
  mount(root) {
    root.innerHTML = '';
    /* 示例：一键填入并切到对应模式，便于快速理解两种口径的差异 */
    const EXAMPLES = [
      { label: '中文参数值', m: 'encode', s: 'component', v: '运维工具箱' },
      { label: '整条 URL', m: 'encode', s: 'whole', v: 'https://example.com/?q=运维工具箱&page=1' },
      { label: '已编码中文（反解码）', m: 'decode', s: 'component', v: '%E8%BF%90%E7%BB%B4%E5%B7%A5%E5%85%B7%E7%AE%B1' },
      { label: '结构字符对比', m: 'encode', s: 'whole', v: 'a=运维&b=/q?x=1&c=#z' },
    ];
    const PARSE_EXAMPLE = 'https://example.com/api/v1/list?keyword=运维工具箱&page=2&tag=a&tag=b#结果';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>URL 编解码</div>
          <div class="card-note">分量 component 用于参数值；整串 whole 保留 ? &amp; / 等结构字符</div>
        </div>
        <div class="card-body">
          <div class="tool-bar">
            <div class="seg" id="mode">
              <button data-v="encode" class="active">编码 →</button>
              <button data-v="decode">解码 ←</button>
            </div>
            <div class="seg" id="scope">
              <button data-v="component" class="active">分量 component</button>
              <button data-v="whole">整串 whole</button>
            </div>
            <span class="spacer"></span>
            <button class="btn btn-sm" id="swap">交换</button>
            <button class="btn btn-sm btn-ghost" id="clear">清空</button>
            <button class="btn btn-sm btn-primary" id="run">转换</button>
          </div>
          <div class="chips mt8" id="encExamples">
            ${EXAMPLES.map((e) => `<span class="chip" data-m="${e.m}" data-s="${e.s}" data-v="${esc(e.v)}">${e.label}</span>`).join('')}
          </div>
          <div class="split">
            <div id="in"></div>
            <div id="out"></div>
          </div>
          <div id="msg"></div>
        </div>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>URL 结构与查询参数</div>
          <div class="card-note">粘贴完整 URL 自动拆解，参数值可编辑，改动会同步回地址</div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <input type="text" id="parseInput" placeholder="https://example.com/api/v1/list?keyword=运维&page=2" />
            <button class="btn btn-primary" id="parse">解析</button>
            <button class="btn" id="copyUrl">复制 URL</button>
          </div>
          <div class="chips mt8" id="parseExamples">
            <span class="chip" data-v="${esc(PARSE_EXAMPLE)}">示例：中文 + 重复参数 + 锚点</span>
          </div>
          <div id="parseOut" class="mt12"><div class="empty">解析结果将显示在这里</div></div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const inBox = codeBox({ title: '输入', height: '200px', placeholder: 'https://example.com/search?q=运维工具箱' });
    const outBox = codeBox({ title: '输出（编码结果）', height: '200px', placeholder: '结果…' });
    wrap.querySelector('#in').appendChild(inBox.el);
    wrap.querySelector('#out').appendChild(outBox.el);

    let mode = 'encode';
    let scope = 'component';
    const msgEl = wrap.querySelector('#msg');

    function syncTitles() {
      const enc = mode === 'encode';
      const comp = scope === 'component';
      inBox.setTitle(enc ? '输入（原始文本）' : '输入（编码后的 URL 文本）');
      outBox.setTitle(enc ? `输出（${comp ? 'encodeURIComponent' : 'encodeURI'}）` : '输出（解码结果）');
    }

    const modeSeg = segGroup(wrap.querySelector('#mode'), (v) => {
      mode = v;
      syncTitles();
      run();
    });
    const scopeSeg = segGroup(wrap.querySelector('#scope'), (v) => {
      scope = v;
      syncTitles();
      run();
    });

    // 点击示例：自动切到该示例对应的模式与口径，填入内容并立即转换
    wrap.querySelectorAll('#encExamples .chip').forEach((c) =>
      c.addEventListener('click', () => {
        mode = c.dataset.m;
        scope = c.dataset.s;
        modeSeg.set(mode);
        scopeSeg.set(scope);
        syncTitles();
        inBox.setValue(c.dataset.v);
        outBox.setValue('');
        run();
      })
    );

    function run() {
      msgEl.innerHTML = '';
      const v = inBox.getValue();
      if (!v) return outBox.setValue('');
      try {
        if (mode === 'encode') {
          outBox.setValue(scope === 'component' ? encodeURIComponent(v) : encodeURI(v));
        } else {
          let r;
          try {
            r = decodeURIComponent(v);
          } catch (e) {
            r = decodeURI(v);
            msgEl.innerHTML = `<div class="alert warn">分量解码失败，已按整串 decodeURI 解码</div>`;
          }
          outBox.setValue(r);
        }
      } catch (e) {
        msgEl.innerHTML = `<div class="alert err">${e.message}</div>`;
      }
    }

    wrap.querySelector('#run').addEventListener('click', run);
    wrap.querySelector('#swap').addEventListener('click', () => {
      const a = inBox.getValue();
      inBox.setValue(outBox.getValue());
      outBox.setValue(a);
      mode = mode === 'encode' ? 'decode' : 'encode';
      modeSeg.set(mode);
      syncTitles();
      run();
    });
    wrap.querySelector('#clear').addEventListener('click', () => {
      inBox.setValue('');
      outBox.setValue('');
      msgEl.innerHTML = '';
    });
    inBox.onChange(run);
    syncTitles();

    /* ---------- URL 解析 ---------- */
    const parseInput = wrap.querySelector('#parseInput');
    remember(parseInput, 'url.parse');
    const parseOut = wrap.querySelector('#parseOut');
    const parseErr = formError(parseInput.closest('.field-row'), parseInput);
    let parsed = null;

    function renderParse() {
      if (!parsed) return;
      const rows = [
        ['协议', parsed.protocol],
        ['主机', parsed.host],
        ['主机名', parsed.hostname],
        ['端口', parsed.port || '(默认)'],
        ['路径', parsed.pathname],
        ['查询串', parsed.search || '(空)'],
        ['锚点', parsed.hash || '(空)'],
        ['来源', parsed.origin],
      ];
      const params = [...parsed.searchParams.entries()];
      parseOut.innerHTML = `
        <table class="tbl zebra">
          ${rows.map(([k, v]) => `<tr><th style="width:110px">${esc(k)}</th><td class="mono">${esc(v)}</td></tr>`).join('')}
        </table>
        <div class="note mt12">查询参数（${params.length} 项，值可编辑）</div>
        <div class="mt8" id="paramList">
          ${
            params.length
              ? `<table class="tbl">
                   <tr><th style="width:26%">参数名</th><th>参数值（解码后）</th><th style="width:60px"></th></tr>
                   ${params
                     .map(
                       ([k, v], i) => `<tr data-i="${i}">
                          <td class="mono">${esc(k)}</td>
                          <td><input type="text" data-k="${esc(k)}" class="pv mono" value="${esc(v)}" /></td>
                          <td><button class="btn btn-sm btn-ghost del">删除</button></td>
                        </tr>`
                     )
                     .join('')}
                 </table>`
              : '<div class="empty">无查询参数</div>'
          }
        </div>
      `;
      parseOut.querySelectorAll('.del').forEach((btn) =>
        btn.addEventListener('click', () => {
          const row = btn.closest('tr');
          row.remove();
          rebuildParams();
          syncInput();
          renderParse();
        })
      );
      parseOut.querySelectorAll('.pv').forEach((ipt) =>
        ipt.addEventListener('input', () => {
          rebuildParams();
          syncInput();
        })
      );
    }

    // 按当前行序重建查询串：URLSearchParams.set/delete 会合并同名参数、丢失重复键，这里逐行 append 保序保重
    function rebuildParams() {
      const sp = new URLSearchParams();
      parseOut.querySelectorAll('#paramList tr[data-i]').forEach((tr) => {
        const ipt = tr.querySelector('.pv');
        if (ipt) sp.append(ipt.dataset.k, ipt.value);
      });
      parsed.search = sp.toString() ? `?${sp.toString()}` : '';
    }

    function syncInput() {
      parseInput.value = parsed.toString();
    }

    function doParse() {
      const v = parseInput.value.trim();
      if (!v) return parseErr.show('请先输入 URL');
      parseErr.clear();
      try {
        parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : 'https://' + v);
        renderParse();
      } catch (e) {
        parseOut.innerHTML = '';
        parseErr.show(`URL 解析失败：${e.message}`);
      }
    }

    wrap.querySelector('#parse').addEventListener('click', doParse);
    parseInput.addEventListener('keydown', (e) => e.key === 'Enter' && doParse());

    // 解析示例：填入演示 URL（含中文参数、重复参数、锚点）并自动解析
    wrap.querySelectorAll('#parseExamples .chip').forEach((c) =>
      c.addEventListener('click', () => {
        parseInput.value = c.dataset.v;
        doParse();
      })
    );

    wrap.querySelector('#copyUrl').addEventListener('click', () => {
      const v = parseInput.value.trim();
      if (!v) return parseErr.show('请先输入或解析 URL');
      copy(v, '已复制 URL');
    });
  },
};
