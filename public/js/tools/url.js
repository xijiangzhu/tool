/* URL 编码 / 解码 */
import { h, codeBox, esc } from '../ui.js';

export default {
  id: 'url',
  name: 'URL 编码解码',
  group: '编码转换',
  desc: 'URL 百分号编码 / 解码，输入后自动判断方向与口径，无需选择',
  keywords: 'url 编码 解码 encodeURIComponent percent',
  mount(root) {
    root.innerHTML = '';
    /* 示例：一键填入，方向与口径全自动判断 */
    const EXAMPLES = [
      { label: '中文参数值', v: '运维工具箱' },
      { label: '整条 URL', v: 'https://example.com/?q=运维工具箱&page=1' },
      { label: '已编码中文（反解码）', v: '%E8%BF%90%E7%BB%B4%E5%B7%A5%E5%85%B7%E7%AE%B1' },
    ];
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>URL 编解码</div>
          <div class="card-note">输入后自动转换：含 %XX 序列判为解码；完整 URL 自动保留 ?&amp;/ 等结构字符</div>
        </div>
        <div class="card-body">
          <div class="tool-bar">
            <span class="muted" id="autoHint">粘贴内容即可，无需选择编码或解码</span>
            <span class="spacer"></span>
            <button class="btn btn-sm" id="swap" title="把结果搬回输入框，自动反向转换">交换</button>
            <button class="btn btn-sm btn-ghost" id="clear">清空</button>
          </div>
          <div class="chips mt8 mb12" id="encExamples">
            ${EXAMPLES.map((e) => `<span class="chip" data-v="${esc(e.v)}">${e.label}</span>`).join('')}
          </div>
          <div class="split">
            <div id="in"></div>
            <div id="out"></div>
          </div>
          <div id="msg"></div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const inBox = codeBox({ title: '输入', height: '260px', placeholder: 'https://example.com/search?q=运维工具箱' });
    const outBox = codeBox({ title: '输出', height: '260px', placeholder: '结果…' });
    wrap.querySelector('#in').appendChild(inBox.el);
    wrap.querySelector('#out').appendChild(outBox.el);

    const msgEl = wrap.querySelector('#msg');
    const autoHint = wrap.querySelector('#autoHint');

    /* 全自动判断：
       - 输入含 %XX 转义序列 → 解码（优先 decodeURIComponent，失败降级 decodeURI）
       - 否则编码：像完整 URL（有协议或含 ?& # 结构字符）→ 整串 encodeURI（结构字符保留）
       - 其余（单个词 / 参数值）→ 分量 encodeURIComponent（结构字符一并转义） */
    function detect(v) {
      const isDecode = /%[0-9a-fA-F]{2}/.test(v);
      const scope = !isDecode && (/^[a-z][a-z0-9+.-]*:\/\//i.test(v.trim()) || /[?&#]/.test(v)) ? 'whole' : 'component';
      return { isDecode, scope };
    }

    /** 容错解码：逐个 %HH 还原字节，非法 / 不完整的 % 原样保留，坏字节交给 TextDecoder 替换。
        decodeURI 对孤立 % 同样会抛 URIError，不能作为 decodeURIComponent 的降级方案。 */
    function tolerantDecode(v) {
      const bytes = [];
      const enc = new TextEncoder();
      let plain = '';
      const flush = () => {
        if (plain) {
          for (const b of enc.encode(plain)) bytes.push(b);
          plain = '';
        }
      };
      for (let i = 0; i < v.length; i++) {
        const hex = v.slice(i + 1, i + 3);
        if (v[i] === '%' && /^[0-9a-fA-F]{2}$/.test(hex)) {
          flush();
          bytes.push(parseInt(hex, 16));
          i += 2;
        } else {
          plain += v[i];
        }
      }
      flush();
      return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
    }

    function run() {
      msgEl.innerHTML = '';
      const v = inBox.getValue();
      if (!v) {
        outBox.setValue('');
        autoHint.textContent = '粘贴内容即可，无需选择编码或解码';
        return;
      }
      const { isDecode, scope } = detect(v);
      autoHint.textContent = isDecode
        ? '自动识别：解码 ←（%XX 还原为原文）'
        : `自动识别：编码 →（${scope === 'whole' ? '整串 encodeURI，结构字符保留' : '分量 encodeURIComponent，结构字符一并转义'}）`;
      try {
        if (isDecode) {
          let r;
          try {
            r = decodeURIComponent(v);
          } catch (e) {
            r = tolerantDecode(v);
            msgEl.innerHTML = `<div class="alert warn">部分转义序列不完整，非法片段已原样保留</div>`;
          }
          outBox.setValue(r);
        } else {
          outBox.setValue(scope === 'whole' ? encodeURI(v) : encodeURIComponent(v));
        }
      } catch (e) {
        msgEl.innerHTML = `<div class="alert err">${esc(e.message)}</div>`;
      }
    }

    wrap.querySelectorAll('#encExamples .chip').forEach((c) =>
      c.addEventListener('click', () => {
        inBox.setValue(c.dataset.v);
        outBox.setValue('');
        run();
      })
    );
    wrap.querySelector('#swap').addEventListener('click', () => {
      // 结果搬回输入框：自动判断会随之翻转方向（编码结果 → 解码，反之亦然）
      const a = inBox.getValue();
      inBox.setValue(outBox.getValue());
      outBox.setValue(a);
      run();
    });
    wrap.querySelector('#clear').addEventListener('click', () => {
      inBox.setValue('');
      outBox.setValue('');
      msgEl.innerHTML = '';
    });
    inBox.onChange(run);
  },
};
