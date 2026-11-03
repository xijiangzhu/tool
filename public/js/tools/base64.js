/* Base64 编解码 */
import { h, codeBox, segGroup } from '../ui.js';

function toBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

function fromBase64(str) {
  let s = String(str).replace(/\s+/g, '');
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  if (!/^[A-Za-z0-9+/=]+$/.test(s)) throw new Error('输入不是合法的 Base64 字符串');
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  try {
    return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), bytes };
  } catch (e) {
    let t = '';
    for (let i = 0; i < bin.length; i++) t += String.fromCharCode(bin.charCodeAt(i));
    return { text: t, bytes, warn: '内容不是合法 UTF-8，已按单字节显示' };
  }
}

export default {
  id: 'base64',
  name: 'Base64 编解码',
  group: '编码转换',
  desc: '文本 Base64 编码与解码，完整支持 UTF-8 中文，解码兼容 URL 安全字符',
  keywords: 'base64 编码 解码 encode decode',
  mount(root) {
    root.innerHTML = '';

    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>Base64 编解码</div>
          <div class="card-note">编码使用 UTF-8，解码自动补齐并兼容 URL 安全字符</div>
        </div>
        <div class="card-body">
          <div class="tool-bar">
            <div class="seg" id="mode">
              <button data-v="encode" class="active">编码 →</button>
              <button data-v="decode">解码 ←</button>
            </div>
            <label class="check"><input type="checkbox" id="live" checked /> 实时转换</label>
            <span class="spacer"></span>
            <button class="btn btn-sm" id="swap">交换</button>
            <button class="btn btn-sm btn-ghost" id="clear">清空</button>
            <button class="btn btn-sm btn-primary" id="run">立即转换</button>
          </div>
          <div class="split">
            <div id="inBox"></div>
            <div id="outBox"></div>
          </div>
          <div id="msg"></div>
        </div>
      </section>
    `);
    root.appendChild(wrap);

    const inBox = codeBox({ title: '输入', placeholder: '在此输入要编码的内容…', height: '260px' });
    const outBox = codeBox({ title: '输出（Base64）', placeholder: '转换结果…', height: '260px' });
    wrap.querySelector('#inBox').appendChild(inBox.el);
    wrap.querySelector('#outBox').appendChild(outBox.el);

    const msgEl = wrap.querySelector('#msg');
    const live = wrap.querySelector('#live');
    let mode = 'encode';

    function syncTitles() {
      const enc = mode === 'encode';
      inBox.setTitle(enc ? '输入（原文）' : '输入（Base64）');
      outBox.setTitle(enc ? '输出（Base64）' : '输出（原文）');
      inBox.ta.placeholder = enc ? '在此输入要编码的内容…' : '在此粘贴 Base64 字符串…';
      outBox.ta.placeholder = enc ? '编码结果…' : '解码结果…';
    }

    const modeSeg = segGroup(wrap.querySelector('#mode'), (v) => {
      mode = v;
      syncTitles();
      run();
    });

    function run() {
      msgEl.innerHTML = '';
      const input = inBox.getValue();
      if (!input) {
        outBox.setValue('');
        return;
      }
      try {
        if (mode === 'encode') {
          outBox.setValue(toBase64(input));
        } else {
          const r = fromBase64(input);
          outBox.setValue(r.text);
          if (r.warn) msgEl.innerHTML = `<div class="alert warn">${r.warn}</div>`;
        }
      } catch (e) {
        msgEl.innerHTML = `<div class="alert err">${e.message}</div>`;
      }
    }

    inBox.onChange(() => live.checked && run());
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
  },
};
