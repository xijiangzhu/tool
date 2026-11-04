/* YAML / JSON 互转 */
import { h, codeBox, esc, segGroup } from '../ui.js';
import * as YAML from '../../vendor/js-yaml.mjs';

const YAML_SAMPLE = `# 运维工具箱示例配置
version: "1.2"
enabled: true
replicas: 3
labels:
  app: ops-toolbox
  tier: frontend
ports:
  - 80
  - 443
resources:
  limits: { cpu: "500m", memory: 512Mi }
notes: |
  多行字符串示例
  第二行内容
`;

const JSON_SAMPLE = `{
  "version": "1.2",
  "enabled": true,
  "replicas": 3,
  "labels": { "app": "ops-toolbox", "tier": "frontend" },
  "ports": [80, 443],
  "resources": { "limits": { "cpu": "500m", "memory": "512Mi" } },
  "notes": "运维工具箱示例配置"
}`;

export default {
  id: 'yamljson',
  name: 'YAML / JSON 转换',
  group: '编码转换',
  desc: 'YAML 与 JSON 双向转换，支持多文档合并与缩进设置',
  keywords: 'yaml json 转换 k8s 配置 convert',
  mount(root) {
    root.innerHTML = '';
    const wrap = h(`
      <section class="card">
        <div class="card-head">
          <div class="card-title"><span class="dot"></span>YAML ⇄ JSON</div>
          <div class="card-note">K8s / Ansible / Spring 配置互转，报错定位到行列</div>
        </div>
        <div class="card-body">
          <div class="tool-bar">
            <div class="seg" id="dir">
              <button data-v="y2j" class="active">YAML → JSON</button>
              <button data-v="j2y">JSON → YAML</button>
            </div>
            <select id="indent" class="w150">
              <option value="2">缩进 2</option>
              <option value="4">缩进 4</option>
            </select>
            <label class="check"><input type="checkbox" id="multi" checked /> 多文档合并为数组</label>
            <span class="spacer"></span>
            <button class="btn btn-sm" id="sample">示例</button>
            <button class="btn btn-sm" id="swap">交换</button>
            <button class="btn btn-sm btn-primary" id="run">转换 →</button>
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

    const outOpts = {
      lang: 'json',
      title: 'JSON 输出',
      height: 'var(--yaml-h)',
      download: { name: 'output.json', mime: 'application/json;charset=utf-8' },
    };
    const inBox = codeBox({ lang: 'yaml', title: 'YAML 输入', height: 'var(--yaml-h)', placeholder: '粘贴 YAML…' });
    const outBox = codeBox(outOpts);
    wrap.querySelector('#in').appendChild(inBox.el);
    wrap.querySelector('#out').appendChild(outBox.el);

    let dir = 'y2j';
    const msgEl = wrap.querySelector('#msg');

    const dirSeg = segGroup(wrap.querySelector('#dir'), (v) => {
      dir = v;
      setLabels();
      run();
    });

    function setLabels() {
      const y2j = dir === 'y2j';
      inBox.setLang(y2j ? 'yaml' : 'json');
      outBox.setLang(y2j ? 'json' : 'yaml');
      inBox.setTitle(y2j ? 'YAML 输入' : 'JSON 输入');
      outBox.setTitle(y2j ? 'JSON 输出' : 'YAML 输出');
      outOpts.download.name = y2j ? 'output.json' : 'output.yaml';
      outOpts.download.mime = y2j ? 'application/json;charset=utf-8' : 'text/yaml;charset=utf-8';
      wrap.querySelector('#run').textContent = y2j ? '转为 JSON →' : '转为 YAML →';
      wrap.querySelector('#sample').textContent = '示例';
    }

    function yerr(e) {
      let extra = '';
      if (e && e.mark) {
        const lines = inBox.getValue().split('\n');
        const line = e.mark.line + 1;
        const text = lines[e.mark.line] || '';
        const caret = ' '.repeat(Math.min(e.mark.column, text.length)) + '^';
        extra = `\n位置：第 ${line} 行第 ${e.mark.column + 1} 列\n\n${line} | ${text}\n${' '.repeat(String(line).length + 3)}${caret}`;
      }
      msgEl.innerHTML = `<div class="alert err">${esc(e.message || String(e))}${esc(extra)}</div>`;
    }

    function run() {
      msgEl.innerHTML = '';
      const raw = inBox.getValue();
      if (!raw.trim()) return outBox.setValue('');
      const indent = Number(wrap.querySelector('#indent').value);
      try {
        if (dir === 'y2j') {
          const multi = wrap.querySelector('#multi').checked;
          let value;
          if (multi) {
            const docs = YAML.loadAll(raw);
            if (docs.length === 0) throw new Error('未解析到任何 YAML 文档');
            value = docs.length === 1 ? docs[0] : docs;
          } else {
            value = YAML.load(raw);
          }
          const out = JSON.stringify(value, null, indent);
          outBox.setValue(out);
        } else {
          const out = YAML.dump(JSON.parse(raw), {
            indent,
            lineWidth: 120,
            noRefs: true,
            sortKeys: false,
            forceQuotes: false,
          });
          outBox.setValue(out);
        }
      } catch (e) {
        if (e && e.name === 'YAMLException') yerr(e);
        else msgEl.innerHTML = `<div class="alert err">${esc(e.message || String(e))}</div>`;
      }
    }

    wrap.querySelector('#run').addEventListener('click', run);
    wrap.querySelector('#sample').addEventListener('click', () => {
      inBox.setValue(dir === 'y2j' ? YAML_SAMPLE : JSON_SAMPLE);
      run();
    });
    wrap.querySelector('#swap').addEventListener('click', () => {
      const a = inBox.getValue();
      inBox.setValue(outBox.getValue());
      outBox.setValue(a);
      dir = dir === 'y2j' ? 'j2y' : 'y2j';
      dirSeg.set(dir);
      setLabels();
      run();
    });
    setLabels();
  },
};
