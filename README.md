# 运维工具箱

一套纯前端 + 轻量服务端的运维小工具集合，共 14 个工具，按「网络工具 / 时间与调度 / 格式化与预览 / 编码转换」分组。

**只有一套代码**：服务端是一个 Web 标准处理器（`Request → Response`），同一个入口文件既能被 `node` 直接执行，也能作为 Cloudflare Worker 运行。Node 与 Workers 的差别（DNS、TLS、TCP、静态资源）全部收在 `src/platform/` 下的两个文件里，接口逻辑只有一份。

## 工具清单

**网络工具**：HTTP 调试、SSL 证书检测、DNS 查询、IP 子网计算器、端口扫描、IP 地址查询
**时间与调度**：Cron 生成器、时间戳转换
**格式化与预览**：JSON 格式化、Markdown 预览器、文件差异对比
**编码转换**：Base64 编解码、URL 编解码、YAML / JSON 转换

其中 8 个纯前端工具（Cron、时间戳、JSON、Markdown、差异对比、Base64、URL、YAML）不经过服务端。

## 运行

```bash
npm install

npm start          # Node：       http://localhost:3000
npm run dev        # Workers 本地：http://127.0.0.1:8787
```

两者跑的是**同一个 `src/index.js`**，端口可用 `PORT=8080 npm start` 修改。

## 部署到 Cloudflare

```bash
npx wrangler login     # 首次需要授权
npm run deploy         # 等价于 wrangler deploy
```

部署后在 `*.workers.dev` 可直接访问；也可以在控制台把仓库接到 **Workers Builds**，以后 push 到 main 自动发布。

`wrangler.jsonc`：

```jsonc
{
  "name": "ops-toolbox",
  "main": "src/index.js",
  "assets": { "directory": "./public", "binding": "ASSETS" }
}
```

命中 `public/` 里的文件由边缘节点直接返回，`/api/*` 进入 Worker，前端不需要改接口地址。

## 目录结构

```
src/
  index.js           唯一入口：路由 + 静态资源 + Node 自举（导出 { fetch } 供 Workers 用）
  api/               六个接口，两种运行时共用
    dns.js           DNS 查询（组合/并发/回退）
    http.js          HTTP 调试（重定向、编码、结果整形）
    ssl.js           SSL 检测（握手模式 / CT 模式）
    portscan.js      端口扫描（并发模型与结果）
    ipinfo.js        IP 归属地 + 本机信息
  lib/
    util.js          IP/端口/地址分类/响应封装
    doh.js           DoH 客户端（Workers 的解析实现）
    geo.js           归属地三源兜底
    ct.js            证书透明日志查询（Workers 的证书来源）
  platform/
    index.js         运行时探测 + 按需加载
    node.js          node:dns / node:tls / node:net / node:os / 文件系统
    workers.js       DoH / cloudflare:sockets / request.cf / ASSETS
public/              前端（index.html / js / css / vendor），无构建步骤
wrangler.jsonc       Workers 配置
```

平台接口很薄，只有这几项：`dnsOne`、`lookupIps`、`reverseLookup`、`httpSend`、`tcpProbe`、`tcpOpen`、`inspectTls`、`serveStatic`。其余全部是共享逻辑——加一个新工具只需写 `src/api/xxx.js` 并在 `index.js` 的 `ROUTES` 里登记一行。

## 两种运行时的能力差异

| 能力 | Node 本地 | Cloudflare Workers |
| --- | --- | --- |
| DNS 查询 | 系统解析器，支持任意 DNS 服务器，CAA / PTR 等记录完整 | 走 DoH（Cloudflare / 腾讯 / Google 自动择优 + 回退），自定义服务器仅限已知公共 DNS |
| SSL 证书检测 | 两端同一条路：自解析 TLS 握手（`src/lib/rawtls.js`）拿真实证书链、协议、套件 + 逐版本探测；信任链校验需系统信任库，两端均标记为未校验；握手失败时退 CT 日志 + SSL Labs 兜底 | 同左 |
| 端口扫描 | 2000 端口、80 并发，可扫内网 | 150 端口、6 并发，平台禁止连接内网与本机地址 |
| IP 地址查询 | 归属地 + 反向解析，两端一致 | 同左（公网出口优先显示 IPv4） |
| HTTP 调试 | 分段耗时（DNS/TCP/TLS）、HTTP 版本、可测自签证书 | `fetch` 代理，无分段耗时与版本号，其余一致 |
| 静态资源 | 直接读 `public/` | `ASSETS` 绑定 |

这些差异由 `src/platform/*` 上报的 `limits` 决定，前端据运行环境自动收紧限制（例如端口扫描在云端把上限收紧到 150）。

## 依赖的第三方服务

Workers 版不需要任何密钥，但用到这些公共服务：DoH 解析（Cloudflare / 腾讯 / Google）、归属地（ipwho.is、ip-api.com、ipinfo.io）、证书数据（Cert Spotter、crt.sh、SSL Labs）。都有速率限制，个人使用足够；要做公开服务建议换自建或付费接口。

## 说明

- 「端口扫描」仅用于检测自己有权限的目标。
- 所有查询结果不落库、不写日志，两种运行时都无持久化存储。
- 需要 Node 20+（`import.meta.main`、全局 `Request` / `Response`）。
