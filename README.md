# 运维工具箱

一套纯前端 + 轻量服务端的运维小工具集合，共 14 个工具，按「网络工具 / 时间与调度 / 格式化与预览 / 编码转换」分组。

前端是原生 ES Module，无构建步骤；后端有两套等价实现：

| 运行方式 | 入口 | 说明 |
| --- | --- | --- |
| 本地 Node | `server.js` | 功能最完整，可读本机网卡、可扫内网端口、可做真实 TLS 握手 |
| Cloudflare Workers | `worker/index.js` | 一个 Worker 同时托管静态资源和 `/api/*` 接口，零服务器 |

## 工具清单

**网络工具**：HTTP 调试、SSL 证书检测、DNS 查询、IP 子网计算器、端口扫描、IP 地址查询
**时间与调度**：Cron 生成器、时间戳转换
**格式化与预览**：JSON 格式化、Markdown 预览器、文件差异对比
**编码转换**：Base64 编解码、URL 编解码、YAML / JSON 转换

纯前端工具（Cron、时间戳、JSON、Markdown、差异对比、Base64、URL、YAML）在两种运行方式下完全一致。

## 本地运行（Node）

```bash
npm install
npm start          # 默认 http://localhost:3000
```

## 本地运行（Workers）

```bash
npm install
npm run dev        # wrangler dev，默认 http://127.0.0.1:8787
```

## 部署到 Cloudflare

```bash
npx wrangler login     # 首次需要授权
npm run deploy         # 等价于 wrangler deploy
```

部署后在 `*.workers.dev` 域名可直接访问；也可以在 Cloudflare 控制台把仓库接到 **Workers Builds**，以后 push 到 main 自动发布。

`wrangler.jsonc` 已配置静态资源绑定：

```jsonc
{
  "name": "ops-toolbox",
  "main": "worker/index.js",
  "assets": { "directory": "./public", "binding": "ASSETS" }
}
```

即：命中 `public/` 里的文件直接由边缘节点返回，未命中的 `/api/*` 才进入 Worker，前端代码两边共用，不需要改接口地址。

## 两种模式的差异

| 能力 | Node 本地 | Cloudflare Workers |
| --- | --- | --- |
| DNS 查询 | 系统解析器 / 任意 DNS 服务器 | 走 DoH（Cloudflare / 腾讯 / Google 自动择优），自定义服务器仅支持已知公共 DNS |
| SSL 证书检测 | 真实 TLS 握手：协议、套件、完整证书链、链校验 | 公共 CT 日志取证书元数据 + 实时可达性探测；无协议、套件、链校验 |
| 端口扫描 | 2000 端口、80 并发、支持内网 | 150 端口、6 并发，平台禁止连接内网与本机地址 |
| IP 地址查询 | 归属地 + 本机网卡 + 反向解析 | 归属地 + 反向解析；**读不到本机网卡**，改显示运行环境与边缘节点 |
| HTTP 调试 | 可自定义 Host 头、看原始响应头 | `fetch` 代理，Host 等头由平台接管，看不到重复响应头 |

## 目录结构

```
server.js            Node 版服务端（静态托管 + 6 个接口）
worker/              Workers 版服务端（与 Node 版接口结构一致）
  index.js           路由 + 静态资源
  api/               dns / http / ssl / portscan / ipinfo
  lib/               DoH 封装、IP 与端口工具
public/              前端（index.html / js / css / vendor）
wrangler.jsonc       Workers 配置
```

## 依赖的第三方服务

Workers 版不依赖任何密钥，但用到了这些公共服务：DoH 解析（Cloudflare / 腾讯 / Google）、归属地（ipwho.is、ip-api.com、ipinfo.io）、证书日志（Cert Spotter、crt.sh）。它们都有速率限制，个人使用足够；如果要做成公开服务，建议换成自建或付费接口。

## 说明

- 「端口扫描」仅用于检测自己有权限的目标。
- 所有查询结果不落库、不写日志，Workers 版无任何持久化存储。
