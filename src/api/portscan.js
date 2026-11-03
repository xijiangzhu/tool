/* 端口扫描：并发模型与结果结构统一，单端口探测能力由平台提供。
   两端上限均为 2000 端口；Node 并发 80、可扫内网；Workers 并发 6（平台连接数限制）且禁止内网。 */
import {
  COMMON_PORTS,
  PORT_SERVICE,
  clamp,
  isIP,
  isPrivateHost,
  normalizeHost,
  parsePortSpec,
} from '../lib/util.js';
import { platform } from '../platform/index.js';

/** 平台直接拒绝连接（内网 / 本机 / Cloudflare 网段）时给出的错误特征 */
const BLOCKED = /cannot connect to the specified address|proxy request failed|prohibited|not allowed/i;

export default async function portScan(input) {
  const p = await platform();
  const { limits } = p;

  const host = normalizeHost(input.host);
  if (limits.blockPrivateHost && isIP(host) && isPrivateHost(host)) {
    throw new Error('云端环境禁止连接内网 / 本机地址，端口扫描仅在本地运行时可用');
  }

  const spec = String(input.ports || '').trim();
  const ports = parsePortSpec(spec || COMMON_PORTS.join(','), {
    max: limits.maxPorts,
    suffix: limits.portSuffix || '',
  });
  const timeoutMs = clamp(Number(input.timeout) || 2000, limits.minTimeout, 5000);

  // 先解析成 IP：既方便展示实际目标，也让「禁止内网」的校验覆盖域名解析结果
  let target = host;
  if (!isIP(host)) {
    let ips;
    try {
      ips = await p.lookupIps(host);
    } catch (e) {
      throw new Error(`DNS 解析失败：${e.code || e.message}`);
    }
    if (!ips.length) throw new Error(`DNS 解析失败：${host} 没有解析记录`);
    target = ips[0];
    if (limits.blockPrivateHost && isPrivateHost(target)) {
      throw new Error(`云端环境禁止连接内网 / 本机地址（${host} → ${target}），端口扫描仅在本地运行时可用`);
    }
  }

  const startedAt = Date.now();
  const concurrency = Math.max(1, Math.min(limits.concurrency, ports.length));
  const results = [];

  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency);
    const part = await Promise.all(batch.map((port) => p.tcpProbe(target, port, timeoutMs)));
    results.push(...part);
    // 整批都是「平台拒绝连接」时，继续扫没有意义，立刻中断
    if (limits.blockPrivateHost && part.every((r) => !r.open && r.reason && BLOCKED.test(r.reason))) {
      throw new Error('平台禁止连接该地址（内网、本机或 Cloudflare 网段），请换一个公网目标');
    }
  }

  results.sort((a, b) => a.port - b.port);
  const open = results
    .filter((r) => r.open)
    .map((r) => ({ port: r.port, service: PORT_SERVICE[r.port] || '', ms: r.ms }));

  return {
    host,
    target,
    scanned: ports.length,
    open,
    elapsed: Date.now() - startedAt,
    timeout: timeoutMs,
    limit: limits.maxPorts,
    concurrency,
  };
}
