/* 端口扫描：并发模型与结果结构统一，单端口探测能力由平台提供。
   两端共用同一套限制（上限 2000 端口、最小超时 100ms）；
   仅有的差异是平台固有的：Node 并发 80、可扫内网；Workers 并发 6（平台连接数限制）且禁止内网。 */
import {
  COMMON_PORTS,
  PORT_SERVICE,
  clamp,
  isIP,
  isPrivateHost,
  normalizeHost,
  parsePortSpec,
  badRequest,
  withTimeout,
} from '../lib/util.js';
import { platform } from '../platform/index.js';

/** 两端统一的限制 */
const MAX_PORTS = 2000;
const MIN_TIMEOUT = 100;
const DEADLINE_MS = 30000; // 单次接口请求的整体截止，超出后返回已扫部分，不再继续新批次

/** 平台直接拒绝连接（内网 / 本机 / Cloudflare 网段）时给出的错误特征 */
const BLOCKED = /cannot connect to the specified address|proxy request failed|prohibited|not allowed/i;

export default async function portScan(input) {
  const p = await platform();
  const { limits } = p;

  const host = normalizeHost(input.host);
  if (limits.blockPrivateHost && isIP(host) && isPrivateHost(host)) {
    throw badRequest('云端环境禁止连接内网 / 本机地址，端口扫描仅在本地运行时可用');
  }

  const spec = String(input.ports || '').trim();
  const ports = parsePortSpec(spec || COMMON_PORTS.join(','), { max: MAX_PORTS });
  const timeoutMs = clamp(Number(input.timeout) || 2000, MIN_TIMEOUT, 5000);

  // 先解析成 IP：既方便展示实际目标，也让「禁止内网」的校验覆盖域名解析结果
  let target = host;
  if (!isIP(host)) {
    let ips;
    try {
      ips = await withTimeout(p.lookupIps(host), 6000, 'DNS 解析超时');
    } catch (e) {
      throw badRequest(`DNS 解析失败：${e.code || e.message}`);
    }
    if (!ips.length) throw badRequest(`DNS 解析失败：${host} 没有解析记录`);
    target = ips[0];
    if (limits.blockPrivateHost && isPrivateHost(target)) {
      throw badRequest(`云端环境禁止连接内网 / 本机地址（${host} → ${target}），端口扫描仅在本地运行时可用`);
    }
  }

  const startedAt = Date.now();
  const concurrency = Math.max(1, Math.min(limits.concurrency, ports.length));
  const results = [];
  let truncated = false;

  for (let i = 0; i < ports.length; i += concurrency) {
    const remain = DEADLINE_MS - (Date.now() - startedAt);
    if (remain < MIN_TIMEOUT) {
      truncated = true;
      break;
    }
    const batch = ports.slice(i, i + concurrency);
    const part = await Promise.all(batch.map((port) => p.tcpProbe(target, port, Math.min(timeoutMs, remain))));
    results.push(...part);
    // 整批都是「平台拒绝连接」时，继续扫没有意义，立刻中断
    if (limits.blockPrivateHost && part.every((r) => !r.open && r.reason && BLOCKED.test(r.reason))) {
      throw badRequest('平台禁止连接该地址（内网、本机或 Cloudflare 网段），请换一个公网目标');
    }
  }

  results.sort((a, b) => a.port - b.port);
  const open = results
    .filter((r) => r.open)
    .map((r) => ({ port: r.port, service: PORT_SERVICE[r.port] || '', ms: r.ms }));

  return {
    host,
    target,
    scanned: results.length,
    truncated, // true 表示达到整体时间预算，只扫了前面一部分端口
    open,
    elapsed: Date.now() - startedAt,
    timeout: timeoutMs,
    limit: MAX_PORTS,
    concurrency,
  };
}
