/* 端口扫描（Workers 版）：用 TCP Socket API 探测，受平台限制：
   同请求最多 6 个并发建连、禁止连 Cloudflare / 私有网段、无 UDP */
import { connect } from 'cloudflare:sockets';
import {
  COMMON_PORTS,
  PORT_SERVICE,
  clamp,
  isIP,
  isPrivateHost,
  normalizeHost,
  parsePortSpec,
} from '../lib/util.js';

const MAX_PORTS = 150;
const CONCURRENCY = 6;

function probe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    let socket;
    const finish = (open, reason) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        if (socket) socket.close();
      } catch (_) {}
      resolve({ port, open, ms: Date.now() - t0, reason: reason || null });
    };
    const timer = setTimeout(() => finish(false, 'timeout'), timeoutMs);
    try {
      socket = connect({ hostname: host, port });
      socket.opened.then(
        () => finish(true),
        (e) => finish(false, (e && e.message) || 'error')
      );
    } catch (e) {
      finish(false, (e && e.message) || 'error');
    }
  });
}

const BLOCKED = /cannot connect to the specified address|proxy request failed|prohibited|not allowed/i;

export default async function portScan(input) {
  const host = normalizeHost(input.host);
  if (isIP(host) && isPrivateHost(host)) {
    throw new Error('云端环境禁止连接内网 / 本机地址，端口扫描仅在本地运行时可用');
  }

  const spec = String(input.ports || '').trim();
  const ports = parsePortSpec(spec || COMMON_PORTS.join(','), MAX_PORTS);
  const timeoutMs = clamp(Number(input.timeout) || 1200, 300, 5000);
  const startedAt = Date.now();

  const results = [];
  for (let i = 0; i < ports.length; i += CONCURRENCY) {
    const batch = ports.slice(i, i + CONCURRENCY);
    const part = await Promise.all(batch.map((p) => probe(host, p, timeoutMs)));
    // 平台直接拒绝连接（内网 / Cloudflare 自家地址）时，整批都没意义，立刻中断
    if (part.every((r) => !r.open && r.reason && BLOCKED.test(r.reason))) {
      throw new Error('平台禁止连接该地址（内网、本机或 Cloudflare 网段），请换一个公网目标');
    }
    results.push(...part);
  }

  results.sort((a, b) => a.port - b.port);
  const open = results
    .filter((r) => r.open)
    .map((r) => ({ port: r.port, service: PORT_SERVICE[r.port] || '', ms: r.ms }));

  return {
    host,
    target: host,
    scanned: ports.length,
    open,
    elapsed: Date.now() - startedAt,
    timeout: timeoutMs,
    limit: MAX_PORTS,
    concurrency: CONCURRENCY,
  };
}
