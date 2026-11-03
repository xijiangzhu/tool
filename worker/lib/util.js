/* 公共工具：IP 判断、主机归一化、端口解析、作用域判定等（无 Node 依赖） */

export const clamp = (v, min, max) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return min;
  return Math.min(Math.max(n, min), max);
};

/** 统一 JSON 响应（带 CORS，便于前端同源或跨域调用） */
export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*',
    },
  });
}

export function isIPv4(s) {
  if (typeof s !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return false;
  return s.split('.').every((x) => Number(x) <= 255);
}

export function isIPv6(s) {
  if (typeof s !== 'string' || !s.includes(':') || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
  if (s.includes(':::')) return false;
  const parts = s.split('::');
  if (parts.length > 2) return false;
  const groups = (p) => (p ? p.split(':').filter(Boolean) : []);
  const head = groups(parts[0]);
  const tail = parts.length === 2 ? groups(parts[1]) : [];
  const total = head.length + tail.length;
  if (parts.length === 2 ? total > 7 : total !== 8) return false;
  return [...head, ...tail].every((g) => /^[0-9a-fA-F]{1,4}$/.test(g)) || s.includes('.');
}

export const isIP = (s) => (isIPv4(s) ? 4 : isIPv6(s) ? 6 : 0);

/** 域名/URL 归一化，只允许安全字符 */
export function normalizeHost(raw) {
  let h = String(raw || '').trim();
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '');
  if (h.includes('@')) h = h.split('@').pop();
  h = h.replace(/^\[|\]$/g, '');
  if (!h) throw new Error('请输入域名或 IP');
  if (h.length > 253) throw new Error('域名过长');
  if (!/^[A-Za-z0-9._:-]+$/.test(h)) throw new Error('域名格式不合法（仅支持字母、数字、点、减号、下划线与冒号）');
  return h;
}

/** 私有 / 保留地址判断：Workers 禁止连接这些地址，提前给出友好提示 */
export function isPrivateHost(host) {
  if (!isIP(host)) return false;
  if (isIPv4(host)) {
    const [a, b] = host.split('.').map(Number);
    return (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  const low = host.toLowerCase();
  return low === '::1' || /^f[cd]/.test(low) || /^fe[89ab]/.test(low);
}

export const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445, 465, 587, 636, 873,
  993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 7001,
  8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017,
];

export const PORT_SERVICE = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
  111: 'rpcbind', 123: 'NTP', 135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP',
  443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP Submission', 636: 'LDAPS', 873: 'rsync',
  993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
  2049: 'NFS', 2375: 'Docker', 3000: 'Node/Grafana', 3306: 'MySQL', 3389: 'RDP', 5000: 'Flask/UPnP',
  5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 7001: 'WebLogic', 8000: 'HTTP Alt',
  8080: 'HTTP Proxy', 8443: 'HTTPS Alt', 8888: 'HTTP Alt', 9000: 'PHP-FPM', 9200: 'Elasticsearch',
  11211: 'Memcached', 27017: 'MongoDB',
};

export function parsePortSpec(spec, max = 200) {
  const out = new Set();
  const parts = String(spec || '').split(/[,\s]+/).filter(Boolean);
  for (const p of parts) {
    const m = /^(\d{1,5})\s*-\s*(\d{1,5})$/.exec(p);
    if (m) {
      const a = Number(m[1]);
      const b = Number(m[2]);
      if (a < 1 || b > 65535 || a > b) throw new Error(`端口范围不合法：${p}`);
      for (let i = a; i <= b; i++) out.add(i);
    } else if (/^\d{1,5}$/.test(p)) {
      const n = Number(p);
      if (n < 1 || n > 65535) throw new Error(`端口不合法：${p}`);
      out.add(n);
    } else {
      throw new Error(`端口格式不正确：${p}`);
    }
    if (out.size > max) throw new Error(`单次最多扫描 ${max} 个端口（云端并发受限）`);
  }
  if (!out.size) throw new Error('请填写要扫描的端口');
  return [...out].sort((a, b) => a - b);
}

/** 判断 IP 的用途类型（内网 / 环回 / 保留 …） */
export function ipScope(ip) {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return { kind: 'private', label: '内网私有' };
    if (a === 172 && b >= 16 && b <= 31) return { kind: 'private', label: '内网私有' };
    if (a === 192 && b === 168) return { kind: 'private', label: '内网私有' };
    if (a === 127) return { kind: 'loopback', label: '本机环回' };
    if (a === 169 && b === 254) return { kind: 'linklocal', label: '链路本地' };
    if (a === 100 && b >= 64 && b <= 127) return { kind: 'cgnat', label: '运营商级 NAT' };
    if (a >= 224 && a <= 239) return { kind: 'multicast', label: '组播地址' };
    if (a >= 240 || a === 0) return { kind: 'reserved', label: '保留地址' };
    return { kind: 'public', label: '公网地址' };
  }
  if (v === 6) {
    const low = ip.toLowerCase();
    if (low === '::1') return { kind: 'loopback', label: '本机环回' };
    if (/^f[cd]/.test(low)) return { kind: 'private', label: 'IPv6 唯一本地' };
    if (/^fe[89ab]/.test(low)) return { kind: 'linklocal', label: '链路本地' };
    if (/^ff/.test(low)) return { kind: 'multicast', label: '组播地址' };
    return { kind: 'public', label: '公网地址' };
  }
  return { kind: 'unknown', label: '未知' };
}

/** IPv4 → 十进制整数 */
export function ipv4ToInt(ip) {
  if (!isIPv4(ip)) return null;
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

/** IPv4 / IPv6 反查域名（in-addr.arpa / ip6.arpa） */
export function reverseName(ip) {
  if (isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  if (!isIPv6(ip)) return null;
  const full = expandIPv6(ip);
  if (!full) return null;
  const nibbles = full.replace(/:/g, '').split('').reverse().join('.');
  return nibbles + '.ip6.arpa';
}

export function expandIPv6(ip) {
  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  if (ip.includes('::')) {
    const fill = 8 - h.length - t.length;
    if (fill < 0) return null;
    return [...h, ...new Array(fill).fill('0'), ...t].map((x) => x.padStart(4, '0')).join(':');
  }
  const parts = ip.split(':');
  if (parts.length !== 8) return null;
  return parts.map((x) => x.padStart(4, '0')).join(':');
}

/** 带超时的 fetch（AbortSignal.timeout 在 Workers 可用） */
export function fetchWithTimeout(url, options = {}, ms = 8000) {
  const signal = AbortSignal.timeout(ms);
  return fetch(url, { ...options, signal });
}
