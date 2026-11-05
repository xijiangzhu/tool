/* 公共工具：IP 判断、主机归一化、端口解析、地址分类、请求/响应封装。
   本文件不依赖任何运行时（Node / Workers 通用），只用 Web 标准 API。 */

export const clamp = (v, min, max) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return min;
  return Math.min(Math.max(n, min), max);
};

/* --------------------------------- IP 判断 -------------------------------- */

export function isIPv4(s) {
  if (typeof s !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return false;
  return s.split('.').every((x) => Number(x) <= 255);
}

export function isIPv6(s) {
  if (typeof s !== 'string' || !s.includes(':') || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
  if (s.includes(':::')) return false;
  // 形如 ::ffff:1.2.3.4 的内嵌 IPv4（仅允许出现在地址尾部）展开成两段 hex 再统一校验；
  // 中间混写点分十进制、或 IPv4 段超界一律返回 false
  let core = s;
  const lastColon = s.lastIndexOf(':');
  if (lastColon >= 0 && s.slice(lastColon + 1).includes('.')) {
    const tail = s.slice(lastColon + 1);
    if (!isIPv4(tail)) return false;
    core = s.slice(0, lastColon + 1) + v4ToHexPair(tail);
  }
  if (core.includes('.')) return false;
  const parts = core.split('::');
  if (parts.length > 2) return false;
  const groups = (p) => (p ? p.split(':').filter(Boolean) : []);
  const head = groups(parts[0]);
  const tail = parts.length === 2 ? groups(parts[1]) : [];
  const total = head.length + tail.length;
  if (parts.length === 2 ? total > 7 : total !== 8) return false;
  return [...head, ...tail].every((g) => /^[0-9a-fA-F]{1,4}$/.test(g));
}

/** 点分十进制 IPv4 → 两段 hex（1.2.3.4 → 102:304），供 isIPv6 / expandIPv6 使用 */
function v4ToHexPair(v4) {
  const [a, b, c, d] = v4.split('.').map(Number);
  return `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
}

export const isIP = (s) => (isIPv4(s) ? 4 : isIPv6(s) ? 6 : 0);

export function expandIPv6(ip) {
  // 内嵌 IPv4（::ffff:1.2.3.4）先展开成 hex，否则后续按 8 段 hex 处理会出错
  let s = ip;
  const lastColon = ip.lastIndexOf(':');
  if (lastColon >= 0 && ip.slice(lastColon + 1).includes('.') && isIPv4(ip.slice(lastColon + 1))) {
    s = ip.slice(0, lastColon + 1) + v4ToHexPair(ip.slice(lastColon + 1));
  }
  const [head, tail = ''] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  if (s.includes('::')) {
    const fill = 8 - h.length - t.length;
    if (fill < 0) return null;
    return [...h, ...new Array(fill).fill('0'), ...t].map((x) => x.padStart(4, '0')).join(':');
  }
  const parts = s.split(':');
  if (parts.length !== 8) return null;
  return parts.map((x) => x.padStart(4, '0')).join(':');
}

/** 域名/URL 归一化，只允许安全字符 */
export function normalizeHost(raw) {
  let h = String(raw || '').trim();
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '');
  if (h.includes('@')) h = h.split('@').pop();
  h = h.replace(/^\[|\]$/g, '');
  // 中文 / IDN 域名转 punycode（new URL 会按 IDNA 规则编码 hostname），失败则由后续字符校验报错
  if (/[^\x20-\x7e]/.test(h)) {
    try {
      h = new URL(`http://${h}`).hostname;
    } catch (_) {}
  }
  if (!h) throw new Error('请输入域名或 IP');
  if (h.length > 253) throw new Error('域名过长');
  // 单一冒号 + 数字结尾说明带的是端口，这里不接收 —— 端口属于「端口范围」输入框
  if (/^[^ :]+:\d{0,5}$/.test(h)) {
    throw new Error('请只填写主机名，不要带协议与端口（例如 example.com:8443 应填 example.com）');
  }
  if (!/^[A-Za-z0-9._:-]+$/.test(h)) throw new Error('域名格式不合法（仅支持字母、数字、点、减号、下划线与冒号）');
  return h;
}

/** 私有 / 保留地址判断：云端禁止连接这些地址，需要提前给出友好提示 */
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
  // IPv4-mapped IPv6（::ffff:127.0.0.1 / ::ffff:7f00:1）按内嵌的 IPv4 判断
  const mapped = /^::ffff:(.+)$/.exec(low);
  if (mapped) {
    const tail = mapped[1];
    if (isIPv4(tail)) return isPrivateHost(tail);
    const hex = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(tail);
    if (hex) {
      const hi = parseInt(hex[1], 16);
      const lo = parseInt(hex[2], 16);
      return isPrivateHost(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
  }
  return low === '::1' || /^f[cd]/.test(low) || /^fe[89ab]/.test(low);
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

/** IPv4 / IPv6 反查域名（in-addr.arpa / ip6.arpa） */
export function reverseName(ip) {
  if (isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  if (!isIPv6(ip)) return null;
  const full = expandIPv6(ip);
  if (!full) return null;
  const nibbles = full.replace(/:/g, '').split('').reverse().join('.');
  return nibbles + '.ip6.arpa';
}

/* --------------------------------- 端口扫描 -------------------------------- */

export const COMMON_PORTS = [
  21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 389,
  443, 445, 465, 500, 514, 515, 587, 623, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049,
  2181, 2375, 2376, 3000, 3306, 3389, 4444, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 7001,
  8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017,
];

export const PORT_SERVICE = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
  80: 'HTTP', 110: 'POP3', 111: 'rpcbind', 123: 'NTP', 135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS',
  139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP Trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
  465: 'SMTPS', 500: 'ISAKMP', 514: 'Syslog', 515: 'LPD', 587: 'SMTP Submission', 623: 'IPMI',
  636: 'LDAPS', 873: 'rsync', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL',
  1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS', 2181: 'ZooKeeper', 2375: 'Docker', 2376: 'Docker TLS',
  3000: 'Node/Grafana', 3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit', 5000: 'Flask/UPnP',
  5432: 'PostgreSQL', 5601: 'Kibana', 5672: 'RabbitMQ', 5900: 'VNC', 5984: 'CouchDB',
  6379: 'Redis', 7001: 'WebLogic', 8000: 'HTTP Alt', 8008: 'HTTP Alt', 8080: 'HTTP Proxy',
  8081: 'HTTP Alt', 8088: 'HTTP Alt', 8443: 'HTTPS Alt', 8888: 'HTTP Alt', 9000: 'PHP-FPM',
  9090: 'Prometheus', 9200: 'Elasticsearch', 9300: 'Elasticsearch', 10000: 'Webmin',
  11211: 'Memcached', 27017: 'MongoDB',
};

/** 解析端口表达式（逗号与区间混写），超过上限立即报错 */
export function parsePortSpec(spec, { max = 2000 } = {}) {
  const out = new Set();
  const parts = String(spec || '').split(/[,\s]+/).filter(Boolean);
  for (const p of parts) {
    const m = /^(\d{1,5})\s*-\s*(\d{1,5})$/.exec(p);
    if (m) {
      const a = Number(m[1]);
      const b = Number(m[2]);
      if (a < 1 || b > 65535 || a > b) throw new Error(`端口范围不合法：${p}`);
      for (let i = a; i <= b; i++) {
        out.add(i);
        if (out.size > max) throw new Error(`单次最多扫描 ${max} 个端口`);
      }
    } else if (/^\d{1,5}$/.test(p)) {
      const n = Number(p);
      if (n < 1 || n > 65535) throw new Error(`端口不合法：${p}`);
      out.add(n);
    } else {
      throw new Error(`端口格式不正确：${p}`);
    }
  }
  if (!out.size) throw new Error('请填写要扫描的端口');
  return [...out].sort((a, b) => a - b);
}

/* -------------------------------- DNS 错误 -------------------------------- */

export function friendlyDnsError(e) {
  const code = e && e.code;
  const map = {
    ENOTFOUND: '记录不存在（NXDOMAIN）',
    ENODATA: '该域名没有此类型的记录',
    ETIMEOUT: 'DNS 查询超时',
    ESERVFAIL: 'DNS 服务器返回失败（SERVFAIL）',
    EREFUSED: 'DNS 服务器拒绝查询（REFUSED）',
    ECONNREFUSED: '无法连接该 DNS 服务器',
  };
  return map[code] || (e && e.message) || '查询失败';
}

/* -------------------------------- 请求/响应 -------------------------------- */

const MAX_BODY = 5 * 1024 * 1024; // 5MB

/** 统一 JSON 响应 */
export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

export function textResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
  });
}

/** 读取并解析 JSON 请求体（两种运行时通用） */
export async function readJson(request) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > MAX_BODY) throw new Error('请求体过大（上限 5MB）');
  const raw = await request.text();
  if (raw.length > MAX_BODY) throw new Error('请求体过大（上限 5MB）');
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch (_) {
    throw new Error('请求体不是合法 JSON');
  }
}

/* --------------------------------- 二进制 --------------------------------- */

export const isTextualType = (ctype) =>
  /text|json|xml|javascript|urlencoded|graphql|html|csv|yaml/i.test(String(ctype || ''));

/** 二进制内容转 base64（分块，避免 fromCharCode 参数过多爆栈） */
export function toBase64(bytes) {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}
