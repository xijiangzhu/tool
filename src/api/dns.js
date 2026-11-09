/* DNS 查询：解析层由平台提供（Node 走系统解析器，Workers 走 DoH），
   查询组合、候选服务器回退与返回结构在两种运行时完全一致。 */
import { isIP, normalizeHost, badRequest, friendlyDnsError, withTimeout } from '../lib/util.js';
import { platform } from '../platform/index.js';

const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'];
const ALL_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA']; // SRV 记录多且少见，不进「全部」
const DNS_CONCURRENCY = 8; // 两端统一的批量查询并发
/** 这些错误说明当前解析器本身不可用，值得换下一个服务器再试 */
const SERVER_ERRORS = ['ECONNREFUSED', 'ETIMEOUT', 'ESERVFAIL', 'EDOH', 'EAI_AGAIN'];

export default async function dnsQuery(input) {
  const p = await platform();

  const rawName = String(input.name || '').trim();
  if (!rawName) throw badRequest('请输入域名或 IP');
  const type = String(input.type || 'A').toUpperCase();
  if (type !== 'ALL' && !DNS_TYPES.includes(type)) throw badRequest('不支持的记录类型');

  // PTR 查询时常见 [::1] / [1.2.3.4] 写法：先剥掉方括号再判 IP，
  // 否则 ipv=0，PTR 会被误判成「PTR 需要输入 IP 地址」
  const cleanName = rawName.replace(/^\[|\]$/g, '');
  const ipv = isIP(cleanName);
  const name = ipv ? cleanName : normalizeHost(cleanName);
  if (rawName.includes('@') || /^[a-z][a-z0-9+.-]*:\/\//i.test(rawName)) {
    throw badRequest('请填写域名或 IP，不要带协议与路径');
  }

  // 自定义服务器：Node 支持任意 IP，云端只能是已知的公共 DoH
  const wanted = String(input.server || '').trim();
  let endpoint;
  let usedServer = '';
  if (wanted) {
    if (!isIP(wanted)) throw badRequest('自定义 DNS 服务器需填写 IP 地址');
    const chk = p.checkDnsServer(wanted);
    if (!chk.ok) throw badRequest(chk.error);
    endpoint = chk.endpoint;
    usedServer = chk.label;
  }

  const queryOne = async (t, srv) => {
    if (t === 'PTR' && !ipv) {
      return { type: t, records: [], error: 'PTR 查询需要输入 IP 地址', code: 'EINVAL', elapsed: 0 };
    }
    let r;
    try {
      // 单条查询硬截止，避免某个解析器无响应时把整批（ALL 查询 8 个类型）拖住
      r = await withTimeout(p.dnsOne(name, t, { server: srv, endpoint }), 8000, 'DNS 查询超时');
    } catch (e) {
      return {
        type: t,
        records: [],
        error: friendlyDnsError(e),
        code: e.code || 'ETIMEOUT',
        elapsed: 8000,
      };
    }
    if (r.server) usedServer = r.server; // 回退到新服务器时同步更新展示名称
    return {
      type: t,
      records: r.records || [],
      error: r.error || null,
      code: r.code || null,
      elapsed: r.elapsed || 0,
    };
  };

  /** 用指定解析服务器跑本次查询（ALL 时按平台并发分批） */
  const runWith = async (srv) => {
    const defaultLabel = p.name === 'node' ? '(系统默认)' : '公共 DoH';
    if (type !== 'ALL') {
      const one = await queryOne(type, srv);
      return {
        name,
        type,
        groups: one.records.length ? [one] : [],
        errors: one.error ? [one] : [],
        empty: [],
        error: one.error,
        code: one.code,
        elapsed: one.elapsed,
        server: usedServer || defaultLabel,
      };
    }
    const types = ipv ? ['PTR'] : ALL_TYPES;
    const results = [];
    for (let i = 0; i < types.length; i += DNS_CONCURRENCY) {
      results.push(
        ...(await Promise.all(types.slice(i, i + DNS_CONCURRENCY).map((t) => queryOne(t, srv))))
      );
    }
    return {
      name,
      type,
      groups: results.filter((r) => r.records.length),
      errors: results.filter((r) => r.error && r.code !== 'ENODATA' && r.code !== 'EINVAL'),
      empty: results.filter((r) => !r.records.length && r.code === 'ENODATA').map((r) => r.type),
      elapsed: results.reduce((a, r) => Math.max(a, r.elapsed || 0), 0),
      server: usedServer || defaultLabel,
    };
  };

  // 系统解析器可能指向本机一个没起来的 stub（如 127.0.0.1:53），此时自动退到公共 DNS
  const candidates = await p.dnsCandidates(wanted);
  let last = null;
  for (const srv of candidates) {
    last = await runWith(srv);
    if (last.groups.length) return last;
    const serverDown = (last.errors || []).some((e) => SERVER_ERRORS.includes(e.code));
    if (!serverDown) break;
  }
  return last;
}
