// OSINT Web Console — a browser front end for Shodan, SpiderFoot, Qwen and
// Maltego-style link analysis. Zero npm dependencies: needs Node.js 18+.
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const crypto = require('crypto');

loadDotEnv(path.join(__dirname, '.env'));

const PORT = Number(process.env.PORT) || 3000;
const APP_PASSWORD = process.env.APP_PASSWORD || '';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_ALLOWED_USERS = new Set((process.env.TELEGRAM_ALLOWED_USERS || '')
  .split(/[\s,]+/).filter(Boolean));
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
const SHODAN_API_KEY = process.env.SHODAN_API_KEY || '';
const SPIDERFOOT_URL = (process.env.SPIDERFOOT_URL || '').replace(/\/+$/, '');
const SPIDERFOOT_USER = process.env.SPIDERFOOT_USER || '';
const SPIDERFOOT_PASS = process.env.SPIDERFOOT_PASS || '';
const QWEN_API_KEY = process.env.QWEN_API_KEY || process.env.DASHSCOPE_API_KEY || '';
const QWEN_BASE_URL = (process.env.QWEN_BASE_URL ||
  'https://dashscope-intl.aliyuncs.com/compatible-mode/v1').replace(/\/+$/, '');
const QWEN_MODEL = process.env.QWEN_MODEL || 'qwen-plus';

const PUBLIC_DIR = path.join(__dirname, 'public');
const CATALOG = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'catalog.json'), 'utf8'));
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
};

// ---------------------------------------------------------------- helpers

function loadDotEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m || process.env[m[1]] !== undefined) continue;
    process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
  }
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new HttpError(413, 'Request body too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new HttpError(400, 'Body must be valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;

function requireDomain(v) {
  const d = String(v || '').trim().toLowerCase().replace(/\.$/, '');
  if (!DOMAIN_RE.test(d)) throw new HttpError(400, 'Enter a valid domain, e.g. example.com');
  return d;
}

function requireIp(v) {
  const ip = String(v || '').trim();
  if (!net.isIP(ip)) throw new HttpError(400, 'Enter a valid IPv4 or IPv6 address');
  return ip;
}

function requireText(v, name, max = 500) {
  const s = String(v || '').trim();
  if (!s) throw new HttpError(400, `${name} is required`);
  if (s.length > max) throw new HttpError(400, `${name} is too long (max ${max} chars)`);
  return s;
}

async function fetchJson(url, opts = {}, label = 'upstream') {
  let r;
  try {
    r = await fetch(url, { ...opts, signal: AbortSignal.timeout(opts.timeout || 30000) });
  } catch (e) {
    throw new HttpError(502, `${label} unreachable: ${e.cause?.code || e.message}`);
  }
  const text = await r.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!r.ok) {
    const msg = (data && (data.error?.message || data.error || data.message)) || text || r.statusText;
    throw new HttpError(r.status === 401 || r.status === 403 ? 502 : r.status >= 500 ? 502 : r.status,
      `${label} error (${r.status}): ${String(msg).slice(0, 300)}`);
  }
  return data;
}

// ---------------------------------------------------------------- Shodan

function shodanKey() {
  if (!SHODAN_API_KEY) throw new HttpError(503, 'Shodan is not configured: set SHODAN_API_KEY');
  return encodeURIComponent(SHODAN_API_KEY);
}

const shodan = {
  host: (b) => fetchJson(
    `https://api.shodan.io/shodan/host/${encodeURIComponent(requireIp(b.ip))}?key=${shodanKey()}`,
    {}, 'Shodan'),
  search: (b) => {
    const q = encodeURIComponent(requireText(b.query, 'Query'));
    const page = Math.max(1, Math.min(100, Number(b.page) || 1));
    return fetchJson(
      `https://api.shodan.io/shodan/host/search?key=${shodanKey()}&query=${q}&page=${page}`,
      {}, 'Shodan');
  },
  count: (b) => fetchJson(
    `https://api.shodan.io/shodan/host/count?key=${shodanKey()}&query=${encodeURIComponent(requireText(b.query, 'Query'))}&facets=country,port,org`,
    {}, 'Shodan'),
  domain: (b) => fetchJson(
    `https://api.shodan.io/dns/domain/${encodeURIComponent(requireDomain(b.domain))}?key=${shodanKey()}`,
    {}, 'Shodan'),
  resolve: (b) => fetchJson(
    `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(requireDomain(b.domain))}&key=${shodanKey()}`,
    {}, 'Shodan'),
  info: () => fetchJson(`https://api.shodan.io/api-info?key=${shodanKey()}`, {}, 'Shodan'),
};

// ---------------------------------------------------------------- SpiderFoot
// Talks to a self-hosted SpiderFoot web UI (python3 sf.py -l 0.0.0.0:5001).

function sfBase() {
  if (!SPIDERFOOT_URL) {
    throw new HttpError(503, 'SpiderFoot is not configured: set SPIDERFOOT_URL (e.g. http://your-server:5001)');
  }
  return SPIDERFOOT_URL;
}

function sfHeaders(extra = {}) {
  const h = { Accept: 'application/json', ...extra };
  if (SPIDERFOOT_USER) {
    h.Authorization = 'Basic ' + Buffer.from(`${SPIDERFOOT_USER}:${SPIDERFOOT_PASS}`).toString('base64');
  }
  return h;
}

const SF_USECASES = new Set(['all', 'footprint', 'investigate', 'passive']);
const SF_ID_RE = /^[A-Za-z0-9]{1,64}$/;

function sfId(v) {
  const id = String(v || '').trim();
  if (!SF_ID_RE.test(id)) throw new HttpError(400, 'Invalid scan id');
  return id;
}

const spiderfoot = {
  ping: () => fetchJson(`${sfBase()}/ping`, { headers: sfHeaders() }, 'SpiderFoot'),
  start: async (b) => {
    const target = requireText(b.target, 'Target', 255);
    const usecase = SF_USECASES.has(b.usecase) ? b.usecase : 'passive';
    const form = new URLSearchParams({
      scanname: requireText(b.name || `Web scan ${target}`, 'Scan name', 100),
      scantarget: target,
      usecase,
      modulelist: '',
      typelist: '',
    });
    const r = await fetchJson(`${sfBase()}/startscan`, {
      method: 'POST',
      headers: sfHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: form.toString(),
    }, 'SpiderFoot');
    if (Array.isArray(r) && r[0] === 'SUCCESS') return { id: r[1] };
    throw new HttpError(502, `SpiderFoot refused scan: ${Array.isArray(r) ? r[1] : JSON.stringify(r)}`);
  },
  list: async () => {
    const rows = await fetchJson(`${sfBase()}/scanlist`, { headers: sfHeaders() }, 'SpiderFoot');
    return (rows || []).map((r) => ({
      id: r[0], name: r[1], target: r[2], created: r[3], started: r[4],
      finished: r[5], status: r[6], elements: r[7],
    }));
  },
  status: (b) => fetchJson(`${sfBase()}/scanstatus?id=${sfId(b.id)}`, { headers: sfHeaders() }, 'SpiderFoot'),
  summary: async (b) => {
    const rows = await fetchJson(`${sfBase()}/scansummary?id=${sfId(b.id)}&by=type`,
      { headers: sfHeaders() }, 'SpiderFoot');
    return (rows || []).map((r) => ({ type: r[0], description: r[1], last: r[2], total: r[3], unique: r[4] }));
  },
  results: async (b) => {
    const type = /^[A-Z0-9_]{1,64}$/.test(b.type || '') ? b.type : 'ALL';
    const rows = await fetchJson(
      `${sfBase()}/scaneventresults?id=${sfId(b.id)}&eventType=${type}`,
      { headers: sfHeaders(), timeout: 60000 }, 'SpiderFoot');
    return (rows || []).slice(0, 2000).map((r) => ({
      time: r[0], data: r[1], source: r[2], module: r[3], type: r[10] || r[4],
    }));
  },
  stop: (b) => fetchJson(`${sfBase()}/stopscan?id=${sfId(b.id)}`, { headers: sfHeaders() }, 'SpiderFoot'),
};

// ---------------------------------------------------------------- Qwen (Alibaba Cloud Model Studio, OpenAI-compatible)

const SYSTEM_PROMPT = `You are an OSINT and defensive-security analyst assistant embedded in a web console
that wraps Shodan, SpiderFoot and a Maltego-style link graph. Help the user interpret results,
explain Kali Linux tools and techniques, suggest Shodan queries and next investigative steps,
and point out security exposures and how to fix them. Assume the user is working on assets they
own or are authorised to assess; remind them of that when an action would touch third-party systems.
Be concise and use Markdown.`;

async function qwenChat(b) {
  if (!QWEN_API_KEY) throw new HttpError(503, 'Qwen is not configured: set QWEN_API_KEY');
  const history = Array.isArray(b.messages) ? b.messages : [];
  const messages = history
    .filter((m) => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
    .slice(-20)
    .map((m) => ({ role: m.role, content: m.content.slice(0, 20000) }));
  if (!messages.length) throw new HttpError(400, 'Message is required');
  if (b.context) {
    messages.unshift({
      role: 'user',
      content: `Context data collected in this session (JSON, may be truncated):\n${String(b.context).slice(0, 30000)}`,
    }, { role: 'assistant', content: 'Understood. I will use that data.' });
  }
  const data = await fetchJson(`${QWEN_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${QWEN_API_KEY}` },
    body: JSON.stringify({
      model: QWEN_MODEL,
      messages: [{ role: 'system', content: SYSTEM_PROMPT }, ...messages],
      temperature: 0.4,
    }),
    timeout: 120000,
  }, 'Qwen');
  return { model: data.model || QWEN_MODEL, reply: data.choices?.[0]?.message?.content || '' };
}

// ---------------------------------------------------------------- Maltego-style transforms
// Each transform takes one entity and returns new entities + links for the graph.

async function settle(p) {
  try { return await p; } catch { return []; }
}

const transforms = {
  'domain.dns': async (value) => {
    const d = requireDomain(value);
    const [a, aaaa, mx, ns, txt] = await Promise.all([
      settle(dns.resolve4(d)), settle(dns.resolve6(d)), settle(dns.resolveMx(d)),
      settle(dns.resolveNs(d)), settle(dns.resolveTxt(d)),
    ]);
    return [
      ...a.map((v) => ({ type: 'ip', value: v, label: 'A' })),
      ...aaaa.map((v) => ({ type: 'ip', value: v, label: 'AAAA' })),
      ...mx.map((v) => ({ type: 'mx', value: v.exchange, label: `MX ${v.priority}` })),
      ...ns.map((v) => ({ type: 'ns', value: v, label: 'NS' })),
      ...txt.map((v) => ({ type: 'phrase', value: v.join('').slice(0, 200), label: 'TXT' })),
    ].filter((e) => e.value);
  },
  'domain.subdomains': async (value) => {
    const r = await shodan.domain({ domain: value });
    const d = r.domain || value;
    return (r.subdomains || []).slice(0, 100).map((s) => ({
      type: 'domain', value: s ? `${s}.${d}` : d, label: 'subdomain',
    }));
  },
  'domain.crtsh': async (value) => (await lookups.crtsh({ domain: value })).subdomains
    .slice(0, 150).map((v) => ({ type: 'domain', value: v, label: 'cert' })),
  'domain.whois': async (value) => {
    const r = await lookups.rdap({ query: value });
    return [
      ...r.entities.filter((e) => e.name).map((e) => ({ type: 'org', value: e.name, label: (e.roles || []).join('/') || 'entity' })),
      ...r.events.map((e) => ({ type: 'phrase', value: `${e.action}: ${String(e.date).slice(0, 10)}`, label: 'whois' })),
    ];
  },
  'ip.whois': async (value) => {
    const r = await lookups.rdap({ query: requireIp(value) });
    return [
      r.name && { type: 'org', value: r.name, label: 'network' },
      r.range && { type: 'phrase', value: r.range, label: 'range' },
      r.country && { type: 'location', value: r.country, label: 'country' },
      ...r.entities.filter((e) => e.name).map((e) => ({ type: 'org', value: e.name, label: (e.roles || []).join('/') || 'entity' })),
    ].filter(Boolean);
  },
  'vuln.cve': async (value) => {
    const r = await lookups.cve({ id: value });
    return [
      r.cvss && { type: 'phrase', value: `CVSS ${r.cvss.score} ${r.cvss.severity}`, label: 'score' },
      ...r.weaknesses.map((w) => ({ type: 'phrase', value: w, label: 'CWE' })),
    ].filter(Boolean);
  },
  'ip.reverse': async (value) => {
    const names = await settle(dns.reverse(requireIp(value)));
    return names.map((n) => ({ type: 'domain', value: n, label: 'PTR' }));
  },
  'ip.shodan': async (value) => {
    const h = await shodan.host({ ip: value });
    const out = [];
    for (const p of h.ports || []) out.push({ type: 'port', value: `${value}:${p}`, label: 'open' });
    for (const n of h.hostnames || []) out.push({ type: 'domain', value: n, label: 'hostname' });
    if (h.org) out.push({ type: 'org', value: h.org, label: 'org' });
    if (h.asn) out.push({ type: 'asn', value: h.asn, label: 'ASN' });
    if (h.country_name) out.push({ type: 'location', value: [h.city, h.country_name].filter(Boolean).join(', '), label: 'geo' });
    for (const v of Object.keys(h.vulns || {}).slice(0, 50)) out.push({ type: 'vuln', value: v, label: 'vuln' });
    return out;
  },
  'mx.resolve': async (value) => (await settle(dns.resolve4(requireDomain(value))))
    .map((v) => ({ type: 'ip', value: v, label: 'A' })),
  'ns.resolve': async (value) => (await settle(dns.resolve4(requireDomain(value))))
    .map((v) => ({ type: 'ip', value: v, label: 'A' })),
};

async function runTransform(b) {
  const fn = transforms[b.transform];
  if (!fn) throw new HttpError(400, 'Unknown transform');
  const entities = await fn(String(b.value || '').trim());
  return { entities };
}

// ---------------------------------------------------------------- Free passive lookups (no API key)

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

// RDAP: ask the authoritative registry found via IANA's bootstrap files, falling
// back to the rdap.org redirector (which rate-limits some cloud hosts).
const RDAP_HEADERS = { Accept: 'application/rdap+json', 'User-Agent': 'osint-web-console/1.0' };
const rdapBootstrap = {};

async function rdapServices(kind) {
  const cached = rdapBootstrap[kind];
  if (cached && Date.now() - cached.at < 24 * 3600e3) return cached.services;
  const data = await fetchJson(`https://data.iana.org/rdap/${kind}.json`, { headers: RDAP_HEADERS }, 'IANA');
  rdapBootstrap[kind] = { at: Date.now(), services: data.services || [] };
  return rdapBootstrap[kind].services;
}

function ipToBigInt(ip) {
  if (net.isIPv4(ip)) return { v: 4, n: ip.split('.').reduce((a, o) => (a << 8n) + BigInt(o), 0n) };
  let [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  if (t.length && t[t.length - 1].includes('.')) { // IPv4-mapped tail
    const v4 = ipToBigInt(t.pop()).n;
    t.push((v4 >> 16n).toString(16), (v4 & 0xffffn).toString(16));
  }
  const groups = ip.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  return { v: 6, n: groups.reduce((a, g) => (a << 16n) + BigInt(parseInt(g || '0', 16)), 0n) };
}

function inCidr(ip, cidr) {
  const [base, lenStr] = cidr.split('/');
  const a = ipToBigInt(ip); const b = ipToBigInt(base);
  if (a.v !== b.v) return false;
  const bits = a.v === 4 ? 32n : 128n;
  const len = BigInt(lenStr ?? bits);
  const shift = bits - len;
  return (a.n >> shift) === (b.n >> shift);
}

async function rdapBaseUrls(kind, target) {
  if (kind === 'ip') {
    const services = await rdapServices(net.isIPv4(target) ? 'ipv4' : 'ipv6');
    let best = null;
    for (const [prefixes, urls] of services) {
      for (const p of prefixes) {
        const len = Number(p.split('/')[1] || 0);
        if (inCidr(target, p) && (!best || len > best.len)) best = { len, urls };
      }
    }
    return best ? best.urls : [];
  }
  const services = await rdapServices('dns');
  const labels = target.split('.');
  for (let i = 0; i < labels.length; i++) {
    const suffix = labels.slice(i).join('.');
    const hit = services.find(([tlds]) => tlds.includes(suffix));
    if (hit) return hit[1];
  }
  return [];
}

async function rdapQuery(kind, target) {
  const errors = [];
  try {
    const bases = (await rdapBaseUrls(kind, target)).sort((a, b) => b.startsWith('https') - a.startsWith('https'));
    for (const base of bases.slice(0, 2)) {
      try {
        return await fetchJson(`${base.replace(/\/?$/, '/')}${kind}/${encodeURIComponent(target)}`,
          { headers: RDAP_HEADERS }, 'RDAP registry');
      } catch (e) { errors.push(e.message); }
    }
  } catch (e) { errors.push(e.message); }
  try {
    return await fetchJson(`https://rdap.org/${kind}/${encodeURIComponent(target)}`, { headers: RDAP_HEADERS }, 'rdap.org');
  } catch (e) {
    errors.push(e.message);
    throw new HttpError(502, `WHOIS/RDAP lookup failed: ${errors.join(' | ')}`);
  }
}

const lookups = {
  // Registration data (modern WHOIS) via the RDAP bootstrap redirector.
  rdap: async (b) => {
    const q = String(b.query || '').trim();
    const kind = net.isIP(q) ? 'ip' : 'domain';
    const target = kind === 'ip' ? q : requireDomain(q);
    const r = await rdapQuery(kind, target);
    const vcardName = (e) => (e.vcardArray?.[1] || []).find((f) => f[0] === 'fn')?.[3];
    return {
      query: target,
      name: r.ldhName || r.name,
      handle: r.handle,
      status: r.status,
      range: r.startAddress ? `${r.startAddress} - ${r.endAddress}` : undefined,
      country: r.country,
      events: (r.events || []).map((e) => ({ action: e.eventAction, date: e.eventDate })),
      nameservers: (r.nameservers || []).map((n) => n.ldhName),
      entities: (r.entities || []).map((e) => ({ roles: e.roles, name: vcardName(e) || e.handle })),
    };
  },
  // Certificate Transparency logs: every hostname that has had a public TLS certificate.
  crtsh: async (b) => {
    const d = requireDomain(b.domain);
    const rows = await fetchJson(`https://crt.sh/?q=${encodeURIComponent('%.' + d)}&output=json`,
      { timeout: 60000 }, 'crt.sh');
    const names = new Set();
    for (const r of rows || []) {
      for (const n of String(r.name_value || '').split('\n')) {
        const h = n.trim().toLowerCase().replace(/^\*\./, '');
        if (h === d || h.endsWith('.' + d)) names.add(h);
      }
    }
    return { domain: d, certificates: (rows || []).length, subdomains: [...names].sort().slice(0, 500) };
  },
  // Vulnerability details from the NIST National Vulnerability Database.
  cve: async (b) => {
    const id = String(b.id || '').trim().toUpperCase();
    if (!CVE_RE.test(id)) throw new HttpError(400, 'Enter a CVE id like CVE-2021-44228');
    const r = await fetchJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, {}, 'NVD');
    const c = r.vulnerabilities?.[0]?.cve;
    if (!c) throw new HttpError(404, `${id} not found in NVD`);
    const m = c.metrics || {};
    const cvss = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0]?.cvssData;
    return {
      id: c.id,
      published: c.published,
      status: c.vulnStatus,
      description: c.descriptions?.find((d) => d.lang === 'en')?.value,
      cvss: cvss && { score: cvss.baseScore, severity: cvss.baseSeverity, vector: cvss.vectorString },
      weaknesses: (c.weaknesses || []).flatMap((w) => w.description.map((d) => d.value)),
      references: (c.references || []).slice(0, 10).map((x) => x.url),
    };
  },
  dns: async (b) => ({ domain: requireDomain(b.domain), records: await transforms['domain.dns'](b.domain) }),
  reverseDns: async (b) => ({ ip: requireIp(b.ip), names: await settle(dns.reverse(requireIp(b.ip))) }),
};

// ---------------------------------------------------------------- Tool registry for auto-selection
// Every tool here is read-only or passive. `enabled` hides tools whose service isn't configured.

function findCatalogTools(text) {
  const t = String(text || '').toLowerCase();
  const word = (w) => new RegExp(`(^|[^a-z0-9])${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^a-z0-9])`).test(t);
  return CATALOG.tools.filter((x) => x.id !== 'vm' && (word(x.id) || word(x.name.toLowerCase())));
}

const TOOLS = [
  {
    name: 'kali_tool_info', service: 'Toolkit', enabled: () => true,
    description: 'Get the toolkit entry (purpose, install and safe usage commands, safety notes) for a Kali/OSINT tool such as Tor, Proxychains, TorBot, DarkDump, OnionSearch, Robin, Katana, Maltego, theHarvester, Maigret or Colly. Use it for questions about how to set up or use these tools, and for dark web research safety.',
    params: { name: 'Tool name' },
    run: (a) => {
      const hits = findCatalogTools(a.name);
      return { tools: hits.length ? hits : CATALOG.tools.map((x) => x.name), bestPractices: CATALOG.bestPractices, notice: CATALOG.notice };
    },
  },
  {
    name: 'dns_lookup', service: 'DNS', enabled: () => true,
    description: 'Get A, AAAA, MX, NS and TXT records for a domain.',
    params: { domain: 'Domain name, e.g. example.com' },
    run: (a) => lookups.dns(a),
  },
  {
    name: 'reverse_dns', service: 'DNS', enabled: () => true,
    description: 'Find hostnames (PTR records) for an IP address.',
    params: { ip: 'IPv4 or IPv6 address' },
    run: (a) => lookups.reverseDns(a),
  },
  {
    name: 'whois_rdap', service: 'RDAP/WHOIS', enabled: () => true,
    description: 'Registration data for a domain (registrar, dates, nameservers) or an IP (owner network, range, country).',
    params: { query: 'Domain name or IP address' },
    run: (a) => lookups.rdap(a),
  },
  {
    name: 'cert_transparency_subdomains', service: 'crt.sh', enabled: () => true,
    description: 'List subdomains of a domain found in public TLS certificate transparency logs.',
    params: { domain: 'Domain name' },
    run: (a) => lookups.crtsh(a),
  },
  {
    name: 'cve_details', service: 'NVD', enabled: () => true,
    description: 'Look up a CVE: description, CVSS score/severity, weakness type and references.',
    params: { id: 'CVE id, e.g. CVE-2021-44228' },
    run: (a) => lookups.cve(a),
  },
  {
    name: 'shodan_host', service: 'Shodan', enabled: () => Boolean(SHODAN_API_KEY),
    description: 'Shodan data for one IP: open ports, service banners, software versions, org, location and known CVEs.',
    params: { ip: 'IPv4 or IPv6 address' },
    run: async (a) => {
      const h = await shodan.host(a);
      return {
        ip: h.ip_str, org: h.org, isp: h.isp, asn: h.asn, os: h.os, country: h.country_name, city: h.city,
        hostnames: h.hostnames, ports: h.ports, vulns: Object.keys(h.vulns || {}), last_update: h.last_update,
        services: (h.data || []).map((s) => ({
          port: s.port, transport: s.transport, product: s.product, version: s.version,
          banner: String(s.data || '').slice(0, 200),
        })),
      };
    },
  },
  {
    name: 'shodan_count', service: 'Shodan', enabled: () => Boolean(SHODAN_API_KEY),
    description: 'Count internet hosts matching a Shodan query, with top countries, ports and orgs. Works on free plans.',
    params: { query: 'Shodan query, e.g. product:nginx country:IN' },
    run: (a) => shodan.count(a),
  },
  {
    name: 'shodan_search', service: 'Shodan', enabled: () => Boolean(SHODAN_API_KEY),
    description: 'Search Shodan and return matching hosts (needs a paid Shodan plan for filters).',
    params: { query: 'Shodan query' },
    run: async (a) => {
      const r = await shodan.search(a);
      return {
        total: r.total,
        matches: (r.matches || []).slice(0, 20).map((m) => ({
          ip: m.ip_str, port: m.port, org: m.org, product: m.product, hostnames: m.hostnames,
          country: m.location?.country_name,
        })),
      };
    },
  },
  {
    name: 'shodan_domain', service: 'Shodan', enabled: () => Boolean(SHODAN_API_KEY),
    description: 'Subdomains and DNS records Shodan knows for a domain.',
    params: { domain: 'Domain name' },
    run: async (a) => {
      const r = await shodan.domain(a);
      return { domain: r.domain, subdomains: r.subdomains, records: (r.data || []).slice(0, 100) };
    },
  },
  {
    name: 'spiderfoot_list_scans', service: 'SpiderFoot', enabled: () => Boolean(SPIDERFOOT_URL),
    description: 'List existing SpiderFoot scans with their status and ids.',
    params: {},
    run: () => spiderfoot.list(),
  },
  {
    name: 'spiderfoot_scan_summary', service: 'SpiderFoot', enabled: () => Boolean(SPIDERFOOT_URL),
    description: 'Summarise the data types and counts found by a SpiderFoot scan.',
    params: { id: 'SpiderFoot scan id' },
    run: (a) => spiderfoot.summary(a),
  },
  {
    name: 'spiderfoot_start_passive_scan', service: 'SpiderFoot', enabled: () => Boolean(SPIDERFOOT_URL),
    description: 'Start a PASSIVE SpiderFoot scan (no direct contact with the target). Only use when the user asks for a SpiderFoot scan.',
    params: { target: 'Domain, IP or other target' },
    run: (a) => spiderfoot.start({ target: a.target, usecase: 'passive' }),
  },
];

const toolByName = Object.fromEntries(TOOLS.map((t) => [t.name, t]));

function toolSchemas() {
  return TOOLS.filter((t) => t.enabled()).map((t) => ({
    type: 'function',
    function: {
      name: t.name,
      description: t.description,
      parameters: {
        type: 'object',
        properties: Object.fromEntries(Object.entries(t.params).map(([k, d]) => [k, { type: 'string', description: d }])),
        required: Object.keys(t.params),
      },
    },
  }));
}

function clip(v, max = 8000) {
  const s = JSON.stringify(v);
  return s.length > max ? s.slice(0, max) + '…(truncated)' : s;
}

async function runTool(name, args) {
  const t = toolByName[name];
  if (!t || !t.enabled()) return { ok: false, error: `Tool ${name} is not available` };
  try {
    return { ok: true, result: await t.run(args || {}) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// Keyword/regex router: used when Qwen is not configured, so Auto mode still works.
function planWithoutLlm(question) {
  const q = question.toLowerCase();
  const ips = [...new Set(question.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])].filter((ip) => net.isIPv4(ip));
  const cves = [...new Set((question.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map((c) => c.toUpperCase()))];
  const domains = [...new Set((question.match(/\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}\b/gi) || [])
    .map((d) => d.toLowerCase()).filter((d) => DOMAIN_RE.test(d) && !ips.includes(d)))];
  const plan = [];
  const add = (name, args) => { if (toolByName[name].enabled()) plan.push({ name, args }); };
  for (const id of cves.slice(0, 3)) add('cve_details', { id });
  for (const ip of ips.slice(0, 3)) {
    add('shodan_host', { ip });
    add('reverse_dns', { ip });
    if (/who|owner|whois|registr|isp|network/.test(q) || !SHODAN_API_KEY) add('whois_rdap', { query: ip });
  }
  for (const domain of domains.slice(0, 2)) {
    add('dns_lookup', { domain });
    add('cert_transparency_subdomains', { domain });
    if (/who|owner|whois|registr|expir|creat/.test(q)) add('whois_rdap', { query: domain });
    if (/shodan|port|service|expos/.test(q)) add('shodan_domain', { domain });
    if (/spiderfoot|full scan|deep/.test(q)) add('spiderfoot_start_passive_scan', { target: domain });
  }
  if (!plan.length && /shodan|how many|count|exposed|devices?/.test(q)) {
    const m = question.match(/["“](.+?)["”]/);
    if (m) add('shodan_count', { query: m[1] });
  }
  if (!plan.length && /spiderfoot|scans?/.test(q)) add('spiderfoot_list_scans', {});
  for (const t of findCatalogTools(q).slice(0, 3)) {
    if (t.id === 'shodan' && plan.length) continue;
    plan.push({ name: 'kali_tool_info', args: { name: t.name } });
  }
  if (!plan.length && /dark ?web|onion|\btor\b/.test(q)) plan.push({ name: 'kali_tool_info', args: { name: 'tor proxychains' } });
  return plan;
}

const AGENT_PROMPT = `${SYSTEM_PROMPT}

You can call tools. Decide from the user's question which tools are relevant, call them (in parallel
when independent), then answer using their results. Prefer free passive tools (DNS, RDAP, crt.sh, NVD)
before Shodan. Do not call tools that are not needed. After the tool results, give a clear answer with
the key findings, the security risks, and recommended next steps, including which Kali Linux tools the
user could use next (for assets they are authorised to test).
For dark web research questions: explain the safe setup first (isolated VM, Tor, proxychains, verification),
use kali_tool_info for tool details, and never help locate or access illegal content or services.`;

async function agent(b) {
  const question = requireText(b.question, 'Question', 4000);
  const history = (Array.isArray(b.history) ? b.history : [])
    .filter((m) => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
    .slice(-10).map((m) => ({ role: m.role, content: m.content.slice(0, 8000) }));
  const steps = [];

  if (!QWEN_API_KEY) {
    const plan = planWithoutLlm(question);
    for (const p of plan) steps.push({ tool: p.name, args: p.args, ...(await runTool(p.name, p.args)) });
    return {
      mode: 'rules',
      steps,
      reply: plan.length
        ? 'Ran the tools that matched your question (set QWEN_API_KEY for AI-planned lookups and a written analysis).'
        : 'I could not find an IP, domain or CVE in your question. Include one, e.g. "What is exposed on 8.8.8.8?"',
    };
  }

  const messages = [{ role: 'system', content: AGENT_PROMPT }, ...history, { role: 'user', content: question }];
  const tools = toolSchemas();
  for (let round = 0; round < 5; round++) {
    const data = await fetchJson(`${QWEN_BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${QWEN_API_KEY}` },
      body: JSON.stringify({ model: QWEN_MODEL, messages, tools, temperature: 0.2 }),
      timeout: 120000,
    }, 'Qwen');
    const msg = data.choices?.[0]?.message || {};
    const calls = msg.tool_calls || [];
    if (!calls.length) return { mode: 'ai', model: data.model || QWEN_MODEL, steps, reply: msg.content || '' };
    messages.push({ role: 'assistant', content: msg.content || '', tool_calls: calls });
    const results = await Promise.all(calls.map(async (c) => {
      let args = {};
      try { args = JSON.parse(c.function?.arguments || '{}'); } catch { /* leave empty */ }
      const r = await runTool(c.function?.name, args);
      steps.push({ tool: c.function?.name, args, ...r });
      return { role: 'tool', tool_call_id: c.id, content: clip(r.ok ? r.result : { error: r.error }) };
    }));
    messages.push(...results);
  }
  return { mode: 'ai', model: QWEN_MODEL, steps, reply: 'Stopped after 5 rounds of tool calls; see the results above.' };
}

function listTools() {
  return TOOLS.map((t) => ({ name: t.name, service: t.service, description: t.description, enabled: t.enabled() }));
}

// ---------------------------------------------------------------- Telegram Mini App auth
// https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app

const TELEGRAM_MAX_AGE_S = 24 * 60 * 60;

function verifyTelegramInitData(initData, botToken = TELEGRAM_BOT_TOKEN, now = Date.now()) {
  if (!initData || !botToken) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash || !/^[0-9a-f]{64}$/.test(hash)) return null;
  params.delete('hash');
  const checkString = [...params.entries()]
    .map(([k, v]) => `${k}=${v}`).sort().join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const expected = crypto.createHmac('sha256', secret).update(checkString).digest();
  if (!crypto.timingSafeEqual(expected, Buffer.from(hash, 'hex'))) return null;
  const authDate = Number(params.get('auth_date'));
  if (!authDate || now / 1000 - authDate > TELEGRAM_MAX_AGE_S) return null;
  try {
    return JSON.parse(params.get('user') || 'null');
  } catch {
    return null;
  }
}

function isAuthorized(req) {
  if (!APP_PASSWORD && !TELEGRAM_BOT_TOKEN) return true;
  if (APP_PASSWORD && safeEqual(req.headers['x-app-password'] || '', APP_PASSWORD)) return true;
  const user = verifyTelegramInitData(req.headers['x-telegram-init-data']);
  return Boolean(user && TELEGRAM_ALLOWED_USERS.has(String(user.id)));
}

// Point the bot's menu button at this site so it opens as a Mini App.
async function setupTelegramMenuButton() {
  if (!TELEGRAM_BOT_TOKEN || !PUBLIC_URL.startsWith('https://')) return;
  try {
    const r = await fetchJson(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setChatMenuButton`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ menu_button: { type: 'web_app', text: 'Open console', web_app: { url: PUBLIC_URL } } }),
    }, 'Telegram');
    console.log(`  Telegram menu button -> ${PUBLIC_URL}: ${r?.ok ? 'set' : 'failed'}`);
  } catch (e) {
    console.log(`  Telegram menu button not set: ${e.message}`);
  }
}

// ---------------------------------------------------------------- routing

const routes = {
  'POST /api/shodan/host': shodan.host,
  'POST /api/shodan/search': shodan.search,
  'POST /api/shodan/count': shodan.count,
  'POST /api/shodan/domain': shodan.domain,
  'POST /api/shodan/resolve': shodan.resolve,
  'POST /api/shodan/info': shodan.info,
  'POST /api/spiderfoot/ping': spiderfoot.ping,
  'POST /api/spiderfoot/start': spiderfoot.start,
  'POST /api/spiderfoot/list': spiderfoot.list,
  'POST /api/spiderfoot/status': spiderfoot.status,
  'POST /api/spiderfoot/summary': spiderfoot.summary,
  'POST /api/spiderfoot/results': spiderfoot.results,
  'POST /api/spiderfoot/stop': spiderfoot.stop,
  'POST /api/qwen/chat': qwenChat,
  'POST /api/graph/transform': runTransform,
  'POST /api/agent': agent,
  'POST /api/tools': listTools,
  'POST /api/catalog': () => CATALOG,
  'POST /api/lookup/rdap': lookups.rdap,
  'POST /api/lookup/crtsh': lookups.crtsh,
  'POST /api/lookup/cve': lookups.cve,
};

function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = path.normalize(path.join(PUBLIC_DIR, urlPath === '/' ? 'index.html' : urlPath));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return sendJson(res, 403, { error: 'Forbidden' });
  fs.readFile(file, (err, buf) => {
    if (err) return sendJson(res, 404, { error: 'Not found' });
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://x').pathname;

  if (req.method === 'GET' && pathname === '/api/config') {
    return sendJson(res, 200, {
      authRequired: Boolean(APP_PASSWORD || TELEGRAM_BOT_TOKEN),
      telegram: Boolean(TELEGRAM_BOT_TOKEN),
      shodan: Boolean(SHODAN_API_KEY),
      spiderfoot: Boolean(SPIDERFOOT_URL),
      qwen: Boolean(QWEN_API_KEY),
      qwenModel: QWEN_MODEL,
    });
  }

  if (!pathname.startsWith('/api/')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'Method not allowed' });
    return serveStatic(req, res);
  }

  const handler = routes[`${req.method} ${pathname}`];
  if (!handler) return sendJson(res, 404, { error: 'Unknown API route' });

  if (!isAuthorized(req)) {
    return sendJson(res, 401, { error: 'Not authorised: wrong password, or this Telegram account is not allowed' });
  }

  try {
    const body = await readBody(req);
    sendJson(res, 200, await handler(body));
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    if (status === 500) console.error(e);
    sendJson(res, status, { error: e.message || 'Internal error' });
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`OSINT Web Console on http://localhost:${PORT}`);
    console.log(`  Shodan: ${SHODAN_API_KEY ? 'on' : 'off'} | SpiderFoot: ${SPIDERFOOT_URL || 'off'} | ` +
      `Qwen: ${QWEN_API_KEY ? QWEN_MODEL : 'off'} | Password: ${APP_PASSWORD ? 'on' : 'OFF'} | ` +
      `Telegram: ${TELEGRAM_BOT_TOKEN ? `${TELEGRAM_ALLOWED_USERS.size} allowed user(s)` : 'off'}`);
    if (TELEGRAM_BOT_TOKEN && !TELEGRAM_ALLOWED_USERS.size) {
      console.warn('  Warning: TELEGRAM_ALLOWED_USERS is empty, so no Telegram user can use the API.');
    }
    setupTelegramMenuButton();
  });
}

module.exports = { server, planWithoutLlm, toolSchemas, verifyTelegramInitData, inCidr };
