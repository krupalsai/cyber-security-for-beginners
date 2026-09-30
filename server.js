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
const SHODAN_API_KEY = process.env.SHODAN_API_KEY || '';
const SPIDERFOOT_URL = (process.env.SPIDERFOOT_URL || '').replace(/\/+$/, '');
const SPIDERFOOT_USER = process.env.SPIDERFOOT_USER || '';
const SPIDERFOOT_PASS = process.env.SPIDERFOOT_PASS || '';
const QWEN_API_KEY = process.env.QWEN_API_KEY || process.env.DASHSCOPE_API_KEY || '';
const QWEN_BASE_URL = (process.env.QWEN_BASE_URL ||
  'https://dashscope-intl.aliyuncs.com/compatible-mode/v1').replace(/\/+$/, '');
const QWEN_MODEL = process.env.QWEN_MODEL || 'qwen-plus';

const PUBLIC_DIR = path.join(__dirname, 'public');
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
      authRequired: Boolean(APP_PASSWORD),
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

  if (APP_PASSWORD && !safeEqual(req.headers['x-app-password'] || '', APP_PASSWORD)) {
    return sendJson(res, 401, { error: 'Wrong or missing app password' });
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
      `Qwen: ${QWEN_API_KEY ? QWEN_MODEL : 'off'} | Password: ${APP_PASSWORD ? 'on' : 'OFF'}`);
  });
}

module.exports = { server };
