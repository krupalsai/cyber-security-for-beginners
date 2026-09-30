'use strict';

// ------------------------------------------------------------ state & helpers

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  config: {},
  collected: [], // results gathered this session, fed to the AI as context
  chat: [],
};

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function getPassword() {
  try { return localStorage.getItem('osint-pw') || ''; } catch { return ''; }
}
function setPassword(pw) {
  try { localStorage.setItem('osint-pw', pw); } catch { /* storage blocked */ }
  sessionPw = pw;
}
let sessionPw = getPassword();

// Telegram Mini App: when opened inside Telegram, authenticate with the signed initData.
const tg = window.Telegram?.WebApp;
const tgInitData = tg?.initData || '';
if (tgInitData) {
  tg.ready();
  tg.expand();
  document.documentElement.classList.add('tg');
  const theme = () => document.documentElement.setAttribute('data-theme', tg.colorScheme === 'dark' ? 'dark' : 'light');
  theme();
  tg.onEvent('themeChanged', theme);
}

function askPassword() {
  return new Promise((resolve) => {
    const dlg = $('#pw-dialog');
    const form = $('#pw-form');
    form.pw.value = '';
    form.onsubmit = () => { setPassword(form.pw.value); resolve(); };
    dlg.showModal();
  });
}

async function api(route, body = {}, retry = true) {
  const r = await fetch(`/api/${route}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-App-Password': sessionPw,
      ...(tgInitData && { 'X-Telegram-Init-Data': tgInitData }),
    },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  if (r.status === 401 && retry) {
    await askPassword();
    return api(route, body, false);
  }
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

function remember(source, input, data) {
  state.collected.push({ source, input, data, at: new Date().toISOString() });
  if (state.collected.length > 30) state.collected.shift();
}

function card(title, html, { raw } = {}) {
  const el = document.createElement('div');
  el.className = 'card';
  el.innerHTML = `<h3><span>${esc(title)}</span>
      <span class="row">
        ${raw !== undefined ? '<button class="small secondary" data-act="raw">JSON</button>' : ''}
        <button class="small secondary" data-act="ask">Ask AI</button>
        <button class="small secondary" data-act="close">✕</button>
      </span></h3>
    <div class="body">${html}</div>`;
  el.addEventListener('click', (e) => {
    const act = e.target.dataset?.act;
    if (act === 'close') el.remove();
    if (act === 'raw') {
      const body = $('.body', el);
      body.innerHTML = body.dataset.raw ? body.dataset.html : `<pre>${esc(JSON.stringify(raw, null, 2))}</pre>`;
      if (body.dataset.raw) delete body.dataset.raw;
      else { body.dataset.raw = '1'; body.dataset.html = html; }
    }
    if (act === 'ask') {
      switchTab('ai');
      $('#chat-form').msg.value = `Analyse the "${title}" result: summarise what it reveals, the security risks, and recommended next steps.`;
      $('#chat-form').msg.focus();
    }
  });
  return el;
}

function showError(out, err) {
  const el = document.createElement('div');
  el.className = 'card';
  el.innerHTML = `<p class="error">${esc(err.message || err)}</p>`;
  out.prepend(el);
}

async function busy(btn, fn) {
  if (btn) btn.disabled = true;
  try { return await fn(); } finally { if (btn) btn.disabled = false; }
}

function table(rows, cols) {
  if (!rows.length) return '<p class="muted">No results.</p>';
  return `<div class="tablewrap"><table><thead><tr>${cols.map((c) => `<th>${esc(c.label)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${cols.map((c) => `<td>${c.html ? c.html(r) : esc(c.get(r))}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}

function kv(obj) {
  return `<dl class="kv">${Object.entries(obj)
    .filter(([, v]) => v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length))
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${Array.isArray(v) ? v.map((x) => `<span class="tag">${esc(x)}</span>`).join('') : esc(v)}</dd>`)
    .join('')}</dl>`;
}

// ------------------------------------------------------------ tabs

function switchTab(name) {
  $$('.tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  $$('.panel').forEach((p) => p.classList.toggle('active', p.id === `tab-${name}`));
  if (name === 'graph') graph.ensure();
  if (name === 'toolkit') loadKit();
  try { localStorage.setItem('osint-tab', name); } catch { /* ignore */ }
}
$$('.tabs button').forEach((b) => b.addEventListener('click', () => switchTab(b.dataset.tab)));

// ------------------------------------------------------------ home / config

async function loadConfig() {
  const r = await fetch('/api/config');
  state.config = await r.json();
  const c = state.config;
  const items = [
    ['Shodan', c.shodan, 'SHODAN_API_KEY', 'Internet-wide device & service search engine.'],
    ['SpiderFoot', c.spiderfoot, 'SPIDERFOOT_URL', 'Automated OSINT with 200+ modules.'],
    ['Qwen AI', c.qwen, 'QWEN_API_KEY', `Analyst assistant (model: ${c.qwenModel}).`],
    ['Maltego graph', true, '', 'Link analysis with DNS & Shodan transforms, Maltego export.'],
  ];
  $('#status-cards').innerHTML = items.map(([name, on, env, desc]) => `
    <div class="card"><h3>${esc(name)}</h3>
      <p class="status ${on ? 'on' : 'off'}">${on ? '● Ready' : `○ Not configured — set ${esc(env)}`}</p>
      <p class="muted">${esc(desc)}</p></div>`).join('');
  $('#ai-model').textContent = c.qwen ? c.qwenModel : 'rule-based (no Qwen key)';
  if (c.authRequired && !sessionPw && !tgInitData) await askPassword();
  loadTools();
}

async function loadTools() {
  try {
    const tools = await api('tools');
    $('#tool-list').innerHTML = tools.map((t) => `<div class="tool-row">
        <div><code>${esc(t.name)}</code> <span class="tag">${esc(t.service)}</span><div class="muted">${esc(t.description)}</div></div>
        <span class="status ${t.enabled ? 'on' : 'off'}">${t.enabled ? '●' : '○'}</span></div>`).join('');
  } catch (e) {
    $('#tool-list').innerHTML = `<p class="error">${esc(e.message)}</p>`;
  }
}

$('#home-ask').addEventListener('submit', (e) => {
  e.preventDefault();
  const q = e.target.q.value.trim();
  if (!q) return;
  e.target.q.value = '';
  switchTab('ai');
  const f = $('#chat-form');
  f.msg.value = q;
  f.auto.checked = true;
  f.requestSubmit();
});

// ------------------------------------------------------------ Shodan

function renderShodanHost(h) {
  const services = (h.data || []).map((s) => ({
    port: `${s.port}/${s.transport || 'tcp'}`,
    product: [s.product, s.version].filter(Boolean).join(' '),
    module: s._shodan?.module,
    banner: (s.data || '').slice(0, 300),
  }));
  return kv({
    IP: h.ip_str, Organisation: h.org, ISP: h.isp, ASN: h.asn,
    Location: [h.city, h.region_code, h.country_name].filter(Boolean).join(', '),
    OS: h.os, Hostnames: h.hostnames, Domains: h.domains, Ports: h.ports, Tags: h.tags,
    'Last update': h.last_update,
  }) + (h.vulns ? `<h3 style="margin-top:1rem">Vulnerabilities</h3>${Object.keys(h.vulns).map((v) => `<span class="tag vuln">${esc(v)}</span>`).join('')}` : '')
    + `<h3 style="margin-top:1rem">Services</h3>` + table(services, [
      { label: 'Port', get: (r) => r.port },
      { label: 'Product', get: (r) => r.product },
      { label: 'Module', get: (r) => r.module },
      { label: 'Banner', html: (r) => `<code>${esc(r.banner)}</code>` },
    ]);
}

const shodanActions = {
  'shodan-host': async (f) => {
    const ip = f.ip.value.trim();
    const h = await api('shodan/host', { ip });
    remember('shodan.host', ip, h);
    return card(`Shodan host ${ip}`, renderShodanHost(h), { raw: h });
  },
  'shodan-search': async (f) => {
    const query = f.query.value.trim();
    const r = await api('shodan/search', { query });
    remember('shodan.search', query, { total: r.total, matches: r.matches?.slice(0, 20) });
    return card(`Search "${query}" — ${r.total ?? 0} total`, table(r.matches || [], [
      { label: 'IP', get: (m) => m.ip_str },
      { label: 'Port', get: (m) => m.port },
      { label: 'Org', get: (m) => m.org },
      { label: 'Location', get: (m) => [m.location?.city, m.location?.country_name].filter(Boolean).join(', ') },
      { label: 'Product', get: (m) => m.product },
      { label: 'Hostnames', get: (m) => (m.hostnames || []).join(', ') },
    ]), { raw: r });
  },
  'shodan-count': async (f) => {
    const query = f.query.value.trim();
    const r = await api('shodan/count', { query });
    remember('shodan.count', query, r);
    const facets = Object.entries(r.facets || {}).map(([name, vals]) =>
      `<h3 style="margin-top:.75rem">Top ${esc(name)}</h3>` +
      table(vals, [{ label: 'Value', get: (v) => v.value }, { label: 'Count', get: (v) => v.count }])).join('');
    return card(`Count "${query}" — ${r.total ?? 0} hosts`, facets, { raw: r });
  },
  'shodan-domain': async (f) => {
    const domain = f.domain.value.trim();
    const r = await api('shodan/domain', { domain });
    remember('shodan.domain', domain, { subdomains: r.subdomains, data: r.data?.slice(0, 100) });
    return card(`Domain ${domain} — ${(r.subdomains || []).length} subdomains`,
      `<p>${(r.subdomains || []).map((s) => `<span class="tag">${esc(s)}.${esc(r.domain)}</span>`).join('')}</p>` +
      table((r.data || []).slice(0, 300), [
        { label: 'Sub', get: (d) => d.subdomain || '@' },
        { label: 'Type', get: (d) => d.type },
        { label: 'Value', get: (d) => d.value },
        { label: 'Last seen', get: (d) => d.last_seen },
      ]), { raw: r });
  },
  'shodan-resolve': async (f) => {
    const domain = f.domain.value.trim();
    const r = await api('shodan/resolve', { domain });
    remember('shodan.resolve', domain, r);
    return card(`Resolve ${domain}`, kv(r), { raw: r });
  },
  'shodan-info': async () => {
    const r = await api('shodan/info');
    return card('Shodan API plan', kv(r), { raw: r });
  },
};

// ------------------------------------------------------------ SpiderFoot

const sfPollers = new Map();

async function sfRefresh() {
  const box = $('#sf-list');
  try {
    const scans = await api('spiderfoot/list');
    box.innerHTML = table(scans, [
      { label: 'Name', get: (s) => s.name },
      { label: 'Target', get: (s) => s.target },
      { label: 'Status', get: (s) => s.status },
      { label: 'Items', get: (s) => s.elements },
      { label: '', html: (s) => `<div class="row"><button class="small" data-sf="view" data-id="${esc(s.id)}">View</button>
          ${['RUNNING', 'STARTING', 'STARTED'].includes(s.status) ? `<button class="small secondary" data-sf="stop" data-id="${esc(s.id)}">Stop</button>` : ''}</div>` },
    ]);
  } catch (e) {
    box.innerHTML = `<p class="error">${esc(e.message)}</p>`;
  }
}

async function sfView(id) {
  const out = $('#sf-out');
  const [summary, results] = await Promise.all([
    api('spiderfoot/summary', { id }),
    api('spiderfoot/results', { id }),
  ]);
  remember('spiderfoot.results', id, { summary, results: results.slice(0, 200) });
  const types = [...new Set(results.map((r) => r.type))].sort();
  const el = card(`SpiderFoot scan ${id} — ${results.length} findings`,
    table(summary, [
      { label: 'Data type', get: (s) => s.description },
      { label: 'Unique', get: (s) => s.unique },
      { label: 'Total', get: (s) => s.total },
    ]) +
    `<label style="margin-top:1rem">Filter by type
      <select data-filter><option value="">All types</option>${types.map((t) => `<option>${esc(t)}</option>`).join('')}</select></label>
     <div data-rows></div>
     <button class="small secondary" data-graph>Add findings to graph</button>`, { raw: results });
  const renderRows = (type) => {
    $('[data-rows]', el).innerHTML = `<div class="scroll">${table(results.filter((r) => !type || r.type === type).slice(0, 500), [
      { label: 'Type', get: (r) => r.type },
      { label: 'Data', html: (r) => `<code>${esc(String(r.data).slice(0, 400))}</code>` },
      { label: 'Module', get: (r) => r.module },
    ])}</div>`;
  };
  renderRows('');
  $('[data-filter]', el).addEventListener('change', (e) => renderRows(e.target.value));
  $('[data-graph]', el).addEventListener('click', () => {
    graph.ensure();
    const root = graph.addNode('scan', id, `SpiderFoot ${id}`);
    const map = { IP_ADDRESS: 'ip', INTERNET_NAME: 'domain', DOMAIN_NAME: 'domain', EMAILADDR: 'email', TCP_PORT_OPEN: 'port', VULNERABILITY_CVE_CRITICAL: 'vuln', VULNERABILITY_CVE_HIGH: 'vuln' };
    for (const r of results) {
      const t = map[r.type];
      if (t) graph.addEdge(root, graph.addNode(t, String(r.data)), r.type);
    }
    switchTab('graph');
  });
  out.prepend(el);
}

function sfPoll(id) {
  if (sfPollers.has(id)) return;
  const t = setInterval(async () => {
    try {
      const s = await api('spiderfoot/status', { id });
      const status = Array.isArray(s) ? s[5] : s?.status;
      if (!['RUNNING', 'STARTING', 'STARTED', 'INITIALIZING'].includes(status)) {
        clearInterval(t); sfPollers.delete(id);
      }
      sfRefresh();
    } catch { clearInterval(t); sfPollers.delete(id); }
  }, 10000);
  sfPollers.set(id, t);
}

$('#sf-refresh').addEventListener('click', sfRefresh);
$('#sf-list').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-sf]');
  if (!btn) return;
  await busy(btn, async () => {
    try {
      if (btn.dataset.sf === 'view') await sfView(btn.dataset.id);
      if (btn.dataset.sf === 'stop') { await api('spiderfoot/stop', { id: btn.dataset.id }); sfRefresh(); }
    } catch (err) { showError($('#sf-out'), err); }
  });
});

const sfActions = {
  'sf-start': async (f) => {
    const r = await api('spiderfoot/start', { target: f.target.value, name: f.name.value, usecase: f.usecase.value });
    sfRefresh();
    sfPoll(r.id);
    return card('Scan started', `<p>Scan <code>${esc(r.id)}</code> is running. The list refreshes every 10 seconds; tap <b>View</b> any time to see findings so far.</p>`);
  },
};

// ------------------------------------------------------------ Maltego-style graph

const ENTITY = {
  domain: { color: '#2563eb', shape: 'dot', maltego: 'maltego.Domain', transforms: [['domain.dns', 'DNS records (A/MX/NS/TXT)'], ['domain.crtsh', 'Subdomains (certificate logs)'], ['domain.whois', 'WHOIS / RDAP'], ['domain.subdomains', 'Subdomains (Shodan)']] },
  ip: { color: '#16a34a', shape: 'dot', maltego: 'maltego.IPv4Address', transforms: [['ip.shodan', 'Ports, org, vulns (Shodan)'], ['ip.reverse', 'Reverse DNS'], ['ip.whois', 'Owner network (RDAP)']] },
  mx: { color: '#9333ea', shape: 'diamond', maltego: 'maltego.MXRecord', transforms: [['mx.resolve', 'Resolve to IP']] },
  ns: { color: '#c026d3', shape: 'diamond', maltego: 'maltego.NSRecord', transforms: [['ns.resolve', 'Resolve to IP']] },
  port: { color: '#ea580c', shape: 'square', maltego: 'maltego.Port', transforms: [] },
  org: { color: '#0891b2', shape: 'triangle', maltego: 'maltego.Organization', transforms: [] },
  asn: { color: '#0e7490', shape: 'triangle', maltego: 'maltego.AS', transforms: [] },
  location: { color: '#65a30d', shape: 'star', maltego: 'maltego.Location', transforms: [] },
  vuln: { color: '#dc2626', shape: 'hexagon', maltego: 'maltego.Phrase', transforms: [['vuln.cve', 'CVSS score & weakness (NVD)']] },
  phrase: { color: '#6b7280', shape: 'box', maltego: 'maltego.Phrase', transforms: [] },
  email: { color: '#d97706', shape: 'dot', maltego: 'maltego.EmailAddress', transforms: [] },
  scan: { color: '#111827', shape: 'box', maltego: 'maltego.Phrase', transforms: [] },
};

const graph = {
  network: null, nodes: null, edges: null,
  ensure() {
    if (this.network || !window.vis) return;
    this.nodes = new vis.DataSet();
    this.edges = new vis.DataSet();
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    this.network = new vis.Network($('#graph'), { nodes: this.nodes, edges: this.edges }, {
      nodes: { font: { color: dark ? '#e6edf3' : '#16181d', size: 13 }, size: 14 },
      edges: { arrows: 'to', font: { size: 10, color: dark ? '#8b949e' : '#5d6573', strokeWidth: 0 }, color: { color: dark ? '#484f58' : '#b6bdc9' } },
      physics: { stabilization: { iterations: 150 }, barnesHut: { springLength: 120 } },
      interaction: { hover: true },
    });
    this.network.on('click', (p) => this.select(p.nodes[0]));
  },
  id: (type, value) => `${type}:${value}`.toLowerCase(),
  addNode(type, value, label) {
    this.ensure();
    const id = this.id(type, value);
    if (!this.nodes.get(id)) {
      const e = ENTITY[type] || ENTITY.phrase;
      this.nodes.add({ id, type, entity: value, label: (label || value).slice(0, 60), title: `${type}: ${value}`, color: e.color, shape: e.shape });
    }
    return id;
  },
  addEdge(from, to, label) {
    const id = `${from}->${to}`;
    if (!this.edges.get(id)) this.edges.add({ id, from, to, label });
  },
  select(id) {
    const side = $('#graph-side');
    const n = id && this.nodes.get(id);
    if (!n) { side.innerHTML = '<p class="muted">Select an entity.</p>'; return; }
    const e = ENTITY[n.type] || ENTITY.phrase;
    side.innerHTML = `<p><span class="tag">${esc(n.type)}</span></p><p><b>${esc(n.entity)}</b></p>
      <h3>Transforms</h3>
      ${e.transforms.length ? e.transforms.map(([t, l]) => `<button class="secondary" data-t="${esc(t)}">▶ ${esc(l)}</button>`).join('') : '<p class="muted">No transforms for this entity type.</p>'}
      <button class="secondary" data-t="*remove">✕ Remove entity</button>
      <div data-msg></div>`;
    side.onclick = async (ev) => {
      const btn = ev.target.closest('button[data-t]');
      if (!btn) return;
      if (btn.dataset.t === '*remove') {
        this.nodes.remove(id);
        this.edges.remove(this.edges.get({ filter: (x) => x.from === id || x.to === id }).map((x) => x.id));
        return this.select(null);
      }
      await busy(btn, async () => {
        const msg = $('[data-msg]', side);
        try {
          const { entities } = await api('graph/transform', { transform: btn.dataset.t, value: n.entity });
          for (const ent of entities) this.addEdge(id, this.addNode(ent.type, ent.value), ent.label);
          remember(`graph.${btn.dataset.t}`, n.entity, entities);
          msg.innerHTML = `<p class="muted">${entities.length} entities returned.</p>`;
        } catch (err) { msg.innerHTML = `<p class="error">${esc(err.message)}</p>`; }
      });
    };
  },
  rows() {
    return this.edges.get().map((e) => {
      const a = this.nodes.get(e.from); const b = this.nodes.get(e.to);
      return a && b ? [a, e.label || '', b] : null;
    }).filter(Boolean);
  },
};

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const csvCell = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;

$('#graph-csv').addEventListener('click', () => {
  if (!graph.nodes) return;
  const header = ['source_entity_type', 'source_value', 'link_label', 'target_entity_type', 'target_value'];
  const lines = graph.rows().map(([a, l, b]) => [ENTITY[a.type]?.maltego, a.entity, l, ENTITY[b.type]?.maltego, b.entity].map(csvCell).join(','));
  download('osint-graph.csv', [header.join(','), ...lines].join('\n'), 'text/csv');
});

$('#graph-graphml').addEventListener('click', () => {
  if (!graph.nodes) return;
  const x = (s) => esc(s);
  const nodes = graph.nodes.get().map((n) => `<node id="${x(n.id)}"><data key="type">${x(ENTITY[n.type]?.maltego || n.type)}</data><data key="value">${x(n.entity)}</data></node>`);
  const edges = graph.edges.get().map((e) => `<edge source="${x(e.from)}" target="${x(e.to)}"><data key="label">${x(e.label || '')}</data></edge>`);
  download('osint-graph.graphml', `<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
<key id="type" for="node" attr.name="type" attr.type="string"/>
<key id="value" for="node" attr.name="value" attr.type="string"/>
<key id="label" for="edge" attr.name="label" attr.type="string"/>
<graph edgedefault="directed">
${nodes.join('\n')}
${edges.join('\n')}
</graph></graphml>`, 'application/xml');
});

$('#graph-clear').addEventListener('click', () => {
  if (!graph.nodes) return;
  graph.nodes.clear(); graph.edges.clear(); graph.select(null);
});

const graphActions = {
  'graph-add': async (f) => {
    const id = graph.addNode(f.type.value, f.value.value.trim().toLowerCase());
    graph.network.selectNodes([id]);
    graph.select(id);
    f.value.value = '';
    return null;
  },
};

// ------------------------------------------------------------ Toolkit

const kit = { data: null, cat: '' };

async function loadKit() {
  if (kit.data) return;
  try {
    kit.data = await api('catalog');
  } catch (e) {
    $('#kit-list').innerHTML = `<p class="error">${esc(e.message)}</p>`;
    return;
  }
  const d = kit.data;
  $('#kit-notice').innerHTML = `<strong>Legitimate, defensive use only.</strong> ${esc(d.notice)}`;
  $('#kit-cats').innerHTML = [['', 'All'], ...Object.entries(d.categories).map(([k, v]) => [k, v.split(' (')[0]])]
    .map(([k, v]) => `<button class="small secondary ${k === kit.cat ? 'active' : ''}" data-cat="${esc(k)}">${esc(v)}</button>`).join('');
  $('#kit-practices').innerHTML = d.bestPractices.map((b) => `<div class="card"><h3>${esc(b.title)}</h3><p class="muted">${esc(b.text)}</p></div>`).join('');
  renderKit();
}

function cmdBlock(lines) {
  return lines.map((l) => `<div class="cmd"><pre>${esc(l)}</pre><button class="small secondary" data-copy="${esc(l)}">Copy</button></div>`).join('');
}

function renderKit() {
  const d = kit.data;
  const q = $('#kit-search').value.trim().toLowerCase();
  const match = (t) => (!kit.cat || t.category === kit.cat) &&
    (!q || `${t.name} ${t.summary} ${t.category}`.toLowerCase().includes(q));
  const html = Object.entries(d.categories).map(([cat, title]) => {
    const tools = d.tools.filter((t) => t.category === cat && match(t));
    if (!tools.length) return '';
    return `<h3 class="kit-section">${esc(title)}</h3><div class="kit-grid">${tools.map((t) => `
      <div class="card kit-card">
        <h3>${esc(t.name)}
          ${t.kali ? '<span class="tag">Kali package</span>' : '<span class="tag">GitHub install</span>'}
          ${t.web ? `<button class="small" data-open="${esc(t.web)}">in website ↗</button>` : ''}</h3>
        <p>${esc(t.summary)}</p>
        ${t.install.length ? `<p class="sub">Install</p>${cmdBlock(t.install)}` : ''}
        ${t.usage.length ? `<p class="sub">Use / verify</p>${cmdBlock(t.usage)}` : ''}
        <div class="row" style="margin-top:.5rem">
          <a href="${esc(t.url)}" target="_blank" rel="noopener noreferrer">Official page</a>
          <button class="small secondary" data-ask="${esc(t.name)}">Ask AI about it</button>
        </div>
      </div>`).join('')}</div>`;
  }).join('');
  $('#kit-list').innerHTML = html || '<p class="muted">No tools match.</p>';
}

$('#kit-search').addEventListener('input', () => kit.data && renderKit());
$('#kit-cats').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-cat]');
  if (!b) return;
  kit.cat = b.dataset.cat;
  $$('#kit-cats button').forEach((x) => x.classList.toggle('active', x === b));
  renderKit();
});
$('#tab-toolkit').addEventListener('click', async (e) => {
  const copy = e.target.closest('button[data-copy]');
  if (copy) {
    try { await navigator.clipboard.writeText(copy.dataset.copy); copy.textContent = 'Copied'; } catch { copy.textContent = 'Select & copy'; }
    setTimeout(() => { copy.textContent = 'Copy'; }, 1500);
  }
  const open = e.target.closest('button[data-open]');
  if (open) switchTab(open.dataset.open);
  const ask = e.target.closest('button[data-ask]');
  if (ask) {
    switchTab('ai');
    const f = $('#chat-form');
    f.msg.value = `How do I set up and safely use ${ask.dataset.ask} in an isolated Kali VM?`;
    f.auto.checked = true;
    f.msg.focus();
  }
});

// ------------------------------------------------------------ Qwen AI chat

function renderMarkdown(text) {
  if (window.marked && window.DOMPurify) return DOMPurify.sanitize(marked.parse(text));
  return `<p>${esc(text).replace(/\n/g, '<br>')}</p>`;
}

function renderSteps(steps) {
  return `<div class="steps">${steps.map((s) => `<details>
      <summary class="${s.ok ? '' : 'fail'}">${s.ok ? '✔' : '✖'} <code>${esc(s.tool)}</code> ${esc(Object.values(s.args || {}).join(', '))}</summary>
      <pre>${esc(JSON.stringify(s.ok ? s.result : s.error, null, 2))}</pre></details>`).join('')}</div>`;
}

function renderChat() {
  $('#chat').innerHTML = state.chat.map((m) => `<div class="msg ${m.role}">
      <div class="who">${m.role === 'user' ? 'You' : 'Assistant'}</div>
      ${m.steps?.length ? renderSteps(m.steps) : ''}
      ${m.role === 'user' ? `<p>${esc(m.content).replace(/\n/g, '<br>')}</p>` : renderMarkdown(m.content)}
    </div>`).join('') || `<p class="muted">Ask about an IP, domain or CVE and the matching tools run automatically
      (DNS, WHOIS/RDAP, certificate logs, NVD, Shodan, SpiderFoot). Turn off "Auto-select tools" to just chat with Qwen.</p>`;
}

$('#chat-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const content = f.msg.value.trim();
  if (!content) return;
  state.chat.push({ role: 'user', content });
  f.msg.value = '';
  renderChat();
  const btn = $('button', f.querySelector('.row'));
  await busy(btn, async () => {
    try {
      if (f.auto.checked) {
        const history = state.chat.slice(0, -1).map(({ role, content }) => ({ role, content }));
        const r = await api('agent', { question: content, history });
        for (const s of r.steps) if (s.ok) remember(`auto.${s.tool}`, s.args, s.result);
        state.chat.push({ role: 'assistant', content: r.reply || '(empty reply)', steps: r.steps });
      } else {
        const context = f.ctx.checked && state.collected.length ? JSON.stringify(state.collected) : undefined;
        const messages = state.chat.map(({ role, content }) => ({ role, content }));
        const r = await api('qwen/chat', { messages, context });
        state.chat.push({ role: 'assistant', content: r.reply || '(empty reply)' });
      }
    } catch (err) {
      state.chat.push({ role: 'assistant', content: `**Error:** ${err.message}` });
    }
    renderChat();
    window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
  });
});
$('#chat-form').msg.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); $('#chat-form').requestSubmit(); }
});
$('#chat-clear').addEventListener('click', () => { state.chat = []; renderChat(); });

// ------------------------------------------------------------ form wiring

const actions = { ...shodanActions, ...sfActions, ...graphActions };

async function runAction(name, form, btn) {
  const out = form.closest('.panel').querySelector('.output');
  await busy(btn, async () => {
    try {
      const el = await actions[name](form);
      if (el && out) out.prepend(el);
    } catch (err) {
      if (out) showError(out, err); else alert(err.message);
    }
  });
}

$$('form[data-action]').forEach((form) => {
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    runAction(form.dataset.action, form, e.submitter || $('button', form));
  });
  $$('button[data-alt]', form).forEach((btn) => btn.addEventListener('click', () => {
    if (form.reportValidity()) runAction(btn.dataset.alt, form, btn);
  }));
});

// ------------------------------------------------------------ boot

renderChat();
loadConfig().then(() => { if (state.config.spiderfoot) sfRefresh(); }).catch(console.error);
try {
  const tab = localStorage.getItem('osint-tab');
  if (tab && $(`#tab-${tab}`)) switchTab(tab);
} catch { /* ignore */ }
