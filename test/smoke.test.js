// Smoke tests: start the server with no API keys and check routing, auth and validation.
'use strict';

const assert = require('assert');

process.env.APP_PASSWORD = 'test-pw';
process.env.SHODAN_API_KEY = '';
process.env.QWEN_API_KEY = '';
process.env.SPIDERFOOT_URL = '';

const { server, planWithoutLlm, toolSchemas } = require('../server');

async function main() {
  await new Promise((r) => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (route, body, pw = 'test-pw') => fetch(`${base}/api/${route}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-App-Password': pw },
    body: JSON.stringify(body),
  });

  const tests = {
    'serves index page': async () => {
      const r = await fetch(base + '/');
      assert.strictEqual(r.status, 200);
      assert.match(await r.text(), /OSINT Web Console/);
    },
    'blocks path traversal': async () => {
      const r = await fetch(base + '/..%2fserver.js');
      assert.notStrictEqual(r.status, 200);
    },
    'config reports services': async () => {
      const c = await (await fetch(base + '/api/config')).json();
      assert.deepStrictEqual([c.authRequired, c.shodan, c.qwen, c.spiderfoot], [true, false, false, false]);
    },
    'rejects wrong password': async () => {
      assert.strictEqual((await post('shodan/host', { ip: '1.1.1.1' }, 'nope')).status, 401);
    },
    'validates IP input': async () => {
      const r = await post('shodan/host', { ip: 'not-an-ip' });
      assert.strictEqual(r.status, 400);
    },
    'unconfigured Shodan returns 503': async () => {
      const r = await post('shodan/search', { query: 'apache' });
      assert.strictEqual(r.status, 503);
      assert.match((await r.json()).error, /SHODAN_API_KEY/);
    },
    'unconfigured SpiderFoot returns 503': async () => {
      assert.strictEqual((await post('spiderfoot/list', {})).status, 503);
    },
    'unconfigured Qwen returns 503': async () => {
      assert.strictEqual((await post('qwen/chat', { messages: [{ role: 'user', content: 'hi' }] })).status, 503);
    },
    'transform rejects bad domain': async () => {
      const r = await post('graph/transform', { transform: 'domain.dns', value: 'bad domain!' });
      assert.strictEqual(r.status, 400);
    },
    'unknown transform rejected': async () => {
      assert.strictEqual((await post('graph/transform', { transform: 'x', value: 'a.com' })).status, 400);
    },
    'router picks tools from the question': async () => {
      const names = (q) => planWithoutLlm(q).map((p) => p.name);
      assert.deepStrictEqual(names('Explain cve-2021-44228'), ['cve_details']);
      assert.deepStrictEqual(names('who owns 8.8.8.8?'), ['reverse_dns', 'whois_rdap']); // no Shodan key
      assert.deepStrictEqual(names('subdomains of example.com'), ['dns_lookup', 'cert_transparency_subdomains']);
      assert.ok(names('whois example.com').includes('whois_rdap'));
      assert.deepStrictEqual(names('hello there'), []);
    },
    'unconfigured tools are hidden from the AI': async () => {
      const names = toolSchemas().map((t) => t.function.name);
      assert.ok(names.includes('dns_lookup') && names.includes('cve_details'));
      assert.ok(!names.some((n) => n.startsWith('shodan') || n.startsWith('spiderfoot')));
    },
    'agent without Qwen falls back to rules': async () => {
      const r = await (await post('agent', { question: 'hello' })).json();
      assert.strictEqual(r.mode, 'rules');
      assert.deepStrictEqual(r.steps, []);
    },
    'tool list endpoint': async () => {
      const tools = await (await post('tools', {})).json();
      assert.ok(tools.find((t) => t.name === 'shodan_host' && t.enabled === false));
    },
    'invalid JSON rejected': async () => {
      const r = await fetch(`${base}/api/graph/transform`, {
        method: 'POST', headers: { 'X-App-Password': 'test-pw' }, body: '{',
      });
      assert.strictEqual(r.status, 400);
    },
  };

  let failed = 0;
  for (const [name, fn] of Object.entries(tests)) {
    try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.log(`FAIL ${name}\n     ${e.message}`); }
  }
  server.close();
  process.exit(failed ? 1 : 0);
}

main();
