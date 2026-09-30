// Smoke tests: start the server with no API keys and check routing, auth and validation.
'use strict';

const assert = require('assert');

process.env.APP_PASSWORD = 'test-pw';
process.env.SHODAN_API_KEY = '';
process.env.QWEN_API_KEY = '';
process.env.SPIDERFOOT_URL = '';

const { server } = require('../server');

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
