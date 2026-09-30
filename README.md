# OSINT Web Console

A website that brings Kali Linux OSINT tools to your browser, so you can use them from a phone
or any computer, with no laptop or Kali install needed.

| Tab | What it does | Needs |
|---|---|---|
| **Shodan** | Host lookup (open ports, services, banners, CVEs), search, facet counts, subdomains, DNS resolve, API credits | `SHODAN_API_KEY` |
| **SpiderFoot** | Start passive/footprint/investigate scans, watch progress, browse findings by type, push findings into the graph | A running SpiderFoot server (`SPIDERFOOT_URL`) |
| **Maltego Graph** | Maltego-style link graph: add a domain/IP, tap it, run transforms (DNS, reverse DNS, Shodan ports/org/vulns, subdomains). Export to **CSV for Maltego** or GraphML | Nothing for DNS transforms; Shodan key for Shodan ones |
| **Ask (Auto)** | Type a question in plain words; the right tools are **selected automatically** and run, then Qwen writes the analysis. Every tool call is shown and can be expanded | `QWEN_API_KEY` for AI planning; works without it using a keyword router |
| **Extra lookups** | WHOIS/RDAP (domain & IP owner), certificate-transparency subdomains (crt.sh), CVE details & CVSS (NIST NVD), DNS & reverse DNS. Also available as graph transforms | Nothing, all free |

| **Toolkit** | Dark web & OSINT tool guide: Tor, Proxychains, isolated VM, TorBot, DarkDump, OnionSearch, Robin, Katana, Maltego, theHarvester, Maigret, Colly. Each has its purpose, copyable install/verify commands and official link, plus best practices. Auto mode answers questions about them | Nothing |

> **Legal:** only investigate targets you own or have written permission to test.
> The Toolkit tools run in **your own isolated Kali VM**. The website deliberately does not connect to Tor
> or crawl `.onion` sites itself: a public server doing that could fetch illegal content, break the hosting
> provider's terms, and skip the VM isolation that safe dark web research needs.

## How auto tool selection works

The server keeps a registry of tools (see the *Available tools* list on the home page). When you ask
something like *"What is exposed on 8.8.8.8?"* or *"Find subdomains of example.com and who registered it"*:

- **With a Qwen key:** Qwen gets the list of tools that are configured, calls the ones it needs
  (several at once, up to 5 rounds), reads the results and writes an answer with risks and next steps.
- **Without a Qwen key:** a rule-based router spots IPs, domains and CVE ids in your question and runs
  the matching free tools.

All auto-selected tools are passive/read-only. The only SpiderFoot scan Auto mode can start is a
*passive* one, and only when you ask for SpiderFoot. To add a tool, add an entry to `TOOLS` in `server.js`.

## 1. Get your API keys

- **Shodan:** sign up at <https://account.shodan.io> and copy the API key. The free plan covers host
  lookups and counts; search filters and `domain` need a paid plan (the one-time membership is enough).
- **Qwen:** create an Alibaba Cloud Model Studio account → *API Keys* → create a key.
  Set `QWEN_MODEL` to any model ID your account lists (e.g. `qwen-plus`, `qwen-max`, or a newer
  Qwen3.x model such as the "Qwen3.7-Plus" you mentioned, using its exact ID from the console).
- **SpiderFoot** (optional): this is self-hosted. On any Linux server/VPS:
  ```bash
  git clone https://github.com/smicallef/spiderfoot && cd spiderfoot
  pip3 install -r requirements.txt
  python3 sf.py -l 0.0.0.0:5001
  ```
  Then set `SPIDERFOOT_URL=http://<server-ip>:5001`. Protect it with SpiderFoot's `passwd` file and set
  `SPIDERFOOT_USER` / `SPIDERFOOT_PASS`.
- **Maltego:** Maltego is a desktop app with no public web API, so the graph tab gives you the same
  entity/transform workflow in the browser. When you have Maltego again, use **Export CSV** and open it
  with *Import → Import Graph from Table* (the columns already use Maltego entity types).

## 2. Put it online (no laptop needed)

All of these work from a phone browser:

- **Render (free):** Fork/push this repo to GitHub → <https://render.com> → *New → Blueprint* → pick
  this repo (it reads `render.yaml`) → fill in the environment variables.
- **Replit:** *Create Repl → Import from GitHub* → add the variables under *Secrets* → Run.
- **Any VPS / Docker:** `docker build -t osint . && docker run -p 3000:3000 --env-file .env osint`
  (you can run SpiderFoot on the same VPS).

**Always set `APP_PASSWORD`** when it's public, so strangers can't spend your Shodan/Qwen credits.

## 3. Run locally (optional)

Requires Node.js 18+; there's nothing to `npm install`.

```bash
cp .env.example .env   # fill in your keys
npm start              # http://localhost:3000
npm test               # smoke tests
```

## Configuration

See [`.env.example`](.env.example) for every variable: `APP_PASSWORD`, `SHODAN_API_KEY`,
`QWEN_API_KEY`, `QWEN_MODEL`, `QWEN_BASE_URL`, `SPIDERFOOT_URL`, `SPIDERFOOT_USER`,
`SPIDERFOOT_PASS`, `PORT`.

API keys stay on the server; the browser never sees them.

## Project layout

```
server.js          Node HTTP server + API proxy (Shodan, SpiderFoot, Qwen, graph transforms)
data/catalog.json  Toolkit entries and best practices (edit to add tools)
public/            Front end (index.html, app.js, style.css, vendored vis-network/marked/DOMPurify)
test/smoke.test.js Routing, auth and validation tests
Dockerfile, render.yaml  Deployment
```
