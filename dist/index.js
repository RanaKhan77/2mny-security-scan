// 2MNY Security Scan — GitHub Action core (dependency-free, Node 20+)
// Free standalone checks: security headers, TLS/SSL health, cookie flags.
// Full 200+ module report: https://2mny.com
'use strict';
const https = require('https');
const http = require('http');
const tls = require('tls');
const { URL } = require('url');

// ---------- GitHub Actions helpers (no toolkit dependency) ----------
function getInput(name, def = '') {
  const v = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`];
  return (v === undefined || v === '') ? def : v.trim();
}
function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  if (!f) return;
  const fs = require('fs');
  fs.appendFileSync(f, `${name}=${value}\n`);
}
function setFailed(msg) { console.log(`::error::${msg}`); process.exitCode = 1; }

function fetchWithRedirects(rawUrl, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    let url = rawUrl;
    let hops = 0;
    const doFetch = () => {
      let u;
      try { u = new URL(url); } catch (e) { return reject(new Error(`Invalid URL: ${url}`)); }
      if (!/^https?:$/.test(u.protocol)) return reject(new Error(`Unsupported protocol: ${u.protocol}`));
      const mod = u.protocol === 'https:' ? https : http;
      const req = mod.request(u, { method: 'GET', timeout: 20000, headers: { 'User-Agent': '2MNY-Security-Scan-Action/1.0 (+https://2mny.com)' } }, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && hops < maxRedirects) {
          hops++;
          res.resume();
          url = new URL(res.headers.location, u).toString();
          return doFetch();
        }
        const chunks = [];
        res.on('data', (c) => { if (chunks.reduce((a, b) => a + b.length, 0) + c.length <= 512 * 1024) chunks.push(c); });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), finalUrl: u.toString() }));
      });
      req.on('timeout', () => { req.destroy(new Error('Request timeout (20s)')); });
      req.on('error', reject);
      req.end();
    };
    doFetch();
  });
}

function checkTls(hostname) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, timeout: 12000, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const proto = socket.getProtocol() || 'unknown';
      const cipher = socket.getCipher();
      const daysLeft = cert && cert.valid_to ? Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000) : null;
      socket.end();
      resolve({ ok: true, proto, cipher: cipher ? cipher.name : null, daysLeft, issuer: cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN || null) : null });
    });
    socket.on('timeout', () => { socket.destroy(); resolve({ ok: false, error: 'TLS connection timeout' }); });
    socket.on('error', (e) => resolve({ ok: false, error: e.message }));
  });
}

// ---------- Checks ----------
const HEADER_CHECKS = [
  { name: 'Strict-Transport-Security', severity: 'high', why: 'Forces HTTPS, prevents protocol downgrade and cookie hijacking.' },
  { name: 'Content-Security-Policy', severity: 'high', why: 'Prevents XSS, clickjacking and content injection by whitelisting sources.' },
  { name: 'X-Frame-Options', severity: 'medium', why: 'Clickjacking protection (legacy but still recommended alongside CSP frame-ancestors).' },
  { name: 'X-Content-Type-Options', severity: 'medium', why: 'Stops MIME-type sniffing (nosniff).' },
  { name: 'Referrer-Policy', severity: 'medium', why: 'Controls referrer leakage to third parties.' },
  { name: 'Permissions-Policy', severity: 'low', why: 'Restricts powerful browser features (camera, geolocation, microphone).' },
];

async function run() {
  const target = getInput('target');
  const failOnIssues = getInput('fail-on-issues', 'false') === 'true';
  const postComment = getInput('post-comment', 'true') === 'true';
  if (!target) return setFailed("Input 'target' is required (e.g. https://example.com).");

  console.log(`🛡️ 2MNY Security Scan — target: ${target}`);

  // 1) Fetch page (follow redirects)
  let page;
  try { page = await fetchWithRedirects(target); }
  catch (e) { return setFailed(`Could not reach ${target}: ${e.message}`); }
  const finalHost = new URL(page.finalUrl).hostname;
  const isHttps = new URL(page.finalUrl).protocol === 'https:';
  console.log(`✅ Reachable (HTTP ${page.status}${page.finalUrl !== target ? ` → ${page.finalUrl}` : ''})`);

  const issues = [];
  const passes = [];

  if (!isHttps) issues.push({ sev: 'critical', title: 'Site is not served over HTTPS', detail: `Final URL ${page.finalUrl} uses plain HTTP — traffic and credentials are interceptable.` });
  else passes.push('Site served over HTTPS');

  // 2) Security headers
  const h = page.headers;
  for (const c of HEADER_CHECKS) {
    const val = h[c.name.toLowerCase()];
    if (val) {
      passes.push(`${c.name} present`);
      if (c.name === 'Strict-Transport-Security' && !/max-age=\d{4,}/i.test(val)) {
        issues.push({ sev: 'medium', title: 'HSTS max-age too short', detail: `Strict-Transport-Security: ${val} — use at least max-age=31536000.` });
      }
    } else {
      issues.push({ sev: c.severity, title: `Missing ${c.name} header`, detail: c.why });
    }
  }

  // 3) Cookie flags (only Secure/HttpFirst quick pass on Set-Cookie)
  const setCookies = h['set-cookie'] ? (Array.isArray(h['set-cookie']) ? h['set-cookie'] : [h['set-cookie']]) : [];
  for (const sc of setCookies) {
    const nameMatch = sc.match(/^([^=]+)=/);
    const cname = nameMatch ? nameMatch[1] : 'cookie';
    // CSRF meta-cookies (e.g. Laravel XSRF-TOKEN) are read by app JS by design — HttpOnly not applicable.
    if (/xsrf|csrf/i.test(cname)) continue;
    if (/session|sess|sid|auth|token|login/i.test(cname)) {
      if (!/httponly/i.test(sc)) issues.push({ sev: 'medium', title: `Session cookie '${cname}' without HttpOnly`, detail: 'Cookie readable by JavaScript — XSS can steal the session.' });
      if (!/secure/i.test(sc)) issues.push({ sev: 'high', title: `Session cookie '${cname}' without Secure flag`, detail: 'Cookie can leak over plain HTTP.' });
    }
  }

  // 4) TLS health (HTTPS only)
  let tlsInfo = null;
  if (isHttps) {
    tlsInfo = await checkTls(finalHost);
    if (!tlsInfo.ok) {
      issues.push({ sev: 'high', title: 'TLS handshake problem', detail: tlsInfo.error });
    } else {
      passes.push(`TLS ${tlsInfo.proto} (${tlsInfo.cipher})`);
      if (tlsInfo.daysLeft !== null && tlsInfo.daysLeft < 0) issues.push({ sev: 'critical', title: 'TLS certificate EXPIRED', detail: `Certificate expired ${-tlsInfo.daysLeft} day(s) ago (issuer: ${tlsInfo.issuer || 'unknown'}).` });
      else if (tlsInfo.daysLeft !== null && tlsInfo.daysLeft < 21) issues.push({ sev: 'high', title: `TLS certificate expires in ${tlsInfo.daysLeft} day(s)`, detail: `Issuer: ${tlsInfo.issuer || 'unknown'}. Renew before it lapses.` });
      else if (tlsInfo.daysLeft !== null) passes.push(`Cert valid ${tlsInfo.daysLeft} more days`);
      if (tlsInfo.proto && ['TLSv1', 'TLSv1.1'].includes(tlsInfo.proto)) issues.push({ sev: 'high', title: `Outdated TLS protocol: ${tlsInfo.proto}`, detail: 'Disable TLS 1.0/1.1 — modern clients should use TLS 1.2+.' });
    }
  }

  // 5) Directory listing quick probe (non-blocking value add)
  try {
    const probe = await fetchWithRedirects(new URL('/.', page.finalUrl).toString(), 1).catch(() => null);
    if (probe && probe.status === 200 && /<title>Index of \/\.?<\/title>/i.test(probe.body)) {
      issues.push({ sev: 'high', title: 'Directory listing enabled', detail: 'Web server exposes file listings — disable autoindex.' });
    }
  } catch (_) { /* non-fatal */ }

  // ---------- Score ----------
  const sevWeight = { critical: 20, high: 12, medium: 5, low: 2 };
  let penalty = issues.reduce((a, i) => a + (sevWeight[i.sev] || 2), 0);
  const score = Math.max(0, Math.min(100, 100 - penalty));
  setOutput('issues-found', issues.length);
  setOutput('score', score);

  // ---------- Markdown report ----------
  const sevBadge = { critical: '🔴 Critical', high: '🟠 High', medium: '🟡 Medium', low: '🔵 Low' };
  const lines = [];
  lines.push(`### 🛡️ 2MNY Security Scan — ${finalHost}`);
  lines.push('');
  lines.push(`**Security score: ${score}/100** · ${issues.length} issue(s) found · ${passes.length} check(s) passed`);
  lines.push('');
  if (issues.length) {
    lines.push('| Severity | Issue | Why it matters |');
    lines.push('|---|---|---|');
    for (const i of issues) lines.push(`| ${sevBadge[i.sev]} | ${i.title} | ${i.detail} |`);
    lines.push('');
  }
  if (passes.length) lines.push(`**Passed:** ${passes.map((p) => `\`${p}\``).join(' · ')}`);
  lines.push('');
  lines.push('---');
  lines.push('🔍 **Need the full picture?** This quick scan checks headers, TLS, and cookies. Run the complete open-source [2MNY Website Vulnerability Scanner](https://github.com/RanaKhan77/Website-Vulnerability-Scanner) with 200+ modules (SQLi, XSS, SSRF, SSTI, subdomain takeover, CMS, TLS deep-dive), or get a professional CVSS-scored report at **[2mny.com](https://2mny.com)**.');
  const markdown = lines.join('\n');
  console.log(markdown);

  // GitHub Actions job summary
  if (process.env.GITHUB_STEP_SUMMARY) {
    require('fs').appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + '\n');
  }

  // PR comment (best effort)
  if (postComment && process.env.GITHUB_TOKEN && process.env.GITHUB_EVENT_NAME === 'pull_request') {
    try {
      const ev = JSON.parse(require('fs').readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
      const prNumber = ev.pull_request && ev.pull_request.number;
      if (prNumber) {
        const [owner, repo] = process.env.GITHUB_REPOSITORY.split('/');
        await new Promise((res, rej) => {
          const body = JSON.stringify({ body: markdown });
          const req = https.request({
            hostname: 'api.github.com', path: `/repos/${owner}/${repo}/issues/${prNumber}/comments`,
            method: 'POST', headers: {
              'User-Agent': '2mny-security-scan-action',
              Authorization: `token ${process.env.GITHUB_TOKEN}`,
              Accept: 'application/vnd.github+json',
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(body),
            },
          }, (r) => { r.resume(); r.on('end', () => res(r.statusCode)); });
          req.on('error', rej); req.end(body);
        });
        console.log(`💬 Posted results as PR comment (#${prNumber})`);
      }
    } catch (e) { console.log(`(PR comment skipped: ${e.message})`); }
  }

  const hasHighOrCritical = issues.some((i) => i.sev === 'critical' || i.sev === 'high');
  if (failOnIssues && hasHighOrCritical) {
    return setFailed(`${issues.filter((i) => ['critical', 'high'].includes(i.sev)).length} high/critical issue(s) found (score ${score}/100). See report above.`);
  }
  console.log(`✅ Scan complete — score ${score}/100, ${issues.length} issue(s).`);
}

run().catch((e) => setFailed(e.message));
