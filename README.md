# 🛡️ 2MNY Security Scan — GitHub Action

**Free website security checks in every CI run** — security headers, TLS/SSL certificate health, cookie flags, and directory-listing probes — posted right into your Pull Request. Zero configuration, zero cost, no account needed.

Part of the open-source [**2MNY Website Vulnerability Scanner**](https://github.com/RanaKhan77/Website-Vulnerability-Scanner) family — 200+ scanning modules for SQLi, XSS, SSRF, SSTI, subdomain takeover, CMS, headers, and TLS.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-2MNY%20Security%20Scan-blue?logo=github)](https://github.com/marketplace)
![License](https://img.shields.io/badge/license-MIT-green)
![Runtime](https://img.shields.io/badge/runtime-node20-339933?logo=node.js)
![Checks](https://img.shields.io/badge/free%20checks-10%2B-2ea44f)

---

## ⚡ Quickstart (15 seconds)

Create `.github/workflows/security-scan.yml` in any repo:

```yaml
name: Security Scan
on:
  pull_request:
  schedule:
    - cron: "0 6 * * 1" # every Monday 06:00 UTC

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: RanaKhan77/2mny-security-scan@v1
        with:
          target: https://example.com
```

That's it. Every PR gets a comment like this:

> ### 🛡️ 2MNY Security Scan — example.com
> **Security score: 39/100** · 7 issue(s) found · 0 check(s) passed
>
> | Severity | Issue | Why it matters |
> |---|---|---|
> | 🔴 Critical | Site is not served over HTTPS | ... |
> | 🟠 High | Missing Strict-Transport-Security header | Forces HTTPS, prevents downgrade attacks. |
> | 🟠 High | Missing Content-Security-Policy header | Prevents XSS and content injection. |
> | 🟡 Medium | Missing X-Content-Type-Options header | Stops MIME-type sniffing. |

## 📥 Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `target` | ✅ | — | Website URL to scan (e.g. `https://example.com`) |
| `fail-on-issues` | ❌ | `false` | Fail the step if any high/critical issue is found — use as a security gate |
| `post-comment` | ❌ | `true` | Post results as a PR comment (only on `pull_request` events) |

## 📤 Outputs

| Output | Description |
|---|---|
| `issues-found` | Number of security issues found |
| `score` | Security score out of 100 |

## 🔍 What it checks (free, standalone, in your runner)

- **HTTPS enforcement** — plain-HTTP final targets are flagged critical
- **6 security headers** — HSTS (with max-age validation), CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **TLS/SSL health** — protocol version (TLS 1.0/1.1 flagged), cipher, certificate expiry (< 21 days = high, expired = critical), issuer
- **Session cookie flags** — missing `Secure` / `HttpOnly` on session cookies
- **Directory listing exposure** — probes for open autoindex

No data leaves your runner except the HTTP(S) requests to the target you specify. The action never sends your code anywhere.

## 🚀 Full 200+ module scan

This action is the quick CI check. For the deep audit — SQLi, XSS, SSRF, SSTI, subdomain takeover, WordPress/CMS deep enumeration, TLS deep-dive with CVSS-scored, evidence-backed reports:

- 🧰 **Self-hosted, open source:** [Website-Vulnerability-Scanner](https://github.com/RanaKhan77/Website-Vulnerability-Scanner)
- ☁️ **Managed scans + professional PDF reports:** [2mny.com](https://2mny.com)

## 📰 Example: gate merges on security

```yaml
      - uses: RanaKhan77/2mny-security-scan@v1
        with:
          target: https://staging.example.com
          fail-on-issues: true
```

## 📄 License

MIT — see [LICENSE](LICENSE).

## 🐛 Issues & PRs

Found a bug or a false positive? [Open an issue](https://github.com/RanaKhan77/2mny-security-scan/issues) — reports with a repro URL get fixed fastest.
