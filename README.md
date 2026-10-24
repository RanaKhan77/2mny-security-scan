# 🛡️ 2MNY Security Scan — GitHub Action

<a href="https://2mny.com"><img src="docs/banner.png" alt="2MNY Security Scan — Free security checks in every CI run" width="100%"></a>

**Free website security checks in every CI run** — security headers, TLS/SSL certificate health, cookie flags, and directory-listing probes — posted right into your Pull Request. Zero configuration, zero cost, no account, no signup.

Part of the open-source [**2MNY Website Vulnerability Scanner**](https://github.com/RanaKhan77/Website-Vulnerability-Scanner) family — 201+ scanning modules for SQLi, XSS, SSRF, SSTI, subdomain takeover, CMS, headers, and TLS.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-2MNY%20Security%20Scan-blue?logo=github)](https://github.com/marketplace/actions/2mny-security-scan)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Runtime](https://img.shields.io/badge/runtime-node24-339933?logo=node.js)](action.yml)
[![Checks](https://img.shields.io/badge/free%20checks-10%2B-2ea44f)](#-what-it-checks)
[![Made by 2MNY](https://img.shields.io/badge/made_by-2MNY_Security-1E3A8A)](https://2mny.com)

---

## 🔍 What it checks

Every run performs 10+ deterministic checks — no AI, no guessing, every finding is evidence-backed:

| Category | Checks |
|---|---|
| 🔐 **Transport** | HTTPS enforced, TLS protocol version, certificate expiry (< 30 days warning, expired = critical), handshake problems |
| 📋 **Security headers** | Strict-Transport-Security (incl. max-age length), Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| 🍪 **Cookie security** | Session cookies missing `HttpOnly`, session cookies missing `Secure` |
| 📂 **Common exposures** | Directory listing enabled on common paths |
| 🔎 **Configuration** | HSTS misconfigurations, missing baseline hardening |

Findings are severity-ranked (🔴 Critical / 🟠 High / 🟡 Medium) with a plain-language "why it matters" for each issue, plus an overall **security score out of 100**.

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
> | 🔴 Critical | Site is not served over HTTPS | Everything you send — logins, cookies, form data — travels in plaintext. |
> | 🟠 High | Missing Strict-Transport-Security header | Forces HTTPS, prevents downgrade attacks. |
> | 🟠 High | Missing Content-Security-Policy header | Prevents XSS and content injection. |
> | 🟡 Medium | Missing X-Content-Type-Options header | Stops MIME-type sniffing. |

## ⚙️ Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `target` | ✅ | — | Website URL to scan (e.g. `https://example.com`) |
| `fail-on-issues` | ❌ | `false` | Fail the workflow step if any high-severity issue is found (missing HSTS/CSP, expiring/expired TLS) |
| `post-comment` | ❌ | `true` | Post the results as a comment on the triggering pull request |

## 📤 Outputs

| Output | Description |
|---|---|
| `issues-found` | Number of security issues found |
| `score` | Security score out of 100 |

## 💡 Why free?

This action is the CI-sized tip of a much bigger iceberg. The same team runs [**2mny.com**](https://2mny.com) — a full security scanning platform with **291 scanner modules** and a hosted scanner suite (including the 201 open-source Community Edition modules: SQLi, XSS, SSRF, SSTI, subdomain takeover, CMS deep-dives, TLS analysis, OSINT exposure checks). The GitHub Action is our way of putting basic hygiene checks where developers actually work — in the PR.

Need more than headers and TLS?

- 🧰 **Self-host the full engine:** [Website-Vulnerability-Scanner](https://github.com/RanaKhan77/Website-Vulnerability-Scanner) — 201 deterministic modules, Apache-2.0
- ☁️ **Managed scans + professional CVSS-scored PDF reports:** [2mny.com](https://2mny.com)
- 📚 **444 curated free security tools:** [Awesome Cyber Security Heaven](https://github.com/RanaKhan77/awesome-cyber-security-heaven)

## 🤝 Family

- [Website-Vulnerability-Scanner](https://github.com/RanaKhan77/Website-Vulnerability-Scanner) — the full open-source scanning suite this action is built from
- [awesome-cyber-security-heaven](https://github.com/RanaKhan77/awesome-cyber-security-heaven) — 444 license-verified free security tools across 14 realms
- [2mny.com](https://2mny.com) — the hosted platform

## 📄 License

[MIT](LICENSE) — free for personal and commercial use.
