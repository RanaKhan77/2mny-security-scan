# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| v1.x (node24) | ✅ |

## Reporting a Vulnerability

Found a security issue in this GitHub Action? Email **security@2mny.com**
with details and a reproduction path. We answer within 72 hours.

**Scope notes:**

* This action only performs **outbound read-only checks** against the `target`
  you configure — it never writes, never exploits, and never posts anywhere
  except the PR comment you enable.
* If the issue is in a *dependency* of the action, also test against the latest
  `main` branch — we patch and re-tag quickly.
* Testing this action against websites you do not own or have permission to
  test is not authorized. Use `https://example.com` or your own staging site.
