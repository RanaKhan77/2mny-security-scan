# TOOLS_BASELINE — External Scanner Toolchain

Single source of truth for the external tools the 2MNY scan engine shells out to.
Scope: the `2mny-app` scan container (authoritative for all plugin invocations) plus
supporting containers (`2mny-interactsh`). Host binaries are aligned where both exist.

- **Baseline date:** 2026-11-26
- **Baseline owner:** 2MNY Security (regenerated after W160 sync, replacing the 2026-09-07 baseline)
- **Verification:** every version below was read live from the running container on the
  baseline date (banner/`-version`/`--version` output), not copied from a config file.

## Status: all tools at latest release (1 upgraded this cycle)

| Tool | Installed | Latest release (checked 2026-11-26) | Status | Used by |
|------|-----------|--------------------------------------|--------|---------|
| dalfox | **v3.3.0** | v3.3.0 (2026-11-08) | SYNCED this cycle (was 3.2.3) | DalfoxXss / DeepXss payload pool |
| nuclei | v3.11.1 | v3.11.1 (2026-08-08) | in sync | CVE / Afrog packs / template lanes |
| subfinder | v2.17.0 | v2.17.0 | in sync | passive subdomain lane |
| httpx | v1.12.0 | v1.12.0 | in sync | liveness / probe lanes |
| katana | v1.8.0 | v1.8.0 | in sync | crawler lane |
| naabu | 2.7.0 | 2.7.0 | in sync | port lane |
| uncover | v1.2.1 | v1.2.1 | in sync | exposure-DB lookups |
| urlfinder | v0.0.3 | v0.0.3 | in sync | passive URL discovery |
| ghauri | 1.4.3 | 1.4.3 (2025-10-04) | in sync | dual-engine SQLi proof lane |
| commix | v4.2.dev26 | v4.1 (2025-12-20) | dev build ahead of stable | command-injection verification (W160 adoption) |
| interactsh-server | v1.4.1 | v1.4.1 (2026-09-30) | pinned at latest (security fix) | OOB callback infra (`oast.2mny.com`) |
| wafw00f | host install | — | WAF fingerprint (host) | WAF trait eval |
| arjun | host install | — | hidden-parameter discovery | param mining |

## dalfox v3.2.3 -> v3.3.0 upgrade record (2026-11-26)

- Asset: `dalfox-v3.3.0-linux-x86_64-musl.tar.gz`, sha256 verified against the release
  `.sha256` file before install (musl static build — no glibc coupling in the container).
- Installed: container `/usr/local/bin/dalfox` (backup: `dalfox.bak-v3.2.3`),
  host `/root/go/bin/dalfox` (backup: `dalfox.bak-v2.13.0` — host was two majors behind).
- Live smoke test in container against the WackoPicko testbed: `dalfox scan
  http://testbed-wackopicko/calendar.php?month=8 --format json` returned 1 DOM-verified
  finding (V-type, param `query`) — CLI/JSON contract with DalfoxXssScannerPlugin
  unchanged (plugin has been v3-native since 2026-09-07; v3.3.0 is additive: WAF
  confidence scoring, MCP server mode).
- Note: `dalfox version` is not a v3 subcommand (it DNS-resolves "version" as a target);
  version checks must use the banner.

## Version-check cheat sheet

| Tool | How to read the version |
|------|--------------------------|
| dalfox | `dalfox </dev/null 2>&1 \| grep -oE 'Dalfox v[0-9.]+'` (banner; no version subcommand) |
| nuclei / httpx / katana / naabu / uncover / subfinder / urlfinder | `<tool> -version` |
| ghauri | bare `ghauri` banner (shows `{1.4.3}`) |
| commix | `python3 /usr/local/bin/commix --version` |
| interactsh-server | `docker exec 2mny-interactsh /usr/local/bin/interactsh-server -version` |

## Maintenance

- Re-verify after every engine image rebuild (container paths reset to the image).
- `w152-count-sync.py` remains the single source of truth for **module counts**
  (330 commercial / 218 CE); this file covers the **external binary toolchain** only.
- Interaction with scans: upgrades land with a `.bak-<oldversion>` backup next to the
  binary plus a live testbed smoke test before the first production scan cycle.
