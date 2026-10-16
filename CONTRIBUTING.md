# Contributing to 2MNY Security Scan

Thanks for improving the action! 🛡️

## Ways to help

* **Bug reports** — open an issue with: your workflow YAML (redact secrets),
  the target URL, the full job log, and what you expected vs. what happened.
* **New checks** — the action is deliberately small and zero-config. New checks
  must be: read-only, dependency-free (Node built-ins only), fast (< 20s), and
  meaningful for CI (headers, TLS, cookies, basic exposure). Open an issue
  first if unsure.
* **Fixes** — PRs welcome. `index.js` is the source; `dist/index.js` is the
  bundled artifact that runs on GitHub runners. Regenerate the bundle after
  changing `index.js` and commit both.

## Development

```bash
npm install            # if you add a bundling step, keep it dependency-free in dist
node index.js          # local smoke test uses INPUT_* env vars
```

## Ground rules

* Keep the action **zero-configuration by default** — every new input needs a
  safe default and a README row.
* Never add checks that modify the target, brute-force, or send credentials.
* One check (or one fix) per PR, with a clear title.
