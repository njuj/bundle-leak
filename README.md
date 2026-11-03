# bundle-leak

**Find what your web app ships to every visitor that it shouldn't.** Every browser downloads your JavaScript bundles, and often your source maps along with them. AI-built and rushed apps routinely put a Supabase `service_role` key, an OpenAI key or a database URL in there. bundle-leak reads exactly those files, either from a live site (fetching only what a browser would) or from your build folder before you deploy. It finds the secrets, traces each one back to the original source line through the source map, and tells you what the key unlocks. Pure Python standard library, zero dependencies.

[![ci](https://github.com/njuj/bundle-leak/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/bundle-leak/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-00ff9c?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-00ff9c?labelColor=0b0f17)
![rules](https://img.shields.io/badge/rules-28_providers_+_maps_+_env-00ff9c?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-00ff9c?labelColor=0b0f17)

```text
$ bundle-leak examples/demo-dist

 bundle-leak v0.1.0  ·  demo-dist  ·  3 file(s), 1 KB  ·  1 source map(s)  ·  0.0s

 FINDINGS
  ✖ CRITICAL OpenAI API key
             └ assets/index-Bq3xK9.js:1:138  →  src/config.ts:1:14
               sk-proj-D9c_…(64)…JJra
               Anyone can spend on this account. Revoke and rotate it now (it is public already), then move the call that needs it to a server.
  ✖ CRITICAL Supabase service_role key
             └ src/lib/supabase.ts:5:4  (inside assets/index-Bq3xK9.js.map)
               assets/index-Bq3xK9.js:1:260  →  src/lib/supabase.ts:5:3
               eyJh…(219)…nRA3   role=service_role · ref=qwhxkzlpmyrtvbnsdfga · iss=supabase
               A service_role key bypasses Row Level Security: anyone can read and write every table. Revoke and rotate it now (it is public already), then move the call that needs it to a server.
  ⚠ MEDIUM   Source maps expose the original code of 2 file(s)
             └ assets/index-Bq3xK9.js.map
               2 app file(s)   1 map(s): 1 declared · notable: src/config.ts, src/lib/supabase.ts
               Stop deploying .map files (or keep them behind auth / upload them to your error tracker and delete them from the build), e.g. Vite build.sourcemap: false, Next.js productionBrowserSourceMaps: false.
  • LOW      API key shipped through a public variable: VITE_OPENAI_API_KEY
             └ assets/index-Bq3xK9.js:1:117
               VITE_OPENAI_API_KEY = sk-proj-D9c_…(64)…JJra   fine for publishable / browser keys, a leak for anything else
  • LOW      Internal hostnames or private IPs in the shipped code
             └ assets/index-Bq3xK9.js
               10.0.4.12   they map your network for whoever reads the bundle

 PUBLIC ENV VARIABLES (in the bundle)
   VITE_OPENAI_API_KEY  (value inlined)
   VITE_SUPABASE_URL  (value inlined)

 ATTACK SURFACE
   Supabase project             qwhxkzlpmyrtvbnsdfga.supabase.co
   API route                    /api/admin/users

 2 critical  ·  1 medium  ·  2 low
```

That is the build output of a typical AI-built app (`python examples/make_demo.py`; every key in it is fake and generated at run time). The Supabase key is a JWT. bundle-leak decodes its claims offline and sees `role=service_role`, the key that bypasses Row Level Security. A Supabase *anon* key in the same place is reported as `info`, because it is meant to be public. The source map exposes the original files, so the key is traced to `src/lib/supabase.ts` line 5, right under the `// TODO: move this to the server before launch` comment that shipped with it.

## Why this matters

* Frameworks copy every `NEXT_PUBLIC_*`, `VITE_*` and `REACT_APP_*` variable into the JavaScript at build time. Someone hits an "undefined" error, renames `OPENAI_API_KEY` to `VITE_OPENAI_API_KEY`, the error goes away, and the key ships to every visitor.
* Source maps are on by default in many setups. With `sourcesContent` they hand out your original code, comments included. Vite's `sourcemap: 'hidden'` removes the `//# sourceMappingURL` comment but still writes the `.map` file, so the code stays one guessable URL away (`index-abc.js.map`). bundle-leak checks that URL too.
* A secret scanner on your Git repository never sees any of this, because the leak happens at build time.

## What it checks

| | |
|---|---|
| **Secret keys** (28 rules) | Supabase `service_role` JWTs and `sb_secret_` keys, OpenAI, Anthropic, AWS key pairs, Stripe / Clerk live and test secrets, GitHub, npm, SendGrid, Slack tokens and webhooks, Discord webhooks, Telegram bots, Hugging Face, Groq, xAI, Replicate, Shopify, Mapbox secret tokens, Google OAuth secrets, Mailgun, Twilio, Azure Storage connection strings, private keys (only with key material), database URLs and URLs with passwords, plus generic `password = "…"` assignments when the value is random-looking |
| **Public-by-design keys** | Firebase web config, Supabase anon keys and Stripe publishable keys are recognised and *not* raised as leaks. A Google API key outside a Firebase config is `medium`: fine only if it is restricted |
| **Public env vars** | every `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` / `EXPO_PUBLIC_` … variable in the bundle, and an alarm when its *name* says secret (`VITE_SUPABASE_SERVICE_ROLE_KEY`, `NEXT_PUBLIC_DATABASE_URL`) |
| **Source maps** | declared, inline (`data:`), sent in a `SourceMap` header, or *hidden* (served but not referenced). The original files inside them are scanned too, `node_modules` excluded |
| **Attack surface** | internal hosts and private IPs, staging and dev hosts, the backend services the app talks to (Supabase, Firebase, S3, Cloud Run …), API routes such as `/api/admin/*` |

## How it reads a live site

* It fetches the page, its `<script>` and `modulepreload` files, then every chunk those scripts can load. Lazy chunks never appear in the HTML, so it reads them out of the JavaScript statically: ES `import()`, Vite's `__vite__mapDeps` lists, the Next.js build manifest, and webpack's runtime chunk table (`"static/chunks/"+e+"."+{42:"abcd…"}[e]+".js"`), rebuilt into real URLs. Nothing is executed.
* **Polite by construction.** It only sends GET requests, only on the same site by default (`--scope`), within a request budget (400 by default), with every body capped (also after gzip). Redirects are followed only while they stay in scope. The User-Agent says what it is. A host that answers every path with its `index.html` (most SPA hosts do) is recognised, so a guessed `.map` URL never produces a false "exposed".
* Third-party scripts (CDNs, analytics) are listed but never fetched.

## Proof that it works

| Check | Result |
|---|---|
| unit, end-to-end and CLI tests | **64** (plus 2 real-build tests in CI) |
| live-site tests against a local server that behaves like production hosting: a Vite app with declared and hidden maps, gzip, a redirect off-site, an SPA fallback; and a Next.js app with webpack chunks and a build manifest | every key found, every chunk discovered, nothing fetched off-site, no file fetched twice |
| **a real production build**: esbuild bundles, splits, minifies and writes source maps, in CI | keys found in the output and traced back to `src/admin.js:1` and `src/main.js:2` |
| source-map decoder on 4 real webpack / esbuild maps (7 MB) | 96.4% of 3,485 string literals map onto an original line holding that literal; the rest are strings the compiler wrote itself (e.g. `"continue"` from async/await down-levelling) |
| false positives on **211.6 MB of real production JavaScript** (VS Code's own bundles, 782 files) | **0 critical, 0 high**. The two findings are real: a hard-coded OAuth client secret (medium; desktop apps ship these on purpose) and internal addresses such as the cloud metadata IP (low). 72 s |

All fake keys in the tests are assembled at run time from pieces ([`tests/fakes.py`](tests/fakes.py)), so this repository contains no secret-shaped string for secret scanners (or GitHub push protection) to trip over.

## Usage

```bash
pip install git+https://github.com/njuj/bundle-leak

bundle-leak dist/                              # before you deploy: Vite dist/, Next.js .next/, CRA build/
bundle-leak https://app.example.com            # a live site you own or may test
bundle-leak dist/ --sarif bundle-leak.sarif    # for GitHub code scanning
bundle-leak dist/ --json | jq '.findings[] | select(.severity=="critical")'
```

| Option | |
|---|---|
| `--fail-on SEVERITY` | exit 1 when a finding is at least this severe (default `high`): drop it into CI after `npm run build` |
| `--min-severity SEVERITY` | hide findings below this |
| `--json` · `--sarif FILE` | machine-readable output; SARIF 2.1.0 shows findings inline in GitHub |
| `--show-secrets` | print secrets in full (they are redacted by default: `sk_live_51Hx…(107)…Qx9w`) |
| `--include-libraries` | also report hits that a source map attributes to `node_modules` |
| `--scope site\|host\|any` | which hosts a live scan may fetch (default: the same site) |
| `--max-requests N` · `--timeout S` · `--concurrency N` | politeness limits for live scans |
| `--no-map-probe` | fetch only the source maps the bundles declare |
| `--header 'Name: value'` | e.g. a session cookie for a staging site you own |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` the target could not be scanned.

In GitHub Actions, after your build step:

```yaml
- run: pip install git+https://github.com/njuj/bundle-leak
- run: bundle-leak dist/ --sarif bundle-leak.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: bundle-leak.sarif }
```

## Limits, plainly

* It finds secrets by their documented formats. A key with no recognisable format only shows up if it is assigned to a secret-sounding name and looks random.
* It reads what the server sends. Code that only exists after login is out of reach unless you pass a `--header` for a site you own.
* Without the Public Suffix List, the "same site" check treats the last two labels as the site (three for `co.uk`-style names). Use `--scope host` to be strict.
* A finding means the secret is public **now**. Removing it from the next build does not undo that, so rotate it.

## Use responsibly

Scan your own apps, or apps you are allowed to test. bundle-leak only downloads public files a browser would download, never tries a key it finds, and redacts secrets in its output.

## License

MIT
