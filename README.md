# AMS -- Gateway DLP for Claude Code and Cowork

Two approaches to DLP enforcement for Claude Code and OpenCode traffic to `api.anthropic.com`. AMS is leaning toward AI Gateway for production; the Forward Worker is the active POC enforcement point.

## Two approaches

| | AI Gateway with DLP | Forward Worker (this repo) |
|---|---|---|
| DLP engine | Cloudflare DLP -- dashboard profiles, EDM, wordlists | Regex patterns in `src/index.ts` |
| Pattern management | Dashboard, shared with the rest of the org | Edit code, redeploy |
| TLS decryption required | No | Yes |
| Coverage | Clients configured to point at AI Gateway | Any enrolled device hitting `api.anthropic.com` |
| Streaming | Buffers full response before scanning (latency impact) | Scans SSE at block boundaries, streams in real time |
| Logs | AI Gateway logs | Gateway HTTP logs + R2 |

## Start here

**[DEPLOY.md](DEPLOY.md)** -- full deployment guide for both approaches.

- **AI Gateway path (preferred):** Sections 2--9
- **Forward Worker path (POC / fallback):** Sections 10--21
- **Architecture comparison:** Section 1

## What is in this repository

| Path | Purpose |
|---|---|
| `DEPLOY.md` | Deployment guide -- AI Gateway first, Forward Worker second |
| `src/index.ts` | The Forward Worker |
| `test/extract.test.mjs` | 8 tests covering gzip decompression, user-text extraction, fail-closed paths |
| `wrangler.jsonc` | Worker configuration (R2 binding for violation logs) |
| `package.json` | `npm run typecheck`, `npm test`, `npm run deploy` |

## Why a Worker (POC context)

Native Gateway DLP matches on Claude web and Claude Desktop chat. On Claude Code and Cowork it returns Allow with no DLP match, including after request compression was disabled. The Worker is the enforcement point for that traffic: it decompresses the request body, parses the Messages API structure, extracts exactly the user-authored text, scans it, and fails closed on anything it cannot inspect. Every response carries an `x-dlp-decision` header visible in the Gateway HTTP log.

The investigation that led here is recorded in `DEPLOY.md` Section 22.
