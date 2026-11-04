# AMS -- Gateway DLP for Claude Code and Cowork

Two approaches to DLP enforcement for Claude Code and OpenCode traffic to `api.anthropic.com`, covering both Cloudflare AI Gateway (native DLP) and a Secure Web Gateway Forward Worker (code-managed DLP). Built for the American Musical Supply Zero Trust / DLP proof of concept.

## Two approaches

| | AI Gateway with DLP | Forward Worker (this repo) |
|---|---|---|
| DLP engine | Cloudflare DLP -- dashboard profiles, EDM, wordlists | Regex patterns in `src/index.ts` |
| Pattern management | Dashboard, shared with the rest of the org | Edit code, redeploy |
| TLS decryption required | No | Yes |
| Coverage | Clients configured to point at AI Gateway | Any enrolled device hitting `api.anthropic.com` |
| Streaming | Buffers full response before scanning (latency impact) | Scans SSE at block boundaries, streams in real time |
| Logs | AI Gateway logs | Gateway HTTP logs + R2 |

See `DEPLOY.md` Section 1 for the full trade-off analysis and why the Worker was chosen for this POC.

## Start here

**[DEPLOY.md](DEPLOY.md)** -- architecture, what the Worker does, and the seven deployment phases with validation steps.

For the AI Gateway approach, go directly to **[Section 15 of DEPLOY.md](DEPLOY.md#15-alternative-ai-gateway-with-native-dlp)**.

## What is in this repository

| Path | Purpose |
|---|---|
| `DEPLOY.md` | Deployment guide (Worker path + AI Gateway alternative) |
| `src/index.ts` | The Forward Worker |
| `test/extract.test.mjs` | 8 tests covering gzip decompression, user-text extraction, fail-closed paths |
| `wrangler.jsonc` | Worker configuration (R2 binding for violation logs) |
| `package.json` | `npm run typecheck`, `npm test`, `npm run deploy` |

## Why a Worker

Native Gateway DLP matches on Claude web and Claude Desktop chat. On Claude Code and Cowork it returns Allow with no DLP match, including after request compression was disabled. This Worker is the enforcement point for that traffic: it decompresses the request body, parses the Messages API structure, extracts exactly the user-authored text, scans it, and fails closed on anything it cannot inspect. Every response carries an `x-dlp-decision` header visible in the Gateway HTTP log.

The investigation that led here is recorded in `DEPLOY.md` Section 14.
