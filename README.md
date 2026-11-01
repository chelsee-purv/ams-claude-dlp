# AMS -- Gateway DLP for Claude Code and Cowork

Cloudflare Gateway Forward Worker that enforces DLP on Claude Code and Cowork traffic to `api.anthropic.com`. Built for the American Musical Supply Zero Trust / DLP proof of concept.

## Start here

**[DEPLOY.md](DEPLOY.md)** -- architecture, what the Worker does, and the seven deployment phases with validation steps.

## What is in this repository

| Path | Purpose |
|---|---|
| `DEPLOY.md` | Deployment guide |
| `src/index.ts` | The Forward Worker |
| `test/extract.test.mjs` | 8 tests covering gzip decompression, user-text extraction, fail-closed paths |
| `wrangler.jsonc` | Worker configuration (R2 binding for violation logs) |
| `package.json` | `npm run typecheck`, `npm test`, `npm run deploy` |

## Why a Worker

Native Gateway DLP matches on Claude web and Claude Desktop chat. On Claude Code and Cowork it returns Allow with no DLP match, including after request compression was disabled. This Worker is the enforcement point for that traffic: it decompresses the request body, parses the Messages API structure, extracts exactly the user-authored text, scans it, and fails closed on anything it cannot inspect. Every response carries an `x-dlp-decision` header visible in the Gateway HTTP log.

The investigation that led here is recorded in `DEPLOY.md` Section 14.
