# AMS -- Gateway DLP for Claude Code and Cowork

DLP enforcement for Claude Code and OpenCode traffic to `api.anthropic.com`. Two approaches documented -- AI Gateway is the preferred production path.

| | **AI Gateway** ← preferred | **Forward Worker** ← active POC |
|---|---|---|
| DLP engine | Cloudflare DLP (dashboard profiles) | Regex in `src/index.ts` |
| TLS decryption | Not required | Required |
| Coverage | Clients pointing at gateway URL | Any enrolled device |
| Logs | AI Gateway logs | Gateway HTTP logs + R2 |

**[DEPLOY.md](DEPLOY.md)** -- full deployment guide.
Jump to: [Part 1 -- AI Gateway](DEPLOY.md#part-1--ai-gateway) · [Part 2 -- Forward Worker](DEPLOY.md#part-2--forward-worker)

## Repo contents

| Path | Purpose |
|---|---|
| `src/index.ts` | Forward Worker source |
| `test/extract.test.mjs` | 8 tests: gzip, extraction, fail-closed |
| `wrangler.jsonc` | Worker config (R2 binding) |
| `DEPLOY.md` | Deployment guide for both paths |
