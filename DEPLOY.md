# AMS -- Gateway DLP for Claude Code and Cowork

| | |
|---|---|
| **Customer** | American Musical Supply (AMS) |
| **Use case** | 200-seat Zero Trust / DLP POC displacing Proofpoint |
| **Scope** | Claude Code (WSL Ubuntu) and Cowork traffic to `api.anthropic.com`. Claude web and Desktop chat already work with native Gateway DLP and are out of scope. |
| **Active testers** | 9 users in developer environments |
| **Repo** | https://github.com/chelsee-purv/ams-claude-dlp |

---

## Approach comparison

Native Gateway DLP does not match Claude Code or Cowork requests (see [Appendix](#appendix----investigation-history)). Two paths solve this:

| | **AI Gateway** ← AMS preferred | **Forward Worker** ← active POC |
|---|---|---|
| DLP engine | Cloudflare DLP -- shared dashboard profiles | Regex in `src/index.ts` |
| Pattern management | Dashboard, no redeploy needed | Edit code + `wrangler deploy` |
| TLS decryption | Not required | Required |
| Coverage | Clients pointing at the gateway URL | Any enrolled device |
| Streaming | Buffers full response before scan (latency↑) | Scans at block boundaries, real-time |
| Billing | Org Anthropic API key (BYOK) or Unified Billing | No change to developer auth |
| Logs | AI Gateway logs | Gateway HTTP logs + R2 |

**Why AI Gateway for production:** same DLP profiles as the rest of the org, no TLS dependency, centralised billing. **Open question:** coverage requires `ANTHROPIC_BASE_URL` to be set. AMS is evaluating whether MDM-distributed managed settings + `allowedProviders: ["customEndpoint"]` are a sufficient lock, or whether the Worker is needed as a device-enrollment backstop.

---

---

# PART 1 — AI Gateway

---

## A1. Prerequisites

- [ ] Cloudflare account with AI Gateway (all paid plans)
- [ ] Anthropic API key to store as BYOK, **or** Unified Billing credits on the account
- [ ] DLP profiles configured in **Zero Trust > DLP > DLP profiles** (shared -- reuse existing profiles)
- [ ] Claude Code and/or OpenCode installed on test machines

No WARP enrollment, TLS certificates, or Workers Paid plan required.

---

## A2. Create a gateway

1. **AI Gateway > Overview > Create gateway.** Note the gateway slug.
2. **Settings > Authentication > Enabled.** Prevents unauthenticated requests reaching Anthropic.
3. **Settings > Authentication > Create token** (`Run` permissions). Save as `CF_AIG_TOKEN`.

---

## A3. Store the Anthropic API key (BYOK)

Skip if using Unified Billing.

**AI Gateway > [gateway] > Settings > Provider keys > Add provider key** → Anthropic, alias `default`.

Developers do not need individual Anthropic accounts. All usage bills to the org key.

---

## A4. Enable DLP

**AI Gateway > [gateway] > Settings > Data Loss Prevention > Add DLP policy**

- Select profiles (SSN, credit card, API key -- same profiles already in Gateway HTTP policies)
- **Action:** Block (or Flag for audit-only)
- **Check:** Request and response

> **Streaming latency:** Response scanning buffers the full Claude response before delivery -- expect 5--15 s added to time-to-first-token. Set **Check** to **Request** only if that is unacceptable. Request-side catches the primary risk (data leaving the user's machine).

---

## A5. Configure Claude Code

Replace `<ACCOUNT_ID>`, `<GATEWAY_ID>`, `<CF_AIG_TOKEN>` throughout.

**macOS / Linux / WSL** -- add to `~/.bashrc`, `~/.zshrc`, or `~/.claude/settings.json` → `env`:
```bash
export ANTHROPIC_BASE_URL="https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic"
export ANTHROPIC_API_KEY="<CF_AIG_TOKEN>"
export ANTHROPIC_CUSTOM_HEADERS="cf-aig-authorization: Bearer <CF_AIG_TOKEN>"
```

**Windows (PowerShell)** -- or via managed settings / `~/.claude/settings.json` → `env`:
```powershell
$env:ANTHROPIC_BASE_URL = "https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic"
$env:ANTHROPIC_API_KEY = "<CF_AIG_TOKEN>"
$env:ANTHROPIC_CUSTOM_HEADERS = "cf-aig-authorization: Bearer <CF_AIG_TOKEN>"
```

**Lock the endpoint** so developers cannot override it: add `allowedProviders: ["customEndpoint"]` to the managed settings policy (macOS: `com.anthropic.claudefordesktop` / Windows: `HKLM\SOFTWARE\Policies\Claude`).

**WSL note:** Set variables inside WSL, not on the Windows host. Mirrored networking is not required -- requests go directly to `gateway.ai.cloudflare.com`.

---

## A6. Configure OpenCode

```bash
export CF_AIG_TOKEN="<CF_AIG_TOKEN>"
```

In `opencode.json` (project root or `~/.config/opencode/opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "anthropic": {
      "name": "Anthropic via Cloudflare AI Gateway",
      "options": {
        "baseURL": "https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic/v1",
        "apiKey": "",
        "headers": { "cf-aig-authorization": "Bearer {env:CF_AIG_TOKEN}" }
      }
    }
  }
}
```

Leave `apiKey` empty -- AI Gateway supplies credentials. For production, protect the gateway with Cloudflare Access and distribute config centrally via `opencode auth login`. See [OpenCode + Access docs](https://developers.cloudflare.com/ai-gateway/integrations/coding-agents/opencode/#use-with-cloudflare-access).

---

## A7. Validate

Test SSN: `078-05-1120` (Woolworth wallet-card, invalid since the 1930s).

**Clean request** -- should pass:
```bash
curl -s https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic/v1/messages \
  -H "x-api-key: <CF_AIG_TOKEN>" -H "cf-aig-authorization: Bearer <CF_AIG_TOKEN>" \
  -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":20,"messages":[{"role":"user","content":"Say hello"}]}'
```
Expected: valid Claude response. **AI Gateway > [gateway] > Logs** shows status `200`, no DLP findings.

**DLP block** -- should be blocked:
```bash
curl -s https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic/v1/messages \
  -H "x-api-key: <CF_AIG_TOKEN>" -H "cf-aig-authorization: Bearer <CF_AIG_TOKEN>" \
  -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":20,"messages":[{"role":"user","content":"My SSN is 078-05-1120"}]}'
```
Expected: `HTTP 400`, DLP error body. Logs show `dlpAction: block` with the matched profile name.

Repeat both tests from Claude Code and OpenCode directly.

---

## A8. Logs and audit

| Method | Location |
|---|---|
| Dashboard | **AI Gateway > [gateway] > Logs** -- model, tokens, cost, latency, DLP action per request |
| Logpush | **Settings > Logpush > Add job** -- S3, Splunk, Datadog, etc. |
| GraphQL | Dataset `aiGatewayAdaptiveGroups` -- token usage, cost, DLP event counts |

DLP block events include the matched profile name. Matched text is not stored.

---

---

# PART 2 — Forward Worker

---

## B1. What the Worker does

Deployed as a Cloudflare Worker, invoked by a Gateway Forward policy on all `POST api.anthropic.com` traffic from enrolled devices. Use this path if AI Gateway coverage (client config dependency) is not sufficient.

**Request side (primary):** decompresses gzip/deflate, parses the Messages API body, extracts only user-authored text (prompt, system, tool results -- skips tool schemas and assistant turns), scans against regex patterns. Fails closed on anything it cannot inspect.

**Response side (secondary):** SSE streams pass through in real time; Worker accumulates `text_delta` events and scans at each `content_block_stop`. Non-streaming JSON responses are buffered and scanned.

**`x-dlp-decision` header** is set on every response -- visible in the Gateway HTTP log without opening Workers Logs:

| Value | Meaning |
|---|---|
| `block;pattern-match` | DLP pattern matched in request |
| `block;too-large` | Decoded body > 8 MiB (returns 413) |
| `block;unsupported-encoding` | Content-Encoding not gzip/deflate |
| `block;not-json` / `block;invalid-json` / `block;not-messages-api` | Body not inspectable |
| `block;response-pattern-match` | Pattern matched in Claude's response |
| `pass;request-clean;response-clean` | Both directions clean |
| `pass;request-clean;response-stream-inspected` | Request clean, SSE inspected in flight |

---

## B2. Prerequisites

- [ ] Zero Trust with Gateway HTTP filtering and TLS decryption on
- [ ] **Workers Paid** plan (Free plan's 10 ms CPU limit is too low for decompression + scanning)
- [ ] Cloudflare root CA generated and **Available and In-Use**
- [ ] Cloudflare One Client enrolled on all test machines
- [ ] `wrangler` CLI: `npm install -g wrangler`
- [ ] Anthropic API key for validation curls

---

## B3. Gateway foundation

Confirm before deploying the Worker.

1. **TLS decryption on:** Zero Trust > Traffic policies > Traffic settings > Proxy and inspection → ON. Certificate shows **Available and In-Use**.
2. **No Do Not Inspect policy on Anthropic:** Zero Trust > Traffic controls > Firewall policies > HTTP. If one exists, the Worker will never run.
3. **Download root CA:** Traffic settings > Certificates > In-Use cert > More actions > Download .pem.
4. **Install CA on host OS:**
   - Windows: right-click `.crt` > Install Certificate > Trusted Root CAs
   - macOS: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain Cloudflare_CA.crt`
   - Linux: copy to `/usr/local/share/ca-certificates/` → `sudo update-ca-certificates`

---

## B4. WSL setup (Claude Code)

1. **Mirrored networking** -- WSL2 NAT bypasses the WARP tunnel. In `%USERPROFILE%\.wslconfig`:
   ```ini
   [wsl2]
   networkingMode=mirrored
   ```
   Then `wsl --shutdown`. Verify: `curl -sI https://www.cloudflare.com | grep server` → `cloudflare`.

2. **Install CA in WSL:**
   ```bash
   sudo cp /mnt/c/Users/<username>/Downloads/Cloudflare_CA.pem /usr/local/share/ca-certificates/Cloudflare_CA.crt
   sudo update-ca-certificates
   ```

3. **Verify:** run `claude --debug`, send a prompt, confirm the request appears in **Zero Trust > Logs > Gateway > HTTP** filtered on `api.anthropic.com`.

`CLAUDE_CODE_GZIP_REQUEST_BODIES=0` is not required -- the Worker decompresses gzip.

---

## B5. Cowork setup

Cowork runs Claude Code on the host OS. The host CA (B3 step 4) covers certificate trust.

- Do not set `requireCoworkFullVmSandbox: true` -- the VM has its own trust store with no documented CA injection path, breaking TLS interception.
- Cowork reads env vars only from managed settings and `~/.claude/settings.json` on the host, not from shell exports or repo settings files.

**Verify:** send a prompt from Cowork, confirm it appears in the Gateway HTTP log.

---

## B6. Deploy the Worker

```bash
git clone https://github.com/chelsee-purv/ams-claude-dlp.git
cd ams-claude-dlp
npm install
npm run typecheck
node --test test/extract.test.mjs       # 8 tests
npx wrangler r2 bucket create ams-claude-dlp-logs
npx wrangler whoami                     # confirm account
npx wrangler deploy
```

---

## B7. Create the Forward policy

**Dashboard:** Zero Trust > Traffic controls > Firewall policies > HTTP > Add a policy
- Traffic: Host is `api.anthropic.com` AND Method is `POST`
- Action: **Forward** → Worker: `ams-claude-dlp`

**API:**
```bash
curl -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/gateway/rules" \
  -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name": "Claude DLP - Forward Worker",
    "enabled": true,
    "precedence": 100,
    "action": "forward",
    "filters": ["http"],
    "traffic": "http.request.host == \"api.anthropic.com\" and http.request.method == \"POST\"",
    "rule_settings": { "forward": { "worker_id": "'"$WORKER_ID"'" } }
  }'
```

Only the first matching Forward policy runs -- keep this one above any other Forward policies for Anthropic traffic.

---

## B8. Validate

**Worker invoked** (look for the decision header):
```bash
curl -s -o /dev/null -D - https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-5-5","max_tokens":20,"messages":[{"role":"user","content":"Say hello"}]}' \
  | grep -i x-dlp-decision
```
Expected: `pass;request-clean;response-clean`. Header absent → Forward policy not matching, see B10.

**DLP block, plain body:**
```bash
curl -s -D - https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-5-5","max_tokens":20,"messages":[{"role":"user","content":"My SSN is 078-05-1120"}]}'
```
Expected: `HTTP/2 400`, `x-dlp-decision: block;pattern-match`.

**DLP block, gzip body** (what Claude Code sends):
```bash
echo -n '{"model":"claude-sonnet-5-5","max_tokens":20,"messages":[{"role":"user","content":"My SSN is 078-05-1120"}]}' \
  | gzip -c > /tmp/b.gz
curl -s -D - https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -H "content-encoding: gzip" --data-binary @/tmp/b.gz
```
Expected: same 400 block.

Repeat the SSN prompt from Claude Code (WSL) and Cowork. R2 bucket should have a new object under `request/`.

---

## B9. Violation logging

Every block writes to R2 bucket `ams-claude-dlp-logs`:

```
request/<date>/<uuid>.json               pattern match in prompt
request-uninspectable/<date>/<uuid>.json body not inspectable
response-stream/<date>/<uuid>.json       pattern in SSE response
response-json/<date>/<uuid>.json         pattern in non-streaming response
```

Each record includes `timestamp`, `sourceIp`, `user` (identity email), `url`, `violations[]` (pattern name + redacted match), and a 500-char `contentSample`.

```bash
npx wrangler r2 object get "ams-claude-dlp-logs/request/2026-11-04/<uuid>.json" --pipe
aws s3 ls s3://ams-claude-dlp-logs/ --recursive --endpoint-url https://$ACCOUNT_ID.r2.cloudflarestorage.com
```

Set an R2 lifecycle rule for retention (90 days recommended). For SIEM, add a webhook in `logViolation` or configure an R2 event notification.

---

## B10. Troubleshooting

| Symptom | Fix |
|---|---|
| No `x-dlp-decision` header | Forward policy not matching -- check host is exactly `api.anthropic.com`, method is POST, no Block policy precedes it, Worker is deployed (`npx wrangler deployments list`) |
| `block;too-large` on normal prompts | Conversation history > 8 MiB -- raise `REQUEST_BODY_LIMIT` in `src/index.ts` or use `/compact` in Claude Code |
| `block;invalid-json` or `not-messages-api` | Client sending non-Messages-API body -- fetch R2 record under `request-uninspectable/` |
| Certificate error in Claude Code | CA not in Ubuntu trust store -- see B4 step 2 |
| Requests missing from Gateway log | WSL traffic bypassing tunnel -- see B4 step 1 (mirrored networking) |
| False positive | Fetch R2 record, read `contentSample` and `violations[].pattern`, tighten regex or add `validate` function |
| Worker returns 500 | Check Workers Logs -- likely R2 binding missing in `wrangler.jsonc` |

---

## B11. Customizing DLP patterns

Patterns are in `DLP_PATTERNS` in `src/index.ts`. Each entry has `name`, `regex` (must include `g` flag), and optional `validate` for false-positive reduction.

Shipped: US SSN (with area/group/serial validation), credit cards (Luhn), bank routing numbers (ABA checksum), AWS access key IDs, labeled API key/secret strings. Email and phone commented out.

```typescript
// Add AMS-specific patterns:
{ name: "AMS Order Number", regex: /\bAMS-\d{4}-\d{5,}\b/gi },
{ name: "Employee ID",      regex: /\bEMP-\d{6}\b/gi },
```

After changes: `node --test test/extract.test.mjs && npx wrangler deploy`.

To align with dashboard DLP profiles: export custom patterns from **Zero Trust > DLP > Detection entries** and translate. Cloudflare uses Rust regex syntax (no `+`/`*` shorthand); JS regexes are a superset so translation is straightforward.

---

## Appendix -- Investigation history

Why native Gateway DLP was not used for Claude Code:

1. **TLS pinning** -- rejected. Electron uses the OS trust store; Gateway was confirmed decrypting.
2. **SSE streaming** -- weakened. Failing symptom was request-side (prompt not matching), not response format. SSE reassembly retained as the response-side mechanism.
3. **Gzip compression** -- ruled out. Tested `CLAUDE_CODE_GZIP_REQUEST_BODIES=0`. Result: still Allow, no DLP match.
4. **Remaining candidates not isolated:** policy host scope (DLP policy scoped to Application may not cover `api.anthropic.com`), body size (Gateway scan window undocumented), JSON encoding (prompt nested inside JSON strings vs. form post).

Decision: make the Worker the enforcement point for the POC. It handles all three remaining candidates by construction. If the root cause needs isolating post-POC, three curl tests cover it: plain body (host scope), 300 KB body (size), SSN inside a `tool_result` block (encoding).
