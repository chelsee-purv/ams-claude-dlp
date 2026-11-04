# AMS -- Gateway DLP for Claude Code and Cowork via Forward Worker

| | |
|---|---|
| **Customer** | American Musical Supply (AMS) |
| **Use case** | 200-seat Zero Trust / DLP POC displacing Proofpoint |
| **Scope** | DLP enforcement on Claude Code (WSL Ubuntu) and Cowork traffic to `api.anthropic.com`, using Secure Web Gateway with a Forward Worker as the inspection point. Claude web and Claude Desktop chat already work with native Gateway DLP and are out of scope. |
| **Active testers** | 9 users in developer environments |
| **Worker source** | https://github.com/chelsee-purv/ams-claude-dlp |
| **Architecture decision** | Forward Worker for POC enforcement; AMS leaning toward AI Gateway with native DLP for production. See [Section 1](#1-architecture) for the full comparison and [Section 15](#15-alternative-ai-gateway-with-native-dlp) for the AI Gateway deployment guide. |

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [What the Worker Does](#2-what-the-worker-does)
3. [Prerequisites](#3-prerequisites)
4. [Phase 1 -- Gateway Foundation](#4-phase-1----gateway-foundation)
5. [Phase 2 -- Claude Code in WSL Ubuntu](#5-phase-2----claude-code-in-wsl-ubuntu)
6. [Phase 3 -- Cowork](#6-phase-3----cowork)
7. [Phase 4 -- Deploy the Worker](#7-phase-4----deploy-the-worker)
8. [Phase 5 -- Create the Forward Policy](#8-phase-5----create-the-forward-policy)
9. [Phase 6 -- Validate](#9-phase-6----validate)
10. [Phase 7 -- Violation Logging and Audit](#10-phase-7----violation-logging-and-audit)
11. [Customizing DLP Patterns](#11-customizing-dlp-patterns)
12. [Limitations](#12-limitations)
13. [Troubleshooting](#13-troubleshooting)
14. [Appendix -- Investigation History](#14-appendix----investigation-history)
15. [Alternative: AI Gateway with Native DLP](#15-alternative-ai-gateway-with-native-dlp)

---

## 1. Architecture

### Why a Worker

Native Gateway DLP matches on Claude web and Claude Desktop chat. On Claude Code and Cowork it does not: the Gateway HTTP log shows **Action: Allow** with no DLP profile match on requests that contain a test SSN. This persisted after disabling Claude Code's gzip request compression, so compression is not the cause. The remaining candidates (policy host scope, request body size, JSON-encoded body structure) are all things Gateway's generic body scan may handle differently from a chat form post; see the [appendix](#14-appendix----investigation-history) for the full list.

Rather than continue isolating which Gateway-side factor is responsible, this POC makes the **Forward Worker the DLP enforcement point** for `api.anthropic.com`. The Worker understands the Messages API body structure, decompresses it if needed, extracts exactly the user-authored text, and scans that. It does not depend on how Gateway's native scan treats the body.

### The native alternative: AI Gateway with DLP

Cloudflare has a purpose-built product for this traffic. **AI Gateway** is a proxy for LLM API calls that runs the same Cloudflare DLP profiles AMS already manages in the Zero Trust dashboard. From Cloudflare's AI Gateway DLP documentation:

> *"AI Gateway DLP uses the same detection profiles as Cloudflare One's DLP solution. Profiles are shared account-level objects, so you can reuse existing predefined or custom profiles."*
>
> *"Streaming (SSE) responses: DLP buffers the full streamed response before scanning."*
>
> *"Tool call arguments and results: DLP scans the text content present in the message body."*
>
> *"No Gateway proxy or TLS decryption required."*

Claude Code is routed to it with one managed setting, `ANTHROPIC_BASE_URL`, and can be pinned there with `allowedProviders: ["customEndpoint"]` so developers cannot bypass it.

| | AI Gateway with DLP | Secure Web Gateway + Forward Worker (this guide) |
|---|---|---|
| DLP engine | **Cloudflare DLP** -- dashboard profiles, EDM, wordlists, confidence thresholds | Regex patterns in Worker code |
| Pattern management | Dashboard, shared with the rest of the org | Edit `src/index.ts`, redeploy |
| SSE response handling | Buffers full response, then scans (documented) | Streams through, scans at block boundaries |
| TLS decryption dependency | None | Required |
| Traffic path | Client -> AI Gateway -> Anthropic | Client -> Cloudflare One Client -> Gateway -> Anthropic |
| Billing model | Routes through an org-held Anthropic API key; developer traffic billed per-token to that key, not to claude.ai subscription seats | No change to how developers authenticate or are billed |
| Logs | AI Gateway logs | Gateway HTTP logs + R2 |
| Coverage | Only clients configured with the base URL | Any client on an enrolled device hitting `api.anthropic.com` |

**AMS is leaning toward AI Gateway as the production path.** The comparison below and the full AI Gateway deployment guide in [Section 15](#15-alternative-ai-gateway-with-native-dlp) reflect that direction. The Forward Worker remains documented here as the POC enforcement point and as a fallback if AI Gateway does not meet requirements.

The factors that favor AI Gateway for production:

1. **Dashboard-managed DLP.** AI Gateway uses the same Cloudflare DLP profiles already managed in the Zero Trust dashboard -- predefined detectors, EDM datasets, wordlists, and confidence thresholds -- without maintaining a separate regex set in code. Pattern changes take effect immediately without a Worker redeploy.
2. **No TLS decryption dependency.** AI Gateway inspects traffic as a purpose-built LLM proxy. The Forward Worker requires TLS decryption to be on and working, which adds certificate trust complexity on WSL and Cowork.
3. **Unified billing and access control.** AI Gateway centralises the Anthropic API key on the org account and supports Cloudflare Access in front of the gateway, so developer identity is captured at the AI layer without relying on device enrollment state.

The remaining consideration is coverage: AI Gateway applies only to clients configured with `ANTHROPIC_BASE_URL`. A developer who removes that setting bypasses DLP. AMS is evaluating whether MDM-distributed managed settings and the `allowedProviders: ["customEndpoint"]` lock are sufficient controls for the developer population, or whether device-enrollment-based enforcement (the Worker path) is required as a backstop.

The Worker's patterns are code-managed rather than dashboard-managed. Section 11 covers how to keep them aligned with the dashboard profiles if the Worker remains in use. The Worker can be retired without changing any other Gateway configuration once AI Gateway is in production.

### Traffic flow

```
Claude Code (WSL)  ---\
Cowork (host OS)   ----+--> Cloudflare One Client --> Gateway --> TLS decryption
                                                                      |
                                                              HTTP policies (Allow)
                                                                      |
                                                       Forward policy: Host is api.anthropic.com
                                                                      |
                                                            ams-claude-dlp Worker
                                                                      |
                                             +------------------------+------------------------+
                                             |                                                 |
                                   request body inspected                           request body clean
                                   violation OR uninspectable                                  |
                                             |                                          next(request)
                                      400/413 block                                            |
                                      x-dlp-decision: block;<reason>                  api.anthropic.com
                                      R2 audit log                                             |
                                                                                   response inspected
                                                                                   (SSE reassembly or JSON)
                                                                                               |
                                                                            x-dlp-decision: pass;... or block;...
```

### Control boundaries

| Control | Covers | Engine | Managed via |
|---|---|---|---|
| Native Gateway DLP policy | Claude web, Desktop chat, and everything else in the org | Cloudflare DLP profiles | Dashboard |
| **This Worker** | Claude Code and Cowork requests and responses on `api.anthropic.com` | Regex patterns in `src/index.ts` | Code + redeploy |

The Worker does **not** use Cloudflare's DLP engine or dashboard profiles. The Forward action does not expose DLP match results to Workers, and there is no API to submit text to the DLP engine. Patterns must be maintained in code. Section 11 covers how.

---

## 2. What the Worker Does

### Request side -- the primary control

For every `POST /v1/messages` on `api.anthropic.com`:

1. **Reads and decompresses the body.** Handles `gzip` and `deflate` (what Claude Code sends by default) via the platform `DecompressionStream`. The 8 MiB limit is measured on **decoded** bytes.
2. **Parses the Messages API JSON** and extracts only user-authored text:
   - `system` (string or text blocks -- Claude Code puts `CLAUDE.md` here)
   - `messages[role=user].content` as a string
   - `messages[role=user].content[].text` -- what the user typed
   - `messages[role=user].content[].tool_result` -- file contents and command output that Claude Code read on the user's behalf and is sending to the model
3. **Skips** assistant turns (model output already seen), `tools[].input_schema` (JSON Schema, not user data), and image/document blocks (base64).
4. **Scans** the extracted text against the pattern list.
5. **Blocks** with a Claude-compatible `400` error if any pattern matches.

**Fails closed.** A body that cannot be decompressed, is not JSON, is not a Messages API object, uses an unsupported `Content-Encoding` (Brotli), or exceeds the size limit is **blocked** -- not passed through. The only non-ok outcome that forwards is an empty body.

Why extraction matters: a 2 MB Claude Code request body with 40 tool schemas and a one-line prompt is scanned for exactly that one line. A tool schema that happens to contain `123-45-6789` as a documentation example does not trigger a block (verified by test).

### Response side -- secondary

- **SSE streams** (`"stream": true`) pass through to the client in real time. In parallel the Worker accumulates `text_delta` events and scans at each `content_block_stop`. On a match it injects an SSE `error` event and terminates the stream.
- **Non-streaming JSON** responses are buffered, text blocks extracted, scanned, and replaced with an error if matched.
- Upstream 4xx/5xx and compressed responses pass through.

### Every decision is visible

The Worker sets `x-dlp-decision` on every response it returns:

| Value | Meaning |
|---|---|
| `block;pattern-match` | Request contained a DLP pattern |
| `block;too-large` | Decoded body over 8 MiB (returns 413) |
| `block;unsupported-encoding` | `Content-Encoding` other than gzip/deflate |
| `block;not-json` / `block;invalid-json` / `block;not-messages-api` | Body not inspectable |
| `block;response-pattern-match` | Claude's non-streaming response contained a pattern |
| `pass;empty-body` | POST with no body |
| `pass;request-clean;response-clean` | Both directions scanned, nothing found |
| `pass;request-clean;response-stream-inspected` | Request clean; SSE stream was inspected in flight |
| `pass;request-clean;upstream-NNN` | Request clean; Anthropic returned an error |

This header appears in the Gateway HTTP log's response headers, so the outcome of every request is visible without opening Workers Logs. Violations are also written to R2 (Section 10).

---

## 3. Prerequisites

- [ ] Zero Trust account with Gateway HTTP filtering and TLS decryption on
- [ ] **Workers Paid** plan on the same account (Free plan's 10 ms CPU limit is insufficient for body decompression and scanning)
- [ ] Cloudflare root certificate generated and **Available and In-Use**
- [ ] Cloudflare One Client installed and enrolled on all test machines
- [ ] `wrangler` CLI installed (`npm install -g wrangler`)
- [ ] AMS has confirmed which patterns they need (Section 11)
- [ ] An Anthropic API key for the validation `curl` commands in Phase 6 (a few dollars of credit)

---

## 4. Phase 1 -- Gateway Foundation

These confirm Gateway is intercepting and decrypting `api.anthropic.com`. AMS has already observed Allow entries for Claude Code in the HTTP log, so this is a checklist, not an investigation.

### 4.1 TLS decryption is on

**Zero Trust > Traffic policies > Traffic settings > Proxy and inspection**: **Inspect HTTPS requests with TLS decryption** is ON. Under **Certificates**, the root certificate shows **Available and In-Use**.

### 4.2 No Do Not Inspect policy covers Anthropic

**Zero Trust > Traffic controls > Firewall policies > HTTP**. Confirm no **Do Not Inspect** policy matches Application *Claude*/*Anthropic* or Host `api.anthropic.com`. Do Not Inspect is evaluated before everything else and would prevent the Forward Worker from ever running. (The observed Allow entries confirm this is not currently the case; verify it stays that way.)

### 4.3 Download the root certificate

**Traffic settings > Certificates** > select the In-Use certificate > **More actions** > **Download .pem**. Save as `Cloudflare_CA.pem`.

### 4.4 Install on the host OS

The Cloudflare One Client normally does this. To verify or do it manually:

- **Windows:** Right-click `.crt` > Install Certificate > Current User > Trusted Root Certification Authorities
- **macOS:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain Cloudflare_CA.crt`
- **Linux:** copy to `/usr/local/share/ca-certificates/` and `sudo update-ca-certificates`

Full per-OS detail: [Install certificate manually](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/user-side-certificates/manual-deployment/).

---

## 5. Phase 2 -- Claude Code in WSL Ubuntu

Three things, in order: traffic reaches Gateway, Claude Code trusts Gateway's certificate, Claude Code sends a body the Worker can read.

### 5.1 WSL mirrored networking

WSL2's default NAT mode may bypass the host's Cloudflare One Client tunnel. **Mirrored mode** shares the host network stack.

On the host, create or edit `%USERPROFILE%\.wslconfig`:

```ini
[wsl2]
networkingMode=mirrored
```

Then in PowerShell: `wsl --shutdown`, and relaunch WSL. Verify from inside WSL:

```bash
curl -sI https://www.cloudflare.com | grep -i "server:"    # expect: server: cloudflare
```

### 5.2 Certificate trust in WSL

The host OS certificate store is not shared with WSL. Install the certificate in Ubuntu's store:

```bash
sudo cp /mnt/c/Users/<username>/Downloads/Cloudflare_CA.pem /usr/local/share/ca-certificates/Cloudflare_CA.crt
sudo update-ca-certificates
```

Claude Code's native installer trusts both its bundled Mozilla CAs **and** the OS store (`CLAUDE_CODE_CERT_STORE` defaults to `bundled,system`). In WSL, "system" is Ubuntu's store, so this step is sufficient. `NODE_EXTRA_CA_CERTS` is only needed for npm installs on Node older than 22.15.

### 5.3 Request compression (optional with this Worker)

The Worker decompresses gzip, so `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` is **no longer required** for inspection to work. Leave it set if already deployed; it does no harm and keeps Gateway's own logs showing plaintext body sizes.

### 5.4 Verify

```bash
claude --debug
```

Send any prompt, then check **Zero Trust > Logs > Gateway > HTTP** filtered on Host `api.anthropic.com`. The request should appear. Once the Worker and Forward policy are deployed (Phases 4-5), the response headers on that entry will include `x-dlp-decision`.

---

## 6. Phase 3 -- Cowork

Cowork is the Claude Code engine running inside Claude Desktop on the **host OS** (not WSL). Anthropic: *"Cowork runs Claude Code on the member's computer, so Claude Code's managed settings apply to Cowork tasks as well as to the terminal."*

### 6.1 Certificate trust

Cowork uses the host OS certificate store. Phase 1 step 4.4 covers it. If the Claude Desktop policy sets `requireCoworkFullVmSandbox: true`, Claude Code runs inside Cowork's VM, which has its own trust store with no documented way to inject a CA -- TLS interception would fail. **Leave that key unset for the POC.** Check macOS `com.anthropic.claudefordesktop` profile / Windows `HKLM\SOFTWARE\Policies\Claude`.

### 6.2 Settings delivery

Cowork reads `env` variables (including `NODE_EXTRA_CA_CERTS` if needed) **only** from managed settings and `~/.claude/settings.json` on the host. It ignores repository `.claude/settings.json` files and shell exports.

### 6.3 Verify

Send a prompt from Cowork. The request appears in the Gateway HTTP log with Host `api.anthropic.com` and, once the Worker is deployed, an `x-dlp-decision` response header.

---

## 7. Phase 4 -- Deploy the Worker

```bash
git clone https://github.com/chelsee-purv/ams-claude-dlp.git
cd ams-claude-dlp
npm install
npm run typecheck                       # tsc --noEmit
node --test test/extract.test.mjs       # 8 tests: gzip, extraction, fail-closed, pass-through
npx wrangler r2 bucket create ams-claude-dlp-logs
npx wrangler whoami                     # confirm the AMS account
npx wrangler deploy
```

Expected: `Uploaded ams-claude-dlp` / `Published ams-claude-dlp`.

### Get the Worker's ID

The Forward policy needs the Worker's immutable 32-character hex ID, not its name:

```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/workers" \
  -H "Authorization: Bearer $API_TOKEN" \
  | jq -r '.result[] | select(.name == "ams-claude-dlp") | .id'
```

The dashboard Forward policy editor resolves this for you if you select the Worker by name.

---

## 8. Phase 5 -- Create the Forward Policy

### Dashboard

**Zero Trust > Traffic controls > Firewall policies > HTTP > Add a policy**

- **Name:** `Claude DLP -- Forward Worker`
- **Traffic:** Host *is* `api.anthropic.com` **And** HTTP Method *is* `POST`
- **Action:** Forward
- **Worker:** `ams-claude-dlp`

### API

```bash
curl -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/gateway/rules" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
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

### Ordering

- Forward runs **after** HTTP Allow/Block and **before** body inspection. An Allow decision does not skip Forward.
- A **Block** policy matching `api.anthropic.com` prevents the Worker from running. None should exist.
- Only the **first** matching Forward policy runs. If AMS adds other Forward policies, keep this one higher in precedence for Anthropic traffic.

---

## 9. Phase 6 -- Validate

Use the test SSN `078-05-1120` (the Woolworth wallet-card number, invalid since the 1930s).

### 9.1 Confirm the Worker is invoked

From any enrolled device:

```bash
curl -s -o /dev/null -D - https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-5-5","max_tokens":20,"messages":[{"role":"user","content":"Say hello"}]}' \
  | grep -i "x-dlp-decision"
```

Expected: `x-dlp-decision: pass;request-clean;response-clean`. If the header is absent, the Forward policy is not matching -- see Troubleshooting.

### 9.2 Request-side block, plain body

```bash
curl -s -D - https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-5-5","max_tokens":20,"messages":[{"role":"user","content":"My SSN is 078-05-1120"}]}'
```

Expected: `HTTP/2 400`, `x-dlp-decision: block;pattern-match`, body `{"type":"error","error":{"type":"dlp_violation",...}}`.

### 9.3 Request-side block, gzip body (what Claude Code sends)

```bash
echo -n '{"model":"claude-sonnet-5-5","max_tokens":20,"messages":[{"role":"user","content":"My SSN is 078-05-1120 GZIP"}]}' | gzip -c > /tmp/b.gz
curl -s -D - https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -H "content-encoding: gzip" --data-binary @/tmp/b.gz
```

Expected: same 400 block. This proves the Worker decompresses before scanning.

### 9.4 Real Claude Code

From WSL, start `claude` and send: `My SSN is 078-05-1120, can you help me?`

Expected: Claude Code displays an API error containing "Request blocked: your message contains sensitive data". Gateway HTTP log entry shows `x-dlp-decision: block;pattern-match`. R2 bucket has a new object under `request/`.

Then send a normal coding prompt. Expected: normal response, log shows `pass;request-clean;response-stream-inspected`.

### 9.5 Real Cowork

Same two prompts from Cowork on the host. Same expected outcomes.

### 9.6 Response-side (optional)

```bash
curl -s -N https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-5-5","max_tokens":60,"stream":true,"messages":[{"role":"user","content":"Output exactly this and nothing else: 078-05-1120"}]}'
```

Note the request itself contains the SSN and will be blocked on the request side first. To exercise response-side alone, temporarily comment out the SSN pattern, redeploy, run this, confirm the stream ends with an `event: error` whose data contains `dlp_violation`, then restore the pattern.

### 9.7 No false positives

Have two testers work normally in Claude Code for 30 minutes. Review the Gateway log for any `block;` decisions. Investigate each one in R2 (Section 10).

---

## 10. Phase 7 -- Violation Logging and Audit

Every block writes a JSON object to R2 bucket `ams-claude-dlp-logs`:

```
request/<date>/<uuid>.json                  pattern match in user prompt
request-uninspectable/<date>/<uuid>.json    body could not be inspected (reason in "violations[0].pattern")
response-stream/<date>/<uuid>.json          pattern in SSE response
response-json/<date>/<uuid>.json            pattern in non-streaming response
```

Each record: `timestamp`, `direction`, `policyId`, `accountId`, `sourceIp`, `user` (Gateway identity email), `url`, `violations[]` with pattern name and redacted match, and a 500-char `contentSample`.

**Browse:** R2 dashboard > `ams-claude-dlp-logs` > Objects.
**Fetch one:** `npx wrangler r2 object get "ams-claude-dlp-logs/request/2026-10-30/<uuid>.json" --pipe`
**List via S3 API:** `aws s3 ls s3://ams-claude-dlp-logs/request/ --recursive --endpoint-url https://$ACCOUNT_ID.r2.cloudflarestorage.com`

Set an R2 lifecycle rule for retention (e.g. 90 days). For SIEM integration, add a webhook `fetch()` in `logViolation` or configure an R2 event notification.

---

## 11. Customizing DLP Patterns

Patterns live in the `DLP_PATTERNS` array in `src/index.ts`. Each has `name`, `regex` (must use the `g` flag), and optional `validate` for false-positive reduction.

**Shipped:** US SSN (area/group/serial validation), credit cards (Luhn), US bank routing numbers (ABA checksum), AWS access key IDs, labeled API keys/secrets. Email and US phone are present but commented out.

**Add AMS-specific:**
```typescript
{ name: "AMS Order Number", regex: /\bAMS-\d{4}-\d{5,}\b/gi },
{ name: "Employee ID",      regex: /\bEMP-\d{6}\b/gi },
```

After any change: `node --test test/extract.test.mjs && npx wrangler deploy`.

To keep the Worker's patterns aligned with AMS's dashboard DLP profiles, export the profile's custom pattern entries from **Zero Trust > DLP > Detection entries** and translate them. Cloudflare DLP regexes are Rust syntax without `+`/`*`; JavaScript regexes can use them, so translation is usually a relaxation, not a tightening.

---

## 12. Limitations

- **Not the Cloudflare DLP engine.** Dashboard profiles, EDM datasets, wordlists, and confidence thresholds do not apply. AMS maintains two pattern sets: dashboard (everything else) and code (Claude Code/Cowork).
- **Response-side streaming delivers some content before a block.** Scanning happens at `content_block_stop`; text already streamed cannot be recalled. Request-side is the primary control and has no such gap.
- **Pattern-match on response JSON returns HTTP 200** with an error body, so Claude Code does not retry. Request-side blocks return 400/413.
- **8 MiB decoded body limit.** Claude Code bodies at 1-3 MiB are routine; 8 MiB is generous but finite. Over-limit requests are blocked with 413 and a message telling the user to shorten the conversation.
- **Brotli is not supported** by `DecompressionStream` in Workers. Claude Code does not send it; if a future client does, those requests are blocked.
- **The Worker does not see `/v1/messages/count_tokens`.** That endpoint is a dry run with no model output; skipping it avoids double-logging.

---

## 13. Troubleshooting

**No `x-dlp-decision` header on any response.** The Forward policy is not matching. Check it is enabled, the host is exactly `api.anthropic.com`, method is POST, and no Block policy precedes it. Confirm the Worker is deployed: `npx wrangler deployments list`.

**`x-dlp-decision: block;too-large` on normal prompts.** The conversation history has grown past 8 MiB decoded. Either raise `REQUEST_BODY_LIMIT` (Workers have 128 MiB; 16 or 32 MiB is safe) or have users `/compact` in Claude Code.

**`x-dlp-decision: block;invalid-json` or `not-messages-api`.** A client is sending something other than a Messages API body to `/v1/messages`. Fetch the R2 record under `request-uninspectable/` for the content sample.

**Claude Code shows a connection or certificate error.** Phase 2 step 5.2 -- the Cloudflare CA is not in Ubuntu's trust store, or (for npm installs on old Node) `NODE_EXTRA_CA_CERTS` is not set in `~/.claude/settings.json`.

**Claude Code requests do not appear in the Gateway log at all.** WSL traffic is bypassing the tunnel. Phase 2 step 5.1 -- mirrored networking.

**False positive.** Fetch the R2 record, read `contentSample` and `violations[].pattern`. Tighten the regex or add a `validate` function. Common: 9-digit numbers that are not SSNs (the shipped validator already excludes area 000/666/9xx).

**Worker returns 500.** Check Workers Logs (**Workers & Pages > ams-claude-dlp > Logs**). The handler fails closed on inspection errors with a 400, so a 500 indicates an exception outside that path -- most likely R2 binding missing (`wrangler.jsonc` → `r2_buckets`).

---

## 14. Appendix -- Investigation History

For the record, the sequence that led to the Worker-as-control decision:

1. **Initial hypothesis: TLS certificate pinning in Claude Desktop.** Rejected -- Electron uses the OS trust store, and the reported symptom ("Gateway IS decrypting") contradicts pinning.
2. **Second hypothesis: SSE response streaming defeats DLP.** The Worker's SSE reassembly was built for this. Weakened once it became clear the failing symptom was request-side (the prompt not matching), which a response-format issue cannot explain. Retained as the response-side mechanism.
3. **Third hypothesis: gzip request bodies.** Anthropic documents `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` specifically for "a TLS-inspecting proxy that Claude Code can't detect." AMS tested it. **Result: still Allow, no DLP match.** Ruled out.
4. **Remaining Gateway-side candidates, not isolated:**
   - Policy host scope -- a DLP policy scoped to `Application is Claude` may not include `api.anthropic.com`
   - Request body size -- Gateway's body-scan window is not publicly documented; Claude Code bodies are large
   - JSON encoding -- the prompt sits inside nested JSON strings; proximity-keyword confidence scoring may behave differently than on form posts
5. **Decision:** make the Worker the control. It handles all three remaining candidates by construction (host-scoped Forward policy, schema-aware extraction with no size dependency, parses JSON before scanning). AI Gateway with DLP was identified as the native alternative (Section 1) and deliberately not selected for this POC for the reasons stated there.

If the Gateway-side root cause is still of interest after the POC, three `curl` tests isolate it: plain body to `api.anthropic.com` (host scope), 300 KB body (size), and a body with the SSN inside a `tool_result` block (encoding). Each is a five-minute check against the Gateway HTTP log with the Forward policy temporarily disabled.

---

## 15. Alternative: AI Gateway with Native DLP

This section is a self-contained guide for the AI Gateway path. It does not require the Forward Worker, TLS decryption, or the Gateway HTTP policy from Sections 4--8. Use it if AMS wants to evaluate AI Gateway alongside or instead of the Worker approach.

### 15.1 What is different

| | Forward Worker (Sections 1--14) | AI Gateway with DLP (this section) |
|---|---|---|
| DLP engine | Regex in `src/index.ts` | Cloudflare DLP -- same dashboard profiles as the rest of the org |
| Pattern management | Edit code, redeploy | Dashboard (**Zero Trust > DLP > DLP profiles**), shared with all Gateway policies |
| TLS decryption | Required | Not required |
| Coverage | Any enrolled device hitting `api.anthropic.com` | Clients configured to point at AI Gateway |
| Streaming | Scans SSE at `content_block_stop`, real-time delivery | Buffers full response before scanning; time-to-first-token increases |
| Logs | Gateway HTTP logs + R2 | AI Gateway logs (separate from Gateway HTTP logs) |
| Auth model | Developer's own claude.ai / Anthropic account | Org Anthropic API key (BYOK) or Cloudflare Unified Billing credits |

**Key limitation of the AI Gateway path:** coverage depends on the client being configured to use the gateway URL. A developer who removes or overrides `ANTHROPIC_BASE_URL` bypasses DLP entirely. The Forward Worker applies to any enrolled device regardless of client config.

### 15.2 Prerequisites

- [ ] A Cloudflare account with AI Gateway available (all paid plans; Free plan has limited log retention)
- [ ] Either: an Anthropic API key stored as a provider key (BYOK) in AI Gateway, **or** Cloudflare Unified Billing credits loaded on the account
- [ ] DLP profiles already configured in **Zero Trust > DLP > DLP profiles** (they are shared -- no new profiles needed if the org already has them)
- [ ] Claude Code and/or OpenCode installed on test machines

No WARP enrollment, no TLS certificate installation, and no Workers Paid plan are required for this path.

### 15.3 Step 1 -- Create an AI Gateway

1. In the Cloudflare dashboard, go to **AI Gateway > Overview > Create gateway**.
2. Name it (e.g. `ams-claude-dlp`) and note the **gateway slug** -- you will use it in the URLs below.
3. Enable **Authenticated gateway** (**Settings > Authentication > Enabled**). This prevents requests without a valid gateway token from reaching Anthropic.
4. Copy or create a **gateway token** with `Run` permissions (**Settings > Authentication > Create token**). Save it as `CF_AIG_TOKEN`.

### 15.4 Step 2 -- Store the Anthropic API key (BYOK)

If using an org-held Anthropic API key rather than Unified Billing:

1. Go to **AI Gateway > [your gateway] > Settings > Provider keys > Add provider key**.
2. Select **Anthropic**, paste the API key, set the alias to `default`, and save.

Developers do not need their own Anthropic accounts or API keys when using BYOK or Unified Billing. All usage is billed to the org key.

### 15.5 Step 3 -- Enable DLP on the gateway

1. Go to **AI Gateway > [your gateway] > Settings > Data Loss Prevention**.
2. Click **Add DLP policy**.
3. Select the DLP profiles to apply (e.g. the same SSN, credit card, and API key profiles already in use in Gateway HTTP policies).
4. Set **Action** to **Block** for violations, **Flag** for audit-only.
5. Set **Check** to **Request and response** (or **Request** only if streaming latency is a concern -- see note below).
6. Save.

> **Streaming latency note:** When **Check** includes responses, AI Gateway buffers the full provider response before scanning and releasing it to the client. For a typical Claude response this adds 5--15 seconds to time-to-first-token. If that is unacceptable, set **Check** to **Request** only. Request-side is the primary control in the Worker path as well, and catches the most important case (sensitive data leaving the user's machine).

### 15.6 Step 4 -- Configure Claude Code

Claude Code reads its endpoint from the `ANTHROPIC_BASE_URL` environment variable. Set it to your AI Gateway's Anthropic endpoint and authenticate with your gateway token.

Replace `<ACCOUNT_ID>`, `<GATEWAY_ID>`, and `<CF_AIG_TOKEN>` with your values.

**macOS / Linux / WSL:**

```bash
export ANTHROPIC_BASE_URL="https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic"
export ANTHROPIC_API_KEY="<CF_AIG_TOKEN>"
export ANTHROPIC_CUSTOM_HEADERS="cf-aig-authorization: Bearer <CF_AIG_TOKEN>"
```

**Windows (PowerShell):**

```powershell
$env:ANTHROPIC_BASE_URL = "https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic"
$env:ANTHROPIC_API_KEY = "<CF_AIG_TOKEN>"
$env:ANTHROPIC_CUSTOM_HEADERS = "cf-aig-authorization: Bearer <CF_AIG_TOKEN>"
```

To persist across sessions, add to `~/.claude/settings.json` under the `env` key:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic",
    "ANTHROPIC_API_KEY": "<CF_AIG_TOKEN>",
    "ANTHROPIC_CUSTOM_HEADERS": "cf-aig-authorization: Bearer <CF_AIG_TOKEN>"
  }
}
```

Start Claude Code normally:

```bash
claude
```

To lock Claude Code so developers cannot point it at a different endpoint, add `allowedProviders: ["customEndpoint"]` to the managed settings policy (macOS: `com.anthropic.claudefordesktop`, Windows: `HKLM\SOFTWARE\Policies\Claude`).

**WSL note:** The environment variables must be set inside WSL, not on the Windows host. Add them to `~/.bashrc` or `~/.zshrc` inside Ubuntu, or to `~/.claude/settings.json` on the WSL filesystem. WSL mirrored networking (`networkingMode=mirrored` in `.wslconfig`) is not required for the AI Gateway path -- requests go directly to `gateway.ai.cloudflare.com` over the internet, not through the WARP tunnel.

### 15.7 Step 5 -- Configure OpenCode

OpenCode supports custom provider configuration via `opencode.json`. Create or update the file in your project root (or globally at `~/.config/opencode/opencode.json`).

Replace `<ACCOUNT_ID>`, `<GATEWAY_ID>`, and `<CF_AIG_TOKEN>` with your values. The token can also be set as an environment variable and referenced with `{env:CF_AIG_TOKEN}`.

```bash
export CF_AIG_TOKEN="<CF_AIG_TOKEN>"
```

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "anthropic": {
      "name": "Anthropic via Cloudflare AI Gateway",
      "options": {
        "baseURL": "https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic/v1",
        "apiKey": "",
        "headers": {
          "cf-aig-authorization": "Bearer {env:CF_AIG_TOKEN}"
        }
      }
    }
  }
}
```

Leave `apiKey` empty -- AI Gateway supplies credentials from your stored provider key (BYOK) or Unified Billing. Start OpenCode normally:

```bash
opencode
```

> **OpenCode with Cloudflare Access:** If you protect the AI Gateway with Cloudflare Access (recommended for production), OpenCode can authenticate with a short-lived Access token via `cloudflared`. See the [OpenCode + Access docs](https://developers.cloudflare.com/ai-gateway/integrations/coding-agents/opencode/#use-with-cloudflare-access) for the full setup including centrally-hosted config distribution.

### 15.8 Step 6 -- Validate

**Confirm traffic is reaching AI Gateway:**

```bash
curl -s https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic/v1/messages \
  -H "x-api-key: <CF_AIG_TOKEN>" \
  -H "cf-aig-authorization: Bearer <CF_AIG_TOKEN>" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":20,"messages":[{"role":"user","content":"Say hello"}]}'
```

Expected: a valid Claude response. Check **AI Gateway > [your gateway] > Logs** -- the request should appear with provider `anthropic`, status `200`, and no DLP findings.

**Trigger a DLP block:**

```bash
curl -s https://gateway.ai.cloudflare.com/v1/<ACCOUNT_ID>/<GATEWAY_ID>/anthropic/v1/messages \
  -H "x-api-key: <CF_AIG_TOKEN>" \
  -H "cf-aig-authorization: Bearer <CF_AIG_TOKEN>" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":20,"messages":[{"role":"user","content":"My SSN is 078-05-1120"}]}'
```

Expected: `HTTP 400`, body contains a DLP error. AI Gateway logs show the request with a DLP **Block** action and the matched profile name. The `cf-aig-dlp` response header is present on flagged (non-blocked) requests.

**Confirm from Claude Code:**

Send `My SSN is 078-05-1120` as a prompt in Claude Code. Expected: Claude Code displays an API error. AI Gateway logs show the block.

**Confirm from OpenCode:**

Same prompt from OpenCode. Same expected outcome.

### 15.9 Logs and audit

AI Gateway logs are separate from Gateway HTTP logs. To view them:

**Dashboard:** **AI Gateway > [your gateway] > Logs** -- shows each request with model, tokens, cost, latency, cache status, and DLP action.

**Logpush:** For SIEM integration, configure a Logpush job to export AI Gateway logs to your destination (S3, Splunk, Datadog, etc.): **AI Gateway > [your gateway] > Settings > Logpush > Add Logpush job**.

**GraphQL Analytics:** AI Gateway exposes token usage, cost, and DLP event counts via the Cloudflare GraphQL Analytics API. Use dataset `aiGatewayAdaptiveGroups`.

DLP block events appear in logs with `dlpAction: "block"` and include the matched profile name. The matched text itself is not logged (consistent with Cloudflare DLP behavior in Gateway HTTP policies).

### 15.10 Trade-offs vs. the Forward Worker

If after evaluating both approaches AMS wants to move from the Worker to AI Gateway full-time:

1. Remove the Forward Worker Gateway policy (Section 8) so traffic flows directly to `api.anthropic.com` through Gateway, then to AI Gateway via the client's `ANTHROPIC_BASE_URL`.
2. Keep the native Gateway DLP policy in place for Claude web and Desktop chat -- those are unaffected.
3. Distribute the `ANTHROPIC_BASE_URL` and `CF_AIG_TOKEN` settings to all developer machines via MDM or managed settings.
4. The Worker and R2 bucket can be left in place but will no longer receive traffic -- decommission them when ready.

The Worker can be retired without changing any other Zero Trust configuration.
