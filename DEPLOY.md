# AMS Zero Trust DLP for Claude Code and Cowork -- Diagnostic and Deployment Guide

**Customer:** American Musical Supply (AMS)
**Use Case:** 200-seat Zero Trust / DLP POC displacing Proofpoint
**Scope:** Gateway DLP is working for Claude web and Claude Desktop chat. It is **not** matching for **Claude Code** (CLI in WSL Ubuntu) and **Cowork** (the Claude Code engine embedded in Claude Desktop). This guide isolates the cause and then applies the right fix.
**Active testers:** 9 users in developer environments
**Forward Worker source:** https://gitlab.cfdata.org/chelsee/ams-claude-dlp

> **Status: root cause not yet confirmed.** The Forward Worker in this repository was built on the hypothesis that SSE response streaming defeats Gateway DLP. That hypothesis has **not been verified**, and the evidence gathered since points at a different, request-side cause. **Run the diagnostic in Section 2 before deploying anything.** The Worker may turn out to be unnecessary.

---

## Table of Contents

1. [What We Know](#1-what-we-know)
2. [Root Cause Diagnostic -- Run This First](#2-root-cause-diagnostic----run-this-first)
3. [Prerequisites](#3-prerequisites)
4. [Phase 1 -- Gateway Foundation](#4-phase-1----gateway-foundation)
5. [Phase 2 -- Claude Desktop Chat (Reference, Already Working)](#5-phase-2----claude-desktop-chat-reference-already-working)
6. [Phase 3 -- Claude Code in WSL Ubuntu](#6-phase-3----claude-code-in-wsl-ubuntu)
7. [Phase 3b -- Cowork](#7-phase-3b----cowork)
8. [Phase 4 -- Deploy the Forward Worker (Only If Diagnostic Confirms SSE)](#8-phase-4----deploy-the-forward-worker-only-if-diagnostic-confirms-sse)
9. [Phase 5 -- Create the Gateway Forward Policy](#9-phase-5----create-the-gateway-forward-policy)
10. [Phase 6 -- Testing and Validation](#10-phase-6----testing-and-validation)
11. [Phase 7 -- Violation Logging and Audit](#11-phase-7----violation-logging-and-audit)
12. [Customizing DLP Patterns](#12-customizing-dlp-patterns)
13. [Architecture Notes and Limitations](#13-architecture-notes-and-limitations)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. What We Know

### The failure pattern

| Surface | Engine making the API call | Inference host | Request body | DLP matches? |
|---|---|---|---|---|
| Claude web | Browser (Chromium) | `claude.ai` | Plain JSON | **Yes** |
| Claude Desktop chat tab | Electron (Chromium) | `claude.ai` (unverified -- see Test 1) | Plain JSON | **Yes** |
| Claude Code (WSL Ubuntu) | **Claude Code / Node.js** | **`api.anthropic.com`** | **gzip-compressed JSON** (default) | **No** |
| Cowork (in Claude Desktop) | **Claude Code / Node.js** | **`api.anthropic.com`** | **gzip-compressed JSON** (default) | **No** |

Cowork is not a separate product in this respect. Anthropic's documentation states "Cowork runs Claude Code on the member's computer" -- it is the same Claude Code engine, so whatever breaks DLP for Claude Code breaks it for Cowork too.

### Four candidate causes

The working and failing surfaces differ in several ways at once. Any one of these could be the cause, and the diagnostic in Section 2 isolates them one at a time:

| # | Candidate cause | Direction affected | Evidence for it | Fix if confirmed |
|---|---|---|---|---|
| **A** | **Policy selector does not cover `api.anthropic.com`.** A policy built as `Application is Claude` may only match Claude's web-app hostnames, not the Platform API host that Claude Code uses. | Request + response | Working surfaces hit `claude.ai`; failing surfaces hit `api.anthropic.com` | Add `Host is api.anthropic.com` to the policy, or add Platform API operations in Granular Controls. **No Worker needed.** |
| **B** | **Gzip-compressed request bodies.** Claude Code compresses request bodies with gzip by default. Anthropic's own docs say: *"If [a TLS-inspecting] proxy mishandles gzip-compressed request bodies, set `CLAUDE_CODE_GZIP_REQUEST_BODIES=0`."* Browsers do not compress request bodies. | **Request** | Exactly matches the pattern: only the Claude Code engine compresses; only the Claude Code engine fails. Anthropic documents this as a known proxy issue. | Set `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` via managed settings (applies to both Claude Code and Cowork). **No Worker needed.** |
| **C** | **Request body too large for the DLP scan window.** Claude Code sends full file contents, tool schemas, and conversation history -- bodies of 50 KB to several MB. The user's prompt may sit past whatever portion Gateway scans. | Request | Plausible but unconfirmed. Gateway's body-scan limits are not publicly documented. | Worker's schema-aware extraction (pulls user text from `messages[]` regardless of total body size), or request Gateway limit increase. |
| **D** | **SSE response streaming.** Response text arrives as many small `text_delta` events; a pattern spanning events might not match. This was the **original hypothesis** and the reason the Worker was built. | **Response only** | Weakened: Claude Code's request-side DLP failing cannot be explained by a response-format issue. Only relevant if response-side DLP is in scope. | Forward Worker's SSE reassembly. |

**Cause B is now the leading hypothesis.** It is the only one that (a) exactly fits the working/failing split, (b) is documented by the vendor as a known interaction with TLS-inspecting proxies, and (c) explains a *request-side* failure, which is what "DLP policy isn't matching on the prompt" describes. Cause D cannot explain a request-side failure at all.

---

## 2. Root Cause Diagnostic -- Run This First

Work through these tests in order. Each one isolates a single variable. Record the result of each before moving on; the decision table at the end tells you which fix to apply and whether the Worker is needed.

**You will need:**
- A machine enrolled in the Cloudflare One Client, with the Cloudflare root CA installed (Phase 1)
- An Anthropic API key (console.anthropic.com; a few dollars of credit is sufficient)
- `curl` and `gzip` (`curl` on Windows host via PowerShell works; or run from WSL after completing Phase 3 setup)
- Access to **Zero Trust > Logs > Gateway > HTTP** in the AMS dashboard
- The existing DLP policy that works for Claude web, left exactly as it is

**Test data:** Use the SSN `078-05-1120` throughout. It is the famous Woolworth wallet-card number, has been invalid since the 1930s, and is a standard DLP test value. Confirm first with **Zero Trust > Data loss prevention > Test scan** that AMS's DLP profile detects it -- if it does not, fix the profile before continuing.

### Test 1 -- Baseline: what does Gateway see from each surface?

**Goal:** Establish exactly what differs between a working request and a failing one, using Gateway's own logs rather than assumptions.

1. From **Claude Desktop chat**, send: `My SSN is 078-05-1120, can you help me?`
2. From **Claude Code** in WSL (any folder), send the same prompt.
3. From **Cowork**, send the same prompt.
4. In **Zero Trust > Logs > Gateway > HTTP**, filter by the test user's email and the last 10 minutes. For each of the three requests, record:

| Field in Gateway log | Desktop chat | Claude Code | Cowork |
|---|---|---|---|
| Host | | | |
| URL path | | | |
| Request `Content-Type` | | | |
| Request `Content-Encoding` | | | |
| Request body size | | | |
| Response `Content-Type` | | | |
| Policy matched (name) | | | |
| DLP profile matched | | | |
| Action (Allow / Block) | | | |

**Interpretation:**
- If Claude Code / Cowork requests **do not appear at all** -> traffic is not reaching Gateway. This is a WSL networking or Cloudflare One Client problem, not a DLP problem. Go to Phase 3 (WSL) / Phase 3b (Cowork) and fix routing first.
- If they appear with **Host = `api.anthropic.com`** and Desktop chat shows **Host = `claude.ai`** -> **Cause A is live.** Continue to Test 2.
- If Claude Code / Cowork show **Request `Content-Encoding: gzip`** and Desktop chat does not -> **Cause B is live.** Continue to Test 3.
- Note whether the **Response `Content-Type`** is `text/event-stream` for Desktop chat. If it is, and Desktop chat's DLP matched, **Cause D is ruled out** -- Gateway already handles SSE fine. If Desktop chat does *not* use `text/event-stream`, Cause D stays open until Test 5.

### Test 2 -- Does the DLP policy cover `api.anthropic.com`?

**Goal:** Confirm the policy's traffic selector matches the host Claude Code uses, independent of body encoding.

1. Open the DLP policy that works for Claude web. Note its **Traffic** expression.
   - If it is `Application is Claude` -> open **Zero Trust > Team & Resources > App Library > Claude** and check whether `api.anthropic.com` is listed under **Hostnames**. If it is not, the policy cannot match Claude Code.
   - If it is `Host is claude.ai` or `Domain is claude.ai` -> it does not cover `api.anthropic.com`.
2. From the enrolled host machine (not WSL), send a **plain, uncompressed** request:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-5-5","max_tokens":50,"messages":[{"role":"user","content":"My SSN is 078-05-1120"}]}'
```

3. Check the Gateway HTTP log for this request.

**Interpretation:**
- **DLP matched / Blocked** -> the policy covers `api.anthropic.com` and plain JSON bodies work. Cause A is ruled out. Continue to Test 3.
- **No DLP match / Allowed** -> **Cause A confirmed.** Fix: add a condition `Host is api.anthropic.com` (OR with the existing condition) to the policy, or in Granular Controls select Claude's **Platform API** operations in addition to the web-app ones. Re-run this test to confirm, then re-run Test 1 against Claude Code. If Claude Code now matches, **you are done -- no Worker is needed.** If Claude Code still fails, continue to Test 3.

### Test 3 -- Isolate gzip request compression

**Goal:** Send the exact same request body compressed and uncompressed. This is the single most important test.

Run both commands back to back from the same enrolled host machine:

```bash
BODY='{"model":"claude-sonnet-5-5","max_tokens":50,"messages":[{"role":"user","content":"My SSN is 078-05-1120 -- UNCOMPRESSED TEST"}]}'

# 3a: uncompressed (control)
curl -s -o /dev/null -w "3a uncompressed: HTTP %{http_code}\n" https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d "$BODY"

# 3b: gzip-compressed (what Claude Code sends by default)
BODY_GZ='{"model":"claude-sonnet-5-5","max_tokens":50,"messages":[{"role":"user","content":"My SSN is 078-05-1120 -- GZIP TEST"}]}'
echo -n "$BODY_GZ" | gzip -c > /tmp/body.gz
curl -s -o /dev/null -w "3b gzip: HTTP %{http_code}\n" https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -H "content-encoding: gzip" \
  --data-binary @/tmp/body.gz
```

The distinct marker text (`UNCOMPRESSED TEST` / `GZIP TEST`) lets you tell the two log entries apart.

Check both entries in the Gateway HTTP log.

**Interpretation:**

| 3a (plain) | 3b (gzip) | Conclusion |
|---|---|---|
| Blocked | Blocked | Gateway handles gzip fine. Cause B ruled out. Continue to Test 4. |
| **Blocked** | **Allowed** | **Cause B confirmed.** Gateway DLP is not scanning gzip-compressed request bodies. **Fix:** set `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` on all Claude Code / Cowork machines via managed settings (Phase 3 / 3b). Re-run Test 1 against Claude Code to confirm. **No Worker is needed for request-side DLP.** Also open a Cloudflare support case: Gateway DLP should decompress request bodies. |
| Allowed | Allowed | Neither matched. Cause A was not actually fixed, or the DLP profile / match count / confidence is wrong. Re-check Test 2 and Test scan. |

### Test 4 -- Isolate request body size

**Goal:** Determine whether a large body (as Claude Code sends) pushes the prompt past Gateway's scan window. Only needed if Tests 2 and 3 both passed but Claude Code still fails.

```bash
# Generate ~300 KB of filler in a system prompt, with the SSN at the END of the user message
FILLER=$(head -c 300000 /dev/zero | tr '\0' 'A')
cat > /tmp/large.json <<EOF
{"model":"claude-sonnet-5-5","max_tokens":50,
 "system":"You are a helpful assistant. Context follows. ${FILLER}",
 "messages":[{"role":"user","content":"My SSN is 078-05-1120 -- LARGE BODY TEST"}]}
EOF
ls -la /tmp/large.json   # confirm ~300 KB

curl -s -o /dev/null -w "Test 4 large body: HTTP %{http_code}\n" https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  --data-binary @/tmp/large.json
```

Anthropic may reject this with a 400 (too many tokens). That does not matter -- Gateway scans the request on the way out regardless of the upstream response. Check the Gateway log.

**Interpretation:**
- **Blocked** -> body size is not an issue. Cause C ruled out.
- **Allowed** (while the small body in Test 3a was Blocked) -> **Cause C confirmed.** Gateway's request-body DLP has a size limit that Claude Code's large contexts exceed. **Fix options:** (1) open a Cloudflare support case asking for the limit and whether it can be raised; (2) deploy the Forward Worker, whose request-side logic parses the Messages API JSON and extracts only `messages[].content` text, so the user's prompt is scanned regardless of total body size. This is a legitimate reason to use the Worker, but it is a different reason than SSE.

### Test 5 -- Isolate SSE response streaming

**Goal:** Determine whether Gateway DLP can scan sensitive data in Claude's *response* when it is delivered as SSE. Only relevant if AMS needs response-side DLP (data coming *back* from Claude), and only meaningful once request-side tests pass.

Your DLP policy must apply to the **download** body phase for this test. Check the policy does not have `Body Phase is upload` restricting it.

```bash
PROMPT='Repeat this exact string back to me and nothing else: 078-05-1120'

# 5a: non-streaming response (plain JSON)
curl -s -o /dev/null -w "5a non-stream: HTTP %{http_code}\n" https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d "{\"model\":\"claude-sonnet-5-5\",\"max_tokens\":50,\"stream\":false,\"messages\":[{\"role\":\"user\",\"content\":\"$PROMPT\"}]}"

# 5b: streaming response (SSE)
curl -s -o /dev/null -w "5b stream: HTTP %{http_code}\n" https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d "{\"model\":\"claude-sonnet-5-5\",\"max_tokens\":50,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"$PROMPT\"}]}"
```

Note: the **request** in both cases contains the SSN too, so request-side DLP will block both before the response is ever generated if request DLP is working. To test response-side in isolation, either temporarily scope the policy to `Body Phase is download`, or use a prompt that does not itself contain the pattern but reliably elicits one (e.g. `Generate one realistic-looking but fake US SSN in the format XXX-XX-XXXX and output only that`). Use the Gateway log's body-phase indicator to confirm which direction matched.

**Interpretation:**

| 5a (JSON response) | 5b (SSE response) | Conclusion |
|---|---|---|
| Blocked | Blocked | Gateway scans SSE responses correctly. **Cause D ruled out. The Worker's SSE reassembly is unnecessary.** |
| **Blocked** | **Allowed** | **Cause D confirmed** for the response direction. The Forward Worker's SSE reassembly is justified -- but only for response-side DLP. Request-side is handled by whatever Test 2-4 found. |
| Allowed | Allowed | Response-side DLP is not configured, or body phase is restricted to upload. Fix the policy and re-test. |

### Test 6 -- Confirm the fix on real Claude Code and Cowork

After applying whichever fix the tests above indicated:

1. Apply the fix (policy change, `CLAUDE_CODE_GZIP_REQUEST_BODIES=0`, or Worker deployment).
2. For the gzip fix, confirm it took effect: run `claude --debug` in WSL, send any prompt, then check the Gateway log for that request -- **Request `Content-Encoding` should now be absent.**
3. Re-run Test 1 from Claude Code and Cowork.
4. Both should now show **DLP profile matched / Blocked**.

### Decision table

| Diagnostic result | Root cause | Fix | Forward Worker needed? |
|---|---|---|---|
| Test 1: Claude Code absent from logs | WSL/Cowork traffic bypassing Gateway | Phase 3 / 3b network + cert setup | No |
| Test 2: plain curl not blocked | **A** -- policy doesn't cover `api.anthropic.com` | Add Host condition / Platform API operations | No |
| Test 3: plain blocked, gzip allowed | **B** -- gzip request bodies not scanned | `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` via managed settings | No |
| Test 4: small blocked, large allowed | **C** -- body exceeds scan window | Support case, or Worker request-side extraction | Yes -- request side only |
| Test 5: JSON blocked, SSE allowed | **D** -- SSE responses not scanned | Worker response-side reassembly | Yes -- response side only (if response DLP is in scope) |
| Tests 2-5 all blocked, Claude Code still fails | Unknown -- Claude Code-specific | Enable DLP payload logging, capture Claude Code's actual request, open support case | Hold |

---

## 2b. The Forward Worker (Conditional)

**Deploy only if the diagnostic confirms Cause C or Cause D.** If it confirms A or B, the fix is a policy change or a client setting, and the Worker adds operational complexity for no benefit.

The Worker is a **Gateway Forward Worker** (Programmable Gateway) that intercepts `api.anthropic.com` traffic after TLS decryption. It:

- **Request side (Cause C):** Parses the Messages API JSON, extracts only the user-authored text from `messages[].content` and `system`, and scans that -- so the prompt is inspected regardless of how large the surrounding tool schemas and file context are
- **Response side (Cause D):** Streams SSE events to the client in real time while accumulating `text_delta` content in parallel, and scans the accumulated text at each `content_block_stop` boundary
- **On violation:** Blocks the request (request side) or terminates the stream with an error event (response side), and logs the violation to R2

> **Known gap:** the Worker's request-side inspection currently **skips bodies with `Content-Encoding: gzip`** (it does not decompress). If Cause B is confirmed, the fix is `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` on the client, which also makes the Worker's request path work. Do not rely on the Worker as a workaround for gzip.

### Native Cloudflare capabilities to use first

Two built-in Gateway capabilities should be the default tools for this problem. The Worker is a fallback, not a starting point.

**1. Application Granular Controls for Claude.** Gateway natively recognizes Claude as a supported AI application (alongside ChatGPT, Gemini, and Perplexity). You can build an HTTP policy with **Application** *is* **Claude**, choose the operations that carry prompt content, and attach a DLP profile. **AI prompt topic detection entries** (Content: PII, Content: Credentials and Secrets, Content: Source Code, Intent: Jailbreak, etc.) are available as predefined detection entries and work with Claude. All dashboard-managed, all using the real Cloudflare DLP engine. When building this policy, confirm that it covers Claude's **Platform API** (`api.anthropic.com`) operations, not only the web-app operations -- see Test 2. Docs: [Application Granular Controls](https://developers.cloudflare.com/cloudflare-one/traffic-controls/http-policies/granular-controls/), [AI prompt topics](https://developers.cloudflare.com/cloudflare-one/data-loss-prevention/detection-entries/configure-detection-entries/#ai-prompt-topics).

**2. Custom Validation Workers for DLP.** Cloudflare DLP can invoke a Worker (`DlpValidationEntrypoint`) when a custom pattern entry matches, to adjust confidence or veto the match. This plugs into the real DLP engine and is the correct mechanism if AMS needs organization-specific validation logic (e.g. checking a matched ID against an internal allowlist). It is unrelated to streaming or compression. Docs: [Validate DLP matches with Workers](https://developers.cloudflare.com/cloudflare-one/data-loss-prevention/detection-entries/custom-validation-workers/).

### DLP engine scope of the Forward Worker

> **The Forward Worker uses its own regex-based pattern matching, not the Cloudflare One DLP engine.**
>
> The Forward action does not expose DLP match results to Workers, and there is no public API to submit arbitrary text to Cloudflare DLP for scanning. Patterns live in `src/index.ts`, not the dashboard; changes require a redeploy; dashboard profiles, EDM datasets, and wordlists do not apply to the Worker's scanning.
>
> Cloudflare's built-in DLP **does** still scan the original request body before the Worker receives it, and the final response after the Worker returns it. The Worker supplements that scanning only in the two cases the diagnostic can confirm: oversized request bodies (Cause C) and SSE response reassembly (Cause D).
>
> If dashboard-managed DLP for streaming responses is a hard requirement and Cause D is confirmed, see [Alternative: Buffer-and-Release Mode](#alternative-buffer-and-release-mode).

### Traffic flow

```
Claude Web (browser)           --\
Claude Desktop chat (Electron) ---|--> claude.ai          ---\
                                                              |--> Cloudflare One Client --> Gateway
Claude Code (WSL, Node.js)     --\                            |         |
Cowork (Claude Code engine)    ---|--> api.anthropic.com  ---/    TLS decryption
                                   gzip request bodies                  |
                                   SSE responses               HTTP policies + DLP
                                                                        |
                                                              [Forward policy -- only if
                                                               diagnostic confirms C or D]
                                                                        |
                                                                   Forward Worker
                                                                        |
                                                                  upstream / block
```

### Coverage matrix (target state after the correct fix is applied)

| Surface | Host | Request body | Response | Primary DLP control | Worker role |
|---|---|---|---|---|---|
| Claude web | `claude.ai` | JSON | (verify in Test 1) | Native Gateway DLP -- **already working** | None |
| Claude Desktop chat | `claude.ai` (verify) | JSON | (verify in Test 1) | Native Gateway DLP -- **already working** | None |
| Claude Code (WSL) | `api.anthropic.com` | JSON (gzip off via managed settings) | SSE | Native Gateway DLP, once policy covers host and gzip is disabled | Only if Cause C or D confirmed |
| Cowork | `api.anthropic.com` | JSON (gzip off via managed settings) | SSE | Native Gateway DLP, once policy covers host and gzip is disabled | Only if Cause C or D confirmed |

---

## 3. Prerequisites

Before starting, confirm the following are in place:

- [ ] AMS has an active Cloudflare Zero Trust account (any plan with Gateway)
- [ ] Workers **Paid** plan is active on the same Cloudflare account (the Free plan's 10 ms CPU limit is insufficient for stream parsing)
- [ ] TLS decryption is turned on in Gateway settings
- [ ] A Cloudflare root certificate has been generated and activated (Status: **Available and In-Use**)
- [ ] The Cloudflare One Client is installed on all 9 test machines
- [ ] Cloudflare One Client is enrolled in the AMS Zero Trust organization
- [ ] `wrangler` CLI is installed for Worker deployment (`npm install -g wrangler`)
- [ ] AMS has confirmed which DLP patterns they need (SSN, credit cards, API keys, etc.)

---

## 4. Phase 1 -- Gateway Foundation

These steps ensure Gateway is correctly intercepting and decrypting HTTPS traffic.

### 4.1 Verify TLS Decryption Is Enabled

1. In the Cloudflare dashboard, go to **Zero Trust** > **Traffic policies** > **Traffic settings**
2. Under **Proxy and inspection**, confirm **Inspect HTTPS requests with TLS decryption** is ON
3. Under **Certificates**, confirm the root certificate shows **Available and In-Use**

### 4.2 Verify No Do Not Inspect Conflict

This is the most common cause of "DLP doesn't fire" issues. Check that no existing policy is bypassing inspection for Claude traffic.

1. Go to **Zero Trust** > **Traffic controls** > **Firewall policies** > **HTTP**
2. Look for any **Do Not Inspect** policy that matches:
   - Application: `Anthropic` or `Claude`
   - Host: `api.anthropic.com`, `claude.ai`, or `*.anthropic.com`
3. If found, either **remove** it or **narrow** it so it doesn't cover `api.anthropic.com`

> **Why this matters:** Do Not Inspect policies are evaluated before all other HTTP policies regardless of their position in the list. If Anthropic traffic matches a Do Not Inspect rule, Gateway will not decrypt it, the Forward Worker will never be invoked, and DLP will not function. This is a common, silent cause of "DLP isn't matching" and should be ruled out before any other troubleshooting. Note: the original AMS symptom ("Gateway IS decrypting but policy isn't matching") is inconsistent with a Do Not Inspect match -- and the fact that Claude web and Desktop chat work confirms Anthropic hosts are being decrypted. This step is a sanity check only; the real diagnosis is in Section 2.

### 4.3 Download the Cloudflare Root Certificate

You will need the root certificate in `.pem` format for the host OS and any WSL distributions.

1. Go to **Zero Trust** > **Traffic policies** > **Traffic settings** > **Certificates**
2. Select the **In-Use** certificate
3. Click **More actions** > **Download .pem**
4. Save as `Cloudflare_CA.pem` somewhere accessible on the host machine

### 4.4 Install the Root Certificate on the Host OS

The Cloudflare One Client should install this automatically. To verify or install manually, follow the procedure for your operating system:

- **Windows:** Right-click the `.crt` file > **Open** > **Install Certificate** > **Current User Store** > **Trusted Root Certification Authorities**
- **macOS:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain Cloudflare_CA.crt`
- **Linux:** Copy the `.crt` to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`

For detailed instructions per OS, see [Install certificate manually](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/user-side-certificates/manual-deployment/).

---

## 5. Phase 2 -- Claude Desktop Chat (Reference, Already Working)

AMS reports that DLP already works for the Claude Desktop **chat** tab. This phase exists only as a reference point for the diagnostic. No changes are needed.

Claude Desktop's chat tab is an Electron (Chromium) UI. It uses the host OS certificate store, does not pin certificates, and -- like a browser -- sends plain, uncompressed JSON request bodies. The Code tab and Cowork inside the same app are different: they run the Claude Code engine, which has its own network behavior (Phase 3 and 3b).

### 5.1 Capture the reference log entry

As part of Test 1 in the diagnostic, record the Gateway HTTP log entry for a Desktop chat request. The fields that matter for comparison are **Host**, **Request Content-Encoding**, **Response Content-Type**, and **DLP profile matched**. This is the known-good baseline the failing surfaces are compared against.

---

## 6. Phase 3 -- Claude Code in WSL Ubuntu

Claude Code in WSL Ubuntu has three things to get right, in order: (1) traffic has to reach Gateway, (2) Claude Code has to trust Gateway's certificate, and (3) Claude Code's request bodies have to be in a form Gateway DLP can scan.

### 6.0 Turn off gzip request compression (likely the actual fix)

Claude Code gzip-compresses request bodies to the Claude API by default. Anthropic's enterprise network documentation states:

> *"If such a [TLS-inspection] proxy mishandles gzip-compressed request bodies, set `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` to turn off compression for Claude API, telemetry, and artifact publish requests."*

If Test 3 in the diagnostic confirmed Cause B, this is the fix. Set it in Claude Code's settings rather than the shell so it also reaches Cowork and background agents:

**Per-user (for the POC):** add to `~/.claude/settings.json` inside WSL:
```json
{
  "env": {
    "CLAUDE_CODE_GZIP_REQUEST_BODIES": "0"
  }
}
```

**Org-wide (for the 200-seat rollout):** deliver the same `env` block via Claude Code [managed settings](https://code.claude.com/docs/en/managed-settings) (`managed-settings.json` or MDM policy). Managed settings apply to Claude Code in the terminal, the Desktop Code tab, and Cowork.

Verify: send a prompt from Claude Code and confirm in the Gateway HTTP log that the request no longer shows `Content-Encoding: gzip`.

### 6.1 Configure WSL Mirrored Networking

By default, WSL2 uses NAT networking with its own virtual network adapter. Traffic from WSL may bypass the Cloudflare One Client tunnel on the host. **Mirrored networking mode** makes WSL share the host's network stack, ensuring all WSL traffic routes through the Cloudflare One Client.

**On each of the 9 test machines:**

1. Open a text editor (Notepad, VS Code) and create or edit `%USERPROFILE%\.wslconfig`:

```ini
[wsl2]
networkingMode=mirrored
```

2. Open PowerShell and restart WSL:

```powershell
wsl --shutdown
```

3. Relaunch your WSL Ubuntu terminal

4. Verify traffic is routing through the Cloudflare One Client:

```bash
# Inside WSL -- check that Cloudflare is intercepting
curl -sI https://www.cloudflare.com 2>&1 | grep -i "server:"
# Expected: server: cloudflare

# Check that api.anthropic.com resolves through Gateway DNS
nslookup api.anthropic.com
# Should resolve (not fail with NXDOMAIN)
```

### 6.2 Install the Cloudflare Root Certificate in WSL

The host OS certificate store is not shared with WSL Ubuntu. You must install the certificate separately inside WSL. Claude Code's native installer reads the **operating system** trust store -- in WSL that means Ubuntu's `/etc/ssl/certs`, not the Windows store -- so once the certificate is in Ubuntu's store, Claude Code trusts it without further configuration.

```bash
# 1. Copy the certificate from the host filesystem into WSL
#    (adjust the path to where you saved the certificate)
sudo cp /mnt/c/Users/<username>/Downloads/Cloudflare_CA.pem \
  /usr/local/share/ca-certificates/Cloudflare_CA.crt

# 2. Update the system CA store
sudo update-ca-certificates

# 3. Verify the certificate was added
openssl s_client -connect api.anthropic.com:443 -CApath /etc/ssl/certs 2>/dev/null | head -5
# Should show a successful TLS connection, not "verify error"
```

### 6.3 Certificate trust -- when `NODE_EXTRA_CA_CERTS` is still needed

Per Anthropic's docs, Claude Code's default trust store is `bundled,system`: it trusts both its bundled Mozilla CAs **and** the OS store. With the native installer, step 6.2 is sufficient. You only need `NODE_EXTRA_CA_CERTS` if:

- Claude Code was installed via **npm** on a Node version older than 22.15 (no OS-store support), or
- You want an explicit, auditable trust path independent of the system store

If needed, set it in `~/.claude/settings.json` (not just the shell), so it also reaches Cowork and background agents:

```json
{
  "env": {
    "NODE_EXTRA_CA_CERTS": "/usr/local/share/ca-certificates/Cloudflare_CA.crt",
    "CLAUDE_CODE_GZIP_REQUEST_BODIES": "0"
  }
}
```

**Common mistakes:**
- Setting the variable only on the host OS side (PowerShell) -- it does not propagate into WSL
- Pointing to a directory instead of a `.pem`/`.crt` **file**
- Using `REQUESTS_CA_BUNDLE` or `SSL_CERT_FILE` -- those are for Python, not Node.js
- Exporting it only in `.bashrc` -- shell exports do not reach Cowork or the background-agent supervisor; use the settings `env` block

### 6.4 Verify the configuration loaded

```bash
# Start Claude Code with debug logging
claude --debug

# Send any prompt, then exit and inspect the log
ls -t ~/.claude/debug/*.txt | head -1 | xargs grep -iE "CA certs|NODE_EXTRA_CA|gzip|Failed to (read|load)"
```

Expected lines include `CA certs: Appended extra certificates from NODE_EXTRA_CA_CERTS (...)` if you set it. A `Failed to read` line means the path is wrong.

Then confirm end-to-end in the Gateway HTTP log (**Zero Trust > Logs > Gateway > HTTP**, filter Host = `api.anthropic.com`):
- The request **appears** (traffic is reaching Gateway)
- **Request Content-Encoding is absent** (gzip is off)
- The DLP profile **matches** when the prompt contains the test SSN

---

## 7. Phase 3b -- Cowork

Cowork is the Claude Code engine running inside Claude Desktop, with shell commands executed in a local VM. Anthropic's documentation: *"Cowork runs Claude Code on the member's computer, so Claude Code's managed settings apply to Cowork tasks as well as to the terminal."* Whatever fix resolves Claude Code also resolves Cowork -- but it must be delivered through the right channel.

### 7.1 How Cowork reads network settings

For Cowork sessions (and Code tab sessions on third-party providers), Claude Code reads `NODE_EXTRA_CA_CERTS`, `CLAUDE_CODE_GZIP_REQUEST_BODIES`, and the proxy variables **only from managed settings and `~/.claude/settings.json`**. It ignores them in repository `.claude/settings.json` files and in shell exports. So:

| Delivery method | Reaches Claude Code terminal? | Reaches Cowork? |
|---|---|---|
| Shell `export` in `.bashrc` | Yes | **No** |
| Repository `.claude/settings.json` | Yes (after trust) | **No** |
| `~/.claude/settings.json` `env` block | Yes | Yes |
| Managed settings (`managed-settings.json` / MDM) `env` block | Yes | Yes |

For the POC, `~/.claude/settings.json` on each tester's machine is sufficient. For the 200-seat rollout, use managed settings.

### 7.2 Apply the fix

On the **host OS** (where Claude Desktop runs -- not inside WSL), edit `~/.claude/settings.json` (Windows: `%USERPROFILE%\.claude\settings.json`):

```json
{
  "env": {
    "CLAUDE_CODE_GZIP_REQUEST_BODIES": "0"
  }
}
```

Add `NODE_EXTRA_CA_CERTS` to the same block only if the host-OS certificate store does not already contain the Cloudflare root CA (Phase 1, step 4.4). Point it at a host-OS path, e.g. `C:\\ProgramData\\Cloudflare\\Cloudflare_CA.pem`.

Restart Claude Desktop so Cowork picks up the change.

### 7.3 The `requireCoworkFullVmSandbox` caveat

Claude Desktop has a policy key, `requireCoworkFullVmSandbox`. When it is `true`, the **entire** Claude Code process runs inside Cowork's VM -- and per Anthropic's docs, Claude Code then *"doesn't read the computer's managed settings."* In that mode:

- The `env` block fix above does **not** reach Cowork
- The VM has its own network stack and certificate store (Anthropic-provided image); there is no documented way to inject the Cloudflare root CA into it
- Gateway would see Cowork's API traffic originate from the VM, and TLS interception would fail unless the VM trusts the Cloudflare CA

**Recommendation for the POC:** leave `requireCoworkFullVmSandbox` unset (default `false`). Confirm in the Claude Desktop policy on the test machines (macOS: `com.anthropic.claudefordesktop` profile; Windows: `HKLM\SOFTWARE\Policies\Claude`) that this key is absent or `false`. If AMS's security policy later requires the full VM sandbox, that is a separate conversation with Anthropic about CA injection into the Cowork VM image.

### 7.4 Cowork's own network egress control (not a Cloudflare control)

Separately from Gateway, Anthropic provides an organization-level setting at **claude.ai > Organization settings > Capabilities > Allow network egress** that controls which hosts Cowork's VM can reach for shell commands. This is an Anthropic-side control and operates independently of Cloudflare. It does not affect the Claude Code engine's API calls to `api.anthropic.com` (those always go out), only the egress of commands Claude runs in the VM. Note it for completeness; it is not part of the DLP fix.

### 7.5 Verify

Send a prompt containing the test SSN from Cowork. In the Gateway HTTP log, confirm the request appears with Host `api.anthropic.com`, no `Content-Encoding: gzip`, and the DLP profile matched.

---

## 8. Phase 4 -- Deploy the Forward Worker (Only If Diagnostic Confirms Cause C or D)

> **Gate:** Do not proceed with this phase unless the Section 2 diagnostic produced one of these results:
> - **Test 4:** small body blocked, large body allowed (Cause C -- oversized request bodies)
> - **Test 5:** JSON response blocked, SSE response allowed (Cause D -- SSE responses not scanned)
>
> If the diagnostic pointed at Cause A (policy scope) or Cause B (gzip), the fix is a policy edit or a client setting respectively. Skip this phase entirely; the Worker would add a code-managed DLP layer with no benefit.

The Forward Worker performs supplementary DLP inspection on `api.anthropic.com` traffic. Source code:

**https://gitlab.cfdata.org/chelsee/ams-claude-dlp**

Prerequisite: `CLAUDE_CODE_GZIP_REQUEST_BODIES=0` must already be deployed to clients (Phase 3 / 3b). The Worker does not decompress gzip request bodies.

### 8.1 Clone the Repository

```bash
git clone git@gitlab.cfdata.org:chelsee/ams-claude-dlp.git
cd ams-claude-dlp
```

### 8.2 Install Dependencies

```bash
npm install
```

### 8.3 Create the R2 Bucket for Violation Logs

```bash
npx wrangler r2 bucket create ams-claude-dlp-logs
```

### 8.4 Authenticate Wrangler

Ensure Wrangler is authenticated to the AMS Cloudflare account:

```bash
npx wrangler whoami
# Should show the AMS account
# If not:
npx wrangler login
```

### 8.5 Deploy the Worker

```bash
npx wrangler deploy
```

Expected output:
```
Uploaded ams-claude-dlp
Published ams-claude-dlp
```

### 8.6 Note the Worker ID

You will need the Worker's immutable ID (a 32-character hex string, **not** the Worker name) for the Gateway Forward policy. Retrieve it from the Workers API:

```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/workers" \
  -H "Authorization: Bearer $API_TOKEN" \
  | jq -r '.result[] | select(.name == "ams-claude-dlp") | .id'
```

If you prefer the dashboard, the Forward policy editor lists deployed Workers by name and resolves the ID for you.

### What the Worker Does

| Direction | Content Type | Inspection |
|-----------|-------------|------------|
| **Request** (prompt to Claude) | `application/json` | Buffers body (up to 512 KiB), extracts user messages and system prompt, scans against DLP patterns |
| **Response** (non-streaming) | `application/json` | Buffers body, extracts assistant text blocks, scans against DLP patterns |
| **Response** (streaming) | `text/event-stream` | Streams through to client in real time while accumulating `text_delta` content. Scans at `content_block_stop` boundaries |

**Built-in DLP patterns:**
- US Social Security Numbers (with area/group/serial validation)
- Credit card numbers (Visa, MC, Amex, Discover with Luhn check)
- US bank routing numbers (with ABA checksum validation)
- AWS access key IDs
- API keys and secrets (labeled key=value patterns)
- Email addresses and US phone numbers (available, commented out by default)

---

## 9. Phase 5 -- Create the Gateway Forward Policy

### 9.1 Via the Dashboard

1. Go to **Zero Trust** > **Traffic controls** > **Firewall policies** > **HTTP**
2. Click **Add a policy**
3. Set the policy name: `Claude DLP -- Forward Worker`
4. Configure traffic conditions:
   - Selector: **Host** | Operator: **is** | Value: `api.anthropic.com`
   - Click **And**
   - Selector: **HTTP Method** | Operator: **is** | Value: `POST`
5. Set the action: **Forward**
6. Select Worker: `ams-claude-dlp`
7. Click **Create policy**

### 9.2 Via the API

```bash
ACCOUNT_ID="<ams-account-id>"
API_TOKEN="<api-token>"

# Get the Worker's immutable ID (32-char hex)
WORKER_ID=$(curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/workers" \
  -H "Authorization: Bearer $API_TOKEN" \
  | jq -r '.result[] | select(.name == "ams-claude-dlp") | .id')

# Create the Forward policy
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
    "rule_settings": {
      "forward": {
        "worker_id": "'$WORKER_ID'"
      }
    }
  }'
```

### 9.3 Policy Ordering

Ensure this Forward policy does **not** conflict with other HTTP policies:

- **Block policies** take precedence over Forward -- a Block policy for `api.anthropic.com` will prevent the Worker from running
- **Do Not Inspect** policies prevent TLS decryption, which means the Forward Worker cannot be invoked
- **Other Forward policies** -- only the first matching Forward policy runs

Recommended policy order:
1. Any Block policies for specific threats
2. **Claude DLP Forward policy** (this one)
3. Standard Allow/DLP policies
4. Do Not Inspect policies for other apps (ensure Claude/Anthropic is NOT in this list)

---

## 10. Phase 6 -- Testing and Validation

Run these tests on each surface with a test user enrolled in the Cloudflare One Client.

### Test 1: Request-Side DLP -- Sensitive Data in Prompt

**What it tests:** The Worker blocks prompts containing sensitive data before they reach Anthropic.

**From any surface (web, desktop, or CLI), or via curl:**
```bash
curl -X POST https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-5-5",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "My SSN is 123-45-6789, can you help me?"}]
  }'
```

**Expected result:** HTTP 400 response:
```json
{
  "type": "error",
  "error": {
    "type": "dlp_violation",
    "message": "Request blocked: your message contains sensitive data..."
  }
}
```

### Test 2: Response-Side DLP -- Streaming Response

**What it tests:** The Worker detects sensitive data in Claude's SSE streaming response and terminates the stream.

```bash
curl -X POST https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-5-5",
    "max_tokens": 200,
    "stream": true,
    "messages": [{"role": "user", "content": "Generate a realistic-looking (but fake) credit card number for testing. Format: XXXX-XXXX-XXXX-XXXX with a valid Luhn checksum."}]
  }'
```

**Expected result:** The stream starts normally, then terminates with an SSE error event:
```
event: error
data: {"type":"error","error":{"type":"dlp_violation","message":"Response blocked: sensitive data detected..."}}
```

### Test 3: Claude Desktop

1. Open Claude Desktop on a machine enrolled in the Cloudflare One Client
2. Type a prompt containing a test SSN: `My social security number is 078-05-1120`
3. **Expected:** Error message about DLP violation (the request never reaches Claude)
4. Type a normal prompt: `What is the capital of France?`
5. **Expected:** Normal response with no interference

### Test 4: Claude Code in WSL Ubuntu

1. Open a WSL Ubuntu terminal on a machine enrolled in the Cloudflare One Client
2. Verify the environment:
   ```bash
   echo $NODE_EXTRA_CA_CERTS
   # Should print the path to Cloudflare_CA.crt
   ```
3. Start Claude Code:
   ```bash
   claude
   ```
4. Type a prompt containing a test SSN
5. **Expected:** Error message about DLP violation
6. Type a normal coding prompt
7. **Expected:** Normal response

### Test 5: Clean Traffic (No False Positives)

Verify normal development workflows are not impacted:

1. **Claude Desktop:** Have a test user work normally for 30 minutes -- code review, writing, debugging
2. **Claude Code in WSL:** Have a test user run typical coding tasks -- file edits, test runs, code generation
3. **Expected:** No false positive blocks, no noticeable latency increase

### Test 6: Verify Gateway Logs

1. Go to **Zero Trust** > **Logs** > **Gateway** > **HTTP**
2. Filter by **Host** = `api.anthropic.com`
3. Confirm you see entries from all three surfaces
4. Entries should show the Forward policy name and Worker invocation

---

## 11. Phase 7 -- Violation Logging and Audit

All DLP violations are logged to the R2 bucket `ams-claude-dlp-logs` with the following structure:

```
ams-claude-dlp-logs/
  request/                          # Violations in user prompts
    2026-10-28/
      <uuid>.json
  response-stream/                  # Violations in SSE streaming responses
    2026-10-28/
      <uuid>.json
  response-json/                    # Violations in non-streaming responses
    2026-10-28/
      <uuid>.json
```

### View Violation Logs

Wrangler does not provide an `r2 object list` command. Use the dashboard or the S3-compatible API to browse the bucket; use Wrangler to fetch a specific object once you know its key.

**Dashboard:** Go to **R2** > **ams-claude-dlp-logs** > **Objects** and browse by the `request/`, `response-stream/`, or `response-json/` prefix.

**Fetch a specific log with Wrangler** (object path is `<bucket>/<key>`):
```bash
npx wrangler r2 object get "ams-claude-dlp-logs/request/2026-10-28/<uuid>.json" --pipe
```

**List objects with the S3 API** (requires an [R2 API token](https://developers.cloudflare.com/r2/api/tokens/)):
```bash
aws s3 ls "s3://ams-claude-dlp-logs/request/" --recursive \
  --endpoint-url "https://$ACCOUNT_ID.r2.cloudflarestorage.com"
```

For ongoing operational visibility, consider forwarding violation events to a SIEM via a Logpush job or having the Worker POST to a webhook in addition to writing to R2.

### Violation Log Format

Each log entry contains:

```json
{
  "timestamp": "2026-10-28T14:30:00.000Z",
  "direction": "request",
  "policyId": "abc123",
  "accountId": "def456",
  "sourceIp": "203.0.113.10",
  "user": "developer@ams.com",
  "url": "https://api.anthropic.com/v1/messages",
  "violations": [
    {
      "pattern": "US SSN",
      "matchRedacted": "123-***-6789"
    }
  ],
  "contentSample": "My SSN is 123-45-6789, can you help me... [truncated]"
}
```

### Set Up R2 Lifecycle Rules

For compliance, configure retention on the R2 bucket:

1. Go to **R2** > **ams-claude-dlp-logs** > **Settings** > **Object lifecycle rules**
2. Add a rule to delete objects after your retention period (e.g., 90 days)

---

## 12. Customizing DLP Patterns

Edit `src/index.ts` in the Worker project and modify the `DLP_PATTERNS` array.

Each pattern has:
- `name` -- Display name for logs and error messages
- `regex` -- Regular expression (use the `g` flag for global matching)
- `validate` -- Optional function to reduce false positives

### Enable Additional Built-in Patterns

Uncomment the email and phone patterns in `src/index.ts`:

```typescript
// US Phone Numbers
{
  name: "US Phone Number",
  regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
},

// Email Addresses
{
  name: "Email Address",
  regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
},
```

### Add AMS-Specific Patterns

```typescript
// AMS customer order numbers (example: AMS-2026-12345)
{
  name: "AMS Order Number",
  regex: /\bAMS-\d{4}-\d{5,}\b/gi,
},

// Internal employee IDs
{
  name: "Employee ID",
  regex: /\bEMP-\d{6}\b/gi,
},
```

### Redeploy After Changes

```bash
npx wrangler deploy
```

---

## 13. Architecture Notes and Limitations

### Streaming DLP Timing

The Worker streams responses to the client in real time -- there is no buffering delay. DLP scanning runs in parallel at `content_block_stop` boundaries (Claude's natural pause points between content blocks).

**Implication:** If a violation is detected mid-stream, some content may have already been delivered to the client. The stream is terminated immediately and an error event is injected, but earlier chunks cannot be recalled.

For zero-tolerance environments, the Worker can be modified to fully buffer the response before delivering any content. This eliminates the streaming UX (the user waits for the full response) but guarantees no sensitive data is ever delivered.

### Request-Side DLP

Request-side DLP has no meaningful latency impact. The Worker buffers the JSON request body (up to 512 KiB), scans it (~1ms for typical prompts), and either blocks or forwards. The user experiences no delay.

### Worker Execution Limits

- Wall-clock duration for HTTP-triggered Workers is **unlimited** as long as the client stays connected, so long-running Claude streams are not at risk of timing out.
- CPU time is 10 ms on the Workers Free plan and 30 seconds by default on Workers Paid (raisable to 5 minutes via `limits.cpu_ms`). Time spent waiting on the upstream stream does not count as CPU time. The Worker's per-chunk parsing and regex scanning is cheap, but **the Workers Free plan's 10 ms CPU limit is not sufficient** for this Worker -- AMS must be on Workers Paid.
- The Worker accumulates up to 2 MiB of response text. Responses exceeding this are still streamed but no longer scanned.

### DLP Coverage Summary

| Traffic Type | DLP Engine Used | Managed via Dashboard? |
|-------------|----------------|----------------------|
| Claude Web (chat) -- request body | Cloudflare DLP | Yes |
| Claude Web (chat) -- response body | Cloudflare DLP | Yes |
| Claude Desktop/Code -- request body (JSON) | Cloudflare DLP scans first, then Worker scans | Both (Cloudflare DLP runs before Worker) |
| Claude Desktop/Code -- response (SSE streaming) | Cloudflare DLP on the stream **plus** Worker reassembly scan | Partially -- Worker patterns are code-managed |
| Claude Desktop/Code -- response (non-streaming) | Cloudflare DLP scans after Worker, plus Worker scans | Both |

Gateway DLP inspects the original request body before the Worker receives it and inspects the final response after the Worker returns it. Gateway's behavior on chunked `text/event-stream` bodies is not publicly documented in detail; whether it reassembles the stream before pattern matching should be **tested empirically** for AMS's account rather than assumed. The Worker guarantees reassembly on the response side regardless of how Gateway handles it.

### Alternative: Buffer-and-Release Mode

If AMS requires all DLP scanning to use Cloudflare's built-in DLP engine (dashboard-managed profiles, EDM, custom wordlists), the Worker can be restructured to **buffer the entire SSE response, reassemble it into a standard JSON body, and return it as a non-streaming response**. This lets Gateway's native DLP engine scan the complete response text after the Worker.

**How it would work:**

1. Worker receives the streaming SSE response from `api.anthropic.com`
2. Worker consumes the entire stream, accumulating all `text_delta` events
3. Worker reconstructs a complete Claude Messages API response object (JSON)
4. Worker returns the JSON response to Gateway (non-streaming)
5. Gateway's response-side DLP scans the full JSON body using dashboard-configured profiles
6. If DLP passes, the response is delivered to the client

**Caveats:**

- **No streaming UX.** The user sees nothing until Claude's entire response is generated. For long code generation or detailed explanations, this could mean 10-30+ seconds of blank screen before any text appears. This fundamentally changes the Claude Desktop and Claude Code experience.
- **Gateway inspection limits are the real constraint, not Workers.** Workers have no wall-clock limit for HTTP requests, so waiting for Claude's full response is fine on the Workers side. However, Gateway's own HTTP inspection has body size and processing limits that are not fully documented; a very large buffered response returned to Gateway for DLP scanning may be truncated or skipped. Test with representative response sizes before relying on this.
- **Client compatibility.** Claude Desktop and Claude Code request streaming (`"stream": true`) and expect SSE back. Returning a non-streaming JSON response to a client expecting SSE may cause client-side parsing errors. The Worker would need to either: (a) strip `"stream": true` from the request before forwarding (changing what Claude sees), or (b) reconstruct a synthetic SSE stream from the buffered response (adding complexity).
- **Memory pressure.** Buffering a full response in Worker memory (up to the 128 MB limit) works for most responses but could be an issue for very large outputs.
- **Double scanning on requests.** Request-side DLP would still work as-is -- Cloudflare DLP scans the original request body before the Worker, and the Worker can also scan it. No conflict here.

**When to consider this approach:**
- AMS has complex DLP profiles (EDM datasets, multi-pattern correlation rules) that can't be replicated with regex
- Compliance requires that all DLP decisions are made by the same engine and appear in the same DLP incident logs
- The streaming UX tradeoff is acceptable to the team (most likely not for developer tooling)

**Recommendation:** Start with the current streaming approach for the POC. If AMS decides they need unified dashboard DLP for streaming traffic, the buffer-and-release modification can be scoped as a follow-on. The regex patterns in the Worker should be configured to mirror their most critical dashboard profiles so coverage is equivalent even if the engine is different.

### Forward Action Constraints

Per Cloudflare documentation:
- The Forward Worker requires TLS decryption to be ON
- Gateway does **not** invoke the Worker for traffic matching Do Not Inspect
- WebSocket traffic bypasses the Worker
- `next()` can only be called once per invocation
- The Worker cannot change the destination URL

---

## 14. Troubleshooting

### Claude Desktop: "Connection failed" or SSL errors

- Verify the Cloudflare root CA is in the host OS trusted certificate store
- Check that the Cloudflare One Client is connected and enrolled
- Check for a Do Not Inspect policy blocking decryption

### Claude Code in WSL: `UNABLE_TO_VERIFY_LEAF_SIGNATURE`

```bash
# Check the variable is set
echo $NODE_EXTRA_CA_CERTS
# Should print: /usr/local/share/ca-certificates/Cloudflare_CA.crt

# Check the file exists and is readable
ls -la $NODE_EXTRA_CA_CERTS

# Check it's a valid certificate
openssl x509 -in $NODE_EXTRA_CA_CERTS -noout -subject
# Should print the certificate subject, not an error
```

### Claude Code in WSL: Traffic not going through Gateway

```bash
# Check WSL networking mode
cat /proc/sys/net/ipv4/conf/all/forwarding
# In mirrored mode, check the host .wslconfig:
cat /mnt/c/Users/$USER/.wslconfig

# Test connectivity through Gateway
curl -v https://api.anthropic.com 2>&1 | grep "issuer"
# Should show "Cloudflare" as the issuer if TLS interception is working
```

### Forward Worker not running

1. Check the Forward policy is enabled and has the correct traffic conditions
2. Verify no Do Not Inspect policy matches first (check policy ordering)
3. Verify the Worker is deployed: `npx wrangler deployments list`
4. Check Workers Logs for invocation errors: **Workers & Pages** > **ams-claude-dlp** > **Logs**

### False positives

If legitimate content is being blocked:
1. Check the violation log in R2 to see which pattern matched
2. Tighten the regex or add a `validate` function to reduce false positives
3. Common false positive: 9-digit numbers that look like SSNs but aren't. The built-in SSN pattern already validates area codes (excludes 000, 666, 900+), but you may need to add contextual checks.

### DLP not catching expected violations

1. Verify the Forward policy is matching (`api.anthropic.com` + `POST`)
2. Check Gateway HTTP logs for the request -- does it show the Forward policy?
3. If the response is non-streaming (no `"stream": true` in the request), the Worker inspects the JSON response body instead
4. For very long responses exceeding 2 MiB, the Worker stops accumulating text. Increase `RESPONSE_TEXT_LIMIT` in `src/index.ts` if needed.
