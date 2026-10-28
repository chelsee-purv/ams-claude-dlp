# AMS Zero Trust DLP for Claude AI -- Complete Deployment Guide

**Customer:** American Musical Supply (AMS)
**Use Case:** 200-seat Zero Trust / DLP POC displacing Proofpoint
**Scope:** DLP coverage across Claude chat (web), Claude Desktop, and Claude Code (WSL Ubuntu)
**Active testers:** 9 users in developer environments
**Forward Worker source:** https://gitlab.cfdata.org/chelsee/ams-claude-dlp

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Phase 1 -- Gateway Foundation](#3-phase-1----gateway-foundation)
4. [Phase 2 -- Claude Desktop Configuration](#4-phase-2----claude-desktop-configuration)
5. [Phase 3 -- Claude Code in WSL Ubuntu](#5-phase-3----claude-code-in-wsl-ubuntu)
6. [Phase 4 -- Deploy the Forward Worker (SSE DLP)](#6-phase-4----deploy-the-forward-worker-sse-dlp)
7. [Phase 5 -- Create the Gateway Forward Policy](#7-phase-5----create-the-gateway-forward-policy)
8. [Phase 6 -- Testing and Validation](#8-phase-6----testing-and-validation)
9. [Phase 7 -- Violation Logging and Audit](#9-phase-7----violation-logging-and-audit)
10. [Customizing DLP Patterns](#10-customizing-dlp-patterns)
11. [Architecture Notes and Limitations](#11-architecture-notes-and-limitations)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Architecture Overview

### The Problem

Standard Gateway DLP inspects HTTP request and response bodies as complete objects. Claude Desktop and Claude Code use the Anthropic Messages API (`api.anthropic.com/v1/messages`) with `"stream": true`, which returns responses as **Server-Sent Events (SSE)**. Each SSE event contains a small text fragment (`text_delta`). Gateway DLP scans these fragments individually and cannot match patterns (SSNs, credit card numbers, etc.) that span across multiple SSE chunks.

### The Solution

A **Gateway Forward Worker** (Programmable Gateway) intercepts Claude API traffic after TLS decryption. The Worker:

- **Request side:** Buffers the JSON request body, extracts user messages, and scans for sensitive data before the prompt reaches Anthropic
- **Response side:** Streams SSE events to the client in real time while accumulating `text_delta` content in parallel. At each `content_block_stop` boundary, it scans the accumulated text for DLP violations
- **On violation:** Blocks the request (request-side) or terminates the stream with an error event (response-side) and logs the violation to R2

### Important: DLP Engine Scope

> **This Worker uses its own regex-based pattern matching, not the Cloudflare One DLP engine.**
>
> The Forward Worker cannot call or integrate with Cloudflare's built-in DLP profiles, Exact Data Match (EDM) datasets, or custom wordlists configured in the Zero Trust dashboard. The Gateway Forward action does not expose DLP match results to Workers, and there is no public API to submit text to the Cloudflare DLP engine for scanning.
>
> **What this means for AMS:**
> - DLP patterns for streaming Claude traffic are defined in the Worker's source code (`src/index.ts`), not the dashboard
> - Changes to patterns require editing code and redeploying the Worker
> - Predefined detection profiles (PCI, HIPAA, financial identifiers) available in the dashboard do not apply to the Worker's scanning -- equivalent patterns must be implemented as regex in the Worker
> - Cloudflare's built-in DLP **does** still apply to non-streaming traffic (Claude web chat, and the request body of all Claude API calls before the Worker receives them)
>
> If centralized, dashboard-managed DLP is a hard requirement for streaming traffic, see [Alternative: Buffer-and-Release Mode](#alternative-buffer-and-release-mode) in the Architecture Notes section.

### Traffic Flow

```
Claude Web (browser)     ---\
Claude Desktop (Electron) ---|---> Cloudflare One Client ---> Cloudflare Gateway
Claude Code (WSL/Node.js) --/         |                    |
                                      |              TLS Decryption
                                      |                    |
                                      |             HTTP Policies
                                      |                    |
                                      |             Forward Policy
                                      |                    |
                                      |            DLP Forward Worker
                                      |              /          \
                                      |         [CLEAN]      [VIOLATION]
                                      |            |              |
                                      |     api.anthropic.com   Block + Log
                                      |            |
                                      |      SSE Response
                                      |            |
                                      |     Worker scans accumulated text
                                      |            |
                                      |      Stream to client
```

### Coverage Matrix

| Surface | API Endpoint | Traffic Format | DLP Method | Client Interception |
|---------|-------------|---------------|------------|-------------------|
| Claude Web (chat) | claude.ai | JSON (non-streaming) | Standard Gateway DLP | Cloudflare One Client |
| Claude Desktop | api.anthropic.com | SSE streaming | Forward Worker | Cloudflare One Client (Electron uses OS cert store) |
| Claude Code (CLI) | api.anthropic.com | SSE streaming | Forward Worker | Cloudflare One Client (WSL requires mirrored networking) |

---

## 2. Prerequisites

Before starting, confirm the following are in place:

- [ ] AMS has an active Cloudflare Zero Trust account (any plan with Gateway)
- [ ] Workers are enabled on the same Cloudflare account
- [ ] TLS decryption is turned on in Gateway settings
- [ ] A Cloudflare root certificate has been generated and activated (Status: **Available and In-Use**)
- [ ] The Cloudflare One Client is installed on all 9 test machines
- [ ] Cloudflare One Client is enrolled in the AMS Zero Trust organization
- [ ] `wrangler` CLI is installed for Worker deployment (`npm install -g wrangler`)
- [ ] AMS has confirmed which DLP patterns they need (SSN, credit cards, API keys, etc.)

---

## 3. Phase 1 -- Gateway Foundation

These steps ensure Gateway is correctly intercepting and decrypting HTTPS traffic.

### 3.1 Verify TLS Decryption Is Enabled

1. In the Cloudflare dashboard, go to **Zero Trust** > **Traffic policies** > **Traffic settings**
2. Under **Proxy and inspection**, confirm **Inspect HTTPS requests with TLS decryption** is ON
3. Under **Certificates**, confirm the root certificate shows **Available and In-Use**

### 3.2 Verify No Do Not Inspect Conflict

This is the most common cause of "DLP doesn't fire" issues. Check that no existing policy is bypassing inspection for Claude traffic.

1. Go to **Zero Trust** > **Traffic controls** > **Firewall policies** > **HTTP**
2. Look for any **Do Not Inspect** policy that matches:
   - Application: `Anthropic` or `Claude`
   - Host: `api.anthropic.com`, `claude.ai`, or `*.anthropic.com`
3. If found, either **remove** it or **narrow** it so it doesn't cover `api.anthropic.com`

> **Why this matters:** Do Not Inspect policies take precedence over DLP policies. If Anthropic traffic matches a Do Not Inspect rule, Gateway will not decrypt it, the Forward Worker will never be invoked, and DLP will not function. This was likely the root cause of the original issue.

### 3.3 Download the Cloudflare Root Certificate

You will need the root certificate in `.pem` format for the host OS and any WSL distributions.

1. Go to **Zero Trust** > **Traffic policies** > **Traffic settings** > **Certificates**
2. Select the **In-Use** certificate
3. Click **More actions** > **Download .pem**
4. Save as `Cloudflare_CA.pem` somewhere accessible on the host machine

### 3.4 Install the Root Certificate on the Host OS

The Cloudflare One Client should install this automatically. To verify or install manually, follow the procedure for your operating system:

- **Windows:** Right-click the `.crt` file > **Open** > **Install Certificate** > **Current User Store** > **Trusted Root Certification Authorities**
- **macOS:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain Cloudflare_CA.crt`
- **Linux:** Copy the `.crt` to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`

For detailed instructions per OS, see [Install certificate manually](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/user-side-certificates/manual-deployment/).

---

## 4. Phase 2 -- Claude Desktop Configuration

Claude Desktop is an Electron application. Electron uses Chromium's networking stack, which respects the host OS certificate store. If the Cloudflare root CA is installed in the system's trusted certificate store (Phase 1), Claude Desktop will accept Gateway's re-signed certificates without any additional configuration.

### 4.1 Verify Traffic Is Being Intercepted

From a machine enrolled in the Cloudflare One Client with Claude Desktop installed:

1. Open Claude Desktop and send a test message
2. In the Cloudflare dashboard, go to **Zero Trust** > **Logs** > **Gateway** > **HTTP**
3. Filter by **Host** = `api.anthropic.com`
4. Confirm you see log entries for the request

If you see entries, TLS decryption is working. If not, check:
- Cloudflare One Client is connected and enrolled
- No Split Tunnel exclude rule for `api.anthropic.com`
- No Do Not Inspect policy (Phase 1, Step 3.2)

### 4.2 No Additional Claude Desktop Configuration Needed

Unlike mobile apps that use certificate pinning, Claude Desktop does **not** pin certificates. Once the Cloudflare root CA is in the OS certificate store and the Cloudflare One Client is routing traffic, Claude Desktop traffic flows through Gateway normally.

---

## 5. Phase 3 -- Claude Code in WSL Ubuntu

Claude Code running in WSL Ubuntu has two additional challenges: getting WSL traffic through the Cloudflare One Client, and getting Node.js to trust the Cloudflare certificate.

### 5.1 Configure WSL Mirrored Networking

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

### 5.2 Install the Cloudflare Root Certificate in WSL

The host OS certificate store is not shared with WSL Ubuntu. You must install the certificate separately inside WSL.

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

### 5.3 Configure Node.js to Trust the Cloudflare Certificate

Claude Code is a Node.js application. Node.js uses its own bundled CA certificates and does **not** read the Ubuntu system certificate store by default. You must explicitly tell Node.js where to find the Cloudflare root CA.

```bash
# 1. Set the NODE_EXTRA_CA_CERTS environment variable
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/Cloudflare_CA.crt

# 2. Make it persistent across sessions
echo 'export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/Cloudflare_CA.crt' >> ~/.bashrc

# 3. Reload your shell
source ~/.bashrc

# 4. Verify Node.js can connect through Gateway
node -e "
const https = require('https');
https.get('https://api.anthropic.com/v1/models', (res) => {
  console.log('Status:', res.statusCode);
  console.log('TLS OK - Gateway interception working');
}).on('error', (e) => {
  console.error('ERROR:', e.message);
  if (e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
    console.error('NODE_EXTRA_CA_CERTS is not set correctly');
  }
});
"
# Expected: Status: 401 (auth required, but TLS succeeded)
# If you see UNABLE_TO_VERIFY_LEAF_SIGNATURE, the cert path is wrong
```

**Common mistakes to avoid:**
- Setting `NODE_EXTRA_CA_CERTS` on the host OS side (e.g., `set NODE_EXTRA_CA_CERTS=...` in PowerShell) -- this does NOT propagate into WSL
- Pointing to a directory instead of a file -- the variable must point to a `.pem` or `.crt` **file**
- Using `REQUESTS_CA_BUNDLE` or `SSL_CERT_FILE` -- these work for Python, not Node.js
- The file must be readable by the user running Claude Code (`ls -la $NODE_EXTRA_CA_CERTS` should show read permissions)

### 5.4 Verify Claude Code Works Through Gateway

```bash
# Start Claude Code
claude

# Inside Claude Code, send a test message
# Then check Gateway logs in the dashboard:
# Zero Trust > Logs > Gateway > HTTP > filter Host = api.anthropic.com
```

---

## 6. Phase 4 -- Deploy the Forward Worker (SSE DLP)

The Forward Worker performs custom DLP inspection on Claude's SSE streaming responses. Source code is available at:

**https://gitlab.cfdata.org/chelsee/ams-claude-dlp**

### 6.1 Clone the Repository

```bash
git clone git@gitlab.cfdata.org:chelsee/ams-claude-dlp.git
cd ams-claude-dlp
```

### 6.2 Install Dependencies

```bash
npm install
```

### 6.3 Create the R2 Bucket for Violation Logs

```bash
npx wrangler r2 bucket create ams-claude-dlp-logs
```

### 6.4 Authenticate Wrangler

Ensure Wrangler is authenticated to the AMS Cloudflare account:

```bash
npx wrangler whoami
# Should show the AMS account
# If not:
npx wrangler login
```

### 6.5 Deploy the Worker

```bash
npx wrangler deploy
```

Expected output:
```
Uploaded ams-claude-dlp
Published ams-claude-dlp
```

### 6.6 Note the Worker ID

You will need the Worker ID for the Gateway policy:

```bash
# Option A: from wrangler
npx wrangler deployments list

# Option B: from the API
curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/scripts" \
  -H "Authorization: Bearer $API_TOKEN" \
  | jq '.result[] | select(.id == "ams-claude-dlp") | .id'
```

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

## 7. Phase 5 -- Create the Gateway Forward Policy

### 7.1 Via the Dashboard

1. Go to **Zero Trust** > **Traffic controls** > **Firewall policies** > **HTTP**
2. Click **Add a policy**
3. Set the policy name: `Claude DLP -- SSE Stream Inspection`
4. Configure traffic conditions:
   - Selector: **Host** | Operator: **is** | Value: `api.anthropic.com`
   - Click **And**
   - Selector: **HTTP Method** | Operator: **is** | Value: `POST`
5. Set the action: **Forward**
6. Select Worker: `ams-claude-dlp`
7. Click **Create policy**

### 7.2 Via the API

```bash
ACCOUNT_ID="<ams-account-id>"
API_TOKEN="<api-token>"

# Get the Worker ID
WORKER_ID=$(curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/scripts" \
  -H "Authorization: Bearer $API_TOKEN" \
  | jq -r '.result[] | select(.id == "ams-claude-dlp") | .tag')

# Create the Forward policy
curl -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/gateway/rules" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Claude DLP - SSE Stream Inspection",
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

### 7.3 Policy Ordering

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

## 8. Phase 6 -- Testing and Validation

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
    "model": "claude-sonnet-4-20250514",
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
    "model": "claude-sonnet-4-20250514",
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

## 9. Phase 7 -- Violation Logging and Audit

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

```bash
# List recent request-side violations
npx wrangler r2 object list ams-claude-dlp-logs --prefix "request/"

# List recent response-side violations
npx wrangler r2 object list ams-claude-dlp-logs --prefix "response-stream/"

# Read a specific violation
npx wrangler r2 object get ams-claude-dlp-logs "request/2026-10-28/<uuid>.json"
```

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

## 10. Customizing DLP Patterns

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

## 11. Architecture Notes and Limitations

### Streaming DLP Timing

The Worker streams responses to the client in real time -- there is no buffering delay. DLP scanning runs in parallel at `content_block_stop` boundaries (Claude's natural pause points between content blocks).

**Implication:** If a violation is detected mid-stream, some content may have already been delivered to the client. The stream is terminated immediately and an error event is injected, but earlier chunks cannot be recalled.

For zero-tolerance environments, the Worker can be modified to fully buffer the response before delivering any content. This eliminates the streaming UX (the user waits for the full response) but guarantees no sensitive data is ever delivered.

### Request-Side DLP

Request-side DLP has no meaningful latency impact. The Worker buffers the JSON request body (up to 512 KiB), scans it (~1ms for typical prompts), and either blocks or forwards. The user experiences no delay.

### Worker Execution Limits

- Workers have a 30-second CPU time limit (Paid plan) or 10ms (Free plan). Long Claude responses with many content blocks are fine because the Worker uses streaming, not buffering.
- The Worker accumulates up to 2 MiB of response text. Responses exceeding this are still streamed but no longer scanned.

### DLP Coverage Summary

| Traffic Type | DLP Engine Used | Managed via Dashboard? |
|-------------|----------------|----------------------|
| Claude Web (chat) -- request body | Cloudflare DLP | Yes |
| Claude Web (chat) -- response body | Cloudflare DLP | Yes |
| Claude Desktop/Code -- request body (JSON) | Cloudflare DLP scans first, then Worker scans | Both (Cloudflare DLP runs before Worker) |
| Claude Desktop/Code -- response (SSE streaming) | **Worker regex only** | **No -- code changes required** |
| Claude Desktop/Code -- response (non-streaming) | Cloudflare DLP scans after Worker, plus Worker scans | Both |

Gateway DLP inspects the original request body before the Worker receives it and inspects the final response after the Worker returns it. For SSE streaming responses, the "final response" is still chunked `text/event-stream` data, which is where standard DLP matching fails. The Worker's regex scanning fills this gap.

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
- **Worker execution time limits.** Workers have a 30-second wall-clock limit on the Paid plan. If Claude takes longer than 30 seconds to generate a full response, the Worker will time out and the request will fail. Long responses with extended thinking or tool use are at risk.
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

## 12. Troubleshooting

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
