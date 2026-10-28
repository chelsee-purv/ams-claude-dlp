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

### Traffic Flow

```
Claude Web (browser)     ---\
Claude Desktop (Electron) ---|---> WARP Client ---> Cloudflare Gateway
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

| Surface | API Endpoint | Traffic Format | DLP Method | WARP Interception |
|---------|-------------|---------------|------------|-------------------|
| Claude Web (chat) | claude.ai | JSON (non-streaming) | Standard Gateway DLP | Windows WARP client |
| Claude Desktop | api.anthropic.com | SSE streaming | Forward Worker | Windows WARP client (Electron uses OS cert store) |
| Claude Code (CLI) | api.anthropic.com | SSE streaming | Forward Worker | Windows WARP client via WSL mirrored networking |

---

## 2. Prerequisites

Before starting, confirm the following are in place:

- [ ] AMS has an active Cloudflare Zero Trust account (any plan with Gateway)
- [ ] Workers are enabled on the same Cloudflare account
- [ ] TLS decryption is turned on in Gateway settings
- [ ] A Cloudflare root certificate has been generated and activated (Status: **Available and In-Use**)
- [ ] The WARP client is installed on all 9 test machines (Windows)
- [ ] WARP client is enrolled in the AMS Zero Trust organization
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

You will need the root certificate in `.pem` format for both Windows and WSL installations.

1. Go to **Zero Trust** > **Traffic policies** > **Traffic settings** > **Certificates**
2. Select the **In-Use** certificate
3. Click **More actions** > **Download .pem**
4. Save as `Cloudflare_CA.pem` somewhere accessible (e.g., `C:\Users\<username>\Downloads\Cloudflare_CA.pem`)

### 3.4 Install the Root Certificate on Windows

The WARP client should install this automatically. To verify or install manually:

1. Right-click the `.crt` file > **Open** > **Install Certificate**
2. Choose **Current User Store**
3. Select **Browse** > **Trusted Root Certification Authorities**
4. Click **OK** > **Finish**

Verify in PowerShell:
```powershell
Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*Cloudflare*" }
```

---

## 4. Phase 2 -- Claude Desktop Configuration

Claude Desktop is an Electron application. Electron uses Chromium's networking stack, which respects the Windows OS certificate store. If the Cloudflare root CA is installed in the Windows Trusted Root Certification Authorities store (Phase 1), Claude Desktop will accept Gateway's re-signed certificates without any additional configuration.

### 4.1 Verify Traffic Is Being Intercepted

From a WARP-enrolled machine with Claude Desktop installed:

1. Open Claude Desktop and send a test message
2. In the Cloudflare dashboard, go to **Zero Trust** > **Logs** > **Gateway** > **HTTP**
3. Filter by **Host** = `api.anthropic.com`
4. Confirm you see log entries for the request

If you see entries, TLS decryption is working. If not, check:
- WARP client is connected and enrolled
- No Split Tunnel exclude rule for `api.anthropic.com`
- No Do Not Inspect policy (Phase 1, Step 3.2)

### 4.2 No Additional Claude Desktop Configuration Needed

Unlike mobile apps that use certificate pinning, Claude Desktop does **not** pin certificates. Once the Cloudflare root CA is in the Windows certificate store and WARP is routing traffic, Claude Desktop traffic flows through Gateway normally.

---

## 5. Phase 3 -- Claude Code in WSL Ubuntu

Claude Code running in WSL Ubuntu has two additional challenges: getting WSL traffic through WARP, and getting Node.js to trust the Cloudflare certificate.

### 5.1 Configure WSL Mirrored Networking

By default, WSL2 uses NAT networking with its own virtual network adapter. Traffic from WSL may bypass the Windows WARP tunnel. **Mirrored networking mode** makes WSL share the Windows host's network stack, ensuring all WSL traffic routes through WARP.

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

4. Verify traffic is routing through WARP:

```bash
# Inside WSL -- check that Cloudflare is intercepting
curl -sI https://www.cloudflare.com 2>&1 | grep -i "server:"
# Expected: server: cloudflare

# Check that api.anthropic.com resolves through WARP DNS
nslookup api.anthropic.com
# Should resolve (not fail with NXDOMAIN)
```

### 5.2 Install the Cloudflare Root Certificate in WSL

The Windows certificate store is not shared with WSL Ubuntu. You must install the certificate separately inside WSL.

```bash
# 1. Copy the certificate from the Windows filesystem into WSL
#    (adjust the Windows username as needed)
sudo cp /mnt/c/Users/<windows-username>/Downloads/Cloudflare_CA.pem \
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
- Setting `NODE_EXTRA_CA_CERTS` on the Windows side (`set NODE_EXTRA_CA_CERTS=...`) -- this does NOT propagate into WSL
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

Run these tests on each surface with a WARP-enrolled test user.

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

1. Open Claude Desktop on a WARP-enrolled Windows machine
2. Type a prompt containing a test SSN: `My social security number is 078-05-1120`
3. **Expected:** Error message about DLP violation (the request never reaches Claude)
4. Type a normal prompt: `What is the capital of France?`
5. **Expected:** Normal response with no interference

### Test 4: Claude Code in WSL Ubuntu

1. Open a WSL Ubuntu terminal on a WARP-enrolled machine
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

- Verify the Cloudflare root CA is in the Windows Trusted Root Certification Authorities store
- Check that WARP is connected and enrolled
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
# In mirrored mode, check Windows .wslconfig:
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
