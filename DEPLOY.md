# AMS Claude DLP – Deployment Guide

## Overview

This Gateway Forward Worker performs custom DLP inspection on Claude API traffic
(api.anthropic.com) by reassembling SSE streaming responses that standard Gateway
DLP cannot pattern-match across chunk boundaries.

## What It Does

| Direction | Format | Inspection Method |
|-----------|--------|-------------------|
| Request (prompt to Claude) | JSON body | Buffer, extract user messages, scan |
| Response (non-streaming) | JSON body | Buffer, extract assistant text, scan |
| Response (streaming) | SSE text/event-stream | Accumulate text_delta events, scan at block boundaries |

## Prerequisites

1. AMS must be on a Zero Trust plan with Gateway HTTP filtering enabled
2. TLS decryption must be ON and working for api.anthropic.com
3. WARP client installed on the 9 test devices
4. Workers enabled on the same Cloudflare account
5. R2 bucket for violation logging

## Step 1: Deploy the Worker

```bash
# Clone or copy the project files
cd ams-claude-dlp

# Install dependencies
npm install

# Create the R2 bucket for DLP violation logs
npx wrangler r2 bucket create ams-claude-dlp-logs

# Deploy the Worker
npx wrangler deploy
```

Note the Worker name: `ams-claude-dlp`. You'll need the Worker ID for the policy.

Get the Worker ID:
```bash
npx wrangler deployments list
# Or via API:
curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/scripts" \
  -H "Authorization: Bearer $API_TOKEN" | jq '.result[] | select(.id == "ams-claude-dlp") | .id'
```

## Step 2: Create the Gateway Forward Policy

### Via Dashboard

1. Go to **Zero Trust** > **Traffic controls** > **Firewall policies** > **HTTP**
2. Click **Add a policy**
3. Configure:
   - **Name:** `Claude DLP – SSE Stream Inspection`
   - **Traffic conditions:**
     - Selector: **Host** | Operator: **is** | Value: `api.anthropic.com`
     - AND
     - Selector: **HTTP Method** | Operator: **is** | Value: `POST`
   - **Action:** **Forward**
   - **Worker:** Select `ams-claude-dlp`
4. Click **Create policy**

### Via API

```bash
# Get the Worker ID first
WORKER_ID=$(curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/scripts" \
  -H "Authorization: Bearer $API_TOKEN" | jq -r '.result[] | select(.id == "ams-claude-dlp") | .tag')

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

## Step 3: Also cover claude.ai (web interface)

If you want the Worker to also cover the Claude web UI (though standard DLP works
there -- this is for consistency):

Add a second Forward policy with:
- Host is `claude.ai`
- HTTP Method is POST
- Action: Forward → same Worker

## Step 4: Test with the POC Users

### Test 1: Request-side DLP (sensitive data in prompt)

From a WARP-enrolled device, have a test user send a prompt containing a test SSN:

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

Expected: 400 response with `dlp_violation` error.

### Test 2: Response-side DLP (Claude generates sensitive data)

```bash
curl -X POST https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 200,
    "stream": true,
    "messages": [{"role": "user", "content": "Generate a realistic-looking (but fake) credit card number for testing purposes. Format: XXXX-XXXX-XXXX-XXXX"}]
  }'
```

Expected: Stream terminates with an SSE error event containing `dlp_violation`.

### Test 3: Claude Desktop

1. Open Claude Desktop on a WARP-enrolled machine
2. Type a prompt containing a test SSN
3. Expect: Error message about DLP violation
4. Type a normal prompt
5. Expect: Normal response (no interference)

### Test 4: Claude Code in WSL

1. Open Claude Code in WSL Ubuntu terminal
2. Ensure NODE_EXTRA_CA_CERTS points to the Cloudflare root CA
3. Use Claude Code normally -- sensitive data in prompts should be blocked

## Step 5: Check Violation Logs

```bash
# List recent violations
npx wrangler r2 object list ams-claude-dlp-logs --prefix "request/" 
npx wrangler r2 object list ams-claude-dlp-logs --prefix "response-stream/"

# Read a specific violation log
npx wrangler r2 object get ams-claude-dlp-logs <key>
```

## Customizing DLP Patterns

Edit `src/index.ts` and modify the `DLP_PATTERNS` array. Each pattern has:
- `name`: Display name for logs and error messages
- `regex`: Regular expression (use `g` flag for global matching)
- `validate`: Optional function to reduce false positives

Common additions for AMS:
- Customer order numbers
- Internal product SKUs
- Employee IDs
- Database connection strings

Redeploy after changes: `npx wrangler deploy`

## Architecture Notes

- The Worker streams responses in real-time -- no buffering delay to the user
- DLP scanning happens at SSE `content_block_stop` boundaries (natural pause points)
- If a violation is detected mid-stream, some content may have already been
  delivered to the client. The stream is terminated immediately and an error
  event is injected. This is a fundamental limitation of real-time streaming DLP.
- For zero-tolerance scenarios, you could modify the Worker to fully buffer the
  response before delivering it (see commented section in the code). This adds
  latency equal to the full response generation time.
- Request-side DLP has no latency impact beyond the scan time (~1ms for typical prompts)
