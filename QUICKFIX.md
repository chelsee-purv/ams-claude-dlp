# Claude Code and Cowork -- DLP Quick Fix

**For:** American Musical Supply (AMS) Zero Trust POC
**Applies to:** Claude Code (WSL Ubuntu) and Cowork
**Does not apply to:** Claude web or Claude Desktop chat -- those already work
**Time required:** About 5 minutes per machine

---

## What is happening

Cloudflare Gateway DLP works for Claude web and Claude Desktop chat, but not for Claude Code or Cowork. The likely reason is a difference in how Claude Code sends its requests.

Claude Code compresses (gzips) the body of every request it sends to `api.anthropic.com`. Browsers and the Desktop chat tab do not. Anthropic documents this behavior and provides a setting to turn it off specifically for environments with TLS-inspecting proxies like Cloudflare Gateway:

> *"By default, Claude Code compresses large request bodies on direct connections and skips compression when you send requests through a proxy, configure a client certificate, or set `NODE_EXTRA_CA_CERTS`. Use `0` if a TLS-inspecting proxy that Claude Code can't detect mishandles compressed requests."*
> -- Anthropic, Claude Code environment variable reference

The Cloudflare One Client is a transparent tunnel. Claude Code cannot detect it, so it keeps compressing. This fix tells Claude Code to stop.

Cowork is the same Claude Code engine running inside Claude Desktop, so the same fix applies there.

---

## The fix

### Step 1 -- Turn off request compression

**In WSL Ubuntu**, open (or create) the file `~/.claude/settings.json` and make sure it contains this `env` block. If the file already has other settings, add the `env` key alongside them. If it already has an `env` block, add the one line inside it.

```json
{
  "env": {
    "CLAUDE_CODE_GZIP_REQUEST_BODIES": "0"
  }
}
```

The file must be valid JSON: no trailing commas, no comments.

### Step 2 -- Restart Claude Code and send a test prompt

Quit any running Claude Code session. Start it again:

```bash
claude
```

Send this prompt exactly:

```
My SSN is 078-05-1120, can you help me?
```

(`078-05-1120` is a standard test SSN that has been invalid since the 1930s. Nothing sensitive is being sent.)

### Step 3 -- Check what Gateway did

In the Cloudflare dashboard go to **Zero Trust > Logs > Gateway > HTTP**. Filter by your email address and the last 10 minutes. Find the request to `api.anthropic.com`.

| What you see | What it means | What to do |
|---|---|---|
| **Action: Block**, DLP profile shown as matched | The fix worked. Compression was the problem. | Apply Step 1 on every tester's machine, then roll out org-wide (see below). Nothing else is needed. |
| **Action: Allow**, no DLP match, but the request appears | Compression was not the only issue. | Let us know -- there is a follow-up diagnostic we will walk through together. |
| The request does not appear at all | Claude Code's traffic is not reaching Gateway from WSL. | Let us know -- this is a WSL networking or certificate setup step, separate from DLP. |

### Step 4 -- Repeat for Cowork

Cowork runs on the **host operating system**, not inside WSL, so it reads a different settings file.

On the host (Windows: `%USERPROFILE%\.claude\settings.json`; macOS: `~/.claude/settings.json`), add the same `env` block from Step 1. Restart Claude Desktop. Send the same test prompt from Cowork and check the Gateway log the same way.

---

## Rolling it out to everyone

Once confirmed on the test machines, the setting belongs in Claude Code **managed settings** so it reaches all 200 seats automatically. Add the same `env` block to your `managed-settings.json` or deliver it via your MDM policy for Claude Code. Managed settings apply to Claude Code in the terminal, the Desktop Code tab, and Cowork.

Reference: https://code.claude.com/docs/en/managed-settings

---

## One question that helps us

During earlier troubleshooting, did anyone set the `NODE_EXTRA_CA_CERTS` environment variable **inside WSL** (as opposed to on the Windows side)?

Setting that variable has a side effect of turning off compression. So if it was set correctly inside WSL and DLP still did not match, that would point away from compression as the cause and we would skip straight to the follow-up diagnostic. If it was set on Windows only, or not at all, the fix above is the right first step.
