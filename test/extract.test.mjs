import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { gzipSync } from "node:zlib";

// Stub cloudflare:workers so the module loads in Node. R2Bucket type is erased.
registerHooks({
  resolve(s, c, n) {
    if (s === "cloudflare:workers")
      return { url: "data:text/javascript,export class WorkerEntrypoint{constructor(c,e){this.ctx=c;this.env=e}}", shortCircuit: true };
    return n(s, c);
  },
});

// Transpile TS on the fly via esbuild (already a wrangler dependency).
import { build } from "esbuild";
const out = await build({
  entryPoints: ["src/index.ts"], bundle: false, write: false, format: "esm", platform: "neutral",
  loader: { ".ts": "ts" },
});
const mod = await import("data:text/javascript;base64," + Buffer.from(out.outputFiles[0].text).toString("base64"));
const { extractUserText, GatewayMiddleware } = mod;

// --- A body shaped like what Claude Code actually sends -------------------
const claudeCodeBody = {
  model: "claude-sonnet-5-5",
  max_tokens: 32000,
  stream: true,
  system: [
    { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
    { type: "text", text: "# CLAUDE.md\nProject conventions. Never commit secrets.", cache_control: { type: "ephemeral" } },
  ],
  tools: Array.from({ length: 40 }, (_, i) => ({
    name: `tool_${i}`, description: "x".repeat(2000),
    input_schema: { type: "object", properties: { ssn_like_field_name: { type: "string", description: "123-45-6789 is an EXAMPLE in a schema" } } },
  })),
  messages: [
    { role: "user", content: [{ type: "text", text: "Read the customer file and summarize it." }] },
    { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "Read", input: { path: "customers.csv" } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "name,ssn\nJane Doe,078-05-1120\n" }] },
    { role: "assistant", content: [{ type: "text", text: "The file has one row. SSN 999-99-9999 is a placeholder." }] },
    { role: "user", content: "Now help me with my own SSN 219-09-9999 please" },
  ],
};

test("extractUserText: includes system, user text, user tool_result; excludes assistant + tool schemas", () => {
  const t = extractUserText(claudeCodeBody);
  assert.ok(t.includes("CLAUDE.md"), "system blocks included");
  assert.ok(t.includes("Read the customer file"), "user text block included");
  assert.ok(t.includes("078-05-1120"), "user tool_result content included");
  assert.ok(t.includes("219-09-9999"), "user string content included");
  assert.ok(!t.includes("999-99-9999"), "assistant text EXCLUDED");
  assert.ok(!t.includes("123-45-6789"), "tool input_schema EXCLUDED");
  assert.ok(!t.includes("xxxxxxxx"), "tool descriptions EXCLUDED");
});

test("extractUserText: body size does not dilute extraction", () => {
  const full = JSON.stringify(claudeCodeBody);
  const extracted = extractUserText(claudeCodeBody);
  assert.ok(full.length > 80_000, `body is large (${full.length} bytes)`);
  assert.ok(extracted.length < 400, `extracted is small (${extracted.length} chars)`);
});

test("extractUserText: non-object / array returns null (caller blocks)", () => {
  assert.equal(extractUserText(null), null);
  assert.equal(extractUserText([1, 2]), null);
  assert.equal(extractUserText("str"), null);
});

// --- End-to-end through GatewayMiddleware.handle -------------------------
function mkCtx() { return { host: "api.anthropic.com", uri: "https://api.anthropic.com/v1/messages", policyId: "p", accountId: "a", srcIp: "1.2.3.4", identity: async () => ({ email: "t@x.com" }) }; }
function mkEnv() { const puts = []; return { env: { DLP_LOGS: { put: async (k, v) => { puts.push({ k, v }); } } }, puts }; }
function mkExec() { return { waitUntil: (p) => p.catch(() => {}) }; }
const upstreamOk = async () => new Response(JSON.stringify({ content: [{ type: "text", text: "ok" }] }), { status: 200, headers: { "content-type": "application/json" } });

test("handle: gzip-compressed request body with SSN is DECOMPRESSED and BLOCKED", async () => {
  const { env } = mkEnv();
  const w = new GatewayMiddleware(mkExec(), env);
  const gz = gzipSync(Buffer.from(JSON.stringify(claudeCodeBody)));
  const req = new Request("https://api.anthropic.com/v1/messages", {
    method: "POST", body: gz,
    headers: { "content-type": "application/json", "content-encoding": "gzip" },
  });
  const res = await w.handle(req, mkCtx(), upstreamOk);
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("x-dlp-decision"), "block;pattern-match");
  const j = await res.json();
  assert.match(j.error.message, /US SSN/);
});

test("handle: uncompressed clean body PASSES with decision header", async () => {
  const { env } = mkEnv();
  const w = new GatewayMiddleware(mkExec(), env);
  const clean = { ...claudeCodeBody, messages: [{ role: "user", content: "What is the capital of France?" }] };
  const req = new Request("https://api.anthropic.com/v1/messages", {
    method: "POST", body: JSON.stringify(clean), headers: { "content-type": "application/json" },
  });
  const res = await w.handle(req, mkCtx(), upstreamOk);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-dlp-decision"), "pass;request-clean;response-clean");
});

test("handle: oversized body FAILS CLOSED with 413", async () => {
  const { env } = mkEnv();
  const w = new GatewayMiddleware(mkExec(), env);
  const huge = { ...claudeCodeBody, messages: [{ role: "user", content: "a".repeat(9 * 1024 * 1024) }] };
  const req = new Request("https://api.anthropic.com/v1/messages", {
    method: "POST", body: JSON.stringify(huge), headers: { "content-type": "application/json" },
  });
  const res = await w.handle(req, mkCtx(), upstreamOk);
  assert.equal(res.status, 413);
  assert.equal(res.headers.get("x-dlp-decision"), "block;too-large");
});

test("handle: brotli encoding FAILS CLOSED (unsupported, not passed)", async () => {
  const { env } = mkEnv();
  const w = new GatewayMiddleware(mkExec(), env);
  const req = new Request("https://api.anthropic.com/v1/messages", {
    method: "POST", body: new Uint8Array([1, 2, 3]),
    headers: { "content-type": "application/json", "content-encoding": "br" },
  });
  const res = await w.handle(req, mkCtx(), upstreamOk);
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("x-dlp-decision"), "block;unsupported-encoding");
});

test("handle: count_tokens endpoint is NOT inspected", async () => {
  const { env } = mkEnv();
  const w = new GatewayMiddleware(mkExec(), env);
  let called = false;
  const req = new Request("https://api.anthropic.com/v1/messages/count_tokens", {
    method: "POST", body: JSON.stringify(claudeCodeBody), headers: { "content-type": "application/json" },
  });
  const res = await w.handle(req, mkCtx(), async () => { called = true; return new Response("{}", { status: 200 }); });
  assert.equal(called, true);
  assert.equal(res.status, 200);
});
