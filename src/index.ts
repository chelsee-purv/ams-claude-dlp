/**
 * AMS Claude DLP – Gateway Forward Worker
 *
 * This Worker is the DLP enforcement point for Claude Code and Cowork traffic
 * to api.anthropic.com. Native Gateway DLP was observed returning Allow on
 * Claude Code requests containing test SSNs even after gzip was disabled, so
 * this Worker performs its own inspection rather than relying on Gateway's
 * body scan. It uses regex pattern matching, NOT the Cloudflare DLP engine.
 *
 * Request side (the primary control -- what users send to Claude):
 *   - Decompresses gzip/deflate/br request bodies. Claude Code compresses by
 *     default and a client missing the managed setting must not bypass scanning.
 *   - Parses the Messages API JSON and extracts every user-authored text field:
 *     messages[].content (string or text/tool_result blocks) and system.
 *     Tool schemas and assistant turns are skipped so a 500 KB body with a
 *     one-line prompt is scanned for exactly that prompt.
 *   - FAILS CLOSED: a body that cannot be decoded, parsed, or that exceeds
 *     REQUEST_BODY_LIMIT is blocked, not passed through.
 *
 * Response side (secondary -- what Claude sends back):
 *   - SSE streams are passed through in real time while text_delta events are
 *     accumulated and scanned at content_block_stop boundaries.
 *   - Non-streaming JSON responses are buffered and scanned.
 *
 * Every decision sets an x-dlp-decision response header (pass | block | error)
 * so the outcome is visible in Gateway HTTP logs without opening Workers Logs.
 * Violations are additionally written to R2 for audit.
 *
 * Deploy with: npx wrangler deploy
 * Scope with a Gateway Forward policy matching:
 *   Host = api.anthropic.com AND HTTP Method = POST
 */

import { WorkerEntrypoint } from "cloudflare:workers";
import type {
  GatewayMiddlewareContext,
  GatewayMiddlewareNext,
} from "@cloudflare/zt-types";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

interface Env {
  DLP_LOGS: R2Bucket;
}

/**
 * Maximum DECODED request body size to inspect (8 MiB). Claude Code bodies
 * carry full conversation history, tool schemas, and file contents; 1-3 MiB is
 * routine. A body over this limit is BLOCKED (fail closed), never passed.
 * Workers have 128 MiB of memory per isolate; 8 MiB leaves ample headroom.
 */
const REQUEST_BODY_LIMIT = 8 * 1024 * 1024;

/** Maximum accumulated response text before we stop buffering (2 MiB).
 *  Claude responses can be long; we cap to avoid OOM. */
const RESPONSE_TEXT_LIMIT = 2 * 1024 * 1024;

/** Response header that records the Worker's decision for every request. */
const DECISION_HEADER = "x-dlp-decision";

// ---------------------------------------------------------------------------
// DLP Patterns
// ---------------------------------------------------------------------------

/**
 * Each pattern has a name (for logging), a regex, and an optional validator
 * function for reducing false positives (e.g., Luhn check for credit cards).
 *
 * CUSTOMIZE THESE for AMS's specific data types. These are common defaults
 * that mirror what Proofpoint would typically catch.
 */
interface DlpPattern {
  name: string;
  regex: RegExp;
  validate?: (match: string) => boolean;
}

const DLP_PATTERNS: DlpPattern[] = [
  // US Social Security Numbers: XXX-XX-XXXX or XXXXXXXXX
  {
    name: "US SSN",
    regex: /\b(\d{3}-\d{2}-\d{4}|\d{9})\b/g,
    validate: (m) => {
      const digits = m.replace(/-/g, "");
      // SSN cannot start with 000, 666, or 9xx
      const area = parseInt(digits.substring(0, 3), 10);
      if (area === 0 || area === 666 || area >= 900) return false;
      const group = parseInt(digits.substring(3, 5), 10);
      const serial = parseInt(digits.substring(5, 9), 10);
      return group !== 0 && serial !== 0;
    },
  },

  // Credit Card Numbers (Visa, MC, Amex, Discover) with optional separators
  {
    name: "Credit Card Number",
    regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,4}\b/g,
    validate: (m) => luhnCheck(m.replace(/[\s-]/g, "")),
  },

  // US Bank Routing Numbers (9 digits, starts with valid Fed prefix)
  {
    name: "US Bank Routing Number",
    regex: /\b[0-3]\d{8}\b/g,
    validate: (m) => {
      const d = m.split("").map(Number);
      // ABA checksum: (3(d1+d4+d7) + 7(d2+d5+d8) + (d3+d6+d9)) mod 10 === 0
      return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 === 0;
    },
  },

  // AWS Access Key IDs
  {
    name: "AWS Access Key",
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g,
  },

  // Generic API Keys / Secrets (long hex or base64 strings labeled as keys)
  {
    name: "API Key/Secret",
    regex: /(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key|private[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9_\-/.+=]{32,})/gi,
  },

  // Email addresses (for detecting PII leakage in prompts/responses)
  // Disabled by default -- uncomment if AMS wants email DLP
  // {
  //   name: "Email Address",
  //   regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  // },

  // US Phone Numbers
  // {
  //   name: "US Phone Number",
  //   regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  // },

  // Custom: Add AMS-specific patterns here
  // Example: Internal project codes, customer IDs, etc.
];

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Luhn algorithm for credit card validation. */
function luhnCheck(num: string): boolean {
  if (num.length < 13 || num.length > 19) return false;
  let sum = 0;
  let alternate = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let n = parseInt(num[i], 10);
    if (isNaN(n)) return false;
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

interface Violation {
  pattern: string;
  match: string;
}

/**
 * Scan text against all DLP patterns. Returns array of violations.
 *
 * Uses String.prototype.matchAll() which creates a fresh iterator per call,
 * so the module-level regex objects are never mutated. This is required
 * because a Worker isolate handles concurrent requests and the SSE
 * transform runs asynchronously -- sharing lastIndex across calls would
 * cause missed or duplicated matches.
 *
 * @param text         The text to scan.
 * @param minEndIndex  Only report matches that END after this index. Used by
 *                     the incremental SSE scanner: the overlap window re-covers
 *                     already-scanned text, and this prevents re-reporting
 *                     matches that were fully contained in that region.
 */
function scanForViolations(text: string, minEndIndex = 0): Violation[] {
  const violations: Violation[] = [];

  for (const pattern of DLP_PATTERNS) {
    for (const match of text.matchAll(pattern.regex)) {
      const candidate = match[0];
      const start = match.index ?? 0;
      if (start + candidate.length <= minEndIndex) continue;
      if (!pattern.validate || pattern.validate(candidate)) {
        violations.push({
          pattern: pattern.name,
          // Redact most of the match for the log -- keep first 4 and last 4 chars
          match: candidate.length > 10
            ? candidate.substring(0, 4) + "***" + candidate.substring(candidate.length - 4)
            : "***",
        });
      }
    }
  }

  return violations;
}

/** Outcome of reading a request body. Only `ok` carries text. */
type BodyRead =
  | { kind: "ok"; text: string; encodedBytes: number; decodedBytes: number }
  | { kind: "empty" }
  | { kind: "unsupported-encoding"; encoding: string }
  | { kind: "not-json"; contentType: string }
  | { kind: "too-large"; decodedBytes: number }
  | { kind: "decode-error"; message: string };

/**
 * Read, decompress, and buffer a request body up to REQUEST_BODY_LIMIT
 * (measured on the DECODED bytes). Handles gzip, deflate, and br via the
 * platform DecompressionStream so a client that still compresses is inspected
 * rather than skipped. Returns a discriminated result so the caller can fail
 * closed on every non-ok outcome.
 */
async function readRequestBody(request: Request): Promise<BodyRead> {
  if (!request.body) return { kind: "empty" };

  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json\b/i.test(contentType)) {
    void request.body.cancel().catch(() => {});
    return { kind: "not-json", contentType };
  }

  // Claude Code sends gzip. DecompressionStream in Workers supports gzip and
  // deflate only (no Brotli). Any other encoding is a block, not a pass.
  const encoding = (request.headers.get("content-encoding") ?? "").trim().toLowerCase();
  let stream: ReadableStream<Uint8Array> = request.body;
  if (encoding && encoding !== "identity") {
    if (encoding !== "gzip" && encoding !== "deflate") {
      void request.body.cancel().catch(() => {});
      return { kind: "unsupported-encoding", encoding };
    }
    stream = request.body.pipeThrough(new DecompressionStream(encoding));
  }

  const reader = stream.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  let decodedBytes = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      decodedBytes += value.byteLength;
      if (decodedBytes > REQUEST_BODY_LIMIT) {
        void reader.cancel().catch(() => {});
        return { kind: "too-large", decodedBytes };
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } catch (err) {
    void reader.cancel().catch(() => {});
    return { kind: "decode-error", message: err instanceof Error ? err.message : String(err) };
  } finally {
    reader.releaseLock();
  }

  const encodedLen = Number(request.headers.get("content-length"));
  return {
    kind: "ok",
    text,
    encodedBytes: Number.isFinite(encodedLen) ? encodedLen : decodedBytes,
    decodedBytes,
  };
}

// ---------------------------------------------------------------------------
// SSE Stream DLP Inspector
// ---------------------------------------------------------------------------

/**
 * Maximum length of any single DLP pattern match. Used as the overlap window
 * when scanning incrementally so a match that straddles two content blocks
 * is still detected without rescanning the whole accumulated text.
 */
const MAX_PATTERN_LEN = 64;

/**
 * Parse SSE events from a text/event-stream response, accumulate text content,
 * and scan for DLP violations at block boundaries.
 *
 * Returns a TransformStream that:
 *  - Passes all SSE bytes through to the client unchanged (real-time streaming)
 *  - Accumulates text_delta content in parallel
 *  - On content_block_stop, scans only the NEW text since the last scan
 *    (plus a small overlap window) so cost is O(n), not O(n^2)
 *  - On violation, terminates the stream with an SSE error event
 */
function createDlpInspectionStream(
  onViolation: (violations: Violation[], accumulatedText: string) => void,
): TransformStream<Uint8Array, Uint8Array> {
  let accumulatedText = "";
  let scannedUpTo = 0; // Index into accumulatedText that has already been scanned
  let sseBuffer = ""; // Buffer for incomplete SSE events
  let blocked = false;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  /**
   * Scan the unscanned tail of accumulatedText. Includes a MAX_PATTERN_LEN
   * overlap so patterns straddling the previous scan boundary are caught.
   * Only matches that END past the old boundary are reported, so anything
   * fully inside the already-scanned region is not double-reported.
   */
  function scanNewText(): Violation[] {
    if (scannedUpTo >= accumulatedText.length) return [];
    const from = Math.max(0, scannedUpTo - MAX_PATTERN_LEN);
    const boundaryOffset = scannedUpTo - from; // boundary in window coordinates
    const violations = scanForViolations(accumulatedText.slice(from), boundaryOffset);
    scannedUpTo = accumulatedText.length;
    return violations;
  }

  function emitBlockAndTerminate(
    controller: TransformStreamDefaultController<Uint8Array>,
    violations: Violation[],
  ) {
    blocked = true;
    const errorEvent = [
      "event: error",
      `data: ${JSON.stringify({
        type: "error",
        error: {
          type: "dlp_violation",
          message:
            "Response blocked: sensitive data detected by DLP policy. " +
            `${violations.length} violation(s) found: ${violations.map((v) => v.pattern).join(", ")}. ` +
            "Contact your administrator.",
        },
      })}`,
      "",
      "",
    ].join("\n");
    controller.enqueue(encoder.encode(errorEvent));
    onViolation(violations, accumulatedText);
    controller.terminate();
  }

  function processSSEEvent(
    eventText: string,
    controller: TransformStreamDefaultController<Uint8Array>,
  ) {
    const dataLines: string[] = [];
    for (const rawLine of eventText.split("\n")) {
      const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
      if (line.startsWith("data: ")) {
        dataLines.push(line.substring(6));
      } else if (line === "data:") {
        dataLines.push("");
      }
    }
    if (dataLines.length === 0) return;

    let data: any;
    try {
      data = JSON.parse(dataLines.join("\n"));
    } catch {
      return; // Not JSON (e.g. ping or comment) -- skip
    }

    // Accumulate text from content_block_delta events
    if (data.type === "content_block_delta" && data.delta) {
      let piece: string | undefined;
      if (data.delta.type === "text_delta") piece = data.delta.text;
      else if (data.delta.type === "input_json_delta") piece = data.delta.partial_json;
      if (piece && accumulatedText.length < RESPONSE_TEXT_LIMIT) {
        accumulatedText += piece;
      }
    }

    // At content block boundaries, scan the new text since the last scan
    if (data.type === "content_block_stop") {
      const violations = scanNewText();
      if (violations.length > 0) {
        emitBlockAndTerminate(controller, violations);
      }
    }
  }

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      if (blocked) return;

      // Pass the chunk through to the client immediately
      controller.enqueue(chunk);

      // Accumulate for parsing. Normalize CRLF to LF so event splitting works
      // regardless of the upstream's line ending convention.
      sseBuffer += decoder.decode(chunk, { stream: true }).replace(/\r\n/g, "\n");

      // SSE events are separated by a blank line
      const events = sseBuffer.split("\n\n");
      sseBuffer = events.pop() ?? ""; // keep the trailing partial event

      for (const event of events) {
        processSSEEvent(event, controller);
        if (blocked) return;
      }
    },

    flush(controller) {
      if (blocked) return;

      // Process any trailing event that didn't get a terminating blank line
      sseBuffer += decoder.decode(); // flush decoder
      if (sseBuffer.trim()) {
        processSSEEvent(sseBuffer, controller);
        if (blocked) return;
      }

      // Catch anything that arrived after the last content_block_stop
      const violations = scanNewText();
      if (violations.length > 0) {
        // Stream is ending anyway; content already delivered. Log, but still
        // append an error event so the client knows the response was flagged.
        emitBlockAndTerminate(controller, violations);
      }
    },
  });
}

// ---------------------------------------------------------------------------
// Messages API text extraction
// ---------------------------------------------------------------------------

/**
 * Pull every user-authored or user-supplied text field out of a Messages API
 * request body. Scanning only these fields -- rather than the whole JSON --
 * means a 2 MB body with tool schemas and conversation history is scanned for
 * exactly what the user typed or what Claude Code read from disk on the user's
 * behalf, with no size-related gaps.
 *
 * Included:
 *   - system (string or text blocks) -- Claude Code puts CLAUDE.md here
 *   - messages[role=user].content as a string
 *   - messages[role=user].content[].text        (what the user typed)
 *   - messages[role=user].content[].tool_result (file contents, command output
 *     that Claude Code read and is sending to the model)
 *
 * Excluded by design:
 *   - messages[role=assistant] -- model output already seen; response-side
 *     inspection covers new output
 *   - tools[].input_schema -- JSON Schema, not user data
 *   - image/document blocks -- base64, not scannable as text
 *
 * Returns the concatenated text, or null if the body is not a Messages API
 * request object (the caller treats null as a block).
 */
export function extractUserText(payload: unknown): string | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const p = payload as Record<string, unknown>;
  const parts: string[] = [];

  const pushBlocks = (blocks: unknown) => {
    if (typeof blocks === "string") {
      parts.push(blocks);
      return;
    }
    if (!Array.isArray(blocks)) return;
    for (const b of blocks) {
      if (!b || typeof b !== "object") continue;
      const blk = b as Record<string, unknown>;
      if (blk.type === "text" && typeof blk.text === "string") {
        parts.push(blk.text);
      } else if (blk.type === "tool_result") {
        // content may be a string or an array of text blocks
        pushBlocks(blk.content);
      }
    }
  };

  pushBlocks(p.system);

  if (Array.isArray(p.messages)) {
    for (const m of p.messages) {
      if (!m || typeof m !== "object") continue;
      const msg = m as Record<string, unknown>;
      if (msg.role === "user") pushBlocks(msg.content);
    }
  }

  return parts.join("\n");
}

/**
 * Return a copy of an upstream response with the decision header set.
 * Upstream Response headers are immutable, so copy into a new Response.
 */
function withDecision(response: Response, decision: string): Response {
  const headers = new Headers(response.headers);
  headers.set(DECISION_HEADER, decision);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/** Build the error response returned when the Worker blocks a request. */
function blockedResponse(reason: string, detail: string, status = 400): Response {
  return new Response(
    JSON.stringify({
      type: "error",
      error: { type: "dlp_violation", message: detail },
    }),
    {
      status,
      headers: {
        "content-type": "application/json",
        [DECISION_HEADER]: `block;${reason}`,
        "cache-control": "no-store",
      },
    },
  );
}

// ---------------------------------------------------------------------------
// Main GatewayMiddleware
// ---------------------------------------------------------------------------

export class GatewayMiddleware extends WorkerEntrypoint<Env> {
  async handle(
    request: Request,
    context: GatewayMiddlewareContext,
    next: GatewayMiddlewareNext,
  ): Promise<Response> {
    // Only inspect the Messages endpoint. count_tokens is a dry-run that
    // carries the same body but produces no model output; skipping it avoids
    // double-counting violations in logs.
    const url = new URL(request.url);
    if (
      request.method !== "POST" ||
      url.pathname !== "/v1/messages"
    ) {
      return next(request);
    }

    // -----------------------------------------------------------------------
    // STEP 1: Inspect the REQUEST body (what the user is sending to Claude).
    // This is the primary control. Every non-ok outcome fails closed.
    // -----------------------------------------------------------------------
    const read = await readRequestBody(request.clone());

    if (read.kind !== "ok") {
      // "empty" is the only non-ok case that is safe to forward: a POST with
      // no body cannot contain sensitive data.
      if (read.kind === "empty") return this.passThrough(next, request, "empty-body");

      const detail =
        read.kind === "too-large"
          ? `Request body (${Math.round(read.decodedBytes / 1024)} KiB) exceeds the inspectable limit. Shorten the conversation or reduce attached context and retry.`
          : read.kind === "unsupported-encoding"
            ? `Request uses Content-Encoding "${read.encoding}", which cannot be inspected.`
            : read.kind === "not-json"
              ? `Request Content-Type "${read.contentType}" is not inspectable JSON.`
              : `Request body could not be decoded for inspection: ${read.message}`;

      this.ctx.waitUntil(
        this.logViolation(context, "request-uninspectable", [{ pattern: read.kind, match: "" }], request.url, detail),
      );
      return blockedResponse(read.kind, detail, read.kind === "too-large" ? 413 : 400);
    }

    let payload: unknown;
    try {
      payload = JSON.parse(read.text);
    } catch {
      this.ctx.waitUntil(
        this.logViolation(context, "request-uninspectable", [{ pattern: "invalid-json", match: "" }], request.url),
      );
      return blockedResponse("invalid-json", "Request body is not valid JSON and cannot be inspected.");
    }

    const userText = extractUserText(payload);
    if (userText === null) {
      this.ctx.waitUntil(
        this.logViolation(context, "request-uninspectable", [{ pattern: "not-messages-api", match: "" }], request.url),
      );
      return blockedResponse("not-messages-api", "Request body is not a Messages API object.");
    }

    const violations = scanForViolations(userText);
    if (violations.length > 0) {
      this.ctx.waitUntil(this.logViolation(context, "request", violations, request.url, userText));
      return blockedResponse(
        "pattern-match",
        "Request blocked: your message contains sensitive data that cannot be sent to external AI services. " +
          `${violations.length} violation(s) detected: ${violations.map((v) => v.pattern).join(", ")}. ` +
          "Remove the sensitive data and try again.",
      );
    }

    // -----------------------------------------------------------------------
    // STEP 2: Forward request and inspect the RESPONSE
    // -----------------------------------------------------------------------
    const response = await next(request);

    // Check if the response is SSE (streaming)
    const contentType = response.headers.get("content-type") ?? "";
    const isSSE = contentType.includes("text/event-stream");

    // Upstream error responses (4xx/5xx) carry no model output. Pass them
    // through with the request-side decision recorded.
    if (!response.ok || !response.body) {
      return withDecision(response, "pass;request-clean;upstream-" + response.status);
    }

    // If the upstream body is compressed we cannot parse it as text. Anthropic
    // does not compress SSE in practice; if it ever does, record it and pass
    // through rather than corrupt the stream. Request-side has already passed.
    if (response.headers.has("content-encoding")) {
      return withDecision(response, "pass;request-clean;response-encoded");
    }

    if (!isSSE) {
      if (/^application\/json\b/i.test(contentType)) {
        return this.inspectJsonResponse(response, context);
      }
      return withDecision(response, "pass;request-clean;response-not-json");
    }

    // -----------------------------------------------------------------------
    // STEP 3: SSE stream inspection
    // -----------------------------------------------------------------------
    const transform = createDlpInspectionStream((violations, accumulatedText) => {
      // Log asynchronously -- don't block the stream
      this.ctx.waitUntil(
        this.logViolation(context, "response-stream", violations, request.url, accumulatedText),
      );
    });

    // We may inject an error event and truncate the stream, so any upstream
    // Content-Length would be wrong. Strip it and let the runtime use chunked
    // transfer.
    const headers = new Headers(response.headers);
    headers.delete("content-length");
    headers.set(DECISION_HEADER, "pass;request-clean;response-stream-inspected");

    return new Response(response.body.pipeThrough(transform), {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  /** Forward unchanged and stamp the decision header on the response. */
  private async passThrough(
    next: GatewayMiddlewareNext,
    request: Request,
    reason: string,
  ): Promise<Response> {
    return withDecision(await next(request), `pass;${reason}`);
  }

  /**
   * Inspect a non-streaming JSON response (when Claude responds without streaming).
   */
  private async inspectJsonResponse(
    response: Response,
    context: GatewayMiddlewareContext,
  ): Promise<Response> {
    const clone = response.clone();
    const reader = clone.body!.getReader();
    const decoder = new TextDecoder();
    let size = 0;
    let text = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > RESPONSE_TEXT_LIMIT) {
          void reader.cancel().catch(() => {});
          return withDecision(response, "pass;request-clean;response-too-large");
        }
        text += decoder.decode(value, { stream: true });
      }
      text += decoder.decode();
    } catch {
      return withDecision(response, "pass;request-clean;response-decode-error");
    } finally {
      reader.releaseLock();
    }

    // Extract text content from Claude's response
    let responseText = "";
    try {
      const data = JSON.parse(text);
      if (Array.isArray(data.content)) {
        for (const block of data.content) {
          if (block.type === "text" && block.text) {
            responseText += block.text + "\n";
          }
        }
      }
    } catch {
      return withDecision(response, "pass;request-clean;response-not-json");
    }

    if (responseText) {
      const violations = scanForViolations(responseText);
      if (violations.length > 0) {
        this.ctx.waitUntil(
          this.logViolation(context, "response-json", violations, context.uri, responseText),
        );

        return new Response(
          JSON.stringify({
            type: "error",
            error: {
              type: "dlp_violation",
              message:
                "Response blocked: Claude's response contains sensitive data that " +
                `DLP policy prevents from being delivered. ${violations.length} violation(s): ` +
                `${violations.map((v) => v.pattern).join(", ")}.`,
            },
          }),
          {
            status: 200, // Return 200 so the client doesn't retry
            headers: {
              "content-type": "application/json",
              [DECISION_HEADER]: "block;response-pattern-match",
              "cache-control": "no-store",
            },
          },
        );
      }
    }

    return withDecision(response, "pass;request-clean;response-clean");
  }

  /**
   * Log a DLP violation to R2 for audit/compliance.
   */
  private async logViolation(
    context: GatewayMiddlewareContext,
    direction: string,
    violations: Violation[],
    url: string,
    contentSample?: string,
  ): Promise<void> {
    try {
      let userEmail: string | undefined;
      try {
        const identity = await context.identity();
        userEmail = identity?.email ?? undefined;
      } catch {
        // Identity unavailable
      }

      const record = {
        timestamp: new Date().toISOString(),
        direction,
        policyId: context.policyId,
        accountId: context.accountId,
        sourceIp: context.srcIp,
        user: userEmail ?? "unknown",
        url: url,
        violations: violations.map((v) => ({
          pattern: v.pattern,
          matchRedacted: v.match,
        })),
        // Include a truncated content sample for investigation (first 500 chars)
        contentSample: contentSample
          ? contentSample.substring(0, 500) + (contentSample.length > 500 ? "... [truncated]" : "")
          : undefined,
      };

      await this.env.DLP_LOGS.put(
        `${direction}/${new Date().toISOString().split("T")[0]}/${crypto.randomUUID()}.json`,
        JSON.stringify(record, null, 2),
        {
          httpMetadata: { contentType: "application/json" },
        },
      );
    } catch (err) {
      console.error("Failed to log DLP violation:", err);
    }
  }
}
