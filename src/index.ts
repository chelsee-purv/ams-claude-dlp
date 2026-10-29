/**
 * AMS Claude DLP – Gateway Forward Worker
 *
 * DEPLOY ONLY IF THE DIAGNOSTIC IN DEPLOY.md SECTION 2 CONFIRMS CAUSE C OR D.
 * If the root cause is policy scope (Cause A) or gzip request bodies (Cause B),
 * this Worker is unnecessary -- fix the policy or set
 * CLAUDE_CODE_GZIP_REQUEST_BODIES=0 on clients instead.
 *
 * Intercepts Claude API traffic (api.anthropic.com) and performs supplementary
 * regex-based DLP inspection (NOT the Cloudflare DLP engine) on:
 *   1. REQUEST bodies  – parses the Messages API JSON and scans only the
 *      user-authored text in messages[].content and system, so the prompt is
 *      inspected regardless of total body size (addresses Cause C)
 *   2. RESPONSE bodies – reassembles SSE text_delta events and scans the
 *      accumulated text at content_block_stop boundaries (addresses Cause D,
 *      which is UNVERIFIED -- see DEPLOY.md Test 5)
 *
 * This Worker does NOT decompress gzip request bodies. Clients must have
 * CLAUDE_CODE_GZIP_REQUEST_BODIES=0 set for request-side inspection to work.
 *
 * Architecture:
 *   - The Worker streams the response to the client in real time (no buffering delay).
 *   - In parallel, it accumulates text deltas into a buffer.
 *   - At content_block_stop boundaries and at message_stop, it runs DLP scans
 *     on the accumulated text.
 *   - If a violation is detected mid-stream, the Worker terminates the stream
 *     and injects an SSE error event telling the client the response was blocked.
 *   - Violations are logged to R2 for audit.
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

/** Maximum request body size we'll buffer for inspection (512 KiB). */
const REQUEST_BODY_LIMIT = 512 * 1024;

/** Maximum accumulated response text before we stop buffering (2 MiB).
 *  Claude responses can be long; we cap to avoid OOM. */
const RESPONSE_TEXT_LIMIT = 2 * 1024 * 1024;

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

/**
 * Read and buffer a request body up to a size limit.
 * Returns the body text, or null if the body is too large, compressed, or not JSON.
 * Always drains/cancels the provided stream so the tee'd clone does not leak.
 */
async function bufferRequestBody(request: Request): Promise<string | null> {
  if (!request.body) return null;
  const contentType = request.headers.get("content-type") ?? "";

  if (!/^application\/json\b/i.test(contentType) || request.headers.has("content-encoding")) {
    console.warn("Skipping request DLP: unsupported content-type or encoded body", {
      contentType,
      encoding: request.headers.get("content-encoding"),
    });
    void request.body.cancel().catch(() => {});
    return null;
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  let size = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > REQUEST_BODY_LIMIT) {
        void reader.cancel().catch(() => {});
        return null; // Too large; let standard Gateway DLP handle it
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
  return text;
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
// Main GatewayMiddleware
// ---------------------------------------------------------------------------

export class GatewayMiddleware extends WorkerEntrypoint<Env> {
  async handle(
    request: Request,
    context: GatewayMiddlewareContext,
    next: GatewayMiddlewareNext,
  ): Promise<Response> {
    // Only inspect POST requests to Claude's message endpoints
    const url = new URL(request.url);
    if (
      request.method !== "POST" ||
      !url.pathname.startsWith("/v1/messages")
    ) {
      return next(request);
    }

    // -----------------------------------------------------------------------
    // STEP 1: Inspect the REQUEST body (user prompt to Claude)
    // -----------------------------------------------------------------------
    // Clone so we can read the body without consuming the original
    const requestClone = request.clone();
    const requestBody = await bufferRequestBody(requestClone);

    if (requestBody) {
      // Extract user message content from the Claude API request
      try {
        const payload = JSON.parse(requestBody);
        let userText = "";

        // Claude Messages API: messages is an array of {role, content}
        if (Array.isArray(payload.messages)) {
          for (const msg of payload.messages) {
            if (msg.role === "user") {
              if (typeof msg.content === "string") {
                userText += msg.content + "\n";
              } else if (Array.isArray(msg.content)) {
                for (const block of msg.content) {
                  if (block.type === "text" && block.text) {
                    userText += block.text + "\n";
                  }
                }
              }
            }
          }
        }

        // Also check the system prompt
        if (typeof payload.system === "string") {
          userText += payload.system + "\n";
        } else if (Array.isArray(payload.system)) {
          for (const block of payload.system) {
            if (block.type === "text" && block.text) {
              userText += block.text + "\n";
            }
          }
        }

        if (userText) {
          const violations = scanForViolations(userText);
          if (violations.length > 0) {
            // Log the violation
            await this.logViolation(context, "request", violations, request.url);

            // Return a Claude-compatible error response
            return new Response(
              JSON.stringify({
                type: "error",
                error: {
                  type: "dlp_violation",
                  message:
                    "Request blocked: your message contains sensitive data that cannot be sent " +
                    `to external AI services. ${violations.length} violation(s) detected: ` +
                    `${violations.map((v) => v.pattern).join(", ")}. ` +
                    "Please remove sensitive data and try again.",
                },
              }),
              {
                status: 400,
                headers: {
                  "content-type": "application/json",
                  "x-dlp-blocked": "true",
                },
              },
            );
          }
        }
      } catch {
        // JSON parse failed -- let it pass through, standard Gateway DLP covers it
      }
    }

    // -----------------------------------------------------------------------
    // STEP 2: Forward request and inspect the RESPONSE
    // -----------------------------------------------------------------------
    const response = await next(request);

    // Check if the response is SSE (streaming)
    const contentType = response.headers.get("content-type") ?? "";
    const isSSE = contentType.includes("text/event-stream");

    // If the upstream body is compressed we cannot parse it as text. Pass it
    // through untouched rather than risk corrupting the stream. Anthropic
    // does not compress SSE in practice, but guard against it anyway.
    if (response.headers.has("content-encoding")) {
      console.warn("Skipping response DLP: upstream body is content-encoded", {
        encoding: response.headers.get("content-encoding"),
        contentType,
      });
      return response;
    }

    if (!isSSE || !response.body) {
      // Non-streaming response -- buffer and scan the JSON body
      if (/^application\/json\b/i.test(contentType) && response.body) {
        return this.inspectJsonResponse(response, context);
      }
      return response;
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

    return new Response(response.body.pipeThrough(transform), {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
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
          // Too large -- return original, rely on standard DLP
          return response;
        }
        text += decoder.decode(value, { stream: true });
      }
      text += decoder.decode();
    } catch {
      return response;
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
      return response;
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
              "x-dlp-blocked": "true",
            },
          },
        );
      }
    }

    return response;
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
