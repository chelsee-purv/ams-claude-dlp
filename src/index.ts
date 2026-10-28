/**
 * AMS Claude DLP – Gateway Forward Worker
 *
 * Intercepts Claude API traffic (api.anthropic.com) and performs custom DLP
 * inspection on both:
 *   1. REQUEST bodies  – user prompts sent to Claude (JSON, non-streaming)
 *   2. RESPONSE bodies – Claude's SSE streaming responses (text/event-stream)
 *
 * Standard Gateway DLP sees SSE chunks individually and can't match patterns
 * that span chunk boundaries. This Worker reassembles the full text content
 * from streaming text_delta events and scans the accumulated output.
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

/** Scan text against all DLP patterns. Returns array of violations. */
function scanForViolations(text: string): Array<{ pattern: string; match: string }> {
  const violations: Array<{ pattern: string; match: string }> = [];

  for (const pattern of DLP_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(text)) !== null) {
      const candidate = match[0];
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
 * Returns the body text, or null if the body is too large or not JSON.
 */
async function bufferRequestBody(request: Request): Promise<string | null> {
  if (!request.body) return null;
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json\b/i.test(contentType)) return null;
  if (request.headers.has("content-encoding")) return null;

  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
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
 * Parse SSE events from a text/event-stream response, accumulate text content,
 * and scan for DLP violations at block boundaries.
 *
 * Returns a TransformStream that:
 *  - Passes all SSE bytes through to the client unchanged (real-time streaming)
 *  - Accumulates text_delta content in parallel
 *  - On content_block_stop, scans accumulated text for violations
 *  - On violation, terminates the stream with an SSE error event
 */
function createDlpInspectionStream(
  onViolation: (violations: Array<{ pattern: string; match: string }>, accumulatedText: string) => void,
): {
  transform: TransformStream<Uint8Array, Uint8Array>;
  getAccumulatedText: () => string;
  getViolations: () => Array<{ pattern: string; match: string }>;
} {
  let accumulatedText = "";
  let allViolations: Array<{ pattern: string; match: string }> = [];
  let sseBuffer = ""; // Buffer for incomplete SSE lines
  let blocked = false;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const transform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      if (blocked) return; // Stop forwarding after a block

      // Decode the chunk and pass it through immediately
      const text = decoder.decode(chunk, { stream: true });
      controller.enqueue(chunk);

      // Also accumulate for DLP scanning
      sseBuffer += text;

      // Process complete SSE events (double newline separated)
      const events = sseBuffer.split(/\n\n/);
      // Last element might be incomplete -- keep it in the buffer
      sseBuffer = events.pop() ?? "";

      for (const event of events) {
        processSSEEvent(event, controller);
        if (blocked) return;
      }
    },

    flush(controller) {
      // Process any remaining buffer
      if (sseBuffer.trim() && !blocked) {
        processSSEEvent(sseBuffer, controller);
      }

      // Final scan of all accumulated text
      if (!blocked && accumulatedText.length > 0) {
        const violations = scanForViolations(accumulatedText);
        if (violations.length > 0) {
          allViolations.push(...violations);
          onViolation(violations, accumulatedText);
          // At flush, the stream is ending anyway -- log but don't inject
          // (the response is already delivered)
        }
      }
    },
  });

  function processSSEEvent(
    eventText: string,
    controller: TransformableStreamDefaultController<Uint8Array>,
  ) {
    // Parse SSE event: extract event type and data
    let eventType = "";
    let dataLines: string[] = [];

    for (const line of eventText.split("\n")) {
      if (line.startsWith("event: ")) {
        eventType = line.substring(7).trim();
      } else if (line.startsWith("data: ")) {
        dataLines.push(line.substring(6));
      } else if (line === "data:") {
        dataLines.push("");
      }
    }

    if (dataLines.length === 0) return;

    const dataStr = dataLines.join("\n");
    let data: any;
    try {
      data = JSON.parse(dataStr);
    } catch {
      return; // Not JSON, skip (e.g., ping)
    }

    // Extract text from content_block_delta events
    if (data.type === "content_block_delta" && data.delta) {
      if (data.delta.type === "text_delta" && data.delta.text) {
        if (accumulatedText.length < RESPONSE_TEXT_LIMIT) {
          accumulatedText += data.delta.text;
        }
      }
      // Also capture input_json_delta for tool use content
      if (data.delta.type === "input_json_delta" && data.delta.partial_json) {
        if (accumulatedText.length < RESPONSE_TEXT_LIMIT) {
          accumulatedText += data.delta.partial_json;
        }
      }
    }

    // At content block boundaries, run a scan on accumulated text so far
    // This gives us early detection without waiting for the full response
    if (data.type === "content_block_stop") {
      const violations = scanForViolations(accumulatedText);
      if (violations.length > 0) {
        allViolations.push(...violations);
        blocked = true;

        // Inject an SSE error event to terminate the client's stream
        const errorEvent = [
          "event: error",
          `data: ${JSON.stringify({
            type: "error",
            error: {
              type: "dlp_violation",
              message: "Response blocked: sensitive data detected by DLP policy. " +
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
        return;
      }
    }
  }

  return {
    transform,
    getAccumulatedText: () => accumulatedText,
    getViolations: () => allViolations,
  };
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
    let violationCallback: Array<{ pattern: string; match: string }> = [];

    const { transform, getViolations } = createDlpInspectionStream(
      (violations, accumulatedText) => {
        violationCallback = violations;
        // Log asynchronously -- don't block the stream
        this.ctx.waitUntil(
          this.logViolation(context, "response-stream", violations, request.url, accumulatedText),
        );
      },
    );

    // Pipe the response through our inspection transform
    const inspectedBody = response.body.pipeThrough(transform);

    return new Response(inspectedBody, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
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
    violations: Array<{ pattern: string; match: string }>,
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
