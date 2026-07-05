// Framework-free skill. The LangChain wrapper lives in httpEndpointWrapper.ts.

import httpModule  = require("node:http");
import httpsModule = require("node:https");
import urlModule   = require("node:url");

// ── Types ─────────────────────────────────────────────────────────────────────

export interface HttpEndpointResult {
  url: string;
  method: string;
  status_code?: number;
  status_text?: string;
  // Time-to-first-byte: duration from request start until the first response byte.
  ttfb_ms?: number;
  // Total duration until the response headers were fully received.
  total_ms: number;
  // Selected response headers (lowercase keys).
  headers?: Record<string, string>;
  // Populated for redirects: the Location header value.
  redirect_location?: string;
  // Human-readable verdict for the Reporter LLM.
  summary: string;
  // Populated on network-level errors.
  error_code?: string;
}

// ── Core skill function ───────────────────────────────────────────────────────

// Sends a HEAD (falling back to GET) request to the given URL and captures
// status code, TTFB, and key response headers.  Never rejects.
async function httpEndpointProbe(
  targetUrl: string,
  method: "HEAD" | "GET" = "HEAD",
  timeoutMs = 8000
): Promise<HttpEndpointResult> {
  const start = Date.now();

  return new Promise((resolve) => {
    let parsed: ReturnType<typeof urlModule.parse>;
    try {
      parsed = urlModule.parse(targetUrl);
    } catch {
      resolve({
        url: targetUrl,
        method,
        total_ms: Date.now() - start,
        summary: `Invalid URL: ${targetUrl}`,
        error_code: "EINVALID_URL",
      });
      return;
    }

    const isHttps = parsed.protocol === "https:";
    const requester = isHttps ? httpsModule : httpModule;
    const port = parsed.port
      ? parseInt(parsed.port, 10)
      : isHttps ? 443 : 80;

    const options: httpModule.RequestOptions = {
      hostname: parsed.hostname ?? "",
      port,
      path: (parsed.pathname ?? "/") + (parsed.search ?? ""),
      method,
      timeout: timeoutMs,
      headers: {
        "User-Agent":
          "NetSkill-Agent/1.0 (network diagnostics; +https://github.com/netskill)",
        Accept: "*/*",
      },
    };

    const req = requester.request(options, (res) => {
      const ttfb_ms = Date.now() - start;

      // Flatten header values to plain strings for JSON serialisation.
      const headers: Record<string, string> = {};
      const KEPT_HEADERS = [
        "content-type", "server", "x-cache", "cf-cache-status",
        "cache-control", "location", "x-powered-by", "via",
        "strict-transport-security", "content-length",
      ];
      for (const name of KEPT_HEADERS) {
        const val = res.headers[name];
        if (val !== undefined) {
          headers[name] = Array.isArray(val) ? val.join(", ") : val;
        }
      }

      // Drain the body to allow socket reuse (important for HEAD responses too).
      res.resume();
      res.on("end", () => {
        const total_ms = Date.now() - start;
        const sc = res.statusCode ?? 0;
        const isRedirect = sc >= 300 && sc < 400;

        let summary: string;
        if (sc >= 500) {
          summary = `Server error ${sc} from ${targetUrl} — service-side failure detected.`;
        } else if (sc >= 400) {
          summary = `Client error ${sc} from ${targetUrl} — endpoint exists but returned an error.`;
        } else if (isRedirect) {
          summary = `Redirect ${sc} from ${targetUrl} → ${headers["location"] ?? "unknown"} (TTFB: ${ttfb_ms} ms).`;
        } else if (sc >= 200 && sc < 300) {
          summary = `Endpoint ${targetUrl} is UP — HTTP ${sc} in ${ttfb_ms} ms TTFB.`;
        } else {
          summary = `Unexpected status ${sc} from ${targetUrl}.`;
        }

        resolve({
          url: targetUrl,
          method,
          status_code: sc,
          status_text: res.statusMessage ?? "",
          ttfb_ms,
          total_ms,
          headers,
          ...(isRedirect && headers["location"]
            ? { redirect_location: headers["location"] }
            : {}),
          summary,
        });
      });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({
        url: targetUrl,
        method,
        total_ms: Date.now() - start,
        summary: `Request to ${targetUrl} timed out after ${timeoutMs} ms — service may be down or overloaded.`,
        error_code: "ETIMEDOUT",
      });
    });

    req.on("error", (err: NodeJS.ErrnoException) => {
      resolve({
        url: targetUrl,
        method,
        total_ms: Date.now() - start,
        error_code: err.code ?? "UNKNOWN",
        summary: `Network error reaching ${targetUrl} — ${err.message}`,
      });
    });

    req.end();
  });
}

module.exports = { httpEndpointProbe };
