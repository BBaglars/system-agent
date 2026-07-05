import toolsModule = require("@langchain/core/tools");
import zodModule = require("zod");
import httpEndpointSkill = require("../../../../skills/httpEndpointProbe");

import type { HttpEndpointResult } from "../../../../skills/httpEndpointProbe";

const { tool } = toolsModule;
const { z } = zodModule;

const { httpEndpointProbe } = httpEndpointSkill as {
  httpEndpointProbe: (
    targetUrl: string,
    method?: "HEAD" | "GET",
    timeoutMs?: number
  ) => Promise<HttpEndpointResult>;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const httpEndpointProbeTool = (tool as any)(
  async (input: {
    url: string;
    method?: "HEAD" | "GET";
    timeout_ms?: number;
  }): Promise<string> => {
    const result = await httpEndpointProbe(
      input.url,
      input.method ?? "HEAD",
      input.timeout_ms ?? 8000
    );
    return JSON.stringify(result, null, 2);
  },
  {
    name: "http_endpoint_probe",
    description:
      "Use this tool to test whether an HTTP or HTTPS endpoint is reachable and healthy. " +
      "It sends a real HTTP request and returns: status code, status text, Time-to-First-Byte (TTFB) " +
      "in milliseconds, key response headers (Server, Content-Type, X-Cache, Location), and redirect info. " +
      "Call this tool when: the user reports that a website returns an error code (e.g. 502, 503, 404), " +
      "when a service is 'running' but not responding to requests, " +
      "when the user asks 'is the site up?', 'what status code does X return?', " +
      "or when you need to measure HTTP response latency (TTFB). " +
      "Always include the full URL with scheme (https://example.com or http://localhost:3000/health).",
    schema: z.object({
      url: z
        .string()
        .url()
        .describe(
          "Full URL to probe including scheme and path. " +
          "Examples: 'https://github.com', 'http://localhost:3000/api/health', 'https://api.example.com/v2/status'."
        ),
      method: z
        .enum(["HEAD", "GET"])
        .optional()
        .describe(
          "HTTP method to use. HEAD (default) is faster and avoids downloading a body. " +
          "Use GET if the server does not support HEAD or you need body-dependent headers."
        ),
      timeout_ms: z
        .number()
        .int()
        .min(500)
        .max(30000)
        .optional()
        .describe("Request timeout in milliseconds. Defaults to 8000 (8 s)."),
    }),
  }
);

const triggerKeywords: readonly string[] = [
  // English
  "http", "https", "status", "endpoint", "url", "website", "site",
  "502", "503", "404", "500", "200", "ttfb", "latency", "response",
  "down", "unreachable", "header", "redirect", "server error",
  // Turkish
  "web sitesi", "site açılmıyor", "hata kodu", "yanıt vermiyor",
  "erişilemiyor", "durum kodu", "500 hatası", "502 hatası", "503 hatası",
  "404 hatası", "yavaş", "gecikme", "sunucu hatası", "yönlendirme",
  "http isteği", "çalışıyor mu", "ayakta mı",
];

module.exports = { httpEndpointProbeTool, triggerKeywords };
