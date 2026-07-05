import toolsModule = require("@langchain/core/tools");
import zodModule = require("zod");
import checkTlsSkill = require("../../../../skills/checkTlsCertificate");

import type { TlsCertificateResult } from "../../../../skills/checkTlsCertificate";

const { tool } = toolsModule;
const { z } = zodModule;

const { checkTlsCertificate } = checkTlsSkill as {
  checkTlsCertificate: (
    host: string,
    port?: number,
    timeoutMs?: number
  ) => Promise<TlsCertificateResult>;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const checkTlsCertificateTool = (tool as any)(
  async (input: { host: string; port?: number; timeout_ms?: number }): Promise<string> => {
    const result = await checkTlsCertificate(
      input.host,
      input.port ?? 443,
      input.timeout_ms ?? 5000
    );
    return JSON.stringify(result, null, 2);
  },
  {
    name: "check_tls_certificate",
    description:
      "Use this tool to inspect the TLS/SSL certificate of a remote host. " +
      "It establishes a TLS connection and returns: common name (CN), Subject Alternative Names (SANs), " +
      "issuer, valid_from / valid_to dates, days_remaining until expiry, and SHA-256 fingerprint. " +
      "Call this tool when: the user asks whether a site's certificate is valid or expired, " +
      "when HTTPS connections are being rejected with certificate errors, " +
      "when the user asks 'is the SSL cert okay?', 'when does the cert expire?', " +
      "or when you need to verify TLS identity of a server. " +
      "Returns a summary that classifies the cert as EXPIRED, WARNING (< 14 days), " +
      "NOTICE (< 30 days), or VALID.",
    schema: z.object({
      host: z
        .string()
        .describe(
          "Hostname or IP address of the TLS endpoint. Do NOT include 'https://' — bare hostname only. " +
          "Examples: 'github.com', 'api.example.com', '1.2.3.4'."
        ),
      port: z
        .number()
        .int()
        .min(1)
        .max(65535)
        .optional()
        .describe("TLS port number. Defaults to 443."),
      timeout_ms: z
        .number()
        .int()
        .min(500)
        .max(15000)
        .optional()
        .describe("Connection timeout in milliseconds. Defaults to 5000 (5 s)."),
    }),
  }
);

const triggerKeywords: readonly string[] = [
  // English
  "tls", "ssl", "certificate", "cert", "https", "expired", "expiry",
  "fingerprint", "san", "x509", "pki",
  // Turkish
  "sertifika", "sertifikanın", "sertifikası", "ssl sertifika", "tls sertifika",
  "süresi dolmuş", "süresi doluyor", "ne zaman bitiyor", "geçerli mi",
  "güvenli mi", "handshake", "şifreleme",
];

module.exports = { checkTlsCertificateTool, triggerKeywords };
