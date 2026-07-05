// Framework-free skill. The LangChain wrapper lives in checkTlsWrapper.ts.

import tlsModule = require("node:tls");

// ── Types ─────────────────────────────────────────────────────────────────────

export interface TlsCertificateResult {
  host: string;
  port: number;
  // Whether the TLS handshake succeeded at all.
  tls_reachable: boolean;
  // Certificate subject fields (populated when tls_reachable is true).
  common_name?: string;
  san?: string[];            // Subject Alternative Names
  issuer?: string;
  valid_from?: string;       // ISO-8601 string
  valid_to?: string;         // ISO-8601 string
  days_remaining?: number;   // Negative means already expired.
  fingerprint?: string;      // SHA-256 fingerprint
  // Human-readable verdict for the Reporter LLM.
  summary: string;
  // Populated on connection-level errors (e.g. ECONNREFUSED, ENOTFOUND).
  error_code?: string;
}

// ── Core skill function ───────────────────────────────────────────────────────

// Connects to host:port via TLS, extracts certificate metadata, and computes
// the number of days until expiry.  Never rejects — all errors are captured.
async function checkTlsCertificate(
  host: string,
  port = 443,
  timeoutMs = 5000
): Promise<TlsCertificateResult> {
  return new Promise((resolve) => {
    const socket = tlsModule.connect(
      { host, port, servername: host, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate(false);
        socket.destroy();

        if (!cert || Object.keys(cert).length === 0) {
          resolve({
            host,
            port,
            tls_reachable: true,
            summary: `Connected to ${host}:${port} but no certificate was returned.`,
          });
          return;
        }

        const validTo    = new Date(cert.valid_to);
        const validFrom  = new Date(cert.valid_from);
        const now        = new Date();
        const daysRemaining = Math.floor(
          (validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        );

        const cn = (cert.subject as Record<string, string> | undefined)?.CN ?? "";

        // Collect SANs from the altnames field (format: "DNS:example.com, DNS:...").
        const sanRaw: string = (cert.subjectaltname as string | undefined) ?? "";
        const san = sanRaw
          .split(",")
          .map((s: string) => s.replace(/^DNS:/, "").trim())
          .filter(Boolean);

        const issuer = (cert.issuer as Record<string, string> | undefined)
          ? Object.entries(cert.issuer as Record<string, string>)
              .map(([k, v]) => `${k}=${v}`)
              .join(", ")
          : "unknown";

        let summary: string;
        if (daysRemaining < 0) {
          summary = `CRITICAL: Certificate for ${host} EXPIRED ${Math.abs(daysRemaining)} day(s) ago (${cert.valid_to}).`;
        } else if (daysRemaining <= 14) {
          summary = `WARNING: Certificate for ${host} expires in ${daysRemaining} day(s) — renew immediately.`;
        } else if (daysRemaining <= 30) {
          summary = `NOTICE: Certificate for ${host} expires in ${daysRemaining} day(s) — plan renewal soon.`;
        } else {
          summary = `Certificate for ${host} is valid for ${daysRemaining} more day(s) (expires ${cert.valid_to}).`;
        }

        resolve({
          host,
          port,
          tls_reachable: true,
          common_name: cn,
          san,
          issuer,
          valid_from: validFrom.toISOString(),
          valid_to:   validTo.toISOString(),
          days_remaining: daysRemaining,
          fingerprint: (cert as unknown as Record<string, string>).fingerprint256 ?? cert.fingerprint,
          summary,
        });
      }
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      resolve({
        host,
        port,
        tls_reachable: false,
        summary: `TLS connection to ${host}:${port} timed out after ${timeoutMs} ms.`,
      });
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      resolve({
        host,
        port,
        tls_reachable: false,
        error_code: err.code ?? "UNKNOWN",
        summary: `TLS connection to ${host}:${port} failed — ${err.message}`,
      });
    });
  });
}

module.exports = { checkTlsCertificate };
