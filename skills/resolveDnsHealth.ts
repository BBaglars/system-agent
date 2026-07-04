// Framework-free skill. The LangChain wrapper lives in dnsHealthWrapper.ts.

import dnsModule = require("node:dns");

const dns = dnsModule.promises;

// ── Types ─────────────────────────────────────────────────────────────────────

export type DnsVerdict = "DNS_OK" | "DNS_FAIL" | "DNS_PARTIAL";

export interface DnsHealthResult {
  domain: string;
  // A records (IPv4) — empty array means the lookup failed.
  a_records: string[];
  a_resolved: boolean;
  a_error?: string;          // e.g. "ENOTFOUND", "ETIMEOUT", "ENODATA"
  // AAAA records (IPv6) — empty array is normal for IPv4-only domains.
  aaaa_records: string[];
  aaaa_resolved: boolean;
  // The DNS resolvers the system is currently configured to use.
  system_resolvers: string[];
  resolution_ms: number;
  // High-level verdict for the Reporter LLM.
  verdict: DnsVerdict;
  summary: string;
}

// ── Core skill function ───────────────────────────────────────────────────────

// Resolves the A and AAAA records for a domain using the system's DNS resolver.
// Never rejects — all failure modes are represented as structured fields.
async function resolveDnsHealth(domain: string): Promise<DnsHealthResult> {
  const start = Date.now();

  // Strip protocol prefix if the user passed a URL instead of a bare domain.
  const cleanDomain = domain
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .trim();

  const result: DnsHealthResult = {
    domain: cleanDomain,
    a_records: [],
    a_resolved: false,
    aaaa_records: [],
    aaaa_resolved: false,
    system_resolvers: dns.getServers(),
    resolution_ms: 0,
    verdict: "DNS_FAIL",
    summary: "",
  };

  // A records (IPv4) — primary health signal.
  try {
    result.a_records  = await dns.resolve4(cleanDomain);
    result.a_resolved = true;
  } catch (err: unknown) {
    result.a_resolved = false;
    result.a_error    = (err as NodeJS.ErrnoException).code ?? "UNKNOWN";
  }

  // AAAA records (IPv6) — informational; failure is not an error.
  try {
    result.aaaa_records  = await dns.resolve6(cleanDomain);
    result.aaaa_resolved = true;
  } catch {
    result.aaaa_resolved = false;
    // Not logged — many domains are IPv4-only and that is expected.
  }

  result.resolution_ms = Date.now() - start;

  // Compute verdict.
  if (result.a_resolved) {
    result.verdict = "DNS_OK";
    result.summary =
      `DNS resolution for "${cleanDomain}" succeeded. ` +
      `A records: ${result.a_records.join(", ")}. ` +
      (result.aaaa_resolved
        ? `AAAA records: ${result.aaaa_records.join(", ")}.`
        : "No AAAA (IPv6) records found.");
  } else {
    result.verdict = "DNS_FAIL";
    result.summary =
      `DNS resolution for "${cleanDomain}" FAILED (${result.a_error ?? "unknown error"}). ` +
      `System resolvers in use: ${result.system_resolvers.join(", ")}. ` +
      `This may indicate an incorrect domain name, a DNS server outage, or a network-level block.`;
  }

  return result;
}

module.exports = { resolveDnsHealth };
