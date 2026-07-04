import toolsModule = require("@langchain/core/tools");
import zodModule = require("zod");
import resolveDnsHealthSkill = require("../../../../skills/resolveDnsHealth");

import type { DnsHealthResult } from "../../../../skills/resolveDnsHealth";

const { tool } = toolsModule;
const { z } = zodModule;

const { resolveDnsHealth } = resolveDnsHealthSkill as {
  resolveDnsHealth: (domain: string) => Promise<DnsHealthResult>;
};

// Cast tool() to any to bypass exactOptionalPropertyTypes/Zod version mismatch.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const resolveDnsHealthTool = (tool as any)(
  async (input: { domain: string }): Promise<string> => {
    const result = await resolveDnsHealth(input.domain);
    return JSON.stringify(result, null, 2);
  },
  {
    name: "resolve_dns_health",
    description:
      "Use this tool to test the DNS resolution health of a domain name. " +
      "It queries both A (IPv4) and AAAA (IPv6) records using the system's configured " +
      "DNS resolvers and returns a structured result including the resolved IP addresses, " +
      "any error codes (ENOTFOUND, ETIMEOUT, ENODATA), and the system resolver addresses. " +
      "Call this tool when the user says a website or domain is not loading, " +
      "when they suspect a DNS issue, or when a domain-based connection is failing " +
      "but an IP-based connection works. " +
      "Do NOT call this for IP address lookups — use 'analyze_external_ip' for those.",
    schema: z.object({
      domain: z
        .string()
        .min(1)
        .describe(
          "The domain name to resolve. Can be a bare domain (e.g. 'google.com') " +
          "or a URL — the protocol prefix will be stripped automatically."
        ),
    }),
  }
);

// Trigger keywords activate this tool in the semantic router.
const triggerKeywords: readonly string[] = [
  // English
  "dns", "domain", "resolve", "resolution", "hostname",
  "nslookup", "lookup", "nameserver", "record",
  // Turkish — DNS / domain resolution intent
  "açılmıyor", "çözümleyemiyor", "domain", "alan adı",
  "siteye giremiyorum", "site yüklenmiyor", "dns sorunu",
  "isim çözümleme", "sunucu bulunamadı", "not found",
];

module.exports = { resolveDnsHealthTool, triggerKeywords };
