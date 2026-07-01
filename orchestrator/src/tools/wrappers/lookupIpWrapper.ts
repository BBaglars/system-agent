import toolsModule = require("@langchain/core/tools");
import zodModule = require("zod");
import lookupIpInfoSkill = require("../../../../skills/lookupIpInfo");

const { tool } = toolsModule;
const { z } = zodModule;

const { lookupIpInfo } = lookupIpInfoSkill as {
  lookupIpInfo: (ip: string) => Promise<string>;
};

// Cast tool() to any to bypass exactOptionalPropertyTypes/Zod version mismatch with @langchain/classic.
// Runtime behaviour is unaffected; only this call site relaxes the strict type-check.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const analyzeExternalIpTool = (tool as any)(
  async (input: { ip: string }): Promise<string> => lookupIpInfo(input.ip),
  {
    name: "analyze_external_ip",
    description:
      "Use this tool to determine the geolocation, ISP, and owning organization of any " +
      "external public IP address observed in network telemetry. " +
      "Call this tool BEFORE classifying an unfamiliar IP as Benign or Suspicious. " +
      "The tool queries ip-api.com and returns the country, ISP, and organization, " +
      "which must be incorporated into the final risk report to justify the classification decision.",
    // z.string().ip() ensures the model cannot pass malformed addresses to the external API.
    schema: z.object({
      ip: z.string().ip({ message: "Must be a valid IPv4 or IPv6 address" }).describe(
        "The external public IP address to investigate"
      ),
    }),
  }
);

// Trigger keywords tell the semantic router when to activate this tool.
// Extend this list as new network telemetry patterns are discovered.
const triggerKeywords: readonly string[] = [
  "ip", "external", "public", "network", "address",
  "remote", "internet", "outbound", "destination", "daddr",
  "isp", "geolocation", "country", "org",
];

module.exports = { analyzeExternalIpTool, triggerKeywords };
