import toolsModule = require("@langchain/core/tools");
import zodModule = require("zod");
import tracerouteSkill = require("../../../../skills/tracerouteAnalysis");

import type { TracerouteResult } from "../../../../skills/tracerouteAnalysis";

const { tool } = toolsModule;
const { z } = zodModule;

const { tracerouteAnalysis } = tracerouteSkill as {
  tracerouteAnalysis: (
    target: string,
    maxHops?: number
  ) => Promise<TracerouteResult>;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const tracerouteAnalysisTool = (tool as any)(
  async (input: { target: string; max_hops?: number }): Promise<string> => {
    const result = await tracerouteAnalysis(input.target, input.max_hops ?? 20);
    return JSON.stringify(result, null, 2);
  },
  {
    name: "traceroute_analysis",
    description:
      "Use this tool to trace the network path (route) to a remote host and identify " +
      "where latency spikes or packet loss occur along the way. " +
      "It runs 'traceroute -n -q 1 -w 2' and returns a structured list of hops with: " +
      "hop number, IP address, RTT in milliseconds, and whether the hop was silent (no response / filtered). " +
      "Also returns: total hop count, max RTT, whether the target was reached, and a plain-language summary. " +
      "Call this tool when: the user says 'packets are slow', 'connection times out halfway', " +
      "'I want to see the route to X', 'traceroute to Y', or when you need to diagnose " +
      "where exactly in the network path a problem is occurring. " +
      "Do NOT use for local port probing — use probe_local_port for that.",
    schema: z.object({
      target: z
        .string()
        .describe(
          "Hostname or IP address to trace the route to. Do NOT include URL scheme. " +
          "Examples: 'github.com', '8.8.8.8', 'api.example.com'."
        ),
      max_hops: z
        .number()
        .int()
        .min(5)
        .max(30)
        .optional()
        .describe("Maximum number of hops to trace. Defaults to 20."),
    }),
  }
);

const triggerKeywords: readonly string[] = [
  // English
  "traceroute", "tracepath", "route", "routing", "hop", "hops",
  "packet loss", "latency", "path", "network path", "bottleneck",
  "where is the packet", "slow network", "high rtt",
  // Turkish
  "rota", "ağ rotası", "yönlendirme", "paket kaybı", "gecikme",
  "nereden geçiyor", "ağ yolu", "hop sayısı", "paket nerede",
  "traceroute yap", "yavaş bağlantı", "hangi noktada",
];

module.exports = { tracerouteAnalysisTool, triggerKeywords };
