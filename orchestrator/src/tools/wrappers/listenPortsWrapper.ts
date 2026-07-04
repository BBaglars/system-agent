import toolsModule = require("@langchain/core/tools");
import zodModule = require("zod");
import listListeningPortsSkill = require("../../../../skills/listListeningPorts");

import type { ListeningPortsResult } from "../../../../skills/listListeningPorts";

const { tool } = toolsModule;
const { z } = zodModule;

const { listListeningPorts } = listListeningPortsSkill as {
  listListeningPorts: (targetPort?: number) => Promise<ListeningPortsResult>;
};

// Cast tool() to any to bypass exactOptionalPropertyTypes/Zod version mismatch.
// Runtime behaviour is unaffected; only this call site relaxes the strict type-check.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const listListeningPortsTool = (tool as any)(
  async (input: { target_port?: number }): Promise<string> => {
    const result = await listListeningPorts(input.target_port);
    // Return the full JSON so the Reporter LLM has both the structured data
    // and the pre-computed summary to incorporate into its answer.
    return JSON.stringify(result, null, 2);
  },
  {
    name: "list_listening_ports",
    description:
      "Use this tool to retrieve the list of TCP ports currently in LISTEN state on " +
      "this system — i.e., ports that have an active process waiting for connections. " +
      "Call this tool when the user asks: which ports are open, whether a specific " +
      "service is running, whether port X is in use, or if a process is accepting " +
      "connections. " +
      "Supply 'target_port' to check a single specific port (e.g. 3000, 6379, 8080); " +
      "omit it to get the full list of all listening ports. " +
      "The tool reads the live system state via 'ss -tlnp' — it reflects the current " +
      "moment, not historical eBPF data.",
    schema: z.object({
      target_port: z
        .number()
        .int()
        .min(1)
        .max(65535)
        .optional()
        .describe(
          "Optional: the specific port number to check (1–65535). " +
          "Omit to retrieve all listening ports."
        ),
    }),
  }
);

// Trigger keywords tell the semantic router when to activate this tool.
const triggerKeywords: readonly string[] = [
  // English
  "port", "listening", "listen", "open", "service",
  "running", "active", "bound", "socket", "daemon",
  "server", "process", "3000", "8080", "443", "80",
  // Turkish — port / service availability intent
  "açık", "dinleyen", "dinliyor", "servis", "çalışıyor",
  "ayakta", "ayakta mı", "çalışıyor mu", "hangi port",
  "port var mı", "bağlantı bekliyor", "başlatıldı mı",
];

module.exports = { listListeningPortsTool, triggerKeywords };
