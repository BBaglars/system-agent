import toolsModule = require("@langchain/core/tools");
import zodModule = require("zod");
import probeLocalPortSkill = require("../../../../skills/probeLocalPort");

import type { ProbeLocalPortResult } from "../../../../skills/probeLocalPort";

const { tool } = toolsModule;
const { z } = zodModule;

const { probeLocalPort } = probeLocalPortSkill as {
  probeLocalPort: (port: number, host?: string, timeoutMs?: number) => Promise<ProbeLocalPortResult>;
};

// Cast tool() to any to bypass exactOptionalPropertyTypes/Zod version mismatch.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const probeLocalPortTool = (tool as any)(
  async (input: { port: number; host?: string; timeout_ms?: number }): Promise<string> => {
    const result = await probeLocalPort(
      input.port,
      input.host ?? "127.0.0.1",
      input.timeout_ms ?? 3000
    );
    return JSON.stringify(result, null, 2);
  },
  {
    name: "probe_local_port",
    description:
      "Use this tool to actively test whether a specific TCP port is reachable on the local " +
      "machine or a given host. It attempts a real TCP connection and returns one of: " +
      "OPEN (a process is listening and accepted the connection), " +
      "REFUSED (port is closed — nothing is listening), or " +
      "TIMEOUT (host is unreachable or port is firewalled). " +
      "Call this tool when the user says they cannot connect to a local service, " +
      "when a specific port is mentioned (e.g. 3000, 5432, 6379, 8080), " +
      "or when you need to verify whether a service is actually running. " +
      "Unlike 'list_listening_ports' which reads the OS port table, this tool performs " +
      "an active network probe and reflects the true reachability of the port.",
    schema: z.object({
      port: z
        .number()
        .int()
        .min(1)
        .max(65535)
        .describe("The TCP port number to probe (1–65535)."),
      host: z
        .string()
        .optional()
        .describe(
          "Hostname or IP address to probe. Defaults to '127.0.0.1' (localhost). " +
          "Use this for LAN addresses such as '192.168.1.10'."
        ),
      timeout_ms: z
        .number()
        .int()
        .min(100)
        .max(10000)
        .optional()
        .describe("Connection timeout in milliseconds. Defaults to 3000 (3 s)."),
    }),
  }
);

// Trigger keywords activate this tool in the semantic router.
const triggerKeywords: readonly string[] = [
  // English
  "connect", "connection", "refused", "timeout", "reachable",
  "probe", "test", "ping", "check", "unreachable",
  // Turkish — connectivity failure intent
  "bağlanamıyorum", "erişim yok", "erişemiyorum", "test et",
  "yanıt vermiyor", "açık mı", "ulaşamıyorum", "red ediyor",
  "bağlantı reddedildi", "zaman aşımı",
];

module.exports = { probeLocalPortTool, triggerKeywords };
