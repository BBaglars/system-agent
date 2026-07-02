import toolsModule = require("@langchain/core/tools");
import zodModule = require("zod");
import snapshotStoreModule = require("../../core/snapshotStore");

import type { SnapshotFilter } from "../../core/snapshotStore";

const { tool } = toolsModule;
const { z } = zodModule;

const { filterEvents } = snapshotStoreModule as {
  filterEvents: (sessionId: string, filters: SnapshotFilter) => object[];
};

// Cast tool() to any to bypass exactOptionalPropertyTypes/Zod version mismatch with @langchain/classic.
// Runtime behaviour is unaffected; only this call site relaxes the strict type-check.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fetchSnapshotDataTool = (tool as any)(
  async (input: {
    session_id: string;
    comm?: string;
    ip_address?: string;
    dport?: number;
    limit?: number;
  }): Promise<string> => {
    const { session_id, comm, ip_address, dport, limit } = input;

    // Build the filter object from only the fields the model provided.
    const filters: SnapshotFilter = {};
    if (comm !== undefined) filters.comm = comm;
    if (ip_address !== undefined) filters.ip_address = ip_address;
    if (dport !== undefined) filters.dport = dport;
    if (limit !== undefined) filters.limit = limit;

    const events = filterEvents(session_id, filters);

    if (events.length === 0) {
      return `No events found in snapshot ${session_id} matching the provided filters.`;
    }

    // Return a compact JSON string so the LLM can reason over the results inline.
    return JSON.stringify(events, null, 2);
  },
  {
    name: "fetch_snapshot_data",
    description:
      "Use this tool to retrieve filtered network telemetry events from a frozen session snapshot. " +
      "You MUST call this tool whenever the user's question relates to network activity and you have been " +
      "given a SESSION_ID. DO NOT attempt to answer network questions without first fetching the data. " +
      "Apply as many filters as possible (comm, ip_address, dport) to keep results focused. " +
      "The 'limit' parameter controls how many rows are returned (default 15, max recommended 20). " +
      "Example: to inspect Chrome traffic, set comm='Chrome'. " +
      "To examine a specific port, set dport=443. " +
      "You may call this tool multiple times with different filters to build a complete picture.",
    schema: z.object({
      session_id: z
        .string()
        .describe("The session ID returned when the snapshot was created. Format: UUID."),
      comm: z
        .string()
        .optional()
        .describe("Filter by process name (case-insensitive substring match). Example: 'Chrome', 'curl'."),
      ip_address: z
        .string()
        .optional()
        .describe("Filter by destination IP address prefix. Example: '8.8' matches 8.8.8.8 and 8.8.4.4."),
      dport: z
        .number()
        .int()
        .min(1)
        .max(65535)
        .optional()
        .describe("Filter by exact destination port number. Example: 443 for HTTPS."),
      limit: z
        .number()
        .int()
        .min(1)
        .max(50)
        .optional()
        .describe("Maximum number of events to return. Defaults to 15. Keep this low to preserve context window."),
    }),
  }
);

// Trigger keywords activate this tool in the semantic router when matched against user input.
const triggerKeywords: readonly string[] = [
  // English
  "session", "snapshot", "filter", "data", "traffic",
  "show", "list", "fetch", "get", "events",
  "connections", "packets", "activity", "history",
  "network", "port", "security", "analyze", "check",
  // Turkish — network / traffic analysis intent
  "ağ", "paket", "trafik", "bağlan", "bağlantı",
  "giriş", "port", "kontrol", "analiz", "hata",
  "internet", "sorun", "çalışmıyor", "erişim",
  "izle", "gözlemle", "denetle", "tarama",
  "güvenlik", "listele", "göster", "süreç",
  "uygulama", "program", "sunucu", "bağlanamıyorum",
  "giremiyorum", "açılmıyor", "yavaş", "engel",
];

module.exports = { fetchSnapshotDataTool, triggerKeywords };
