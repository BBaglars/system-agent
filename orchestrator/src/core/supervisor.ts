import ollamaModule = require("@langchain/ollama");
import messagesModule = require("@langchain/core/messages");
import dnsModule = require("node:dns");
import semanticRouterModule = require("./semanticRouter");
import snapshotStoreModule = require("./snapshotStore");
import lookupIpInfoSkill = require("../../../skills/lookupIpInfo");

const dns = dnsModule.promises;

const { ChatOllama } = ollamaModule;
const { HumanMessage, SystemMessage } = messagesModule;

const { getToolsForContext } = semanticRouterModule as {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getToolsForContext: (input: string) => any[];
};

import type { SnapshotFilter } from "./snapshotStore";

const { filterEvents } = snapshotStoreModule as {
  filterEvents: (sessionId: string, filters: SnapshotFilter) => object[];
};

const { lookupIpInfo } = lookupIpInfoSkill as {
  lookupIpInfo: (ip: string) => Promise<string>;
};

// ── Model instances ────────────────────────────────────────────────────────────

// Extractor: format:"json" engages Ollama's constrained token sampling.
// The model is physically incapable of producing non-JSON output in this mode,
// which eliminates the verbalization hallucination entirely.
const extractorModel = new ChatOllama({
  model: "llama3.1",
  temperature: 0,
  format: "json",
});

// Reporter and chat share a single instance; no tool binding, pure text generation.
const reporterModel = new ChatOllama({
  model: "llama3.1",
  temperature: 0.2,
});

// ── Prompts ────────────────────────────────────────────────────────────────────

const EXTRACTOR_PROMPT = `You are a JSON intent classifier. Output ONLY a single JSON object. No text, no markdown, nothing else.

FIELD RULES — follow these exactly:
1. OMIT a field entirely if its value is unknown, empty, or not mentioned. NEVER use "", null, or 0 as placeholder values.
2. "comm": include ONLY if the user names a specific OS process (e.g. "curl", "chrome.exe"). Web sites (YouTube, Google) and generic phrases ("the internet", "my browser") are NOT process names — omit "comm" for them.
3. "dport": include ONLY if the user names a specific port number. Exception: if the user mentions a web site (YouTube, Google, etc.) or says they cannot access a URL / the internet, infer HTTPS and output "dport": 443.
4. "limit": always include as 15 when tool is fetch_snapshot_data.

CLASSIFICATION:
- Conversational, greeting, or off-topic → {}
- Network traffic inspection needed → {"tool":"fetch_snapshot_data", ...only known fields..., "limit":15}
- A specific IP address must be looked up → {"tool":"analyze_external_ip","ip_address":"<the ip>"}

EXAMPLES:
- "YouTube'a giremiyorum" → {"tool":"fetch_snapshot_data","dport":443,"limit":15}
- "Chrome trafiğini kontrol et" → {"tool":"fetch_snapshot_data","comm":"chrome","dport":443,"limit":15}
- "curl ile bir sorun var" → {"tool":"fetch_snapshot_data","comm":"curl","limit":15}
- "185.199.109.133 şüpheli mi?" → {"tool":"analyze_external_ip","ip_address":"185.199.109.133"}
- "Nasılsın?" → {}`;

const REPORTER_PROMPT = `You are a network security analyst.
Known safe processes: cursor, node, ollama, Chrome_ChildIOT.
Known safe ports: 11434, 3000.
Analyze the provided network data and respond with a clean Markdown security report.
If no data was retrieved, state that no matching events were found.`;

const CHAT_PROMPT = `You are a helpful AI assistant with network security expertise.
Answer conversationally and honestly. If you do not know something, say so.`;

// ── Types ──────────────────────────────────────────────────────────────────────

interface ExtractorResult {
  tool?: "fetch_snapshot_data" | "analyze_external_ip" | null;
  comm?: string;
  ip_address?: string;
  dport?: number;
  limit?: number;
}

// Filtered event shape returned by snapshotStore.filterEvents.
interface TcpEventLike {
  ip_address?: string;
  [key: string]: unknown;
}

interface EnrichedEvent extends TcpEventLike {
  resolved_hostname: string;
}

// ── Post-filtering DNS enrichment ─────────────────────────────────────────────

// Performs reverse DNS lookups only on the small filtered batch (≤ 15 events),
// never on the full 1000-event buffer. All lookups run in parallel so total
// latency equals one lookup, not N lookups.
async function enrichWithReverseDns(events: object[]): Promise<EnrichedEvent[]> {
  const typedEvents = events as TcpEventLike[];

  // Collect unique IPs present in this filtered batch.
  const uniqueIps = new Set<string>(
    typedEvents
      .map((e) => e.ip_address)
      .filter((ip): ip is string => typeof ip === "string" && ip.length > 0)
  );

  const dnsCache = new Map<string, string>();

  await Promise.all(
    [...uniqueIps].map(async (ip) => {
      try {
        const hostnames = await dns.reverse(ip);
        dnsCache.set(ip, hostnames[0] ?? ip);
      } catch {
        // ENOTFOUND / private-range / unresolvable — keep the raw IP address.
        dnsCache.set(ip, ip);
      }
    })
  );

  return typedEvents.map((event) => ({
    ...event,
    resolved_hostname:
      event.ip_address !== undefined
        ? (dnsCache.get(event.ip_address) ?? event.ip_address)
        : "unknown",
  }));
}

// ── Deterministic executor (zero LLM) ─────────────────────────────────────────

// Executes the tool call decided by the extractor using Node.js directly.
// No model is involved here — this is the core of the hallucination-free design.
async function executeToolCall(
  toolCall: ExtractorResult,
  sessionId: string
): Promise<string> {
  if (toolCall.tool === "fetch_snapshot_data") {
    const filters: SnapshotFilter = {};
    if (toolCall.comm !== undefined) filters.comm = toolCall.comm;
    if (toolCall.ip_address !== undefined) filters.ip_address = toolCall.ip_address;
    if (toolCall.dport !== undefined) filters.dport = toolCall.dport;
    filters.limit = toolCall.limit ?? 15;

    const events = filterEvents(sessionId, filters);

    if (events.length === 0) {
      return "No matching events found in snapshot for the given filters.";
    }

    // Enrich filtered events with reverse DNS hostnames before handing to the reporter.
    const enrichedEvents = await enrichWithReverseDns(events);
    return JSON.stringify(enrichedEvents, null, 2);
  }

  if (toolCall.tool === "analyze_external_ip" && toolCall.ip_address !== undefined) {
    return await lookupIpInfo(toolCall.ip_address);
  }

  return "";
}

// ── Helper: invoke a model and extract the string content ─────────────────────

async function invokeText(
  model: InstanceType<typeof ChatOllama>,
  system: string,
  human: string
): Promise<string> {
  const response = await model.invoke([
    new SystemMessage(system),
    new HumanMessage(human),
  ]);
  return typeof response.content === "string"
    ? response.content
    : JSON.stringify(response.content, null, 2);
}

// ── Main pipeline ──────────────────────────────────────────────────────────────

// runDiagnostic orchestrates the 3-stage deterministic pipeline:
//   Stage 1 — Extractor LLM (format:json, no tool tokens)
//   Stage 2 — Node.js Executor (deterministic, no LLM)
//   Stage 3 — Reporter LLM (plain text, no tool tokens)
async function runDiagnostic(userInput: string, sessionId: string): Promise<string> {
  // ── Pre-flight: keyword check avoids the extractor call for pure chat ──────
  const needsTools = getToolsForContext(userInput).length > 0;

  if (!needsTools) {
    console.log("[ SUPERVISOR ] Route: CHAT (no network keywords matched)");
    return invokeText(reporterModel, CHAT_PROMPT, userInput);
  }

  // ── Stage 1: Extractor ─────────────────────────────────────────────────────
  console.log("[ SUPERVISOR ] Route: NETWORK — running extractor...");

  const rawJson = await invokeText(extractorModel, EXTRACTOR_PROMPT, userInput);

  let toolCall: ExtractorResult = {};
  try {
    toolCall = JSON.parse(rawJson) as ExtractorResult;
  } catch (err) {
    // Malformed JSON from extractor — fall back to conversational response.
    console.warn("[ SUPERVISOR ] Extractor JSON parse failed:", err);
    return invokeText(reporterModel, CHAT_PROMPT, userInput);
  }

  if (!toolCall.tool) {
    // Extractor decided no tool is needed (returned {}).
    console.log("[ SUPERVISOR ] Extractor returned no tool — falling back to chat.");
    return invokeText(reporterModel, CHAT_PROMPT, userInput);
  }

  console.log(`[ SUPERVISOR ] Extractor decided: ${JSON.stringify(toolCall)}`);

  // ── Stage 2: Node.js Executor ──────────────────────────────────────────────
  const toolData = await executeToolCall(toolCall, sessionId);
  console.log(`[ SUPERVISOR ] Executor retrieved ${toolData.length} chars of data.`);

  // ── Stage 3: Reporter ──────────────────────────────────────────────────────
  const reporterInput =
    `User question: "${userInput}"\n\nNetwork data retrieved:\n${toolData}`;

  return invokeText(reporterModel, REPORTER_PROMPT, reporterInput);
}

module.exports = { runDiagnostic };
