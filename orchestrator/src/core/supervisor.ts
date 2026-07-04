import ollamaModule = require("@langchain/ollama");
import messagesModule = require("@langchain/core/messages");
import dnsModule = require("node:dns");
import semanticRouterModule = require("./semanticRouter");
import snapshotStoreModule = require("./snapshotStore");
import lookupIpInfoSkill = require("../../../skills/lookupIpInfo");
import listListeningPortsSkill = require("../../../skills/listListeningPorts");
import probeLocalPortSkill = require("../../../skills/probeLocalPort");
import resolveDnsHealthSkill = require("../../../skills/resolveDnsHealth");

import type { ListeningPortsResult } from "../../../skills/listListeningPorts";
import type { ProbeLocalPortResult } from "../../../skills/probeLocalPort";
import type { DnsHealthResult } from "../../../skills/resolveDnsHealth";

const dns = dnsModule.promises;

const { ChatOllama } = ollamaModule;
const { HumanMessage, SystemMessage, AIMessage } = messagesModule;

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

const { listListeningPorts } = listListeningPortsSkill as {
  listListeningPorts: (targetPort?: number) => Promise<ListeningPortsResult>;
};

const { probeLocalPort } = probeLocalPortSkill as {
  probeLocalPort: (port: number, host?: string, timeoutMs?: number) => Promise<ProbeLocalPortResult>;
};

const { resolveDnsHealth } = resolveDnsHealthSkill as {
  resolveDnsHealth: (domain: string) => Promise<DnsHealthResult>;
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
5. "target_port": include ONLY when tool is list_listening_ports AND the user names a specific port number to check. Omit if they ask for all ports.
6. "port": required when tool is probe_local_port. "host": include ONLY if the user mentions a non-localhost address; otherwise omit (defaults to 127.0.0.1).
7. "domain": required when tool is resolve_dns_health. Strip any http:// or https:// prefix and include only the bare domain.

CLASSIFICATION:
- Conversational, greeting, or off-topic → {}
- Network traffic inspection needed → {"tool":"fetch_snapshot_data", ...only known fields..., "limit":15}
- A specific IP address must be looked up → {"tool":"analyze_external_ip","ip_address":"<the ip>"}
- User asks which ports are open OR whether a specific port/service is listening → {"tool":"list_listening_ports"} or {"tool":"list_listening_ports","target_port":<number>}
- User says they CANNOT CONNECT to a specific port/service (connection refused, no response) → {"tool":"probe_local_port","port":<number>}
- User says a website or domain is not loading, DNS error, or domain cannot be resolved → {"tool":"resolve_dns_health","domain":"<bare domain>"}

EXAMPLES:
- "YouTube'a giremiyorum" → {"tool":"fetch_snapshot_data","dport":443,"limit":15}
- "Chrome trafiğini kontrol et" → {"tool":"fetch_snapshot_data","comm":"chrome","dport":443,"limit":15}
- "curl ile bir sorun var" → {"tool":"fetch_snapshot_data","comm":"curl","limit":15}
- "185.199.109.133 şüpheli mi?" → {"tool":"analyze_external_ip","ip_address":"185.199.109.133"}
- "Hangi portlar açık?" → {"tool":"list_listening_ports"}
- "3000 portu dinleniyor mu?" → {"tool":"list_listening_ports","target_port":3000}
- "Redis çalışıyor mu?" → {"tool":"list_listening_ports","target_port":6379}
- "8080'de bir şey var mı?" → {"tool":"list_listening_ports","target_port":8080}
- "3000 portuna bağlanamıyorum" → {"tool":"probe_local_port","port":3000}
- "Postgres'e erişemiyorum" → {"tool":"probe_local_port","port":5432}
- "localhost:8080 yanıt vermiyor" → {"tool":"probe_local_port","port":8080}
- "192.168.1.10:22 açık mı?" → {"tool":"probe_local_port","port":22,"host":"192.168.1.10"}
- "google.com açılmıyor" → {"tool":"resolve_dns_health","domain":"google.com"}
- "api.example.com'a ulaşamıyorum" → {"tool":"resolve_dns_health","domain":"api.example.com"}
- "DNS sorunum var gibi" → {"tool":"resolve_dns_health","domain":"google.com"}
- "Nasılsın?" → {}`;

const REPORTER_PROMPT = `You are a network diagnostics and security analyst.
Known safe processes: cursor, node, ollama, Chrome_ChildIOT.
Known safe ports: 11434, 3000.
Analyze the provided data and respond with a clean Markdown report.
If no data was retrieved, state that no matching events were found.

CRITICAL LANGUAGE RULE: You MUST write your entire final report in the EXACT SAME LANGUAGE as the user's original question.
- If the user asked in Turkish, every part of your response — including headers, summaries, and conclusions — must be in Turkish.
- If the user asked in English, respond entirely in English.
- The raw tool data (JSON, logs) will be in English. Translate and synthesise the key findings into the user's language; do NOT reproduce raw JSON in your final output.`;

const CHAT_PROMPT = `You are a helpful AI assistant with network and system diagnostics expertise.
Answer conversationally and honestly. If you do not know something, say so.

CRITICAL LANGUAGE RULE: Always respond in the EXACT SAME LANGUAGE the user used to write their question.
If the user wrote in Turkish, answer entirely in Turkish. If in English, answer in English.`;

// ── Types ──────────────────────────────────────────────────────────────────────

interface ExtractorResult {
  tool?:
    | "fetch_snapshot_data"
    | "analyze_external_ip"
    | "list_listening_ports"
    | "probe_local_port"
    | "resolve_dns_health"
    | null;
  // fetch_snapshot_data params
  comm?: string;
  ip_address?: string;
  dport?: number;
  limit?: number;
  // list_listening_ports param
  target_port?: number;
  // probe_local_port params
  port?: number;
  host?: string;
  timeout_ms?: number;
  // resolve_dns_health param
  domain?: string;
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

  if (toolCall.tool === "list_listening_ports") {
    // target_port is optional: undefined means "return all listening ports".
    const result = await listListeningPorts(toolCall.target_port);
    return JSON.stringify(result, null, 2);
  }

  if (toolCall.tool === "probe_local_port" && toolCall.port !== undefined) {
    const result = await probeLocalPort(
      toolCall.port,
      toolCall.host,
      toolCall.timeout_ms
    );
    return JSON.stringify(result, null, 2);
  }

  if (toolCall.tool === "resolve_dns_health" && toolCall.domain !== undefined) {
    const result = await resolveDnsHealth(toolCall.domain);
    return JSON.stringify(result, null, 2);
  }

  return "";
}

// ── Helper: invoke a model and extract the string content ─────────────────────

// Builds a message array from system + optional history + human prompt,
// then invokes the model and returns plain string content.
// history is only passed for Reporter calls — never for the Extractor.
async function invokeText(
  model: InstanceType<typeof ChatOllama>,
  system: string,
  human: string,
  history: Array<{ role: string; content: string }> = []
): Promise<string> {
  // Convert {role, content} dicts from Python into LangChain message objects.
  // Unknown roles default to AIMessage so no entry is silently dropped.
  // map() avoids the union-narrowing issue flatMap() causes with TS strict mode.
  const historyMessages = history.map((msg) =>
    msg.role === "user"
      ? new HumanMessage(msg.content)
      : new AIMessage(msg.content)
  );

  // Cast to any[] to satisfy LangChain's overloaded invoke() signatures under
  // exactOptionalPropertyTypes — runtime behaviour is identical.
  const response = await model.invoke([
    new SystemMessage(system),
    ...historyMessages,
    new HumanMessage(human),
  ] as any[]); // eslint-disable-line @typescript-eslint/no-explicit-any

  return typeof response.content === "string"
    ? response.content
    : JSON.stringify(response.content, null, 2);
}

// ── Main pipeline ──────────────────────────────────────────────────────────────

// runDiagnostic orchestrates the 3-stage deterministic pipeline:
//   Stage 1 — Extractor LLM (format:json, userInput only — history deliberately excluded)
//   Stage 2 — Node.js Executor (deterministic, no LLM)
//   Stage 3 — Reporter LLM (userInput + toolData + history for conversational context)
async function runDiagnostic(
  userInput: string,
  sessionId: string,
  history: Array<{ role: string; content: string }> = []
): Promise<string> {
  // ── Pre-flight: keyword check avoids the extractor call for pure chat ──────
  const needsTools = getToolsForContext(userInput).length > 0;

  if (!needsTools) {
    console.log("[ SUPERVISOR ] Route: CHAT (no network keywords matched)");
    // Pass history so the model remembers previous turns in the conversation.
    return invokeText(reporterModel, CHAT_PROMPT, userInput, history);
  }

  // ── Stage 1: Extractor ─────────────────────────────────────────────────────
  // History is intentionally NOT passed here: the extractor uses format:"json"
  // and must classify only the current intent.  Injecting history tokens
  // destabilises the constrained-sampling output and causes parse failures.
  console.log("[ SUPERVISOR ] Route: NETWORK — running extractor...");

  const rawJson = await invokeText(extractorModel, EXTRACTOR_PROMPT, userInput);

  let toolCall: ExtractorResult = {};
  try {
    toolCall = JSON.parse(rawJson) as ExtractorResult;
  } catch (err) {
    // Malformed JSON from extractor — fall back to conversational response.
    console.warn("[ SUPERVISOR ] Extractor JSON parse failed:", err);
    return invokeText(reporterModel, CHAT_PROMPT, userInput, history);
  }

  if (!toolCall.tool) {
    // Extractor decided no tool is needed (returned {}).
    console.log("[ SUPERVISOR ] Extractor returned no tool — falling back to chat.");
    return invokeText(reporterModel, CHAT_PROMPT, userInput, history);
  }

  console.log(`[ SUPERVISOR ] Extractor decided: ${JSON.stringify(toolCall)}`);

  // ── Stage 2: Node.js Executor ──────────────────────────────────────────────
  const toolData = await executeToolCall(toolCall, sessionId);
  console.log(`[ SUPERVISOR ] Executor retrieved ${toolData.length} chars of data.`);

  // ── Stage 3: Reporter ──────────────────────────────────────────────────────
  // history is passed here so the Reporter can synthesise answers that
  // reference previous turns ("Önceki sorumda ne demiştim?" etc.).
  const reporterInput =
    `User question: "${userInput}"\n\nNetwork data retrieved:\n${toolData}`;

  return invokeText(reporterModel, REPORTER_PROMPT, reporterInput, history);
}

module.exports = { runDiagnostic };
