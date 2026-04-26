import ollamaModule = require("@langchain/ollama");
const { ChatOllama } = ollamaModule;

import messagesModule = require("@langchain/core/messages");
const { HumanMessage, SystemMessage } = messagesModule;

const SYSTEM_PROMPT = `
You are a strictly read-only network security observer.
You DO NOT have any system execution permissions.
You CANNOT run shell commands, write files, open sockets, or modify infrastructure.
You MUST NEVER suggest that you took any external action.
Your only responsibility is to analyze provided JSON network telemetry and produce a professional risk report.
For every suspicious indicator, explain WHY it is suspicious, what evidence in the JSON supports it, and what confidence level applies.
Use concise, factual, and auditable language suitable for incident response teams.

KNOWN BENIGN WHITELIST:
- Processes: cursor, node, ollama, Chrome_ChildIOT
- Internal safe ports: 11434 (Ollama API), 3000 (Local Memory API)

Classification rule:
- If an event matches any whitelisted process or safe internal port above, classify it as Benign.
- Do not label whitelisted entities as Suspicious.
- Focus suspicion analysis on non-whitelisted anomalies only.
`;

const chatModel = new ChatOllama({
  model: "llama3",
  temperature: 0.1,
});

async function analyzeNetworkTraffic(memorySnapshotJSON: string): Promise<void> {
  const userPrompt = `
Analyze the following network telemetry snapshot.
Explain suspicious behaviors and why they are suspicious.
If behavior appears benign, explicitly say so and justify it.

JSON Snapshot:
${memorySnapshotJSON}
`;

  try {
    const response = await chatModel.invoke([
      new SystemMessage(SYSTEM_PROMPT),
      new HumanMessage(userPrompt),
    ]);

    const reportText = typeof response.content === "string"
      ? response.content
      : JSON.stringify(response.content, null, 2);

    console.log("\n[ AGENT REPORT ]");
    console.log("=".repeat(70));
    console.log(reportText);
    console.log("=".repeat(70));
  } catch (error) {
    console.error("[ AGENT REPORT ] Failed to analyze network telemetry:", error);
  }
}

// Export for compatibility with CommonJS module settings.
module.exports = { analyzeNetworkTraffic };

// Manual test invocation for local debugging.
analyzeNetworkTraffic(
  JSON.stringify([
    { pid: 31337, comm: "malware_loader", daddr: 2248381829, dport: 443, ip: "185.199.109.133" },
  ])
);