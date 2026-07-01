import ollamaModule = require("@langchain/ollama");
import messagesModule = require("@langchain/core/messages");
import promptsModule = require("@langchain/core/prompts");
import toolsModule = require("@langchain/core/tools");
import zodModule = require("zod");
import classicAgentsModule = require("@langchain/classic/agents");

// Import the pure IP-lookup function from the project-root skills folder.
import lookupIpInfoSkill = require("../../skills/lookupIpInfo");

const { ChatOllama } = ollamaModule;
const { HumanMessage } = messagesModule;
const { ChatPromptTemplate, MessagesPlaceholder } = promptsModule;
const { tool } = toolsModule;
const { z } = zodModule;
const { AgentExecutor, createToolCallingAgent } = classicAgentsModule;

const { lookupIpInfo } = lookupIpInfoSkill as {
  lookupIpInfo: (ip: string) => Promise<string>;
};

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

If you see an external public IP address that is NOT in the whitelist, you MUST use the lookupIpInfo tool to investigate it BEFORE making a final decision. Incorporate the ISP and Country from the tool into your final report to justify if it is Benign or Suspicious.
`;

// Cast tool() to any to bypass exactOptionalPropertyTypes/Zod version mismatch with @langchain/classic.
// The runtime behaviour is unaffected; only the strict type-check is relaxed for this call site.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const lookupIpInfoTool = (tool as any)(
  async (input: { ip: string }): Promise<string> => lookupIpInfo(input.ip),
  {
    name: "lookupIpInfo",
    description:
      "Looks up geolocation and ISP information for a given public IP address using ip-api.com. " +
      "Use this tool when you encounter an unfamiliar external IP to determine its country, ISP, and organization.",
    schema: z.object({
      ip: z.string().describe("The public IPv4 address to investigate"),
    }),
  }
);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const tools: any[] = [lookupIpInfoTool];

const chatModel = new ChatOllama({
  model: "llama3.1",
  temperature: 0.1,
});

// The agent prompt must contain {input} and {agent_scratchpad} placeholders for the ReAct loop.
const agentPrompt = ChatPromptTemplate.fromMessages([
  ["system", SYSTEM_PROMPT],
  ["human", "{input}"],
  new MessagesPlaceholder("agent_scratchpad"),
]);

// bindTools tells the model which tools are available so it can emit tool-call messages.
const modelWithTools = chatModel.bindTools(tools);

const agent = createToolCallingAgent({
  llm: modelWithTools,
  tools,
  prompt: agentPrompt,
});

const agentExecutor = new AgentExecutor({
  agent,
  tools,
  // Cap the reasoning loop to prevent runaway tool calls on adversarial inputs.
  maxIterations: 5,
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
    const response = await agentExecutor.invoke({ input: userPrompt });

    const reportText =
      typeof response["output"] === "string"
        ? response["output"]
        : JSON.stringify(response["output"], null, 2);

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
// analyzeNetworkTraffic(
//   JSON.stringify([
//     { pid: 31337, comm: "malware_loader", daddr: 2248381829, dport: 443, ip: "185.199.109.133" },
//   ])
// );
