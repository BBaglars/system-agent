import ollamaModule = require("@langchain/ollama");
import promptsModule = require("@langchain/core/prompts");
import classicAgentsModule = require("@langchain/classic/agents");
import semanticRouterModule = require("./semanticRouter");

const { ChatOllama } = ollamaModule;
const { ChatPromptTemplate, MessagesPlaceholder } = promptsModule;
const { AgentExecutor, createToolCallingAgent } = classicAgentsModule;

const { getToolsForContext } = semanticRouterModule as {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getToolsForContext: (input: string) => any[];
};

const SYSTEM_PROMPT = `
You are a strictly read-only network security observer.
You DO NOT have any system execution permissions.
Your only responsibility is to analyze provided JSON network telemetry and produce a professional risk report.

KNOWN BENIGN WHITELIST:
- Processes: cursor, node, ollama, Chrome_ChildIOT
- Internal safe ports: 11434 (Ollama API), 3000 (Local Memory API)

CRITICAL RULES (YOU MUST OBEY THESE STRICTLY):
1. NO HALLUCINATION: Only use the tools explicitly provided to you. NEVER invent or call non-existent tools like 'analyze_network_telemetry'.
2. IP FORMATTING: When sending an IP address to a tool, you MUST use the human-readable 'ip_address' field (e.g., "8.8.8.8") from the JSON. NEVER use the decimal 'daddr' field.
3. OUTPUT FORMAT: Always output your final report in clean, readable Markdown. NEVER output raw JSON or internal function call formats as your final response.
4. EXTERNAL IPs: If you see an external public IP address not in the whitelist, you MUST use the analyze_external_ip tool to investigate it. Incorporate the ISP and Country into your final report to justify if it is Benign or Suspicious.
`;

// A single shared ChatOllama instance; tool binding is applied per-invocation.
const chatModel = new ChatOllama({
  model: "llama3.1",
  temperature: 0.1,
});

// The prompt template is stateless and can be shared across invocations.
// {input} carries the user query; {agent_scratchpad} holds the ReAct reasoning trace.
const agentPrompt = ChatPromptTemplate.fromMessages([
  ["system", SYSTEM_PROMPT],
  ["human", "{input}"],
  new MessagesPlaceholder("agent_scratchpad"),
]);

// Runs a full ReAct diagnostic cycle for the given input.
// The tool set is resolved dynamically on every call via the semantic router,
// so adding new tools to the registry immediately affects all future invocations.
async function runDiagnostic(userInput: string): Promise<string> {
  // Route the input through the semantic router to select only relevant tools.
  const contextualTools = getToolsForContext(userInput);

  console.log(
    `[ SUPERVISOR ] Selected ${contextualTools.length} tool(s) for this context.`
  );

  // Bind the selected tools to a fresh model instance for this invocation.
  const modelWithTools = chatModel.bindTools(contextualTools);

  const agent = createToolCallingAgent({
    llm: modelWithTools,
    tools: contextualTools,
    prompt: agentPrompt,
  });

  const agentExecutor = new AgentExecutor({
    agent,
    tools: contextualTools,
    // Cap the reasoning loop to prevent runaway tool calls on adversarial inputs.
    maxIterations: 5,
  });

  const response = await agentExecutor.invoke({ input: userInput });

  return typeof response["output"] === "string"
    ? response["output"]
    : JSON.stringify(response["output"], null, 2);
}

module.exports = { runDiagnostic };
