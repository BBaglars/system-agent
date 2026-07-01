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

// Minimal prompt deliberately avoids imperative tool-call instructions.
// Explicit "you MUST call tool X" phrasing causes Llama 3.1 to verbalize tool
// invocations as text instead of emitting native tool-call tokens, which breaks
// the LangChain ReAct chain. The model selects tools naturally when it needs data.
const SYSTEM_PROMPT = `You are a network security analyst.
Known safe processes: cursor, node, ollama, Chrome_ChildIOT.
Known safe ports: 11434, 3000.
Use your available tools when you need network data or IP information.
Respond only with a clean Markdown security report.`;

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
    // When the model emits malformed tool output (e.g. verbalizes JSON instead of calling
    // the tool natively), LangChain intercepts the parse error and sends an automatic
    // correction message back to the model so the loop can recover without crashing.
    handleParsingErrors: true,
  });

  const response = await agentExecutor.invoke({ input: userInput });

  return typeof response["output"] === "string"
    ? response["output"]
    : JSON.stringify(response["output"], null, 2);
}

module.exports = { runDiagnostic };
