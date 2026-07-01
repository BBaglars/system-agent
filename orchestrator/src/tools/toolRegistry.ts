import lookupIpWrapperModule = require("./wrappers/lookupIpWrapper");

const { analyzeExternalIpTool, triggerKeywords: ipKeywords } = lookupIpWrapperModule as {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  analyzeExternalIpTool: any;
  triggerKeywords: readonly string[];
};

// ToolRegistration ties a LangChain tool to the semantic metadata the router needs.
// When adding a new skill, register it here — no other file needs to change.
export interface ToolRegistration {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly tool: any;
  readonly name: string;
  // Keywords that signal this tool is relevant for a given input.
  readonly triggerKeywords: readonly string[];
  // isDefault=true means the tool is always included when no keyword matches.
  readonly isDefault: boolean;
}

// Central catalogue of every available agent tool.
// Future entries follow the same shape: { tool, name, triggerKeywords, isDefault }.
const toolCatalog: ToolRegistration[] = [
  {
    tool: analyzeExternalIpTool,
    name: "analyze_external_ip",
    triggerKeywords: ipKeywords,
    isDefault: true,
  },
];

// Flat array of tools kept for backwards-compatible consumers.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const agentTools: any[] = toolCatalog.map((entry) => entry.tool);

module.exports = { agentTools, toolCatalog };
