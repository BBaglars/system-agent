import toolRegistryModule = require("../tools/toolRegistry");

import type { ToolRegistration } from "../tools/toolRegistry";

const { toolCatalog } = toolRegistryModule as {
  toolCatalog: ToolRegistration[];
};

// Splits input into lowercase tokens for keyword matching.
// Punctuation is stripped so "185.199.109.133," matches "ip"-related keywords.
function tokenize(input: string): Set<string> {
  return new Set(
    input
      .toLowerCase()
      .replace(/[^a-z0-9.\s]/g, " ")
      .split(/\s+/)
      .filter(Boolean)
  );
}

// Returns the subset of registered tools that are relevant for a given input.
// Matching strategy: if any token in the input equals or contains a registered keyword,
// the tool is included. Falls back to all isDefault tools when nothing matches.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getToolsForContext(input: string): any[] {
  const tokens = tokenize(input);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const matched: any[] = [];

  for (const registration of toolCatalog) {
    const isMatch = registration.triggerKeywords.some(
      (keyword) =>
        tokens.has(keyword) ||
        // Substring match handles compound tokens such as "ip_address" or "daddr".
        [...tokens].some((token) => token.includes(keyword))
    );

    if (isMatch) {
      matched.push(registration.tool);
    }
  }

  if (matched.length > 0) {
    return matched;
  }

  // No keyword matched — return default tools so the agent is never tool-less.
  return toolCatalog
    .filter((registration) => registration.isDefault)
    .map((registration) => registration.tool);
}

module.exports = { getToolsForContext };
