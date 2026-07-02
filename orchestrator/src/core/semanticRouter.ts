import toolRegistryModule = require("../tools/toolRegistry");

import type { ToolRegistration } from "../tools/toolRegistry";

const { toolCatalog } = toolRegistryModule as {
  toolCatalog: ToolRegistration[];
};

// Splits input into lowercase tokens for keyword matching.
// Uses toLocaleLowerCase() for correct Turkish i/İ casing (e.g. "İP" → "ip").
// The Unicode \p{L} class preserves all script letters (Latin, Turkish, etc.)
// while still stripping punctuation, so "bağlan," correctly yields "bağlan".
function tokenize(input: string): Set<string> {
  return new Set(
    input
      .toLocaleLowerCase()
      .replace(/[^\p{L}0-9.\s]/gu, " ")
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

  // Return only the tools that matched. An empty array is intentional:
  // it signals the supervisor that no domain tools are needed, allowing
  // the model to respond conversationally without forcing a security report.
  return matched;
}

module.exports = { getToolsForContext };
