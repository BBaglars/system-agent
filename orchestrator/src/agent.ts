// This module is a thin facade over the supervisor.
// All LangChain/ReAct logic lives in core/supervisor.ts.
// External callers (watcher, HTTP handlers, tests) should prefer importing
// runDiagnostic from supervisor directly when they need the raw report string.

import supervisorModule = require("./core/supervisor");

const { runDiagnostic } = supervisorModule as {
  runDiagnostic: (userInput: string) => Promise<string>;
};

// analyzeNetworkTraffic is kept for backwards compatibility with existing callers.
// It builds the diagnostic prompt, delegates to supervisor, and formats the console output.
async function analyzeNetworkTraffic(memorySnapshotJSON: string): Promise<void> {
  const userPrompt = `
Analyze the following network telemetry snapshot.
Explain suspicious behaviors and why they are suspicious.
If behavior appears benign, explicitly say so and justify it.

JSON Snapshot:
${memorySnapshotJSON}
`;

  try {
    const reportText = await runDiagnostic(userPrompt);

    console.log("\n[ AGENT REPORT ]");
    console.log("=".repeat(70));
    console.log(reportText);
    console.log("=".repeat(70));
  } catch (error) {
    console.error("[ AGENT REPORT ] Failed to analyze network telemetry:", error);
  }
}

module.exports = { analyzeNetworkTraffic };

// Manual test invocation for local debugging.
// analyzeNetworkTraffic(
//   JSON.stringify([
//     { pid: 31337, comm: "malware_loader", daddr: 2248381829, dport: 443, ip: "185.199.109.133" },
//   ])
// );
