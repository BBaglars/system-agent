// Thin facade over the supervisor's deterministic pipeline.
// External callers that need the raw report string should import runDiagnostic
// from core/supervisor.ts directly.

import supervisorModule = require("./core/supervisor");
import snapshotStoreModule = require("./core/snapshotStore");

const { runDiagnostic } = supervisorModule as {
  runDiagnostic: (userInput: string, sessionId: string) => Promise<string>;
};

const { createSnapshot } = snapshotStoreModule as {
  createSnapshot: (events: object[]) => string;
};

// analyzeNetworkTraffic is kept for backwards compatibility.
// It creates an ephemeral snapshot from a pre-serialised JSON blob and
// delegates to the supervisor pipeline, logging the report to the console.
async function analyzeNetworkTraffic(memorySnapshotJSON: string): Promise<void> {
  const events = JSON.parse(memorySnapshotJSON) as object[];
  const sessionId = createSnapshot(events);

  try {
    const reportText = await runDiagnostic(
      "Analyze the current network activity for anything suspicious.",
      sessionId
    );

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
//     { pid: 31337, comm: "malware_loader", daddr: 2248381829, dport: 443, ip_address: "185.199.109.133" },
//   ])
// );
