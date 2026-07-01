import supervisorModule = require("./core/supervisor");

const { runDiagnostic } = supervisorModule as {
  runDiagnostic: (userInput: string) => Promise<string>;
};

const MEMORY_ENDPOINT = "http://localhost:3000/memory";

async function fetchMemorySnapshot(): Promise<string> {
  const response = await fetch(MEMORY_ENDPOINT, { method: "GET" });

  if (!response.ok) {
    throw new Error(`Memory endpoint returned HTTP ${response.status}`);
  }

  const snapshotData = await response.json();
  return JSON.stringify(snapshotData);
}

async function runWatcherCycle(): Promise<void> {
  console.log("[ WATCHER ] Fetching latest memory snapshot...");

  try {
    const memorySnapshotJSON = await fetchMemorySnapshot();

    // Parse the snapshot to check for actual events before invoking the supervisor.
    const snapshot = JSON.parse(memorySnapshotJSON) as unknown[];
    if (!Array.isArray(snapshot) || snapshot.length === 0) {
      console.log("No new network activity detected. Skipping AI analysis.");
      return;
    }

    // Build the diagnostic prompt and route through the supervisor.
    const userPrompt = `
Analyze the following network telemetry snapshot.
Explain suspicious behaviors and why they are suspicious.
If behavior appears benign, explicitly say so and justify it.

JSON Snapshot:
${memorySnapshotJSON}
`;

    const reportText = await runDiagnostic(userPrompt);

    console.log("\n[ AGENT REPORT ]");
    console.log("=".repeat(70));
    console.log(reportText);
    console.log("=".repeat(70));
  } catch (error) {
    // Keep the watcher alive even if the endpoint or supervisor is temporarily unavailable.
    console.warn("[ WATCHER ] Cycle failed:", error);
  }
}

function startWatcher(intervalMs: number): void {
  // Trigger one immediate cycle so operators can verify the watcher quickly.
  void runWatcherCycle();

  setInterval(() => {
    void runWatcherCycle();
  }, intervalMs);
}

startWatcher(30000);
