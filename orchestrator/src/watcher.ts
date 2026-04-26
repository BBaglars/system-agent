import agentModule = require("./agent");

const { analyzeNetworkTraffic } = agentModule as {
  analyzeNetworkTraffic: (memorySnapshotJSON: string) => Promise<void>;
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
    await analyzeNetworkTraffic(memorySnapshotJSON);
  } catch (error) {
    // Keep the watcher alive even if the debug endpoint is temporarily unavailable.
    console.warn("[ WATCHER ] Memory endpoint is unavailable:", error);
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
