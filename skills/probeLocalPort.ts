// Framework-free skill. The LangChain wrapper lives in probePortWrapper.ts.

import netModule = require("node:net");

// ── Types ─────────────────────────────────────────────────────────────────────

export type ProbeStatus = "OPEN" | "REFUSED" | "TIMEOUT" | "ERROR";

export interface ProbeLocalPortResult {
  host: string;
  port: number;
  status: ProbeStatus;
  // Round-trip time from connect() attempt to resolution, in milliseconds.
  latency_ms: number;
  // Populated on ERROR (not REFUSED/TIMEOUT) with the OS error code.
  error_code?: string;
  // Human-readable verdict ready for the Reporter LLM.
  summary: string;
}

// ── Core skill function ───────────────────────────────────────────────────────

// Attempts a TCP connection to host:port and resolves with a structured result.
// Never rejects — all error paths are captured as status fields so the caller
// (executeToolCall) can always safely JSON.stringify the return value.
async function probeLocalPort(
  port: number,
  host = "127.0.0.1",
  timeoutMs = 3000
): Promise<ProbeLocalPortResult> {
  const start = Date.now();

  return new Promise((resolve) => {
    const socket = new netModule.Socket();

    const finish = (status: ProbeStatus, errorCode?: string): void => {
      socket.destroy();
      const latency_ms = Date.now() - start;

      const summaryMap: Record<ProbeStatus, string> = {
        OPEN:    `Port ${port} on ${host} is OPEN — a process is actively listening.`,
        REFUSED: `Port ${port} on ${host} is CLOSED — connection refused (no listener).`,
        TIMEOUT: `Port ${port} on ${host} timed out after ${timeoutMs} ms — host may be unreachable or port filtered.`,
        ERROR:   `Probe failed for ${host}:${port} — OS error: ${errorCode ?? "unknown"}.`,
      };

      resolve({
        host,
        port,
        status,
        latency_ms,
        ...(errorCode !== undefined ? { error_code: errorCode } : {}),
        summary: summaryMap[status],
      });
    };

    socket.setTimeout(timeoutMs);

    socket.connect(port, host, () => finish("OPEN"));

    socket.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ECONNREFUSED") {
        finish("REFUSED");
      } else {
        finish("ERROR", err.code ?? "UNKNOWN");
      }
    });

    socket.on("timeout", () => finish("TIMEOUT"));
  });
}

module.exports = { probeLocalPort };
