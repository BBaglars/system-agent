// Skills live at the project root so they stay free of framework-specific imports.
// The LangChain tool() wrapper is applied in listenPortsWrapper.ts.

import childProcessModule = require("node:child_process");
import utilModule = require("node:util");

const execAsync = utilModule.promisify(childProcessModule.exec);

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ListeningPort {
  port: number;
  local_address: string;  // "0.0.0.0" means all interfaces, "127.0.0.1" means loopback-only
  process_name: string;   // extracted from ss -p output; "unknown" when not available
}

export interface ListeningPortsResult {
  ports: ListeningPort[];
  total: number;
  // If target_port was requested, this is non-null and carries the single match or null.
  target_match: ListeningPort | null;
  // Human-readable summary line for the Reporter LLM.
  summary: string;
}

// ── Parser ────────────────────────────────────────────────────────────────────

// Parses a single output line from either `ss -tlnp` or `netstat -tlnp`.
// Both tools emit lines in roughly the form:
//   tcp  LISTEN  0  128  0.0.0.0:3000  0.0.0.0:*  users:(("node",pid=1234,fd=18))
// or (netstat):
//   tcp  0  0  0.0.0.0:3000  0.0.0.0:*  LISTEN  1234/node
function parseLine(line: string): ListeningPort | null {
  // Normalise whitespace
  const parts = line.trim().split(/\s+/);
  if (parts.length < 5) return null;

  // Both ss and netstat put the local address:port as the 4th column (index 3 or 4).
  // We scan all parts for the "address:port" pattern to stay tool-agnostic.
  let localCol = "";
  for (const part of parts) {
    if (/^[\d.*:[\]]+:\d+$/.test(part)) {
      localCol = part;
      break;
    }
  }
  if (!localCol) return null;

  const colonIdx = localCol.lastIndexOf(":");
  const rawPort  = parseInt(localCol.slice(colonIdx + 1), 10);
  if (isNaN(rawPort) || rawPort < 1 || rawPort > 65535) return null;

  const localAddr = localCol.slice(0, colonIdx) || "0.0.0.0";

  // Extract process name from ss's users:(("name",…)) notation.
  const ssMatch = line.match(/users:\(\("([^"]+)"/);
  if (ssMatch) {
    return { port: rawPort, local_address: localAddr, process_name: ssMatch[1] ?? "unknown" };
  }

  // Extract process name from netstat's  pid/name  notation.
  const netstatMatch = line.match(/\d+\/(\S+)/);
  if (netstatMatch) {
    return { port: rawPort, local_address: localAddr, process_name: netstatMatch[1] ?? "unknown" };
  }

  return { port: rawPort, local_address: localAddr, process_name: "unknown" };
}

// ── Core skill function ───────────────────────────────────────────────────────

// Returns all TCP ports in the LISTEN state, optionally filtered by target_port.
// Uses `ss` (modern iproute2 tool) with `netstat` as a fallback for older systems.
async function listListeningPorts(targetPort?: number): Promise<ListeningPortsResult> {
  let stdout = "";

  try {
    // -t TCP only  -l LISTEN only  -n numeric ports  -p process info
    const result = await execAsync("ss -tlnp", { timeout: 5000 });
    stdout = result.stdout;
  } catch {
    // ss not available — try netstat (net-tools package)
    try {
      const result = await execAsync("netstat -tlnp 2>/dev/null", { timeout: 5000 });
      stdout = result.stdout;
    } catch (fallbackErr) {
      return {
        ports: [],
        total: 0,
        target_match: null,
        summary: `Failed to retrieve listening ports: ${String(fallbackErr)}`,
      };
    }
  }

  const ports: ListeningPort[] = [];

  for (const line of stdout.split("\n")) {
    // Skip header lines (they contain "Local" or "State" but no port numbers)
    if (!line.trim() || /^\s*(Netid|State|tcp)/i.test(line)) {
      const parsed = parseLine(line);
      // Only add if it isn't a pure header match
      if (parsed && !isNaN(parsed.port)) ports.push(parsed);
      continue;
    }
    const parsed = parseLine(line);
    if (parsed) ports.push(parsed);
  }

  // Deduplicate by port number (same port may appear on multiple addresses)
  const seen = new Set<number>();
  const unique = ports.filter((p) => {
    if (seen.has(p.port)) return false;
    seen.add(p.port);
    return true;
  });

  // Sort ascending so low-numbered well-known ports appear first
  unique.sort((a, b) => a.port - b.port);

  const target = targetPort !== undefined
    ? (unique.find((p) => p.port === targetPort) ?? null)
    : null;

  const summary =
    targetPort !== undefined
      ? target
        ? `Port ${targetPort} is OPEN — listened on ${target.local_address} by "${target.process_name}".`
        : `Port ${targetPort} is NOT listening on this system.`
      : `${unique.length} TCP port(s) currently in LISTEN state: ${unique.map((p) => p.port).join(", ")}.`;

  return {
    ports: unique,
    total: unique.length,
    target_match: target,
    summary,
  };
}

module.exports = { listListeningPorts };
