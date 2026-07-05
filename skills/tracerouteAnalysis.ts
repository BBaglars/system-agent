// Framework-free skill. The LangChain wrapper lives in tracerouteWrapper.ts.

import cpModule = require("node:child_process");

const { exec } = cpModule;

// ── Types ─────────────────────────────────────────────────────────────────────

export interface TracerouteHop {
  hop:    number;
  ip:     string | null;   // null when all probes timed out ("* * *")
  rtt_ms: number | null;   // null for non-responsive hops
  // True when every probe for this hop returned "*" (no response / filtered).
  no_response: boolean;
}

export interface TracerouteResult {
  target: string;
  hops: TracerouteHop[];
  total_hops: number;
  // Hops where all probes were lost (index of no_response hops in hops array).
  silent_hop_indices: number[];
  // Maximum round-trip latency observed across all responsive hops.
  max_rtt_ms: number | null;
  // Whether the target was reached (last hop matches the target IP or hostname).
  target_reached: boolean;
  // Human-readable verdict for the Reporter LLM.
  summary: string;
  // Populated on OS-level or command-not-found errors.
  error?: string;
}

// ── Parser ────────────────────────────────────────────────────────────────────

// Parses one line of `traceroute -n` output into a structured hop.
// Example lines:
//   " 1  10.0.0.1  0.541 ms"           → hop 1, ip, rtt
//   " 3  * * *"                         → hop 3, no response
//   " 2  172.16.0.1  1.234 ms  2.100 ms  1.800 ms"  → multi-probe, use first rtt
function parseHopLine(line: string): TracerouteHop | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  // Match hop number
  const hopMatch = trimmed.match(/^(\d+)\s+/);
  if (!hopMatch || hopMatch[1] === undefined) return null;
  const hop = parseInt(hopMatch[1], 10);

  // Silent hop: all probes returned "*"
  if (/^\d+\s+\*\s*(\*\s*)*$/.test(trimmed)) {
    return { hop, ip: null, rtt_ms: null, no_response: true };
  }

  // Extract first IP-like token after the hop number
  const rest = trimmed.slice(hopMatch[0].length);
  const ipMatch = rest.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
  const ip: string | null = ipMatch && ipMatch[1] !== undefined ? ipMatch[1] : null;

  // Extract first RTT value in ms
  const rttMatch = rest.match(/(\d+(?:\.\d+)?)\s*ms/);
  const rtt_ms: number | null =
    rttMatch && rttMatch[1] !== undefined ? parseFloat(rttMatch[1]) : null;

  return { hop, ip, rtt_ms, no_response: false };
}

// ── Core skill function ───────────────────────────────────────────────────────

// Runs `traceroute -n -q 1 -w 2 <target>` and parses the output.
// -n  : skip reverse DNS (faster, we enrich separately if needed)
// -q 1: one probe per hop (speed)
// -w 2: 2-second per-hop timeout
// Never rejects — network or command errors are captured in the result.
async function tracerouteAnalysis(
  target: string,
  maxHops = 20
): Promise<TracerouteResult> {
  return new Promise((resolve) => {
    const cmd = `traceroute -n -q 1 -w 2 -m ${maxHops} ${target}`;

    exec(cmd, { timeout: 60_000 }, (err, stdout, stderr) => {
      // Command not found or permission denied
      if (err && !stdout) {
        // Try fallback to tracepath (available without root on some distros)
        const fallbackCmd = `tracepath -n -m ${maxHops} ${target}`;
        exec(fallbackCmd, { timeout: 60_000 }, (err2, stdout2) => {
          if (err2 && !stdout2) {
            resolve({
              target,
              hops: [],
              total_hops: 0,
              silent_hop_indices: [],
              max_rtt_ms: null,
              target_reached: false,
              summary: `Could not run traceroute or tracepath to ${target}: ${err2.message}`,
              error: err2.message,
            });
            return;
          }
          resolve(buildResult(target, stdout2 || ""));
        });
        return;
      }

      resolve(buildResult(target, stdout || ""));
    });
  });
}

function buildResult(target: string, stdout: string): TracerouteResult {
  const lines = stdout.split("\n");
  const hops: TracerouteHop[] = [];

  // First line is the header ("traceroute to ...") — skip it.
  for (const line of lines.slice(1)) {
    const hop = parseHopLine(line);
    if (hop) hops.push(hop);
  }

  const silentIndices = hops
    .map((h, i) => (h.no_response ? i : -1))
    .filter((i) => i !== -1);

  const responsiveRtts = hops
    .map((h) => h.rtt_ms)
    .filter((r): r is number => r !== null);

  const max_rtt_ms = responsiveRtts.length
    ? Math.max(...responsiveRtts)
    : null;

  // Consider the target reached if the last responsive hop's IP matches the
  // resolved address (simple string match, good enough for LLM context).
  const lastHop = hops.filter((h) => !h.no_response).at(-1);
  const target_reached =
    lastHop !== undefined &&
    lastHop.ip !== null &&
    (target.includes(lastHop.ip) || lastHop.hop === hops.length);

  // Build a concise summary
  const silentCount = silentIndices.length;
  let summary: string;

  if (hops.length === 0) {
    summary = `No route data returned for ${target}.`;
  } else if (target_reached) {
    summary =
      `Route to ${target}: ${hops.length} hops, ${silentCount} silent hop(s). ` +
      `Max RTT: ${max_rtt_ms !== null ? max_rtt_ms.toFixed(1) + " ms" : "N/A"}. Target reached.`;
  } else {
    summary =
      `Route to ${target}: ${hops.length} hops traced, target NOT reached. ` +
      `${silentCount} hop(s) dropped all probes. Possible firewall or routing issue.`;
  }

  return {
    target,
    hops,
    total_hops: hops.length,
    silent_hop_indices: silentIndices,
    max_rtt_ms,
    target_reached,
    summary,
  };
}

module.exports = { tracerouteAnalysis };
