import net = require("node:net");
import fs = require("node:fs");
import http = require("node:http");
import snapshotStoreModule = require("./core/snapshotStore");
import supervisorModule = require("./core/supervisor");

const { createSnapshot } = snapshotStoreModule as {
  createSnapshot: (events: object[]) => string;
};

const { runDiagnostic } = supervisorModule as {
  runDiagnostic: (
    userInput: string,
    sessionId: string,
    history?: Array<{ role: string; content: string }>
  ) => Promise<string>;
};

const SOCKET_PATH = "/tmp/system_agent.sock";
const HTTP_PORT = 3000;

// Converts a uint32 IPv4 address from eBPF into a standard X.X.X.X string format.
// Uses bitwise operations to extract octets based on Network Byte Order.
function intToIPv4(ipInt: number): string {
  if (!ipInt || ipInt < 0) return "0.0.0.0";

  const octet1 = ipInt & 0xff;
  const octet2 = (ipInt >>> 8) & 0xff;
  const octet3 = (ipInt >>> 16) & 0xff;
  const octet4 = (ipInt >>> 24) & 0xff;

  return `${octet1}.${octet2}.${octet3}.${octet4}`;
}
type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

// Represents the incoming TCP connection event from the eBPF sensor
interface TcpEvent {
  pid: number;
  comm: string;
  daddr: number;
  dport: number;
  tcp_state?: number;  // 1=TCP_ESTABLISHED, 7=TCP_CLOSE (connection refused/reset)
  ip_address?: string;
}

class NetworkMemory {
  private static readonly MAX_EVENTS = 1000;
  private readonly events: Array<TcpEvent | undefined> = new Array<TcpEvent | undefined>(NetworkMemory.MAX_EVENTS);
  private writeIndex = 0;
  private size = 0;
  private totalAdded = 0;

  addEvent(event: TcpEvent): void {
    // Overwrite the oldest slot when the fixed-size buffer reaches capacity.
    this.events[this.writeIndex] = event;
    this.writeIndex = (this.writeIndex + 1) % NetworkMemory.MAX_EVENTS;
    this.size = Math.min(this.size + 1, NetworkMemory.MAX_EVENTS);
    this.totalAdded += 1;

    // Emit periodic health logs to prove memory ingestion is happening.
    if (this.totalAdded % 100 === 0) {
      console.log(`Network memory capacity: ${this.size}/${NetworkMemory.MAX_EVENTS}`);
    }
  }

  getRecentEvents(): TcpEvent[] {
    // Return events from oldest to newest so downstream consumers get chronological data.
    const recentEvents: TcpEvent[] = [];
    const startIndex = this.size === NetworkMemory.MAX_EVENTS ? this.writeIndex : 0;

    for (let offset = 0; offset < this.size; offset += 1) {
      const index = (startIndex + offset) % NetworkMemory.MAX_EVENTS;
      const event = this.events[index];
      if (event) {
        recentEvents.push(event);
      }
    }

    return recentEvents;
  }
}

const memory = new NetworkMemory();

async function removeStaleSocketFile(socketPath: string): Promise<void> {
  try {
    await fs.promises.stat(socketPath);
  } catch (error) {
    const fsError = error as NodeJS.ErrnoException;
    if (fsError.code === "ENOENT") {
      return;
    }
    throw error;
  }

  // We probe the existing socket to distinguish a dead file from a live server.
  const socketIsActive = await new Promise<boolean>((resolve) => {
    const probeClient = new net.Socket();

    probeClient.once("connect", () => {
      probeClient.destroy();
      resolve(true);
    });

    probeClient.once("error", (error: NodeJS.ErrnoException) => {
      // ECONNREFUSED/ENOENT mean no live owner exists for this path anymore.
      if (error.code === "ECONNREFUSED" || error.code === "ENOENT") {
        resolve(false);
        return;
      }

      // Unknown connection errors are treated as active to avoid deleting valid sockets.
      resolve(true);
    });

    probeClient.connect(socketPath);
  });

  if (!socketIsActive) {
    await fs.promises.unlink(socketPath);
  }
}

function handleIncomingBuffer(rawBuffer: string): JsonValue | null {
  try {
    return JSON.parse(rawBuffer) as JsonValue;
  } catch (error) {
    console.error("Invalid JSON payload received:", error);
    return null;
  }
}

function registerClientHandlers(client: net.Socket): void {
  let bufferedChunk = "";

  client.on("data", (chunk: Buffer) => {
    // UDS is a byte stream, so we buffer and parse line-delimited JSON messages safely.
    bufferedChunk += chunk.toString("utf8");
    const frames = bufferedChunk.split("\n");
    bufferedChunk = frames.pop() ?? "";

    for (const frame of frames) {
      const payload = frame.trim();
      if (!payload) {
        continue;
      }

      const parsedData = handleIncomingBuffer(payload);
      if (parsedData !== null) {
        // Assume the parsed JSON represents our eBPF tcp_event structure
        const event = parsedData as unknown as TcpEvent;

        // If the payload contains a destination address, format and log it cleanly
        if (event && event.daddr !== undefined) {
           const humanReadableIP = intToIPv4(event.daddr);
           const eventWithIP: TcpEvent = { ...event, ip_address: humanReadableIP };
           memory.addEvent(eventWithIP);

           // Translate numeric tcp_state into a human-readable outcome label.
           const stateLabel =
             event.tcp_state === 1 ? "ESTABLISHED" :
             event.tcp_state === 7 ? "CLOSED/REFUSED" :
             event.tcp_state !== undefined ? `STATE(${event.tcp_state})` : "UNKNOWN";

           console.log(
             `[TCP ${stateLabel}] PID: ${event.pid} | App: ${event.comm} | ` +
             `Dest IP: ${humanReadableIP} | Dest Port: ${event.dport}`
           );
        } else {
           // Fallback for generic JSON messages
           console.log("Received JSON message:", parsedData);
        }
      }
    }
  });

  client.on("error", (error) => {
    console.error("Client socket error:", error);
  });

  client.on("close", () => {
    // Connection lifecycle is logged for easier troubleshooting without crashing.
    console.log("Client disconnected.");
  });
}

async function startIpcServer(): Promise<void> {
  try {
    await removeStaleSocketFile(SOCKET_PATH);
  } catch (error) {
    console.error("Failed during stale socket cleanup:", error);
    process.exit(1);
  }

  const server = net.createServer((client) => {
    registerClientHandlers(client);
  });

  server.on("error", (error: NodeJS.ErrnoException) => {
    console.error("IPC server error:", error);
  });

  server.on("listening", () => {
    console.log(`IPC server listening on ${SOCKET_PATH}`);
  });

  // SIGINT/SIGTERM hooks guarantee socket cleanup during controlled shutdowns.
  const shutdown = async (): Promise<void> => {
    server.close(async () => {
      try {
        await fs.promises.unlink(SOCKET_PATH);
      } catch (error) {
        const fsError = error as NodeJS.ErrnoException;
        if (fsError.code !== "ENOENT") {
          console.error("Failed to remove socket during shutdown:", error);
        }
      }
      process.exit(0);
    });
  };

  process.on("SIGINT", () => {
    void shutdown();
  });

  process.on("SIGTERM", () => {
    void shutdown();
  });

  server.listen(SOCKET_PATH);
}

// Reads and JSON-parses the full HTTP request body.
function readRequestBody(request: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];

    request.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
    });

    request.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw.length > 0 ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("Request body is not valid JSON"));
      }
    });

    request.on("error", reject);
  });
}

function startHttpServer(): void {
  const httpServer = http.createServer((request, response) => {

    // GET /memory — raw circular buffer dump for debugging and legacy consumers.
    if (request.url === "/memory" && request.method === "GET") {
      const recentEvents = memory.getRecentEvents();
      const responseBody = JSON.stringify(Array.isArray(recentEvents) ? recentEvents : []);

      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(responseBody);
      return;
    }

    // POST /api/chat — on-demand snapshot analysis entry point.
    if (request.url === "/api/chat" && request.method === "POST") {
      void (async () => {
        try {
          const body = await readRequestBody(request);
          const typedBody =
            body !== null && typeof body === "object" ? (body as Record<string, unknown>) : {};

          const question =
            typeof typedBody["question"] === "string"
              ? typedBody["question"].trim()
              : "";

          if (!question) {
            response.writeHead(400, { "Content-Type": "application/json" });
            response.end(JSON.stringify({ error: "Missing or empty 'question' field." }));
            return;
          }

          // Extract conversation history forwarded by the Python client.
          // Validated to be an array of {role, content} objects; malformed entries
          // are silently dropped so a bad payload never crashes the pipeline.
          type HistoryEntry = { role: string; content: string };
          const rawHistory = Array.isArray(typedBody["history"]) ? typedBody["history"] : [];
          const history: HistoryEntry[] = (rawHistory as unknown[]).reduce<HistoryEntry[]>(
            (acc, item) => {
              if (
                item !== null &&
                typeof item === "object" &&
                typeof (item as Record<string, unknown>)["role"] === "string" &&
                typeof (item as Record<string, unknown>)["content"] === "string"
              ) {
                acc.push(item as HistoryEntry);
              }
              return acc;
            },
            []
          );

          // Freeze the current network state into an immutable, addressable snapshot.
          const events = memory.getRecentEvents();
          const sessionId = createSnapshot(events);

          console.log(
            `[ API ] Chat request received. question="${question}" session=${sessionId} events=${events.length} history=${history.length}`
          );

          const report = await runDiagnostic(question, sessionId, history);

          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ report }));
        } catch (error) {
          console.error("[ API ] POST /api/chat failed:", error);
          response.writeHead(500, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: "Internal server error. Check server logs." }));
        }
      })();
      return;
    }

    response.writeHead(404, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ error: "Not Found" }));
  });

  httpServer.on("error", (error) => {
    console.error("HTTP server error:", error);
  });

  httpServer.listen(HTTP_PORT, () => {
    console.log(`HTTP debug server listening on http://localhost:${HTTP_PORT}`);
  });
}

startHttpServer();
void startIpcServer();
