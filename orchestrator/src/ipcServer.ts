import net = require("node:net");
import fs = require("node:fs");

const SOCKET_PATH = "/tmp/system_agent.sock";

type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

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
        console.log("Received JSON message:", parsedData);
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

void startIpcServer();
