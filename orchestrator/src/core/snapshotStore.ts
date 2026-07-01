import cryptoModule = require("node:crypto");

// Mirrors the TcpEvent shape produced by the eBPF sensor and stored in ipcServer.
export interface TcpEvent {
  pid: number;
  comm: string;
  daddr: number;
  dport: number;
  ip_address?: string;
}

export interface Snapshot {
  readonly id: string;
  readonly events: readonly TcpEvent[];
  readonly createdAt: Date;
  readonly totalCount: number;
}

// All filter fields are genuinely optional — the caller may omit any combination.
export interface SnapshotFilter {
  comm?: string;
  ip_address?: string;
  dport?: number;
  limit?: number;
}

const SNAPSHOT_TTL_MS = 30 * 60 * 1000;   // 30 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // sweep every 5 minutes

const store = new Map<string, Snapshot>();

// Periodically remove snapshots that have exceeded their TTL.
// unref() ensures this interval does not prevent the process from exiting cleanly.
const cleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [id, snapshot] of store.entries()) {
    if (now - snapshot.createdAt.getTime() > SNAPSHOT_TTL_MS) {
      store.delete(id);
      console.log(`[ SNAPSHOT STORE ] Evicted expired snapshot ${id}`);
    }
  }
}, CLEANUP_INTERVAL_MS);

cleanupTimer.unref();

// Freezes the current state of the network memory into an immutable snapshot.
// Returns the unique session ID that callers must pass to retrieve or filter the data.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function createSnapshot(events: any[]): string {
  const id = cryptoModule.randomUUID();
  const snapshot: Snapshot = {
    id,
    events: events as TcpEvent[],
    createdAt: new Date(),
    totalCount: events.length,
  };

  store.set(id, snapshot);
  console.log(`[ SNAPSHOT STORE ] Created snapshot ${id} with ${events.length} events.`);
  return id;
}

function getSnapshot(sessionId: string): Snapshot | undefined {
  return store.get(sessionId);
}

// Returns a filtered, size-bounded slice of events from a snapshot.
// The LLM uses this to perform lazy, targeted data retrieval instead of
// receiving the entire 1000-event buffer in the context window.
function filterEvents(sessionId: string, filters: SnapshotFilter): TcpEvent[] {
  const snapshot = store.get(sessionId);

  if (!snapshot) {
    return [];
  }

  const limit = filters.limit !== undefined && filters.limit > 0 ? filters.limit : 15;
  const results: TcpEvent[] = [];

  for (const event of snapshot.events) {
    if (results.length >= limit) {
      break;
    }

    // Apply comm filter: case-insensitive substring match.
    if (filters.comm !== undefined) {
      if (!event.comm.toLowerCase().includes(filters.comm.toLowerCase())) {
        continue;
      }
    }

    // Apply ip_address filter: exact prefix match allows CIDR-style narrowing.
    if (filters.ip_address !== undefined) {
      const eventIp = event.ip_address ?? "";
      if (!eventIp.startsWith(filters.ip_address)) {
        continue;
      }
    }

    // Apply dport filter: exact numeric match.
    if (filters.dport !== undefined) {
      if (event.dport !== filters.dport) {
        continue;
      }
    }

    results.push(event);
  }

  return results;
}

function getSessionCount(): number {
  return store.size;
}

module.exports = { createSnapshot, getSnapshot, filterEvents, getSessionCount };
