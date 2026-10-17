/**
 * EASM WebSocket Mini-Service
 *
 * Accepts scan commands from the web terminal and streams ScanEvents
 * back to the connected client in real time. The actual scanning work
 * is performed by the shared EASM engine under src/lib/easm.
 *
 * ── REFRESH-SAFE ARCHITECTURE ──────────────────────────────────────
 * The scan state is GLOBAL, not per-connection. This means:
 *   1. If the browser refreshes mid-scan, the scan KEEPS RUNNING.
 *   2. All emitted events are buffered in a global event log.
 *   3. When the browser reconnects, it requests the event log + live stream.
 *   4. The client receives all missed events + continues receiving new ones.
 *
 * Protocol (client -> server):
 *   socket.emit("scan:start", { target, options })   — start a new scan
 *   socket.emit("scan:resubscribe")                   — reconnect to ongoing scan
 *
 * Protocol (server -> client):
 *   socket.emit("scan:ready")                         — engine ready
 *   socket.emit("scan:event", ScanEvent)              — a scan event
 *   socket.emit("scan:replay", ScanEvent[])           — missed events on reconnect
 *   socket.emit("scan:status", { scanning, target, events }) — current scan status
 *   socket.emit("scan:complete", { target, results }) — scan finished
 *   socket.emit("scan:error", { message })            — error
 */
import { createServer } from "http";
import { Server } from "socket.io";
import {
  EasmScanner,
  ALL_MODULES,
  DEFAULT_PORTS,
  normalizeTarget,
  defaultConfig,
  type ModuleId,
  type ScanEvent,
} from "../../src/lib/easm";

const httpServer = createServer();
const io = new Server(httpServer, {
  path: "/",
  cors: { origin: "*", methods: ["GET", "POST"] },
  pingTimeout: 120000,
  pingInterval: 25000,
});

interface ScanStartPayload {
  target: string;
  modules?: ModuleId[];
  ports?: number[];
  timeout?: number;
  concurrency?: number;
  enumerateSubdomains?: boolean;
  maxSubdomains?: number;
}

function buildConfig(payload: ScanStartPayload) {
  const config = defaultConfig(payload.target);
  if (payload.modules && payload.modules.length) {
    const valid = payload.modules.filter((m) => ALL_MODULES.includes(m));
    if (valid.length) config.modules = valid;
  } else {
    config.modules = [...ALL_MODULES];
  }
  if (payload.ports && payload.ports.length) config.ports = payload.ports;
  else config.ports = [...DEFAULT_PORTS];
  if (payload.timeout) config.timeout = payload.timeout;
  if (payload.concurrency) config.concurrency = payload.concurrency;
  if (payload.enumerateSubdomains === false) config.enumerateSubdomains = false;
  if (payload.maxSubdomains) config.maxSubdomains = payload.maxSubdomains;
  config.target = normalizeTarget(payload.target);
  return config;
}

// ── GLOBAL SCAN STATE (survives client disconnects) ───────────────────────
// This is the key to refresh-safety: the scan + event buffer live here,
// not inside a socket connection handler.

interface GlobalScanState {
  scanner: EasmScanner | null;
  scanning: boolean;
  target: string | null;
  events: ScanEvent[];       // all events emitted so far (for replay)
  results: any | null;       // final results when scan completes
  summary: any | null;       // final summary
  startedAt: number;
  finishedAt: number | null;
}

const globalScan: GlobalScanState = {
  scanner: null,
  scanning: false,
  target: null,
  events: [],
  results: null,
  summary: null,
  startedAt: 0,
  finishedAt: null,
};

// Track all connected clients so we can broadcast events to everyone
const connectedClients = new Set<any>();

/** Broadcast an event to ALL connected clients. */
function broadcastToAll(event: string, data: any) {
  for (const client of connectedClients) {
    try {
      client.emit(event, data);
    } catch {
      /* client may have disconnected — ignore */
    }
  }
}

/** Start a new scan (or refuse if one is already running). */
function startScan(payload: ScanStartPayload, socket: any): boolean {
  if (globalScan.scanning) {
    socket.emit("scan:error", { message: "A scan is already running. Wait for it to finish or refresh to re-subscribe." });
    return false;
  }
  if (!payload?.target || !payload.target.trim()) {
    socket.emit("scan:error", { message: "No target provided." });
    return false;
  }

  const config = buildConfig(payload);
  const scanner = new EasmScanner(config);

  // Reset global state
  globalScan.scanner = scanner;
  globalScan.scanning = true;
  globalScan.target = config.target;
  globalScan.events = [];
  globalScan.results = null;
  globalScan.summary = null;
  globalScan.startedAt = Date.now();
  globalScan.finishedAt = null;

  // Capture every event into the global buffer + broadcast to all clients
  scanner.on("event", (ev: ScanEvent) => {
    globalScan.events.push(ev);
    broadcastToAll("scan:event", ev);
  });

  // Run the scan — this runs to completion regardless of client disconnects
  scanner
    .run()
    .then((results) => {
      globalScan.results = results;
      globalScan.scanning = false;
      globalScan.finishedAt = Date.now();
      broadcastToAll("scan:complete", {
        target: config.target,
        results,
        summary: globalScan.summary,
      });
      console.log(`[easm-service] scan completed for ${config.target} (${globalScan.events.length} events)`);
    })
    .catch((e: any) => {
      globalScan.scanning = false;
      globalScan.finishedAt = Date.now();
      broadcastToAll("scan:error", { message: e?.message || String(e) });
      console.error(`[easm-service] scan error:`, e?.message || e);
    })
    .finally(() => {
      globalScan.scanner = null;
    });

  return true;
}

io.on("connection", (socket) => {
  console.log(`[easm-service] client connected: ${socket.id}`);
  connectedClients.add(socket);
  socket.emit("scan:ready");

  // ── On reconnect: send current scan status + replay all events ────────
  // This is what makes refresh work: the client immediately knows if a
  // scan is ongoing and receives all events it missed.
  socket.emit("scan:status", {
    scanning: globalScan.scanning,
    target: globalScan.target,
    eventCount: globalScan.events.length,
    startedAt: globalScan.startedAt,
    finishedAt: globalScan.finishedAt,
    hasResults: !!globalScan.results,
  });

  // If there's an ongoing scan OR completed results, replay all events
  if (globalScan.events.length > 0) {
    socket.emit("scan:replay", globalScan.events);
    // If the scan already completed, also send the complete signal
    if (!globalScan.scanning && globalScan.results) {
      socket.emit("scan:complete", {
        target: globalScan.target,
        results: globalScan.results,
        summary: globalScan.summary,
      });
    }
  }

  // ── Handle scan:start ─────────────────────────────────────────────────
  socket.on("scan:start", (payload: ScanStartPayload) => {
    startScan(payload, socket);
  });

  // ── Handle scan:resubscribe (explicit request to rejoin ongoing scan) ─
  socket.on("scan:resubscribe", () => {
    socket.emit("scan:status", {
      scanning: globalScan.scanning,
      target: globalScan.target,
      eventCount: globalScan.events.length,
      startedAt: globalScan.startedAt,
      finishedAt: globalScan.finishedAt,
      hasResults: !!globalScan.results,
    });
    if (globalScan.events.length > 0) {
      socket.emit("scan:replay", globalScan.events);
      if (!globalScan.scanning && globalScan.results) {
        socket.emit("scan:complete", {
          target: globalScan.target,
          results: globalScan.results,
          summary: globalScan.summary,
        });
      }
    }
  });

  socket.on("disconnect", () => {
    connectedClients.delete(socket);
    // NOTE: we do NOT cancel the scan on disconnect.
    // The scan keeps running in the background. The client will reconnect
    // and receive all missed events via scan:replay.
    console.log(`[easm-service] client disconnected: ${socket.id} (scan continues in background)`);
  });

  socket.on("error", (err: any) => {
    console.error(`[easm-service] socket error (${socket.id}):`, err);
  });
});

const PORT = 3004;
httpServer.listen(PORT, () => {
  console.log(`[easm-service] WebSocket server running on port ${PORT} (refresh-safe)`);
});

process.on("SIGTERM", () => httpServer.close(() => process.exit(0)));
process.on("SIGINT", () => httpServer.close(() => process.exit(0)));
