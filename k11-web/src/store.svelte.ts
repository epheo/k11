import type {
  AgentSummary,
  ConnectionAccess,
  FileAccess,
  PolicySnapshot,
  ProcessInfo,
  UnixSocketAccess,
} from "./gen/k11_pb.ts";
import type { ParsedEvent } from "./rawlog.ts";

/** One agent tree as the views show it: the server's deltas merged. */
export interface Detail {
  summary: AgentSummary;
  processes: ProcessInfo[];
  files: FileAccess[];
  connections: ConnectionAccess[];
  binds: ConnectionAccess[];
  unixSockets: UnixSocketAccess[];
}

/**
 * Central reactive state. Server data is `$state.raw`: replaced whole, never
 * deep-proxied, so thousands of rows cost one signal each refresh.
 * `sync.ts` writes server data; the setters below are UI-only.
 */
class Store {
  agents = $state.raw<AgentSummary[]>([]);
  detail = $state.raw<Detail | null>(null);
  events = $state.raw<ParsedEvent[]>([]);
  policy = $state.raw<PolicySnapshot | null>(null);

  selectedPid = $state<number | null>(null);
  connected = $state(false);
  failures = $state(0);
  /** Last failed action, shown until dismissed. */
  error = $state<string | null>(null);
  /** Ticks every second so relative times stay current. */
  now = $state(Date.now());

  rawCollapsed = $state(true);
  rawPidFilter = $state<number | null>(null);
  dismissed = $state.raw<ReadonlySet<number>>(new Set());
}

export const store = new Store();

export function dismissAgent(rootPid: number) {
  store.dismissed = new Set([...store.dismissed, rootPid]);
}

export function restoreDismissed() {
  store.dismissed = new Set();
}

export function toggleRawCollapsed() {
  store.rawCollapsed = !store.rawCollapsed;
}

/** Filter the raw log to one process, and show it. */
export function setRawPidFilter(pid: number | null) {
  store.rawPidFilter = store.rawPidFilter === pid ? null : pid;
  if (store.rawPidFilter !== null) store.rawCollapsed = false;
}
