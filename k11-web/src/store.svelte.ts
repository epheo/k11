import type {
  AgentSummary,
  AgentDetail,
  PolicySnapshot,
} from "./gen/k11_pb.ts";
import type { ParsedEvent } from "./rawlog.ts";
import { MAX_EVENTS } from "./constants.ts";

/**
 * Central reactive state. Kept here because `$state` requires a `.svelte.ts` file.
 *
 * Direct mutators for UI-only concerns live alongside. RPC-driven mutations live
 * in `api.ts` and `stream.ts` — they import `store` and assign to it.
 */
export interface Store {
  // server data
  agents: AgentSummary[];
  detail: AgentDetail | null;
  /** Version of `detail`; sent back so an unchanged tree costs no payload. */
  detailVersion: bigint;
  /** Parsed once on arrival; the raw log renders these directly. */
  events: ParsedEvent[];
  policy: PolicySnapshot | null;

  // selection
  selectedPid: number | null;

  // connection
  connected: boolean;
  reconnectAttempts: number;

  // UI preferences (client-side only)
  rawCollapsed: boolean;
  rawPidFilter: number | null;
  dismissedPids: Set<number>;
}

export const store = $state<Store>({
  agents: [],
  detail: null,
  detailVersion: 0n,
  events: [],
  policy: null,
  selectedPid: null,
  connected: false,
  reconnectAttempts: 0,
  rawCollapsed: true,
  rawPidFilter: null,
  dismissedPids: new Set(),
});

// ---------------------------------------------------------------------------
// UI-only mutators (no side effects beyond the store)
// ---------------------------------------------------------------------------

/** Append in place; `$state` arrays are deeply reactive, so no copy per event. */
export function pushEvent(e: ParsedEvent) {
  store.events.push(e);
  const overflow = store.events.length - MAX_EVENTS;
  if (overflow > 0) store.events.splice(0, overflow);
}

export function dismissAgent(rootPid: number) {
  const s = new Set(store.dismissedPids);
  s.add(rootPid);
  store.dismissedPids = s;
  if (store.selectedPid === rootPid) {
    store.selectedPid = null;
    store.detail = null;
    store.detailVersion = 0n;
    store.events = [];
  }
}

export function undismissAll() {
  store.dismissedPids = new Set();
}

export function toggleRawCollapsed() {
  store.rawCollapsed = !store.rawCollapsed;
}

export function setRawPidFilter(pid: number | null) {
  store.rawPidFilter = store.rawPidFilter === pid ? null : pid;
}
