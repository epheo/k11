import type {
  AgentSummary,
  AgentDetail,
  PolicySnapshot,
  Event,
} from "./gen/k11_pb.ts";

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
  events: Event[];
  policy: PolicySnapshot | null;
  sensitivePaths: string[];

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
  events: [],
  policy: null,
  sensitivePaths: [],
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

export function dismissAgent(rootPid: number) {
  const s = new Set(store.dismissedPids);
  s.add(rootPid);
  store.dismissedPids = s;
  if (store.selectedPid === rootPid) {
    store.selectedPid = null;
    store.detail = null;
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
