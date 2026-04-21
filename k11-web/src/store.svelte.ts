import type {
  AgentDetail,
  AgentSummary,
  Event,
  PolicySnapshot,
} from "./gen/k11_pb.ts";
import { RAW_LOG_CAP } from "./constants.ts";

/// Reactive global store using Svelte 5 runes. Modules import `store` and
/// mutate fields directly; components subscribe via $derived / $effect.
export const store = $state({
  agents: [] as AgentSummary[],
  detail: null as AgentDetail | null,
  events: [] as Event[],
  policy: null as PolicySnapshot | null,
  sensitivePaths: [] as string[],
  selectedPid: null as number | null,
  rawPidFilter: null as number | null,
  rawCollapsed: false,
  rawLog: [] as Event[],
  streamConnected: false,
  error: null as string | null,
  hostname: "localhost",
});

/// Append an event to the bounded raw-log ring buffer. Drops oldest when full.
export function pushRawLog(event: Event) {
  store.rawLog.push(event);
  if (store.rawLog.length > RAW_LOG_CAP) {
    store.rawLog.splice(0, store.rawLog.length - RAW_LOG_CAP);
  }
}
