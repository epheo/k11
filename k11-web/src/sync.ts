/**
 * Everything that talks to the daemon. The agent list is polled by version
 * (a quiet store costs nothing); the selected agent gets a filtered event
 * stream for the raw log, and its detail is fetched as deltas, throttled,
 * whenever the stream shows activity.
 */
import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";

import { client } from "./client.ts";
import { store, type Detail } from "./store.svelte.ts";
import { parseRawEvent, type ParsedEvent } from "./rawlog.ts";
import {
  DETAIL_THROTTLE_MS,
  MAX_EVENTS,
  POLL_INTERVAL_MS,
  RECONNECT_DELAY_MS,
} from "./constants.ts";
import { access } from "./format.ts";
import {
  GetAgentDetailRequestSchema,
  GetAgentEventsRequestSchema,
  GetAgentsRequestSchema,
  GetPolicyRequestSchema,
  SetEnforceRequestSchema,
  StreamEventsRequestSchema,
  UpdateDenyRulesRequestSchema,
  type Access,
  type AgentDetail,
  type ConnectionAccess,
  type Event,
  type FileAccess,
  type PolicySnapshot,
  type ProcessInfo,
  type UnixSocketAccess,
} from "./gen/k11_pb.ts";

export function start() {
  loadPolicy();
  pollAgents();
  setInterval(() => (store.now = Date.now()), 1000);
}

// ---------------------------------------------------------------------------
// Agent list
// ---------------------------------------------------------------------------

let agentsVersion = 0n;

async function pollAgents() {
  try {
    const res = await client.getAgents(
      create(GetAgentsRequestSchema, { ifVersionNe: agentsVersion }),
    );
    if (res.version !== agentsVersion) {
      agentsVersion = res.version;
      store.agents = res.agents;
    }
    store.connected = true;
    store.failures = 0;
  } catch {
    store.connected = false;
    store.failures += 1;
  }
  setTimeout(pollAgents, POLL_INTERVAL_MS);
}

// ---------------------------------------------------------------------------
// Selection: raw log stream + detail deltas
// ---------------------------------------------------------------------------

/** Bumped on every selection; work started for an older one is dropped. */
let epoch = 0;
let stream: AbortController | null = null;
let lastSeq = 0n;
let pending: ParsedEvent[] = [];
let flushScheduled = false;
let detailTimer: ReturnType<typeof setTimeout> | null = null;
let detailVersion = 0n;
let merged = emptyMerge();

export async function select(rootPid: number | null) {
  const mine = ++epoch;
  stream?.abort();
  stream = null;
  lastSeq = 0n;
  pending = [];
  detailVersion = 0n;
  merged = emptyMerge();
  store.selectedPid = rootPid;
  store.rawPidFilter = null;
  store.detail = null;
  store.events = [];
  if (rootPid === null) return;

  // Subscribe before the snapshot, buffer, then drop what the snapshot has.
  const early: Event[] = [];
  let live = false;
  openStream(rootPid, mine, (ev) => (live ? receive(ev) : early.push(ev)));
  const [tail] = await Promise.all([
    client
      .getAgentEvents(create(GetAgentEventsRequestSchema, { rootPid, limit: MAX_EVENTS }))
      .catch(() => null),
    refreshDetail(rootPid, mine),
  ]);
  if (mine !== epoch) return;
  tail?.events.forEach(receive);
  early.forEach(receive);
  live = true;
}

async function openStream(rootPid: number, mine: number, onEvent: (ev: Event) => void) {
  const ctrl = new AbortController();
  stream = ctrl;
  try {
    const events = client.streamEvents(create(StreamEventsRequestSchema, { rootPid }), {
      signal: ctrl.signal,
    });
    for await (const ev of events) {
      if (ev.rootPid !== rootPid) continue;
      onEvent(ev);
      scheduleDetail(rootPid, mine);
    }
  } catch {
    // Aborted by a new selection, or the daemon went away.
  }
  if (mine !== epoch || ctrl.signal.aborted) return;
  // Unexpected end: start over, which also catches up on what was missed.
  setTimeout(() => mine === epoch && select(rootPid), RECONNECT_DELAY_MS);
}

function receive(ev: Event) {
  if (ev.seq <= lastSeq) return;
  lastSeq = ev.seq;
  const parsed = parseRawEvent(ev);
  if (!parsed) return;
  pending.push(parsed);
  if (!flushScheduled) {
    flushScheduled = true;
    requestAnimationFrame(flushEvents);
  }
}

/** One array replacement per frame, however many events arrived. */
function flushEvents() {
  flushScheduled = false;
  if (pending.length === 0) return;
  const next = store.events.concat(pending);
  pending = [];
  store.events = next.length > MAX_EVENTS ? next.slice(next.length - MAX_EVENTS) : next;
}

function scheduleDetail(rootPid: number, mine: number) {
  if (detailTimer) return;
  detailTimer = setTimeout(() => {
    detailTimer = null;
    if (mine === epoch) refreshDetail(rootPid, mine);
  }, DETAIL_THROTTLE_MS);
}

async function refreshDetail(rootPid: number, mine: number) {
  try {
    const res = await client.getAgentDetail(
      create(GetAgentDetailRequestSchema, { rootPid, sinceVersion: detailVersion }),
    );
    // A slower, older response must not roll entries back.
    if (mine !== epoch || !res.detail || res.version <= detailVersion) return;
    detailVersion = res.version;
    store.detail = merge(res.detail);
  } catch (e) {
    if (mine === epoch && ConnectError.from(e).code === Code.NotFound) select(null);
  }
}

// ---------------------------------------------------------------------------
// Delta merge: entries replace what is held under the same key.
// ---------------------------------------------------------------------------

function emptyMerge() {
  return {
    processes: new Map<number, ProcessInfo>(),
    files: new Map<string, FileAccess>(),
    connections: new Map<string, ConnectionAccess>(),
    binds: new Map<string, ConnectionAccess>(),
    unixSockets: new Map<string, UnixSocketAccess>(),
  };
}

const peerKey = (c: ConnectionAccess) => `${c.addr} ${c.port}`;
type Counted = { access?: Access };
const byCount = (a: Counted, b: Counted) => access(b).count - access(a).count;
const byRisk = (a: ConnectionAccess, b: ConnectionAccess) =>
  Number(b.external) - Number(a.external) || byCount(a, b);

function merge(d: AgentDetail): Detail {
  for (const p of d.processes) merged.processes.set(p.pid, p);
  for (const f of d.files) merged.files.set(f.path, f);
  for (const c of d.connections) merged.connections.set(peerKey(c), c);
  for (const b of d.binds) merged.binds.set(peerKey(b), b);
  for (const u of d.unixSockets) merged.unixSockets.set(u.path, u);
  return {
    summary: d.summary!,
    processes: [...merged.processes.values()],
    files: [...merged.files.values()],
    connections: [...merged.connections.values()].sort(byRisk),
    binds: [...merged.binds.values()].sort(byRisk),
    unixSockets: [...merged.unixSockets.values()].sort(byCount),
  };
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

async function policy(label: string, call: () => Promise<PolicySnapshot>) {
  try {
    store.policy = await call();
  } catch (e) {
    store.error = `${label}: ${ConnectError.from(e).rawMessage}`;
  }
}

export const loadPolicy = () =>
  policy("policy", () => client.getPolicy(create(GetPolicyRequestSchema, {})));

export const setEnforce = (enforce: boolean) =>
  policy("enforce", () => client.setEnforce(create(SetEnforceRequestSchema, { enforce })));

export const deny = (path: string) =>
  policy("deny", () =>
    client.updateDenyRules(create(UpdateDenyRulesRequestSchema, { addDenyFilePaths: [path] })),
  );

export const undeny = (rule: string) =>
  policy("undeny", () =>
    client.updateDenyRules(create(UpdateDenyRulesRequestSchema, { removeDenyFilePaths: [rule] })),
  );
