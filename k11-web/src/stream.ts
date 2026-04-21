import { create } from "@bufbuild/protobuf";

import { client } from "./client.ts";
import { store } from "./store.svelte.ts";
import { loadDetail, refreshAgents } from "./api.ts";
import { StreamEventsRequestSchema } from "./gen/k11_pb.ts";
import {
  MAX_EVENTS,
  RECONNECT_DELAY_MS,
  REFRESH_INTERVAL_MS,
} from "./constants.ts";

// ---------------------------------------------------------------------------
// Debounced refresh
//
// Stream events arrive in bursts. Rather than refetching the agents list and
// current detail on every event, we schedule one refresh per window.
// ---------------------------------------------------------------------------

let refreshTimer: ReturnType<typeof setTimeout> | null = null;
let refreshPending = false;

function scheduleRefresh() {
  refreshPending = true;
  if (refreshTimer) return;
  refreshTimer = setTimeout(async () => {
    refreshTimer = null;
    if (!refreshPending) return;
    refreshPending = false;
    await refreshAgents();
    if (store.selectedPid !== null) {
      await loadDetail(store.selectedPid);
    }
  }, REFRESH_INTERVAL_MS);
}

// ---------------------------------------------------------------------------
// Stream lifecycle
//
// `streamEpoch` is bumped on every (re)start. When the for-await loop exits,
// we check whether the epoch still matches: if not, a newer stream has replaced
// us (intentional abort during selectAgent / stopStream) and we exit silently.
// If it does match, the disconnect was unexpected — schedule a retry.
// ---------------------------------------------------------------------------

let abortController: AbortController | null = null;
let streamEpoch = 0;

export async function startStream() {
  abortController?.abort();
  abortController = new AbortController();
  const epoch = ++streamEpoch;
  const signal = abortController.signal;

  const req: { rootPid?: number } = {};
  if (store.selectedPid !== null) req.rootPid = store.selectedPid;

  try {
    const stream = client.streamEvents(
      create(StreamEventsRequestSchema, req),
      { signal },
    );

    store.connected = true;
    store.reconnectAttempts = 0;
    for await (const msg of stream) {
      scheduleRefresh();

      if (msg.payload.case === "event" && msg.payload.value) {
        const next =
          store.events.length >= MAX_EVENTS
            ? store.events.slice(store.events.length - MAX_EVENTS + 1)
            : store.events.slice();
        next.push(msg.payload.value);
        store.events = next;
      }
    }
  } catch (_) {
    // Fall through — intentional aborts and real disconnects handled below.
  }

  if (epoch !== streamEpoch) return; // newer stream took over

  store.connected = false;
  store.reconnectAttempts += 1;
  setTimeout(() => {
    if (epoch === streamEpoch) startStream();
  }, RECONNECT_DELAY_MS);
}

export function stopStream() {
  streamEpoch++;
  abortController?.abort();
  abortController = null;
  store.connected = false;
}
