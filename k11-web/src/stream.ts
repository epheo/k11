import { create } from "@bufbuild/protobuf";

import { client } from "./client.ts";
import { store, pushRawLog } from "./store.svelte.ts";
import { StreamEventsRequestSchema, EventFormat } from "./gen/k11_pb.ts";

let activeController: AbortController | null = null;

/// Start (or restart) the live event stream. Called on page load and each
/// time the user selects a different agent — the server filters by root_pid.
export async function startStream() {
  if (activeController) {
    activeController.abort();
    activeController = null;
  }
  const controller = new AbortController();
  activeController = controller;

  const req = create(StreamEventsRequestSchema, {
    rootPid: store.selectedPid ?? undefined,
    format: EventFormat.K11_NATIVE,
  });

  store.streamConnected = false;
  try {
    const stream = client.streamEvents(req, { signal: controller.signal });
    store.streamConnected = true;
    for await (const msg of stream) {
      const payload = msg.payload;
      if (payload?.case === "event" && payload.value) {
        pushRawLog(payload.value);
      }
    }
  } catch (err) {
    if (controller.signal.aborted) return;
    console.warn("[stream]", err);
  } finally {
    if (activeController === controller) {
      store.streamConnected = false;
      activeController = null;
    }
  }
}
