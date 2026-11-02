import { create } from "@bufbuild/protobuf";
import type { MessageInitShape } from "@bufbuild/protobuf";

import { client } from "./client.ts";
import { rpc } from "./rpc.ts";
import { store } from "./store.svelte.ts";
import { startStream } from "./stream.ts";
import { parseRawEvent } from "./rawlog.ts";
import { EVENTS_PAGE_SIZE } from "./constants.ts";
import {
  GetAgentsRequestSchema,
  GetAgentDetailRequestSchema,
  GetAgentEventsRequestSchema,
  GetPolicyRequestSchema,
  SetEnforceRequestSchema,
  UpdateDenyRulesRequestSchema,
} from "./gen/k11_pb.ts";

// ---------------------------------------------------------------------------
// Reads — populate the store from the server
// ---------------------------------------------------------------------------

export async function loadPolicy() {
  const res = await rpc("getPolicy", () =>
    client.getPolicy(create(GetPolicyRequestSchema, {})),
  );
  if (res) store.policy = res;
}

export async function refreshAgents() {
  const res = await rpc("getAgents", () =>
    client.getAgents(create(GetAgentsRequestSchema, {})),
  );
  if (res) store.agents = res.agents;
}

export async function loadDetail(rootPid: number) {
  const res = await rpc("getAgentDetail", () =>
    client.getAgentDetail(
      create(GetAgentDetailRequestSchema, {
        rootPid,
        ifVersionNe: store.detailVersion,
      }),
    ),
  );
  if (!res) {
    store.detail = null;
    store.detailVersion = 0n;
    return;
  }
  // No detail means nothing changed since detailVersion: keep what we have.
  if (res.detail) {
    store.detail = res.detail;
    store.detailVersion = res.version;
  }
}

export async function loadEvents(rootPid: number) {
  const res = await rpc("getAgentEvents", () =>
    client.getAgentEvents(
      create(GetAgentEventsRequestSchema, { rootPid, limit: EVENTS_PAGE_SIZE }),
    ),
  );
  store.events = res ? res.events.map(parseRawEvent) : [];
}

export async function selectAgent(rootPid: number) {
  store.selectedPid = rootPid;
  store.rawPidFilter = null;
  store.detailVersion = 0n;
  await Promise.all([loadDetail(rootPid), loadEvents(rootPid)]);
  // Re-subscribe so the server filters the stream to this root_pid.
  startStream();
}

// ---------------------------------------------------------------------------
// Writes — policy mutations
// ---------------------------------------------------------------------------

export async function toggleEnforce() {
  if (!store.policy) return;
  const res = await rpc("setEnforce", () =>
    client.setEnforce(
      create(SetEnforceRequestSchema, { enforce: !store.policy!.enforce }),
    ),
  );
  if (res) store.policy = res;
}

export async function updateDenyRules(
  patch: MessageInitShape<typeof UpdateDenyRulesRequestSchema>,
) {
  const res = await rpc("updateDenyRules", () =>
    client.updateDenyRules(create(UpdateDenyRulesRequestSchema, patch)),
  );
  if (res) store.policy = res;
}
