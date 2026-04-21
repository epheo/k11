import { create } from "@bufbuild/protobuf";
import type { MessageInitShape } from "@bufbuild/protobuf";

import { client } from "./client.ts";
import { rpc } from "./rpc.ts";
import { store } from "./store.svelte.ts";
import { startStream } from "./stream.ts";
import { EVENTS_PAGE_SIZE } from "./constants.ts";
import {
  GetAgentsRequestSchema,
  GetAgentDetailRequestSchema,
  GetAgentEventsRequestSchema,
  GetPolicyRequestSchema,
  GetConfigRequestSchema,
  SetEnforceRequestSchema,
  UpdateDenyRulesRequestSchema,
} from "./gen/k11_pb.ts";

// ---------------------------------------------------------------------------
// Reads — populate the store from the server
// ---------------------------------------------------------------------------

export async function loadConfig() {
  const res = await rpc("getConfig", () =>
    client.getConfig(create(GetConfigRequestSchema, {})),
  );
  if (res) store.sensitivePaths = res.sensitivePaths;
}

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
    client.getAgentDetail(create(GetAgentDetailRequestSchema, { rootPid })),
  );
  store.detail = res ?? null;
}

export async function loadEvents(rootPid: number) {
  const res = await rpc("getAgentEvents", () =>
    client.getAgentEvents(
      create(GetAgentEventsRequestSchema, { rootPid, limit: EVENTS_PAGE_SIZE }),
    ),
  );
  store.events = res?.events ?? [];
}

export async function selectAgent(rootPid: number) {
  store.selectedPid = rootPid;
  store.rawPidFilter = null;
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
