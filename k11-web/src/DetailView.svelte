<script lang="ts">
  import { create, toJsonString } from "@bufbuild/protobuf";
  import { AgentDetailSchema } from "./gen/k11_pb.ts";
  import { store, type Detail } from "./store.svelte.ts";
  import { formatDateTime, lasted } from "./format.ts";
  import ProcessTab from "./ProcessTab.svelte";
  import FileTab from "./FileTab.svelte";
  import NetworkTab from "./NetworkTab.svelte";
  import UnixTab from "./UnixTab.svelte";

  let { detail }: { detail: Detail } = $props();

  let activeTab = $state<"processes" | "files" | "network" | "unix">("processes");

  const tabs = [
    { id: "processes" as const, label: "○ processes" },
    { id: "files" as const, label: "⌂ files" },
    { id: "network" as const, label: "⇌ network" },
    { id: "unix" as const, label: "⌇ local sockets" },
  ];

  function exportJson() {
    const json = toJsonString(AgentDetailSchema, create(AgentDetailSchema, detail), {
      prettySpaces: 2,
    });
    const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `k11-agent-${detail.summary.rootPid}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

<div class="detail-view">
  <div class="tab-bar">
    {#each tabs as tab (tab.id)}
      <button class="tab-btn" class:active={activeTab === tab.id} onclick={() => (activeTab = tab.id)}>
        {tab.label}
      </button>
    {/each}
    <span class="spacer"></span>
    <button class="export-btn" onclick={exportJson}>[export json]</button>
  </div>

  {#if store.pastId}
    <div class="warn-line">
      a past session, from the record on disk ({formatDateTime(detail.summary.firstSeenMs)}, {lasted(
        detail.summary.firstSeenMs,
        detail.summary.lastSeenMs,
      )}): what it did, without its raw events. <code>k11 report</code> prints the same.
    </div>
  {:else if detail.summary.eventsDropped > 0n || detail.summary.aggregatesCapped}
    <div class="warn-line">
      {#if detail.summary.eventsDropped > 0n}
        raw log kept the newest events only ({detail.summary.eventsDropped} older ones dropped from memory; the OCSF export has them all).
      {/if}
      {#if detail.summary.aggregatesCapped}
        too many distinct paths or addresses: new ones are no longer listed here.
      {/if}
    </div>
  {/if}

  <div class="tab-panel">
    {#if activeTab === "processes"}
      <ProcessTab processes={detail.processes} summary={detail.summary} />
    {:else if activeTab === "files"}
      <FileTab files={detail.files} />
    {:else if activeTab === "network"}
      <NetworkTab connections={detail.connections} binds={detail.binds} />
    {:else}
      <UnixTab sockets={detail.unixSockets} />
    {/if}
  </div>
</div>
