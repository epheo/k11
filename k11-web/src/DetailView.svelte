<script lang="ts">
  import { store } from "./store.svelte.ts";
  import ProcessTab from "./ProcessTab.svelte";
  import FileTab from "./FileTab.svelte";
  import NetworkTab from "./NetworkTab.svelte";
  import UnixTab from "./UnixTab.svelte";

  type Tab = "processes" | "files" | "network" | "unix";
  let activeTab = $state<Tab>("processes");

  const tabs: { id: Tab; label: string; count: (s: typeof store) => number }[] = [
    { id: "processes", label: "processes", count: (s) => s.detail?.processes.length ?? 0 },
    { id: "files", label: "files", count: (s) => s.detail?.files.length ?? 0 },
    {
      id: "network",
      label: "network",
      count: (s) => (s.detail?.connections.length ?? 0) + (s.detail?.binds.length ?? 0),
    },
    { id: "unix", label: "unix", count: (s) => s.detail?.unixSockets.length ?? 0 },
  ];
</script>

<div class="detail-view">
  <div class="proc-summary">
    {#if store.detail?.summary}
      {@const s = store.detail.summary}
      <strong>{s.rootComm}</strong>
      <span class="pid">#{s.rootPid}</span>
      · {s.processCount} proc ({s.runningCount} running)
      · {s.fileCount} files
      · {s.netCount} net
      {#if s.denyCount > 0}
        &middot; <span class="bad">{s.denyCount} denied</span>
      {/if}
    {/if}
  </div>

  <div class="tab-bar">
    {#each tabs as t (t.id)}
      <button
        class="tab-btn"
        class:active={activeTab === t.id}
        onclick={() => (activeTab = t.id)}
      >
        {t.label} ({t.count(store)})
      </button>
    {/each}
  </div>

  <div class="tab-panel">
    {#if store.detail}
      {#if activeTab === "processes"}
        <ProcessTab processes={store.detail.processes} />
      {:else if activeTab === "files"}
        <FileTab files={store.detail.files} />
      {:else if activeTab === "network"}
        <NetworkTab connections={store.detail.connections} binds={store.detail.binds} />
      {:else if activeTab === "unix"}
        <UnixTab sockets={store.detail.unixSockets} />
      {/if}
    {/if}
  </div>
</div>
