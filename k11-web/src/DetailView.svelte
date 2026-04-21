<script lang="ts">
  import type { AgentDetail } from "./gen/k11_pb.ts";
  import ProcessTab from "./ProcessTab.svelte";
  import FileTab from "./FileTab.svelte";
  import NetworkTab from "./NetworkTab.svelte";
  import UnixTab from "./UnixTab.svelte";

  let { detail }: { detail: AgentDetail } = $props();

  let activeTab = $state<"processes" | "files" | "network" | "unix">("processes");

  const tabs = [
    { id: "processes" as const, label: "\u25cb processes" },
    { id: "files" as const, label: "\u2302 files" },
    { id: "network" as const, label: "\u21cc network" },
    { id: "unix" as const, label: "\u2307 unix" },
  ];

  function exportJson() {
    const replacer = (_: string, v: unknown) =>
      typeof v === "bigint" ? v.toString() : v;
    const blob = new Blob([JSON.stringify(detail, replacer, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `k11-agent-${detail.rootPid}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

<div class="detail-view">
  <div class="tab-bar">
    {#each tabs as tab (tab.id)}
      <button
        class="tab-btn"
        class:active={activeTab === tab.id}
        onclick={() => (activeTab = tab.id)}
      >
        {tab.label}
      </button>
    {/each}
    <span class="spacer"></span>
    <button class="export-btn" onclick={exportJson}>[export json]</button>
  </div>

  {#if activeTab === "processes"}
    <div class="tab-panel active">
      <ProcessTab
        processes={detail.processes}
        summary={detail.summary}
        rootPid={detail.rootPid}
      />
    </div>
  {:else if activeTab === "files"}
    <div class="tab-panel active">
      <FileTab files={detail.files} />
    </div>
  {:else if activeTab === "network"}
    <div class="tab-panel active">
      <NetworkTab connections={detail.connections} binds={detail.binds} />
    </div>
  {:else if activeTab === "unix"}
    <div class="tab-panel active">
      <UnixTab sockets={detail.unixSockets} />
    </div>
  {/if}
</div>
