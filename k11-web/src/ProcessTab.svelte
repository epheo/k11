<script lang="ts">
  import type { ProcessInfo } from "./gen/k11_pb.ts";

  import { buildProcessTree, flattenTree } from "./process-tree.ts";
  import { formatRelativeTime } from "./format.ts";
  import { store } from "./store.svelte.ts";

  let { processes }: { processes: ProcessInfo[] } = $props();

  let view = $state<"tree" | "groups">("tree");
  let showExited = $state(false);

  let flat = $derived.by(() => flattenTree(buildProcessTree(processes)));
  let visible = $derived(showExited ? flat : flat.filter((p) => p.running));

  // Summary used by the header line.
  let summary = $derived.by(() => {
    const running = processes.filter((p) => p.running).length;
    return { total: processes.length, running, exited: processes.length - running };
  });

  function focusRaw(pid: number) {
    store.rawPidFilter = pid;
    store.rawCollapsed = false;
  }
</script>

<div class="view-toggles">
  <button class="view-btn" class:active={view === "tree"} onclick={() => (view = "tree")}>
    tree
  </button>
  <button class="view-btn" class:active={view === "groups"} onclick={() => (view = "groups")}>
    groups
  </button>
  <span class="spacer"></span>
  {#if summary.exited > 0}
    <button class="filter-btn" class:active={showExited} onclick={() => (showExited = !showExited)}>
      {showExited ? "hide" : "show"} {summary.exited} exited
    </button>
  {/if}
</div>

{#if visible.length === 0}
  <div class="tab-empty">no processes</div>
{:else if view === "tree"}
  <div class="proc-tree-detail">
    {#each visible as p (p.pid)}
      <div
        class="proc-node"
        class:exited={!p.running}
        onclick={() => focusRaw(p.pid)}
        onkeydown={(e) => e.key === "Enter" && focusRaw(p.pid)}
        role="button"
        tabindex="0"
      >
        <span class="ind">{"  ".repeat(p.depth)}{p.depth > 0 ? "└─" : ""}</span>
        <span class="comm">{p.comm}</span>
        <span class="pid">#{p.pid}</span>
        <span class={p.running ? "status-running" : "status-exited"}>
          {p.running ? "running" : "exited"}
        </span>
        <span class="proc-stats">
          {p.fileCount} f · {p.netCount} n · {p.execCount} x
        </span>
        <span class="proc-ts">{formatRelativeTime(p.lastSeenMs)}</span>
      </div>
    {/each}
  </div>
{:else}
  <!-- Groups view -->
  <table class="net-table">
    <thead>
      <tr>
        <th class="col-comm">comm</th>
        <th class="col-count">#</th>
        <th class="col-count">files</th>
        <th class="col-count">net</th>
        <th class="col-count">exec</th>
        <th class="col-time">last seen</th>
      </tr>
    </thead>
    <tbody>
      {#each Array.from(new Set(visible.map((p) => p.comm))) as comm (comm)}
        {@const members = visible.filter((p) => p.comm === comm)}
        {@const last = Math.max(...members.map((m) => Number(m.lastSeenMs)))}
        <tr>
          <td class="col-comm">{comm}</td>
          <td class="col-count">{members.length}</td>
          <td class="col-count">{members.reduce((s, m) => s + m.fileCount, 0)}</td>
          <td class="col-count">{members.reduce((s, m) => s + m.netCount, 0)}</td>
          <td class="col-count">{members.reduce((s, m) => s + m.execCount, 0)}</td>
          <td class="col-time">{formatRelativeTime(last)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
