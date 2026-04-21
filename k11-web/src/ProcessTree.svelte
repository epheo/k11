<script lang="ts">
  import type { ProcessInfo } from "./gen/k11_pb.ts";
  import { formatRelativeTime } from "./format.ts";
  import { buildProcTree, type ProcSort } from "./process-tree.ts";
  import { store, setRawPidFilter } from "./store.svelte.ts";
  import { toggleInSet } from "./util.ts";

  let { all, visible, rootPid, sort }: {
    all: ProcessInfo[];
    visible: ProcessInfo[];
    rootPid: number;
    sort: ProcSort;
  } = $props();

  let expanded = $state<Set<number>>(new Set());

  const toggle = (pid: number) => (expanded = toggleInSet(expanded, pid));

  let rows = $derived(buildProcTree({ all, visible, rootPid, sort }, expanded));
</script>

<div class="proc-tree-detail">
  {#each rows as row (row.p.pid + ":" + row.depth)}
    <div
      class="proc-node"
      class:exited={!row.p.running}
      class:pinned={store.rawPidFilter === row.p.pid}
      role="button"
      tabindex="0"
      onclick={() => setRawPidFilter(row.p.pid)}
      onkeydown={(e) => e.key === "Enter" && setRawPidFilter(row.p.pid)}
    >
      <span class="prefix">{row.prefix}</span>
      {#if row.hasKids}
        <button
          class="proc-toggle"
          onclick={(e) => { e.stopPropagation(); toggle(row.p.pid); }}
        >{row.expanded ? "\u25bc" : "\u25b6"}</button>
      {:else}
        <span class="proc-toggle">&nbsp;</span>
      {/if}
      <span class="comm">{row.p.comm}</span>
      <span class="pid">:{row.p.pid}</span>
      <span class="proc-stats">
        {row.p.fileCount}f {row.p.netCount}n {row.p.unixCount}u {row.p.execCount}x
      </span>
      {#if !row.p.running}
        <span class="proc-ts">{formatRelativeTime(row.p.lastSeenMs)}</span>
      {/if}
    </div>
  {/each}
</div>
