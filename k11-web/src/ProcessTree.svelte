<script lang="ts">
  import type { ProcessInfo } from "./gen/k11_pb.ts";
  import { containerLabel, formatRelativeTime } from "./format.ts";
  import { activityLabel, buildProcTree, type ProcSort } from "./process-tree.ts";
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
  let byPid = $derived(new Map(all.map((p) => [p.pid, p])));
  /** Shown where a branch enters a container, not on every row below. */
  function enters(p: ProcessInfo): string {
    const here = containerLabel(p.container);
    const parent = p.parentPid === undefined ? undefined : byPid.get(p.parentPid);
    return here !== containerLabel(parent?.container) ? here : "";
  }
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
      {#if row.p.cmdLine}
        <span class="proc-cmd" title={row.p.cmdLine}>{row.p.cmdLine}</span>
      {/if}
      {#if enters(row.p)}
        <span class="proc-ts" title={row.p.container?.id}>in {enters(row.p)}</span>
      {/if}
      <span class="proc-stats">
        {activityLabel({
          files: row.p.fileCount,
          net: row.p.netCount,
          unix: row.p.unixCount,
          exec: row.p.execCount,
        })}
      </span>
      {#if !row.p.running}
        <span class="proc-ts">{formatRelativeTime(row.p.lastSeenMs)}</span>
      {/if}
    </div>
  {/each}
</div>
