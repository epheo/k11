<script lang="ts">
  import Ago from "./Ago.svelte";
  import type { ProcessInfo } from "./gen/k11_pb.ts";
  import { containerLabel, containerTitle, processName } from "./format.ts";
  import { sortProcesses, type ProcSort } from "./process-tree.ts";
  import { store, setRawPidFilter } from "./store.svelte.ts";
  import { PROC_TABLE_CAP as CAP } from "./constants.ts";

  let { processes, sort }: { processes: ProcessInfo[]; sort: ProcSort } = $props();
  let showAll = $state(false);

  let sorted = $derived(sortProcesses(processes, sort));
  let shown = $derived(showAll || sorted.length <= CAP ? sorted : sorted.slice(0, CAP));
  // Host and VM trees have no container: no empty column.
  let inContainers = $derived(processes.some((p) => p.container));
</script>

<table class="net-table">
  <thead>
    <tr>
      <th>process</th><th>command</th><th>pid</th><th>ppid</th>
      {#if inContainers}<th>container</th>{/if}
      <th>status</th>
      <th>files</th><th>net</th><th>unix</th><th>exec</th>
      <th>first seen</th><th>last seen</th>
    </tr>
  </thead>
  <tbody>
    {#each shown as p (p.pid)}
      <tr
        class="clickable"
        class:exited-row={!p.running}
        class:pinned={store.rawPidFilter === p.pid}
        onclick={() => setRawPidFilter(p.pid)}
      >
        <td class="col-comm">{processName(p)}</td>
        <td class="col-cmd" title={p.cmdLine}>{p.cmdLine || "-"}</td>
        <td class="col-port">{p.pid}</td>
        <td class="col-port">{p.parentPid ?? "-"}</td>
        {#if inContainers}
          <td class="col-port" title={containerTitle(p.container)}>{containerLabel(p.container) || "-"}</td>
        {/if}
        <td>
          {#if p.running}
            <span class="status-running">&#x25cf;</span>
          {:else}
            <span class="status-exited">&#x2717;</span>
          {/if}
        </td>
        <td class="col-count">{p.fileCount || "-"}</td>
        <td class="col-count">{p.netCount || "-"}</td>
        <td class="col-count">{p.unixCount || "-"}</td>
        <td class="col-count">{p.execCount || "-"}</td>
        <td class="col-time"><Ago ms={p.firstSeenMs} /></td>
        <td class="col-time"><Ago ms={p.lastSeenMs} /></td>
      </tr>
    {/each}
  </tbody>
</table>

{#if !showAll && sorted.length > CAP}
  <button class="proc-show-all" onclick={() => (showAll = true)}>
    showing {CAP} / {sorted.length} &mdash; click to show all
  </button>
{/if}
