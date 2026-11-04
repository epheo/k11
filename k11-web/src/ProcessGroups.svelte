<script lang="ts">
  import Ago from "./Ago.svelte";
  import type { ProcessInfo } from "./gen/k11_pb.ts";
    import { activityLabel, groupByComm, type ProcSort } from "./process-tree.ts";
  import { store, setRawPidFilter } from "./store.svelte.ts";
  import { toggleInSet } from "./util.ts";

  let { processes, sort }: { processes: ProcessInfo[]; sort: ProcSort } = $props();
  let expanded = $state<Set<string>>(new Set());

  let groups = $derived(groupByComm(processes, sort));

  const toggle = (comm: string) => (expanded = toggleInSet(expanded, comm));

  /** What the group ran most recently: its instances often differ only there. */
  function latestCommand(procs: ProcessInfo[]): string {
    let best: ProcessInfo | undefined;
    for (const p of procs) if (p.cmdLine && (!best || p.lastSeenMs > best.lastSeenMs)) best = p;
    return best?.cmdLine ?? "";
  }

</script>

{#each groups as g (g.comm)}
  {@const exp = expanded.has(g.comm)}
  {@const gs = activityLabel(g.totals)}
  {@const latest = latestCommand(g.procs)}
  <div
    class="proc-group-header"
    role="button"
    tabindex="0"
    onclick={() => toggle(g.comm)}
    onkeydown={(e) => e.key === "Enter" && toggle(g.comm)}
  >
    <span class="gtoggle">{exp ? "\u25bc" : "\u25b6"}</span>
    <span class="gcomm">{g.comm}</span>
    <span class="gcount">
      &times;{g.procs.length}
      {#if g.running && g.exited}
        ({g.running} running &middot; {g.exited} exited)
      {:else if g.exited}
        (all exited)
      {/if}
    </span>
    {#if latest}
      <span class="proc-cmd" title={latest}>{latest}</span>
    {/if}
    {#if gs}
      <span class="gstats">{gs}</span>
    {/if}
    {#if g.maxSeenMs}
      <span class="gtime"><Ago ms={g.maxSeenMs} /></span>
    {/if}
  </div>

  {#if exp}
    <div class="proc-group-children">
      <table class="net-table">
        <thead>
          <tr>
            <th>pid</th><th>command</th><th>ppid</th><th>status</th>
            <th>files</th><th>net</th><th>unix</th><th>exec</th>
            <th>last seen</th>
          </tr>
        </thead>
        <tbody>
          {#each g.procs.slice().sort((a, b) => Number(b.lastSeenMs) - Number(a.lastSeenMs)) as p (p.pid)}
            <tr
              class="clickable"
              class:exited-row={!p.running}
              class:pinned={store.rawPidFilter === p.pid}
              onclick={() => setRawPidFilter(p.pid)}
            >
              <td class="col-port">{p.pid}</td>
              <td class="col-cmd" title={p.cmdLine}>{p.cmdLine || "-"}</td>
              <td class="col-port">{p.parentPid ?? "-"}</td>
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
              <td class="col-time"><Ago ms={p.lastSeenMs} /></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/each}
