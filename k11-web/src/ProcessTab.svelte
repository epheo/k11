<script lang="ts">
  import type { ProcessInfo, AgentSummary } from "./gen/k11_pb.ts";
  import {
    activityLabel,
    countProcesses,
    filterProcesses,
    totalActivity,
    type ProcSort,
  } from "./process-tree.ts";
  import FilterRow from "./FilterRow.svelte";
  import ProcessTree from "./ProcessTree.svelte";
  import ProcessTable from "./ProcessTable.svelte";
  import ProcessGroups from "./ProcessGroups.svelte";

  type ViewMode = "tree" | "table" | "grouped";

  let { processes, summary }: { processes: ProcessInfo[]; summary: AgentSummary } = $props();

  let include = $state("");
  let exclude = $state("");
  let view = $state<ViewMode>("grouped");
  let sortBy = $state<ProcSort>("activity");
  let showExited = $state(true);
  let withFilesOnly = $state(false);
  let withNetOnly = $state(false);

  let visible = $derived(
    filterProcesses(processes, { include, exclude, showExited, withFilesOnly, withNetOnly }),
  );
  let counts = $derived(countProcesses(processes));
  let activity = $derived(activityLabel(totalActivity(visible)));
</script>

<FilterRow bind:include bind:exclude placeholder="filter by name or pid..." />

<div class="filter-row">
  <button class="filter-btn" class:active={showExited} onclick={() => (showExited = !showExited)}>
    show {counts.exited} exited
  </button>
  <button class="filter-btn" class:active={withFilesOnly} onclick={() => (withFilesOnly = !withFilesOnly)}>
    only {counts.withFiles} w/ files
  </button>
  <button class="filter-btn" class:active={withNetOnly} onclick={() => (withNetOnly = !withNetOnly)}>
    only {counts.withNet} w/ net
  </button>

  <div class="sort-toggles">
    <span class="filter-label">sort</span>
    {#each ["pid", "activity", "name", "recent"] as const as s (s)}
      <button class="sort-btn" class:active={sortBy === s} onclick={() => (sortBy = s)}>{s}</button>
    {/each}
  </div>

  <div class="view-toggles">
    {#each ["tree", "table", "grouped"] as const as v (v)}
      <button class="sort-btn" class:active={view === v} onclick={() => (view = v)}>{v}</button>
    {/each}
  </div>
</div>

<div class="proc-summary">
  {visible.length} processes
  {#if visible.length !== processes.length}
    / {processes.length} total
  {/if}
  ({counts.running} running &middot; {counts.exited} exited)
  {#if activity}
    &mdash; {activity}
  {/if}
  {#if summary.denyCount > 0}
    &middot; <span class="bad">{summary.denyCount} denied</span>
  {/if}
  {#if summary.auditCount > 0}
    &middot; <span class="warn">{summary.auditCount} audited</span>
  {/if}
  <span class="legend">f files &middot; n network &middot; u unix &middot; x exec</span>
</div>

{#if visible.length === 0}
  <div class="tab-empty">no processes match filter</div>
{:else if view === "tree"}
  <ProcessTree all={processes} {visible} rootPid={summary.rootPid} sort={sortBy} />
{:else if view === "table"}
  <ProcessTable processes={visible} sort={sortBy} />
{:else}
  <ProcessGroups processes={visible} sort={sortBy} />
{/if}
