<script lang="ts">
  import type { ProcessInfo, AgentSummary } from "./gen/k11_pb.ts";
  import {
    countProcesses,
    filterProcesses,
    totalActivity,
    type ProcFilters,
    type ProcSort,
  } from "./process-tree.ts";
  import ProcessTree from "./ProcessTree.svelte";
  import ProcessTable from "./ProcessTable.svelte";
  import ProcessGroups from "./ProcessGroups.svelte";

  type ViewMode = "tree" | "table" | "grouped";

  let {
    processes,
    summary,
    rootPid,
  }: {
    processes: ProcessInfo[];
    summary: AgentSummary | undefined;
    rootPid: number;
  } = $props();

  let include = $state("");
  let exclude = $state("");
  let view = $state<ViewMode>("grouped");
  let sortBy = $state<ProcSort>("activity");
  let showExited = $state(true);
  let withFilesOnly = $state(false);
  let withNetOnly = $state(false);

  let filters = $derived<ProcFilters>({
    include, exclude, showExited,
    withFilesOnly, withNetOnly,
  });

  let visible = $derived(filterProcesses(processes, filters));
  let counts = $derived(countProcesses(processes));
  let totals = $derived(totalActivity(visible));
</script>

<div class="filter-row">
  <span class="filter-label">find</span>
  <input class="filter-input" placeholder="filter by name or pid..." bind:value={include} />
  <span class="filter-label">not</span>
  <input class="filter-input exclude" placeholder="exclude..." bind:value={exclude} />
</div>

<div class="filter-row">
  <button class="filter-btn" class:active={showExited} onclick={() => (showExited = !showExited)}>
    {counts.exited} exited
  </button>
  <button class="filter-btn" class:active={withFilesOnly} onclick={() => (withFilesOnly = !withFilesOnly)}>
    {counts.withFiles} w/ files
  </button>
  <button class="filter-btn" class:active={withNetOnly} onclick={() => (withNetOnly = !withNetOnly)}>
    {counts.withNet} w/ net
  </button>

  <div class="sort-toggles">
    <span class="filter-label">sort</span>
    {#each ["default", "activity", "name", "recent"] as s (s)}
      <button class="sort-btn" class:active={sortBy === s} onclick={() => (sortBy = s as ProcSort)}>
        {s === "default" ? "tree" : s}
      </button>
    {/each}
  </div>

  <div class="view-toggles">
    {#each ["tree", "table", "grouped"] as v (v)}
      <button class="view-btn" class:active={view === v} onclick={() => (view = v as ViewMode)}>
        {v}
      </button>
    {/each}
  </div>
</div>

{#if summary}
  {@const parts = [
    totals.files ? `${totals.files} files` : "",
    totals.net ? `${totals.net} conn` : "",
    totals.unix ? `${totals.unix} unix` : "",
    totals.exec ? `${totals.exec} exec` : "",
  ].filter(Boolean).join(" \u00b7 ")}
  <div class="proc-summary">
    {visible.length} processes
    {#if visible.length !== processes.length}
      / {processes.length} total
    {/if}
    ({counts.running} running &middot; {counts.exited} exited)
    {#if parts}
      &mdash; {parts}
    {/if}
    {#if summary.denyCount > 0}
      &middot; <span class="bad">{summary.denyCount} denied</span>
    {/if}
  </div>
{/if}

{#if visible.length === 0}
  <div class="tab-empty">no processes match filter</div>
{:else if view === "tree"}
  <ProcessTree all={processes} {visible} {rootPid} sort={sortBy} />
{:else if view === "table"}
  <ProcessTable processes={visible} sort={sortBy} />
{:else}
  <ProcessGroups processes={visible} sort={sortBy} />
{/if}
