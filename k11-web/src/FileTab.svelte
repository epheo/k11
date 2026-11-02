<script lang="ts">
  import type { FileAccess } from "./gen/k11_pb.ts";
  import { buildTree, fileStats, type SortMode } from "./file-tree.ts";
  import FilterRow from "./FilterRow.svelte";
  import FileTreeNode from "./FileTreeNode.svelte";

  let { files }: { files: FileAccess[] } = $props();

  let include = $state("");
  let exclude = $state("");
  let sortBy = $state<SortMode>("default");
  let reads = $state(true);
  let writes = $state(true);
  let sensitiveOnly = $state(false);
  let okOnly = $state(false);
  let errno = $state<string | null>(null);

  let stats = $derived(fileStats(files));
  let errnoKeys = $derived(
    Object.keys(stats.errors).sort((a, b) => stats.errors[b] - stats.errors[a]),
  );
  let tree = $derived(
    buildTree(files, { include, exclude, reads, writes, sensitiveOnly, okOnly, errno }),
  );
</script>

<FilterRow bind:include bind:exclude placeholder="include path..." />

<div class="filter-row">
  <span class="filter-label">show</span>
  <button class="filter-btn" class:active={reads} onclick={() => (reads = !reads)}>
    {stats.paths - stats.writes} reads
  </button>
  <button class="filter-btn" class:active={writes} onclick={() => (writes = !writes)}>
    {stats.writes} writes
  </button>
  <span class="filter-label">only</span>
  {#if stats.sensitive > 0}
    <button
      class="filter-btn sensitive"
      class:active={sensitiveOnly}
      onclick={() => (sensitiveOnly = !sensitiveOnly)}
    >&#9888; {stats.sensitive} sensitive</button>
  {/if}
  <button class="filter-btn" class:active={okOnly} onclick={() => (okOnly = !okOnly)}>
    {stats.paths - stats.failedPaths} ok
  </button>
  {#each errnoKeys as k (k)}
    <button
      class="filter-btn errno"
      class:active={errno === k}
      onclick={() => (errno = errno === k ? null : k)}
    >{k} <span class="errno-count">({stats.errors[k]})</span></button>
  {/each}
  <div class="sort-toggles">
    <span class="filter-label">sort</span>
    {#each ["default", "count", "name", "recent"] as const as s (s)}
      <button class="sort-btn" class:active={sortBy === s} onclick={() => (sortBy = s)}>{s}</button>
    {/each}
  </div>
</div>

<div class="proc-summary">
  <span class="legend">R read &middot; W written &middot; D deleted &middot; X denied &middot; MV renamed &middot; P permissions or owner &middot; L symlink</span>
</div>

{#if tree.stats.paths === 0}
  <div class="tab-empty">no file access recorded</div>
{:else}
  <FileTreeNode node={tree} depth={0} {sortBy} />
{/if}
