<script lang="ts">
  import type { FileAccess } from "./gen/k11_pb.ts";
  import { buildTree, toolbarStats } from "./file-tree.ts";
  import { toggleInSet } from "./util.ts";
  import FileTreeNode from "./FileTreeNode.svelte";

  type SortMode = "default" | "count" | "name" | "recent";

  let { files }: { files: FileAccess[] } = $props();

  let include = $state("");
  let exclude = $state("");
  let sortBy = $state<SortMode>("default");
  let rwFilters = $state<Set<string>>(new Set(["R", "W"]));
  let errnoFilter = $state<string | null>(null);

  const toggleRw = (key: string) => (rwFilters = toggleInSet(rwFilters, key));
  const toggleErrno = (key: string) => (errnoFilter = errnoFilter === key ? null : key);

  let stats = $derived(toolbarStats(files));

  let errnoKeys = $derived(
    Object.keys(stats.errors).sort((a, b) => stats.errors[b] - stats.errors[a]),
  );

  let tree = $derived(
    buildTree(files, { include, exclude, rw: rwFilters, errno: errnoFilter }),
  );
</script>

<div class="filter-row">
  <span class="filter-label">find</span>
  <input class="filter-input" placeholder="include path..." bind:value={include} />
  <span class="filter-label">not</span>
  <input class="filter-input exclude" placeholder="exclude path..." bind:value={exclude} />
</div>

<div class="filter-row">
  <span class="filter-label">filter</span>
  {#if stats.sensitive > 0}
    <button
      class="filter-btn sensitive"
      class:active={rwFilters.has("S")}
      onclick={() => toggleRw("S")}
    >&#9888; {stats.sensitive} sensitive</button>
  {/if}
  <button class="filter-btn" class:active={rwFilters.has("R")} onclick={() => toggleRw("R")}>
    {stats.reads} reads
  </button>
  {#if stats.writes > 0}
    <button class="filter-btn" class:active={rwFilters.has("W")} onclick={() => toggleRw("W")}>
      {stats.writes} writes
    </button>
  {/if}
  <button class="filter-btn" class:active={rwFilters.has("OK")} onclick={() => toggleRw("OK")}>
    {stats.ok} ok
  </button>
  {#each errnoKeys as k (k)}
    <button
      class="filter-btn errno"
      class:active={errnoFilter === k}
      onclick={() => toggleErrno(k)}
    >{k} <span class="errno-count">({stats.errors[k]})</span></button>
  {/each}
  <div class="sort-toggles">
    <span class="filter-label">sort</span>
    {#each ["default", "count", "name", "recent"] as s (s)}
      <button
        class="sort-btn"
        class:active={sortBy === s}
        onclick={() => (sortBy = s as SortMode)}
      >{s}</button>
    {/each}
  </div>
</div>

{#if tree.stats.paths === 0}
  <div class="tab-empty">no file access recorded</div>
{:else}
  <FileTreeNode node={tree} depth={0} {sortBy} />
{/if}
