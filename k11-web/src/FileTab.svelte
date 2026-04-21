<script lang="ts">
  import type { FileAccess } from "./gen/k11_pb.ts";

  import { buildFileTree, sortedChildren } from "./file-tree.ts";
  import { formatRelativeTime, totalFailed, formatErrors } from "./format.ts";
  import { isSensitive, isPathDenied } from "./predicates.ts";
  import { updateDenyRules } from "./api.ts";
  import FileTreeNode from "./FileTreeNode.svelte";

  let { files }: { files: FileAccess[] } = $props();

  let view = $state<"tree" | "flat">("tree");
  let filter = $state("");

  let tree = $derived(buildFileTree(files));
  let children = $derived(sortedChildren(tree));

  let flatSorted = $derived(
    [...files]
      .filter((f) => !filter || f.path.toLowerCase().includes(filter.toLowerCase()))
      .sort((a, b) => {
        if (a.denied !== b.denied) return a.denied ? -1 : 1;
        if (a.deleted !== b.deleted) return a.deleted ? -1 : 1;
        if (a.sensitive !== b.sensitive) return a.sensitive ? -1 : 1;
        if (a.modified !== b.modified) return a.modified ? -1 : 1;
        return b.count - a.count;
      }),
  );

  function toggleDenyFile(path: string) {
    updateDenyRules(
      isPathDenied(path) ? { removeDenyFilePaths: [path] } : { addDenyFilePaths: [path] },
    );
  }
</script>

<div class="filter-row">
  <span class="filter-label">find</span>
  <input class="filter-input" placeholder="filter by path..." bind:value={filter} />
  <span class="spacer"></span>
  <button class="view-btn" class:active={view === "tree"} onclick={() => (view = "tree")}>
    tree
  </button>
  <button class="view-btn" class:active={view === "flat"} onclick={() => (view = "flat")}>
    flat
  </button>
</div>

{#if files.length === 0}
  <div class="tab-empty">no file accesses recorded</div>
{:else if view === "tree"}
  {#each children as child (child.kind === "dir" ? "d:" + child.path : "f:" + child.path)}
    <FileTreeNode node={child} depth={0} />
  {/each}
{:else}
  <table class="net-table">
    <thead>
      <tr>
        <th class="col-addr">path</th>
        <th class="col-count">#</th>
        <th class="col-status">status</th>
        <th class="col-comms">process</th>
        <th class="col-time">last seen</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each flatSorted as f (f.path)}
        {@const denied = isPathDenied(f.path)}
        {@const fails = totalFailed(f.errors)}
        <tr>
          <td class="col-addr">
            <span
              class="fname"
              class:sensitive={f.sensitive || isSensitive(f.path)}
              class:del={f.deleted}
              class:mv={f.renamed}
              class:perm={f.permChanged || f.ownerChanged}
              class:file-rw={f.modified}
            >
              {f.path}
            </span>
          </td>
          <td class="col-count">{f.count}</td>
          <td class="col-status">
            {#if f.denied}
              <span class="fail">denied</span>
            {:else if fails > 0}
              <span class="fail">{formatErrors(f.errors)}</span>
            {:else}
              <span class="ok">ok</span>
            {/if}
          </td>
          <td class="col-comms">{f.comms.join(", ")}</td>
          <td class="col-time">{formatRelativeTime(f.lastSeenMs)}</td>
          <td>
            <button
              class="deny-btn"
              class:active={denied}
              onclick={() => toggleDenyFile(f.path)}
            >
              [{denied ? "undeny" : "deny"}]
            </button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
