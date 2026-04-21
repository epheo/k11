<script lang="ts">
  import type { TreeNode } from "./file-tree.ts";

  import { sortedChildren } from "./file-tree.ts";
  import { formatRelativeTime, totalFailed, formatErrors } from "./format.ts";
  import { isSensitive, isPathDenied } from "./predicates.ts";
  import { updateDenyRules } from "./api.ts";
  import Self from "./FileTreeNode.svelte";

  let { node, depth }: { node: TreeNode; depth: number } = $props();

  // Depth is a prop that doesn't change for a given node instance; capture once.
  const initialExpanded = depth < 1;
  let expanded = $state(initialExpanded);

  function toggleDeny(path: string) {
    updateDenyRules(
      isPathDenied(path) ? { removeDenyFilePaths: [path] } : { addDenyFilePaths: [path] },
    );
  }
</script>

<div class="ftree-node" style="padding-left: {depth * 14}px">
  {#if node.kind === "dir"}
    {@const dirPath = node.path}
    {@const denied = isPathDenied(dirPath)}
    <div class="ftree-dir">
      <span
        class="ftree-dir-toggle"
        onclick={() => (expanded = !expanded)}
        onkeydown={(e) => e.key === "Enter" && (expanded = !expanded)}
        role="button"
        tabindex="0"
      >
        {expanded ? "▾" : "▸"}
      </span>
      <span class="dirname">{node.name}/</span>
      <span class="dirstats">
        {node.fileCount} files
        {#if node.sensitiveCount > 0}
          · <span class="warn">{node.sensitiveCount} sensitive</span>
        {/if}
        {#if node.deniedCount > 0}
          · <span class="bad">{node.deniedCount} denied</span>
        {/if}
      </span>
      <button
        class="deny-btn"
        class:active={denied}
        onclick={() => toggleDeny(dirPath)}
      >
        [{denied ? "denied" : "deny"}]
      </button>
    </div>
    {#if expanded}
      <div class="ftree-children">
        {#each sortedChildren(node) as child (child.kind === "dir" ? "d:" + child.path : "f:" + child.path)}
          <Self node={child} depth={depth + 1} />
        {/each}
      </div>
    {/if}
  {:else}
    {@const f = node.access}
    {@const fails = totalFailed(f.errors)}
    {@const denied = isPathDenied(f.path)}
    <div class="ftree-file">
      <span
        class="fname"
        class:sensitive={f.sensitive || isSensitive(f.path)}
        class:del={f.deleted}
        class:mv={f.renamed}
        class:perm={f.permChanged || f.ownerChanged}
        class:file-rw={f.modified}
      >
        {node.name}
      </span>
      <span class="fmeta">
        {f.count}x
        {#if f.denied}
          · <span class="fail">denied</span>
        {:else if fails > 0}
          · <span class="fail">{formatErrors(f.errors)}</span>
        {/if}
        · {formatRelativeTime(f.lastSeenMs)}
      </span>
      <button class="deny-btn" class:active={denied} onclick={() => toggleDeny(f.path)}>
        [{denied ? "undeny" : "deny"}]
      </button>
    </div>
  {/if}
</div>
