<script lang="ts">
  import { formatRelativeTime, totalFailed, formatErrors } from "./format.ts";
  import { isSensitive, isPathDenied } from "./predicates.ts";
  import { updateDenyRules } from "./api.ts";
  import type { TreeNode } from "./file-tree.ts";
  import FileTreeNode from "./FileTreeNode.svelte";

  type SortMode = "default" | "count" | "name" | "recent";

  const AUTO_COLLAPSE = ["/usr", "/proc", "/sys", "/dev"];

  let { node, depth, sortBy }: {
    node: TreeNode;
    depth: number;
    sortBy: SortMode;
  } = $props();

  let toggleState = $state<Record<string, boolean>>({});

  function shouldExpand(n: TreeNode, d: number): boolean {
    const fp = n.fullPath || "/";
    if (toggleState[fp] !== undefined) return toggleState[fp];
    if (n.stats.hasSensitive) return true;
    if (AUTO_COLLAPSE.some((r) => fp === r || fp.startsWith(r + "/"))) return false;
    if (d <= 1) return true;
    if (n.files.length === 0 && Object.keys(n.children).length === 1) return true;
    return false;
  }

  function toggle(fullPath: string, currentlyExpanded: boolean) {
    toggleState = { ...toggleState, [fullPath]: !currentlyExpanded };
  }

  let sortedChildKeys = $derived(
    Object.keys(node.children)
      .filter((k) => node.children[k].stats.paths > 0)
      .sort((a, b) => {
        const ca = node.children[a], cb = node.children[b];
        if (ca.stats.hasSensitive !== cb.stats.hasSensitive) return cb.stats.hasSensitive ? 1 : -1;
        if ((ca.stats.failedPaths > 0) !== (cb.stats.failedPaths > 0)) return cb.stats.failedPaths > 0 ? 1 : -1;
        return cb.stats.count - ca.stats.count;
      }),
  );

  let sortedFiles = $derived(
    node.files.slice().sort((a, b) => {
      if (sortBy === "count") return b.count - a.count;
      if (sortBy === "name") return a.path.localeCompare(b.path);
      if (sortBy === "recent") return Number(b.lastSeenMs) - Number(a.lastSeenMs);
      // default: denied, then sensitive+writes, then by count
      if (a.denied !== b.denied) return a.denied ? -1 : 1;
      if (a.sensitive !== b.sensitive) return b.sensitive ? 1 : -1;
      if (a.modified !== b.modified) return b.modified ? 1 : -1;
      return b.count - a.count;
    }),
  );

  function fileName(path: string): string {
    return path.split("/").pop() || path;
  }

  function toggleDenyDir(dirPath: string) {
    const p = dirPath.endsWith("/") ? dirPath : dirPath + "/";
    updateDenyRules(
      isPathDenied(p) ? { removeDenyFilePaths: [p] } : { addDenyFilePaths: [p] },
    );
  }

  function toggleDenyFile(path: string) {
    updateDenyRules(
      isPathDenied(path)
        ? { removeDenyFilePaths: [path] }
        : { addDenyFilePaths: [path] },
    );
  }
</script>

{#each sortedChildKeys as key (key)}
  {@const child = node.children[key]}
  {@const exp = shouldExpand(child, depth + 1)}
  {@const dirPath = child.fullPath.endsWith("/") ? child.fullPath : child.fullPath + "/"}
  {@const denied = isPathDenied(dirPath)}
  {@const statsStr = [
    `${child.stats.count}\u00d7`,
    `${child.stats.paths} paths`,
    child.stats.sensitive > 0 ? `\u26a0 ${child.stats.sensitive} sensitive` : "",
    child.stats.writes > 0 ? `${child.stats.writes}W` : "",
    child.stats.failedPaths > 0 ? formatErrors(child.stats.errors) : "",
  ].filter(Boolean).join(" \u00b7 ")}

  <div class="ftree-node">
    <div class="ftree-dir" class:sensitive={child.stats.hasSensitive} class:all-failed={child.stats.allFailed}>
      <button
        class="ftree-dir-toggle"
        onclick={() => toggle(child.fullPath, exp)}
      >
        <span class="arrow">{exp ? "\u25bc" : "\u25b6"}</span>
        <span class="dirname">{child.name}/</span>
      </button>
      <span class="dirstats">{statsStr}</span>
      <button
        class="deny-btn"
        class:active={denied}
        onclick={(e) => { e.stopPropagation(); toggleDenyDir(child.fullPath); }}
      >
        [{denied ? "denied" : "deny"}]
      </button>
    </div>

    {#if exp}
      <div class="ftree-children">
        <FileTreeNode node={child} depth={depth + 1} {sortBy} />
      </div>
    {/if}
  </div>
{/each}

{#each sortedFiles as f (f.path)}
  {@const sens = isSensitive(f.path)}
  {@const denied = isPathDenied(f.path)}
  {@const ff = totalFailed(f.errors)}
  <div class="ftree-file">
    {#if f.denied}
      <span class="file-rw del">X</span>
    {:else if f.deleted}
      <span class="file-rw del">D</span>
    {:else if f.modified}
      <span class="file-rw w">W</span>
    {:else if ff > 0}
      <span class="file-rw fail">R</span>
    {:else}
      <span class="file-rw">R</span>
    {/if}
    {#if f.renamed}<span class="file-rw mv">MV</span>{/if}
    {#if f.permChanged || f.ownerChanged}<span class="file-rw perm">P</span>{/if}
    {#if f.isSymlink}<span class="file-rw link">L</span>{/if}

    <span class="fname" class:sensitive={sens}>{fileName(f.path)}</span>
    <span class="fmeta">
      {f.count}&times;
      {#if f.comms.length > 0}
        &middot; {f.comms.join(", ")}
      {/if}
      {#if ff > 0}
        <span class="fail-count">&middot; {formatErrors(f.errors)}</span>
      {/if}
      &middot; {formatRelativeTime(f.lastSeenMs)}
    </span>
    <button class="deny-btn" class:active={denied} onclick={() => toggleDenyFile(f.path)}>
      [{denied ? "undeny" : "deny"}]
    </button>
    {#if f.denied}
      <span class="denied-badge">DENIED</span>
    {/if}
  </div>
{/each}
