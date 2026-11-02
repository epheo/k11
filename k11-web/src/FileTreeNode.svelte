<script lang="ts">
  import type { FileAccess } from "./gen/k11_pb.ts";
  import { access, formatRelativeTime, totalFailed, formatErrors } from "./format.ts";
  import { coveringRule } from "./deny.ts";
  import { deny, undeny } from "./sync.ts";
  import { store } from "./store.svelte.ts";
  import type { SortMode, TreeNode } from "./file-tree.ts";
  import FileTreeNode from "./FileTreeNode.svelte";

  const AUTO_COLLAPSE = ["/usr", "/proc", "/sys", "/dev"];

  let { node, depth, sortBy }: { node: TreeNode; depth: number; sortBy: SortMode } = $props();

  let toggleState = $state<Record<string, boolean>>({});
  let canDeny = $derived(!!store.policy && !store.policy.unavailable);

  function shouldExpand(n: TreeNode, d: number): boolean {
    const fp = n.fullPath;
    if (toggleState[fp] !== undefined) return toggleState[fp];
    if (n.stats.sensitive > 0) return true;
    if (AUTO_COLLAPSE.some((r) => fp === r || fp.startsWith(r + "/"))) return false;
    return d <= 1 || (n.files.length === 0 && Object.keys(n.children).length === 1);
  }

  /** What both directories and files sort by; `rank` orders the default view. */
  interface Key {
    name: string;
    count: number;
    lastSeenMs: number;
    rank: number;
  }

  const dirKey = (n: TreeNode): Key => ({
    name: n.name,
    count: n.stats.count,
    lastSeenMs: n.stats.lastSeenMs,
    rank: 2 * Number(n.stats.sensitive > 0) + Number(n.stats.failedPaths > 0),
  });

  const fileKey = (f: FileAccess): Key => {
    const a = access(f);
    return {
      name: f.path,
      count: a.count,
      lastSeenMs: Number(a.lastSeenMs),
      rank: 4 * Number(f.denied) + 2 * Number(f.sensitive) + Number(f.modified),
    };
  };

  function compare(a: Key, b: Key): number {
    if (sortBy === "count") return b.count - a.count;
    if (sortBy === "name") return a.name.localeCompare(b.name);
    if (sortBy === "recent") return b.lastSeenMs - a.lastSeenMs;
    return b.rank - a.rank || b.count - a.count;
  }

  function sorted<T>(items: T[], key: (item: T) => Key): T[] {
    return items
      .map((item) => [key(item), item] as const)
      .sort(([a], [b]) => compare(a, b))
      .map(([, item]) => item);
  }

  let dirs = $derived(
    sorted(
      Object.values(node.children).filter((c) => c.stats.paths > 0),
      dirKey,
    ),
  );
  let files = $derived(sorted(node.files, fileKey));
</script>

{#snippet denyButton(path: string)}
  {@const rule = coveringRule(path)}
  {#if rule === path}
    <button class="deny-btn active" onclick={() => undeny(path)}>[undeny]</button>
  {:else if rule}
    <span class="deny-btn active" title="covered by the rule {rule}">[denied]</span>
  {:else}
    <button class="deny-btn" onclick={() => deny(path)}>[deny]</button>
  {/if}
{/snippet}

{#each dirs as child (child.fullPath)}
  {@const exp = shouldExpand(child, depth + 1)}
  {@const statsStr = [
    `${child.stats.count}×`,
    `${child.stats.paths} paths`,
    child.stats.sensitive > 0 ? `⚠ ${child.stats.sensitive} sensitive` : "",
    child.stats.writes > 0 ? `${child.stats.writes}W` : "",
    child.stats.failedPaths > 0 ? formatErrors(child.stats.errors) : "",
  ].filter(Boolean).join(" · ")}

  <div class="ftree-node">
    <div
      class="ftree-dir"
      class:sensitive={child.stats.sensitive > 0}
      class:all-failed={child.stats.failedPaths === child.stats.paths}
    >
      <button
        class="ftree-dir-toggle"
        onclick={() => (toggleState = { ...toggleState, [child.fullPath]: !exp })}
      >
        <span class="arrow">{exp ? "▼" : "▶"}</span>
        <span class="dirname">{child.name}/</span>
      </button>
      <span class="dirstats">{statsStr}</span>
      {#if canDeny}{@render denyButton(child.fullPath)}{/if}
    </div>

    {#if exp}
      <div class="ftree-children">
        <FileTreeNode node={child} depth={depth + 1} {sortBy} />
      </div>
    {/if}
  </div>
{/each}

{#each files as f (f.path)}
  {@const a = access(f)}
  {@const failed = totalFailed(a.errors) > 0}
  <div class="ftree-file">
    {#if f.denied}
      <span class="file-rw del">X</span>
    {:else if f.deleted}
      <span class="file-rw del">D</span>
    {:else if f.modified}
      <span class="file-rw w">W</span>
    {:else}
      <span class="file-rw" class:fail={failed}>R</span>
    {/if}
    {#if f.renamed}<span class="file-rw mv">MV</span>{/if}
    {#if f.permChanged || f.ownerChanged}<span class="file-rw perm">P</span>{/if}
    {#if f.isSymlink}<span class="file-rw link">L</span>{/if}

    <span class="fname" class:sensitive={f.sensitive} title={f.path}>{f.path.split("/").pop()}</span>
    <span class="fmeta">
      {a.count}&times;
      {#if a.comms.length > 0}
        &middot; {a.comms.join(", ")}
      {/if}
      {#if failed}
        <span class="fail-count">&middot; {formatErrors(a.errors)}</span>
      {/if}
      &middot; {formatRelativeTime(a.lastSeenMs)}
    </span>
    {#if canDeny}{@render denyButton(f.path)}{/if}
    {#if f.denied}
      <span class="denied-badge">DENIED</span>
    {:else if f.audited}
      <span class="audit-badge">AUDIT</span>
    {/if}
  </div>
{/each}
