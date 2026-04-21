import type { FileAccess } from "./gen/k11_pb.ts";
import { totalFailed } from "./format.ts";

export interface TreeStats {
  count: number;
  paths: number;
  sensitive: number;
  writes: number;
  hasSensitive: boolean;
  failed: number;
  failedPaths: number;
  allFailed: boolean;
  errors: Record<string, number>;
  lastSeenMs: number;
}

export interface TreeNode {
  name: string;
  fullPath: string;
  children: Record<string, TreeNode>;
  files: FileAccess[];
  stats: TreeStats;
}

export interface TreeFilters {
  include: string;
  exclude: string;
  /** Active R/W/OK/S chips. When both R and W are set, no R/W filtering applies. */
  rw: Set<string>;
  /** When set, keep only files whose errors map contains this key. */
  errno: string | null;
}

const emptyStats = (): TreeStats => ({
  count: 0, paths: 0, sensitive: 0, writes: 0, hasSensitive: false,
  failed: 0, failedPaths: 0, allFailed: false, errors: {}, lastSeenMs: 0,
});

function matchFilter(text: string, q: string): boolean {
  return text.toLowerCase().includes(q.toLowerCase());
}

function passes(f: FileAccess, filters: TreeFilters): boolean {
  if (filters.include && !matchFilter(f.path, filters.include)) return false;
  if (filters.exclude && matchFilter(f.path, filters.exclude)) return false;
  const rwBoth = filters.rw.has("R") && filters.rw.has("W");
  if (!rwBoth) {
    const rw = f.modified ? "W" : "R";
    if (!filters.rw.has(rw)) return false;
  }
  if (filters.rw.has("S") && !f.sensitive) return false;
  if (filters.rw.has("OK") && !filters.errno && totalFailed(f.errors) > 0) return false;
  if (filters.errno && !(f.errors ?? {})[filters.errno]) return false;
  return true;
}

export function buildTree(files: FileAccess[], filters: TreeFilters): TreeNode {
  const root: TreeNode = {
    name: "/", fullPath: "/", children: {}, files: [], stats: emptyStats(),
  };

  for (const f of files) {
    if (!passes(f, filters)) continue;

    const parts = f.path.split("/").filter(Boolean);
    let node = root;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!node.children[part]) {
        node.children[part] = {
          name: part,
          fullPath: "/" + parts.slice(0, i + 1).join("/"),
          children: {}, files: [], stats: emptyStats(),
        };
      }
      node = node.children[part];
    }

    if (parts.length > 0) node.files.push(f);
  }

  aggregateStats(root);
  return root;
}

export function aggregateStats(node: TreeNode) {
  const stats = emptyStats();

  for (const f of node.files) {
    const ff = totalFailed(f.errors);
    stats.count += f.count;
    stats.paths++;
    if (f.sensitive) { stats.sensitive++; stats.hasSensitive = true; }
    if (f.modified) stats.writes++;
    if (ff > 0) { stats.failed += ff; stats.failedPaths++; }
    const lsm = typeof f.lastSeenMs === "bigint" ? Number(f.lastSeenMs) : f.lastSeenMs;
    if (lsm > stats.lastSeenMs) stats.lastSeenMs = lsm;
    for (const [k, v] of Object.entries(f.errors ?? {})) {
      stats.errors[k] = (stats.errors[k] ?? 0) + v;
    }
  }

  for (const child of Object.values(node.children)) {
    aggregateStats(child);
    stats.count += child.stats.count;
    stats.paths += child.stats.paths;
    stats.sensitive += child.stats.sensitive;
    stats.writes += child.stats.writes;
    stats.failed += child.stats.failed;
    stats.failedPaths += child.stats.failedPaths;
    if (child.stats.hasSensitive) stats.hasSensitive = true;
    if (child.stats.lastSeenMs > stats.lastSeenMs) stats.lastSeenMs = child.stats.lastSeenMs;
    for (const [k, v] of Object.entries(child.stats.errors ?? {})) {
      stats.errors[k] = (stats.errors[k] ?? 0) + v;
    }
  }

  stats.allFailed = stats.failedPaths > 0 && stats.failedPaths === stats.paths;
  node.stats = stats;
}

/** Summary counts used to render the toolbar chips. */
export interface ToolbarStats {
  paths: number;
  sensitive: number;
  writes: number;
  reads: number;
  ok: number;
  errors: Record<string, number>;
}

export function toolbarStats(files: FileAccess[]): ToolbarStats {
  let paths = 0, sensitive = 0, writes = 0, ok = 0;
  const errors: Record<string, number> = {};
  for (const f of files) {
    paths++;
    if (f.sensitive) sensitive++;
    if (f.modified) writes++;
    if (totalFailed(f.errors) === 0) ok++;
    for (const [k, v] of Object.entries(f.errors ?? {})) {
      errors[k] = (errors[k] ?? 0) + v;
    }
  }
  return { paths, sensitive, writes, reads: paths - writes, ok, errors };
}
