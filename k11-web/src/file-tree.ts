import type { FileAccess } from "./gen/k11_pb.ts";
import { access, totalFailed } from "./format.ts";
import { textFilter } from "./util.ts";

export type SortMode = "default" | "count" | "name" | "recent";

export interface TreeStats {
  count: number;
  paths: number;
  sensitive: number;
  writes: number;
  failedPaths: number;
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
  reads: boolean;
  writes: boolean;
  sensitiveOnly: boolean;
  okOnly: boolean;
  /** Keep only files that failed with this errno. */
  errno: string | null;
}

const emptyStats = (): TreeStats => ({
  count: 0, paths: 0, sensitive: 0, writes: 0, failedPaths: 0, errors: {}, lastSeenMs: 0,
});

function addFile(stats: TreeStats, f: FileAccess) {
  const a = access(f);
  stats.count += a.count;
  stats.paths++;
  if (f.sensitive) stats.sensitive++;
  if (f.modified) stats.writes++;
  if (totalFailed(a.errors) > 0) stats.failedPaths++;
  stats.lastSeenMs = Math.max(stats.lastSeenMs, Number(a.lastSeenMs));
  addErrors(stats, a.errors);
}

function addStats(stats: TreeStats, child: TreeStats) {
  stats.count += child.count;
  stats.paths += child.paths;
  stats.sensitive += child.sensitive;
  stats.writes += child.writes;
  stats.failedPaths += child.failedPaths;
  stats.lastSeenMs = Math.max(stats.lastSeenMs, child.lastSeenMs);
  addErrors(stats, child.errors);
}

function addErrors(stats: TreeStats, errors: Record<string, number>) {
  for (const [k, v] of Object.entries(errors)) stats.errors[k] = (stats.errors[k] ?? 0) + v;
}

/** Totals over every file, for the toolbar chips. */
export function fileStats(files: FileAccess[]): TreeStats {
  const stats = emptyStats();
  for (const f of files) addFile(stats, f);
  return stats;
}

export function buildTree(files: FileAccess[], filters: TreeFilters): TreeNode {
  const keep = textFilter(filters.include, filters.exclude);
  const passes = (f: FileAccess) => {
    if (!keep(f.path)) return false;
    if (!(f.modified ? filters.writes : filters.reads)) return false;
    if (filters.sensitiveOnly && !f.sensitive) return false;
    const errors = access(f).errors;
    if (filters.errno) return !!errors[filters.errno];
    return !filters.okOnly || totalFailed(errors) === 0;
  };

  const root: TreeNode = { name: "/", fullPath: "/", children: {}, files: [], stats: emptyStats() };
  for (const f of files) {
    if (!passes(f)) continue;
    const parts = f.path.split("/").filter(Boolean);
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      node = node.children[parts[i]] ??= {
        name: parts[i],
        fullPath: "/" + parts.slice(0, i + 1).join("/"),
        children: {},
        files: [],
        stats: emptyStats(),
      };
    }
    if (parts.length > 0) node.files.push(f);
  }
  aggregate(root);
  return root;
}

function aggregate(node: TreeNode) {
  for (const f of node.files) addFile(node.stats, f);
  for (const child of Object.values(node.children)) {
    aggregate(child);
    addStats(node.stats, child.stats);
  }
}
