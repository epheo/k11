import type { ProcessInfo } from "./gen/k11_pb.ts";
import { textFilter } from "./util.ts";

export type ProcSort = "pid" | "activity" | "name" | "recent";

export interface ProcFilters {
  include: string;
  exclude: string;
  showExited: boolean;
  withFilesOnly: boolean;
  withNetOnly: boolean;
}

export function filterProcesses(
  processes: ProcessInfo[],
  f: ProcFilters,
): ProcessInfo[] {
  const keep = textFilter(f.include, f.exclude);
  return processes.filter(
    (p) =>
      (f.showExited || p.running) &&
      (!f.withFilesOnly || p.fileCount > 0) &&
      (!f.withNetOnly || p.netCount > 0) &&
      keep(`${p.comm} ${p.pid}`),
  );
}

export function sortProcesses(list: ProcessInfo[], sort: ProcSort): ProcessInfo[] {
  const out = list.slice();
  if (sort === "activity") {
    out.sort((a, b) => activity(b) - activity(a));
  } else if (sort === "name") {
    out.sort((a, b) => a.comm.localeCompare(b.comm));
  } else if (sort === "recent") {
    out.sort((a, b) => Number(b.lastSeenMs) - Number(a.lastSeenMs));
  } else {
    out.sort((a, b) => a.pid - b.pid);
  }
  return out;
}

function activity(p: ProcessInfo): number {
  return p.fileCount + p.netCount + p.unixCount + p.execCount;
}

export interface ProcCounts {
  running: number;
  exited: number;
  withFiles: number;
  withNet: number;
}

export function countProcesses(processes: ProcessInfo[]): ProcCounts {
  let running = 0, exited = 0, withFiles = 0, withNet = 0;
  for (const p of processes) {
    if (p.running) running++; else exited++;
    if (p.fileCount > 0) withFiles++;
    if (p.netCount > 0) withNet++;
  }
  return { running, exited, withFiles, withNet };
}

export interface ActivityTotals {
  files: number;
  net: number;
  unix: number;
  exec: number;
}

/** "3f 2n 1x": files, network, unix, exec; zeros left out. */
export function activityLabel(t: ActivityTotals): string {
  return [
    t.files ? `${t.files}f` : "",
    t.net ? `${t.net}n` : "",
    t.unix ? `${t.unix}u` : "",
    t.exec ? `${t.exec}x` : "",
  ]
    .filter(Boolean)
    .join(" ");
}

export function totalActivity(processes: ProcessInfo[]): ActivityTotals {
  let files = 0, net = 0, unix = 0, exec = 0;
  for (const p of processes) {
    files += p.fileCount; net += p.netCount;
    unix += p.unixCount; exec += p.execCount;
  }
  return { files, net, unix, exec };
}

// ---------------------------------------------------------------------------
// Tree (re-parents through filtered-out ancestors)
// ---------------------------------------------------------------------------

export interface TreeRow {
  p: ProcessInfo;
  depth: number;
  prefix: string;
  hasKids: boolean;
  expanded: boolean;
}

export interface TreeInput {
  all: ProcessInfo[];
  visible: ProcessInfo[];
  rootPid: number;
  sort: ProcSort;
}

export function buildProcTree(
  input: TreeInput,
  expanded: Set<number>,
): TreeRow[] {
  const { all, visible, rootPid, sort } = input;
  const byPid = new Map<number, ProcessInfo>();
  for (const p of all) byPid.set(p.pid, p);
  const visibleSet = new Set(visible.map((p) => p.pid));

  // Nearest visible ancestor. Bounded: pid reuse can make parent links cycle.
  const visibleParent = (p: ProcessInfo): number | undefined => {
    let parent = p.parentPid;
    for (let hops = 0; parent != null && hops < byPid.size; hops++) {
      if (visibleSet.has(parent)) return parent === p.pid ? undefined : parent;
      parent = byPid.get(parent)?.parentPid;
    }
    return undefined;
  };

  const children = new Map<number, number[]>();
  const roots: number[] = [];
  if (visibleSet.has(rootPid)) roots.push(rootPid);
  for (const p of visible) {
    if (p.pid === rootPid) continue;
    const parent = visibleParent(p);
    if (parent === undefined) {
      roots.push(p.pid);
    } else {
      const list = children.get(parent) ?? [];
      list.push(p.pid);
      children.set(parent, list);
    }
  }

  const sortPids = (pids: number[]) => {
    const procs = pids.map((x) => byPid.get(x)!).filter(Boolean);
    return sortProcesses(procs, sort).map((p) => p.pid);
  };

  const sortedChildren = new Map<number, number[]>();
  for (const [parent, kids] of children) {
    sortedChildren.set(parent, sortPids(kids));
  }

  const sortedRoots = sortPids(roots);

  const rows: TreeRow[] = [];
  const seen = new Set<number>();
  const walk = (pid: number, depth: number, prefix: string, isLast: boolean) => {
    const p = byPid.get(pid);
    if (!p || seen.has(pid)) return;
    seen.add(pid);
    const kids = sortedChildren.get(pid) ?? [];
    const exp = depth === 0 || expanded.has(pid) || kids.length === 0;
    rows.push({ p, depth, prefix, hasKids: kids.length > 0, expanded: exp });
    if (exp) {
      const childPrefix = depth === 0 ? "" : prefix + (isLast ? "  " : "\u2502 ");
      kids.forEach((kpid, i) => walk(kpid, depth + 1, childPrefix, i === kids.length - 1));
    }
  };

  sortedRoots.forEach((rpid, i) => walk(rpid, 0, "", i === sortedRoots.length - 1));
  return rows;
}

// ---------------------------------------------------------------------------
// Groups (by comm)
// ---------------------------------------------------------------------------

export interface ProcGroup {
  comm: string;
  procs: ProcessInfo[];
  running: number;
  exited: number;
  totals: ActivityTotals;
  maxSeenMs: number;
}

export function groupByComm(
  processes: ProcessInfo[],
  sort: ProcSort,
): ProcGroup[] {
  const map = new Map<string, ProcessInfo[]>();
  for (const p of processes) {
    const list = map.get(p.comm) ?? [];
    list.push(p);
    map.set(p.comm, list);
  }

  const groups: ProcGroup[] = [];
  for (const [comm, procs] of map) {
    let running = 0, exited = 0, maxSeenMs = 0;
    for (const p of procs) {
      if (p.running) running++; else exited++;
      const ls = Number(p.lastSeenMs);
      if (ls > maxSeenMs) maxSeenMs = ls;
    }
    groups.push({ comm, procs, running, exited, totals: totalActivity(procs), maxSeenMs });
  }

  const groupActivity = (g: ProcGroup) =>
    g.totals.files + g.totals.net + g.totals.unix + g.totals.exec;

  if (sort === "activity") groups.sort((a, b) => groupActivity(b) - groupActivity(a));
  else if (sort === "name") groups.sort((a, b) => a.comm.localeCompare(b.comm));
  else if (sort === "recent") groups.sort((a, b) => b.maxSeenMs - a.maxSeenMs);
  else groups.sort((a, b) => b.procs.length - a.procs.length);

  return groups;
}
