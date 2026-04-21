import type { ProcessInfo } from "./gen/k11_pb.ts";

export type ProcessNode = ProcessInfo & {
  depth: number;
  children: ProcessNode[];
};

/// Build a forest of ProcessNodes from a flat list, rooted at processes
/// whose parent_pid is missing or not in the set.
export function buildProcessTree(processes: ProcessInfo[]): ProcessNode[] {
  const byPid = new Map<number, ProcessNode>();
  for (const p of processes) {
    byPid.set(p.pid, { ...p, depth: 0, children: [] });
  }
  const roots: ProcessNode[] = [];
  for (const node of byPid.values()) {
    const parent = node.parentPid !== undefined ? byPid.get(node.parentPid) : undefined;
    if (parent) {
      parent.children.push(node);
    } else {
      roots.push(node);
    }
  }
  // Propagate depth.
  const walk = (n: ProcessNode, depth: number) => {
    n.depth = depth;
    n.children.sort((a, b) => a.pid - b.pid);
    for (const c of n.children) walk(c, depth + 1);
  };
  roots.sort((a, b) => a.pid - b.pid);
  for (const r of roots) walk(r, 0);
  return roots;
}

/// Flatten a tree into an ordered list for rendering.
export function flattenTree(nodes: ProcessNode[]): ProcessNode[] {
  const out: ProcessNode[] = [];
  const visit = (n: ProcessNode) => {
    out.push(n);
    for (const c of n.children) visit(c);
  };
  for (const n of nodes) visit(n);
  return out;
}

/// Group processes by comm. Returns one entry per distinct comm, each with
/// the members sorted by pid. Used by ProcessGroups for the summary view.
export function groupByComm(processes: ProcessInfo[]): { comm: string; members: ProcessInfo[] }[] {
  const groups = new Map<string, ProcessInfo[]>();
  for (const p of processes) {
    const list = groups.get(p.comm) ?? [];
    list.push(p);
    groups.set(p.comm, list);
  }
  return Array.from(groups.entries())
    .map(([comm, members]) => ({ comm, members: members.sort((a, b) => a.pid - b.pid) }))
    .sort((a, b) => b.members.length - a.members.length);
}
