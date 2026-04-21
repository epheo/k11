import type { FileAccess } from "./gen/k11_pb.ts";

export type DirNode = {
  kind: "dir";
  name: string;
  path: string;
  children: Map<string, DirNode | FileNode>;
  fileCount: number;
  sensitiveCount: number;
  deniedCount: number;
};

export type FileNode = {
  kind: "file";
  name: string;
  path: string;
  access: FileAccess;
};

export type TreeNode = DirNode | FileNode;

/// Build a path-indexed directory tree from a flat list of FileAccess entries.
export function buildFileTree(files: FileAccess[]): DirNode {
  const root: DirNode = {
    kind: "dir",
    name: "/",
    path: "/",
    children: new Map(),
    fileCount: 0,
    sensitiveCount: 0,
    deniedCount: 0,
  };

  for (const file of files) {
    const segments = file.path.split("/").filter(Boolean);
    if (segments.length === 0) continue;

    let current = root;
    current.fileCount += 1;
    if (file.sensitive) current.sensitiveCount += 1;
    if (file.denied) current.deniedCount += 1;

    for (let i = 0; i < segments.length - 1; i++) {
      const seg = segments[i];
      const path = "/" + segments.slice(0, i + 1).join("/");
      let next = current.children.get(seg);
      if (!next || next.kind !== "dir") {
        next = {
          kind: "dir",
          name: seg,
          path,
          children: new Map(),
          fileCount: 0,
          sensitiveCount: 0,
          deniedCount: 0,
        };
        current.children.set(seg, next);
      }
      next.fileCount += 1;
      if (file.sensitive) next.sensitiveCount += 1;
      if (file.denied) next.deniedCount += 1;
      current = next;
    }

    const leafName = segments[segments.length - 1];
    current.children.set(leafName, {
      kind: "file",
      name: leafName,
      path: file.path,
      access: file,
    });
  }

  return root;
}

/// Stable child iteration: directories first (by sensitive/denied weight, then
/// name), then files (by count descending).
export function sortedChildren(dir: DirNode): TreeNode[] {
  const entries = Array.from(dir.children.values());
  entries.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === "dir" ? -1 : 1;
    if (a.kind === "dir" && b.kind === "dir") {
      const score = (n: DirNode) => n.deniedCount * 4 + n.sensitiveCount * 2;
      const diff = score(b) - score(a);
      if (diff !== 0) return diff;
      return a.name.localeCompare(b.name);
    }
    if (a.kind === "file" && b.kind === "file") {
      return b.access.count - a.access.count;
    }
    return 0;
  });
  return entries;
}
