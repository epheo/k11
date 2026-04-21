import type { Event } from "./gen/k11_pb.ts";
import { isSensitive, isExternal } from "./predicates.ts";

export type RawTag =
  | "EXEC" | "FILE" | "NET" | "FORK" | "EXIT" | "UNIX"
  | "DEL" | "MOV" | "PERM" | "LINK" | "BIND" | "TRACE";

export const ALL_TAGS: RawTag[] = [
  "EXEC", "FILE", "NET", "FORK", "EXIT", "UNIX",
  "DEL", "MOV", "PERM", "LINK", "BIND", "TRACE",
];

export interface ParsedEvent {
  tag: RawTag | "";
  detail: string;
  sens: boolean;
  failed: boolean;
  denied: boolean;
  pid: number | null;
  tsNs: bigint;
}

function errnoStr(ret: number): string {
  return ret < 0 ? ` [errno ${-ret}]` : "";
}

export function parseRawEvent(ev: Event): ParsedEvent {
  const tsNs = ev.timestampNs;
  let tag: RawTag | "" = "";
  let detail = "";
  let sens = false;
  let failed = false;
  let denied = false;
  let pid: number | null = null;

  const p = ev.payload;
  switch (p.case) {
    case "execve": {
      tag = "EXEC"; pid = p.value.pid;
      detail = p.value.filename || p.value.comm;
      denied = p.value.denied;
      break;
    }
    case "openat": {
      tag = "FILE"; pid = p.value.pid;
      detail = p.value.filename;
      sens = isSensitive(p.value.filename);
      failed = p.value.ret < 0;
      denied = p.value.denied;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "connect": {
      tag = "NET"; pid = p.value.pid;
      detail = `${p.value.addr}:${p.value.port}`;
      sens = isExternal(p.value.addr);
      failed = p.value.ret < 0;
      denied = p.value.denied;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "unixConnect": {
      tag = "UNIX"; pid = p.value.pid;
      detail = p.value.path || "";
      failed = p.value.ret < 0;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "fork": {
      tag = "FORK"; pid = p.value.parentPid;
      detail = `${p.value.parentPid} \u2192 ${p.value.childPid}`;
      break;
    }
    case "exit": {
      tag = "EXIT"; pid = p.value.pid;
      detail = `pid:${p.value.pid}`;
      break;
    }
    case "bind": {
      tag = "BIND"; pid = p.value.pid; sens = true;
      detail = `bind ${p.value.addr}:${p.value.port}`;
      failed = p.value.ret < 0;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "listen": {
      tag = "BIND"; pid = p.value.pid; sens = true;
      detail = `listen backlog=${p.value.backlog}`;
      failed = p.value.ret < 0;
      break;
    }
    case "unlink": {
      tag = "DEL"; pid = p.value.pid;
      detail = `unlink ${p.value.filename}`;
      sens = isSensitive(p.value.filename);
      failed = p.value.ret < 0;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "rename": {
      tag = "MOV"; pid = p.value.pid;
      detail = `${p.value.oldPath} \u2192 ${p.value.newPath}`;
      sens = isSensitive(p.value.oldPath) || isSensitive(p.value.newPath);
      failed = p.value.ret < 0;
      break;
    }
    case "chmod": {
      tag = "PERM"; pid = p.value.pid;
      detail = `chmod ${p.value.filename} mode=${(p.value.mode >>> 0).toString(8)}`;
      sens = isSensitive(p.value.filename);
      failed = p.value.ret < 0;
      break;
    }
    case "chown": {
      tag = "PERM"; pid = p.value.pid;
      detail = `chown ${p.value.filename} uid=${p.value.ownerUid} gid=${p.value.ownerGid}`;
      sens = isSensitive(p.value.filename);
      failed = p.value.ret < 0;
      break;
    }
    case "symlink": {
      tag = "LINK"; pid = p.value.pid;
      detail = `${p.value.linkpath} \u2192 ${p.value.target}`;
      sens = isSensitive(p.value.target) || isSensitive(p.value.linkpath);
      failed = p.value.ret < 0;
      break;
    }
    case "ptrace": {
      tag = "TRACE"; pid = p.value.pid; sens = true;
      detail = `ptrace req=${p.value.request} target=${p.value.targetPid}`;
      failed = p.value.ret < 0;
      break;
    }
  }

  return { tag, detail, sens, failed, denied, pid, tsNs };
}
