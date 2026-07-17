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
  comm: string;
  detail: string;
  sens: boolean;
  failed: boolean;
  denied: boolean;
  pid: number;
  tsNs: bigint;
}

function errnoStr(ret: number): string {
  return ret < 0 ? ` [errno ${-ret}]` : "";
}

export function parseRawEvent(ev: Event): ParsedEvent {
  let tag: RawTag | "" = "";
  let detail = "";
  let sens = false;
  let failed = false;
  let denied = false;

  const p = ev.payload;
  switch (p.case) {
    case "execve": {
      tag = "EXEC";
      detail = p.value.filename || ev.comm;
      break;
    }
    case "openat": {
      tag = "FILE";
      detail = p.value.filename;
      sens = isSensitive(p.value.filename);
      failed = p.value.ret < 0;
      denied = p.value.denied;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "connect": {
      tag = "NET";
      detail = `${p.value.addr}:${p.value.port}`;
      sens = isExternal(p.value.addr);
      failed = p.value.ret < 0;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "unixConnect": {
      tag = "UNIX";
      detail = p.value.path || "";
      failed = p.value.ret < 0;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "fork": {
      tag = "FORK";
      detail = `${ev.pid} → ${p.value.childPid}`;
      break;
    }
    case "exit": {
      tag = "EXIT";
      detail = `pid:${ev.pid}`;
      break;
    }
    case "bind": {
      tag = "BIND"; sens = true;
      detail = `bind ${p.value.addr}:${p.value.port}`;
      failed = p.value.ret < 0;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "listen": {
      tag = "BIND"; sens = true;
      detail = `listen backlog=${p.value.backlog}`;
      failed = p.value.ret < 0;
      break;
    }
    case "unlink": {
      tag = "DEL";
      detail = `unlink ${p.value.filename}`;
      sens = isSensitive(p.value.filename);
      failed = p.value.ret < 0;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "rename": {
      tag = "MOV";
      detail = `${p.value.oldPath} → ${p.value.newPath}`;
      sens = isSensitive(p.value.oldPath) || isSensitive(p.value.newPath);
      failed = p.value.ret < 0;
      break;
    }
    case "chmod": {
      tag = "PERM";
      detail = `chmod ${p.value.filename} mode=${(p.value.mode >>> 0).toString(8)}`;
      sens = isSensitive(p.value.filename);
      failed = p.value.ret < 0;
      break;
    }
    case "chown": {
      tag = "PERM";
      detail = `chown ${p.value.filename} uid=${p.value.ownerUid} gid=${p.value.ownerGid}`;
      sens = isSensitive(p.value.filename);
      failed = p.value.ret < 0;
      break;
    }
    case "symlink": {
      tag = "LINK";
      detail = `${p.value.linkpath} → ${p.value.target}`;
      sens = isSensitive(p.value.target) || isSensitive(p.value.linkpath);
      failed = p.value.ret < 0;
      break;
    }
    case "ptrace": {
      tag = "TRACE"; sens = true;
      detail = `ptrace req=${p.value.request} target=${p.value.targetPid}`;
      failed = p.value.ret < 0;
      break;
    }
  }

  return { tag, comm: ev.comm, detail, sens, failed, denied, pid: ev.pid, tsNs: ev.timestampNs };
}
