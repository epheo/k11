import { PolicyOutcome, type Event } from "./gen/k11_pb.ts";

export type RawTag =
  | "EXEC" | "FILE" | "NET" | "FORK" | "EXIT" | "UNIX"
  | "DEL" | "MOV" | "PERM" | "LINK" | "BIND" | "TRACE";

export const ALL_TAGS: RawTag[] = [
  "EXEC", "FILE", "NET", "FORK", "EXIT", "UNIX",
  "DEL", "MOV", "PERM", "LINK", "BIND", "TRACE",
];

export interface ParsedEvent {
  /** Stable render key; events are parsed once on arrival. */
  id: number;
  tag: RawTag | "";
  comm: string;
  detail: string;
  sens: boolean;
  failed: boolean;
  denied: boolean;
  audited: boolean;
  pid: number;
  tsNs: bigint;
}

let nextId = 0;

function errnoStr(ret: number): string {
  return ret < 0 ? ` [errno ${-ret}]` : "";
}

/** Classification (sensitive, external) comes from the server on the wire. */
export function parseRawEvent(ev: Event): ParsedEvent {
  let tag: RawTag | "" = "";
  let detail = "";
  let sens = false;
  let failed = false;
  let denied = false;
  let audited = false;

  const p = ev.payload;
  switch (p.case) {
    case "execve": {
      tag = "EXEC";
      detail = p.value.filename || ev.comm;
      sens = p.value.sensitive;
      break;
    }
    case "openat": {
      tag = "FILE";
      detail = p.value.filename;
      sens = p.value.sensitive;
      failed = p.value.ret < 0;
      denied = p.value.policy === PolicyOutcome.DENIED;
      audited = p.value.policy === PolicyOutcome.AUDITED;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "connect": {
      tag = "NET";
      detail = `${p.value.addr}:${p.value.port}`;
      sens = p.value.external;
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
      detail = `${ev.pid} -> ${p.value.childPid}`;
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
      sens = p.value.sensitive;
      failed = p.value.ret < 0;
      if (failed) detail += errnoStr(p.value.ret);
      break;
    }
    case "rename": {
      tag = "MOV";
      detail = `${p.value.oldPath} -> ${p.value.newPath}`;
      sens = p.value.sensitive;
      failed = p.value.ret < 0;
      break;
    }
    case "chmod": {
      tag = "PERM";
      detail = `chmod ${p.value.filename} mode=${(p.value.mode >>> 0).toString(8)}`;
      sens = p.value.sensitive;
      failed = p.value.ret < 0;
      break;
    }
    case "chown": {
      tag = "PERM";
      detail = `chown ${p.value.filename} uid=${p.value.ownerUid} gid=${p.value.ownerGid}`;
      sens = p.value.sensitive;
      failed = p.value.ret < 0;
      break;
    }
    case "symlink": {
      tag = "LINK";
      detail = `${p.value.linkpath} -> ${p.value.target}`;
      sens = p.value.sensitive;
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

  return {
    id: nextId++,
    tag, comm: ev.comm, detail, sens, failed, denied, audited,
    pid: ev.pid, tsNs: ev.timestampNs,
  };
}
