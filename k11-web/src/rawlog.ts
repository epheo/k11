import type { Event } from "./gen/k11_pb.ts";

export type RawLogLine = {
  tsMs: number;
  pid: number;
  tag: string;
  summary: string;
};

/// Flatten an Event into a single human-readable line for the raw panel.
export function eventToRawLine(event: Event): RawLogLine {
  const tsMs = Number(event.timestampNs / 1_000_000n);
  const payload = event.payload;
  if (!payload?.case) {
    return { tsMs, pid: 0, tag: "?", summary: "" };
  }
  switch (payload.case) {
    case "execve": {
      const p = payload.value;
      return { tsMs, pid: p.pid, tag: "execve", summary: `${p.comm} -> ${p.filename}` };
    }
    case "openat": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.pid,
        tag: "openat",
        summary: `${p.comm} ${p.filename} flags=0x${p.flags.toString(16)} ret=${p.ret}`,
      };
    }
    case "connect": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.pid,
        tag: "connect",
        summary: `${p.comm} ${p.addr}:${p.port} ret=${p.ret}`,
      };
    }
    case "fork": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.parentPid,
        tag: "fork",
        summary: `${p.comm} -> ${p.childPid}`,
      };
    }
    case "unixConnect": {
      const p = payload.value;
      return { tsMs, pid: p.pid, tag: "unix", summary: `${p.comm} ${p.path} ret=${p.ret}` };
    }
    case "exit": {
      const p = payload.value;
      return { tsMs, pid: p.pid, tag: "exit", summary: p.comm };
    }
    case "bind": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.pid,
        tag: "bind",
        summary: `${p.comm} ${p.addr}:${p.port} ret=${p.ret}`,
      };
    }
    case "listen": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.pid,
        tag: "listen",
        summary: `${p.comm} backlog=${p.backlog} ret=${p.ret}`,
      };
    }
    case "unlink": {
      const p = payload.value;
      return { tsMs, pid: p.pid, tag: "unlink", summary: `${p.comm} ${p.filename} ret=${p.ret}` };
    }
    case "rename": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.pid,
        tag: "rename",
        summary: `${p.comm} ${p.oldPath} -> ${p.newPath} ret=${p.ret}`,
      };
    }
    case "chmod": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.pid,
        tag: "chmod",
        summary: `${p.comm} ${p.filename} 0o${p.mode.toString(8)} ret=${p.ret}`,
      };
    }
    case "chown": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.pid,
        tag: "chown",
        summary: `${p.comm} ${p.filename} ${p.ownerUid}:${p.ownerGid} ret=${p.ret}`,
      };
    }
    case "symlink": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.pid,
        tag: "symlink",
        summary: `${p.comm} ${p.target} -> ${p.linkpath} ret=${p.ret}`,
      };
    }
    case "ptrace": {
      const p = payload.value;
      return {
        tsMs,
        pid: p.pid,
        tag: "ptrace",
        summary: `${p.comm} req=${p.request} target=${p.targetPid} ret=${p.ret}`,
      };
    }
  }
  return { tsMs, pid: 0, tag: "?", summary: "" };
}
