import { PolicyOutcome, type Event } from "./gen/k11_pb.ts";

const TAGS = {
  execve: "EXEC",
  open: "FILE",
  connect: "NET",
  unixConnect: "UNIX",
  fork: "FORK",
  exit: "EXIT",
  bind: "BIND",
  listen: "BIND",
  unlink: "DEL",
  rename: "MOV",
  chmod: "PERM",
  chown: "PERM",
  symlink: "LINK",
  ptrace: "TRACE",
  resolve: "DNS",
  resolverConnect: "DNS",
} as const;

export type RawTag = (typeof TAGS)[keyof typeof TAGS];

export const ALL_TAGS: readonly RawTag[] = [...new Set(Object.values(TAGS))];

export interface ParsedEvent {
  seq: bigint;
  tag: RawTag;
  /** The server's one-line summary. */
  text: string;
  pid: number;
  tsNs: bigint;
  /** Sensitive path or external address. */
  flagged: boolean;
  failed: boolean;
  denied: boolean;
  audited: boolean;
}

/** Everything but the tag comes classified from the server. */
export function parseRawEvent(ev: Event): ParsedEvent | null {
  const p = ev.payload;
  if (!p.case) return null;
  const policy = p.case === "open" ? p.value.policy : PolicyOutcome.ALLOWED;
  return {
    seq: ev.seq,
    tag: TAGS[p.case],
    text: ev.summary,
    pid: ev.pid,
    tsNs: ev.timestampNs,
    flagged: ev.sensitive || ev.external,
    failed: ev.error !== "",
    denied: policy === PolicyOutcome.DENIED,
    audited: policy === PolicyOutcome.AUDITED,
  };
}
