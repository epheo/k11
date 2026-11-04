import type { Access, Container } from "./gen/k11_pb.ts";
import { store } from "./store.svelte.ts";

/** The access fields every aggregate carries, without the message envelope. */
export type AccessFields = Pick<
  Access,
  "count" | "errors" | "comms" | "firstSeenMs" | "lastSeenMs"
>;

const NO_ACCESS: AccessFields = {
  count: 0, errors: {}, comms: [], firstSeenMs: 0n, lastSeenMs: 0n,
};

/** `access` is an optional message on the wire; absent means never accessed. */
export function access(x: { access?: Access }): AccessFields {
  return x.access ?? NO_ACCESS;
}

/** As the runtime's `ps` shows it; "" on the host or in a VM. */
export function containerLabel(c?: Container): string {
  if (!c) return "";
  return `${c.runtime} ${c.name || (/^[0-9a-f]{64}$/.test(c.id) ? c.id.slice(0, 12) : c.id)}`;
}

/** The label's tooltip: the id, which identifies it, and the image. */
export function containerTitle(c?: Container): string {
  if (!c) return "";
  return c.image ? `${c.id}\n${c.image}` : c.id;
}

/** The project an agent works in: its directory's last component. */
export function projectName(cwd: string): string {
  return cwd.replace(/\/+$/, "").split("/").pop() ?? "";
}

/**
 * Its project, else its name. A session in the agent's own directory
 * (~/.claude/chrome) is the agent's helper, not a project.
 */
export function sessionTitle(a: { rootCwd: string; rootComm: string }): string {
  if (a.rootCwd.split("/").includes(`.${a.rootComm}`)) return `${a.rootComm} helper`;
  return projectName(a.rootCwd) || a.rootComm;
}

const startedAt = (ms: bigint) =>
  new Date(Number(ms)).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });

/**
 * What the sidebar titles an agent. Two sessions of one project are told
 * apart by when they started, or by pid when that is the same minute.
 */
export function agentTitle(rootPid: number, name: string): string {
  const a = store.agents.find((x) => x.rootPid === rootPid);
  if (!a) return name;
  const title = sessionTitle(a);
  const same = store.agents.filter((x) => sessionTitle(x) === title);
  if (same.length < 2) return title;
  const at = startedAt(a.firstSeenMs);
  const alone = same.every((x) => x === a || startedAt(x.firstSeenMs) !== at);
  return `${title} (${alone ? at : `pid ${a.rootPid}`})`;
}

/**
 * A binary run under another name reads as that name, the binary after it:
 * Claude Code runs its own binary as `ugrep`, which the kernel names
 * `2.1.317`. A script keeps its name: it is in its command line.
 */
export function processName(p: { comm: string; cmdLine: string }): string {
  const argv0 = /^'([^']*)'|^(\S+)/.exec(p.cmdLine);
  const name = (argv0?.[1] ?? argv0?.[2] ?? "").split("/").pop()!.replace(/^-/, "");
  return name && !p.cmdLine.includes(p.comm) ? `${name} (${p.comm})` : p.comm;
}

/** How long a session lasted: "40s", "12m", "2h 5m". */
export function lasted(fromMs: bigint, toMs: bigint): string {
  const s = Math.max(0, Number(toMs - fromMs) / 1000);
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}

/** 3600 as "3.6k": counts read at a glance. */
export function compact(n: number): string {
  if (n < 1000) return String(n);
  if (n < 10_000) return (Math.floor(n / 100) / 10).toFixed(1).replace(/\.0$/, "") + "k";
  if (n < 1_000_000) return Math.floor(n / 1000) + "k";
  return (Math.floor(n / 100_000) / 10).toFixed(1).replace(/\.0$/, "") + "M";
}

/** "1 command", "3.6k commands". */
export function count(n: number, one: string, many = one + "s"): string {
  return `${compact(n)} ${n === 1 ? one : many}`;
}

/** The date and time to the second, for a tooltip under "12s ago". */
export function formatDateTime(epochMs: bigint | number): string {
  const ms = typeof epochMs === "bigint" ? Number(epochMs) : epochMs;
  return ms ? new Date(ms).toLocaleString("en-GB") : "";
}

/** Format nanosecond epoch timestamp to HH:MM:SS. */
export function formatTime(ns: bigint | number): string {
  if (!ns) return "";
  const ms = typeof ns === "bigint" ? Number(ns / 1000000n) : ns / 1e6;
  const d = new Date(ms);
  return d.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Epoch milliseconds as "12s ago". Reads `store.now`, so it stays current. */
export function formatRelativeTime(epochMs: bigint | number): string {
  const ms = typeof epochMs === "bigint" ? Number(epochMs) : epochMs;
  if (!ms) return "";
  const diffS = Math.floor((store.now - ms) / 1000);
  if (diffS < 0) return "just now";
  if (diffS < 60) return diffS + "s ago";
  if (diffS < 3600) return Math.floor(diffS / 60) + "m ago";
  if (diffS < 86400) return Math.floor(diffS / 3600) + "h ago";
  return Math.floor(diffS / 86400) + "d ago";
}

/** Sum all error counts from an errors map. */
export function totalFailed(errors: { [k: string]: number }): number {
  return Object.values(errors).reduce((a, b) => a + b, 0);
}

/** Format errors map for display: {"ENOENT":3} -> "3 ENOENT" */
export function formatErrors(errors: { [k: string]: number }): string {
  return Object.entries(errors)
    .map(([k, v]) => `${v} ${k}`)
    .join(", ");
}

/** Country ISO code to flag emoji. */
export function countryFlag(iso: string): string {
  if (!iso || iso.length !== 2) return "";
  return String.fromCodePoint(
    ...iso
      .toUpperCase()
      .split("")
      .map((c) => 0x1f1e6 + c.charCodeAt(0) - 65),
  );
}
