import type { Access } from "./gen/k11_pb.ts";

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

/** Format epoch milliseconds to relative time string. */
export function formatRelativeTime(epochMs: bigint | number): string {
  const ms = typeof epochMs === "bigint" ? Number(epochMs) : epochMs;
  if (!ms) return "";
  const diffS = Math.floor((Date.now() - ms) / 1000);
  if (diffS < 0) return "just now";
  if (diffS < 60) return diffS + "s ago";
  if (diffS < 3600) return Math.floor(diffS / 60) + "m ago";
  if (diffS < 86400) return Math.floor(diffS / 3600) + "h ago";
  return Math.floor(diffS / 86400) + "d ago";
}

/** Sum all error counts from an errors map. */
export function totalFailed(errors: { [k: string]: number }): number {
  if (!errors) return 0;
  return Object.values(errors).reduce((a, b) => a + b, 0);
}

/** Format errors map for display: {"ENOENT":3} -> "3 ENOENT" */
export function formatErrors(errors: { [k: string]: number }): string {
  if (!errors) return "";
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

interface RiskInput {
  hasSensitiveFiles: boolean;
  hasSensitiveWrites: boolean;
  hasSensitiveDelete: boolean;
  hasExternalNet: boolean;
  hasListener: boolean;
  hasPtrace: boolean;
  denyCount?: number;
  auditCount?: number;
}

/** Compute risk level from agent summary flags. */
export function riskLevel(s: RiskInput): "high" | "med" | "low" {
  if (
    s.hasSensitiveWrites ||
    s.hasSensitiveDelete ||
    s.hasPtrace ||
    (s.denyCount ?? 0) > 0
  ) {
    return "high";
  }
  if (
    s.hasSensitiveFiles ||
    s.hasExternalNet ||
    s.hasListener ||
    (s.auditCount ?? 0) > 0
  ) {
    return "med";
  }
  return "low";
}

/** Human-readable reasons behind a risk badge. */
export function riskReasons(s: RiskInput): string {
  const r: string[] = [];
  if (s.hasSensitiveWrites) r.push("sensitive writes");
  if (s.hasSensitiveDelete) r.push("sensitive deletion");
  if (s.hasSensitiveFiles && s.hasExternalNet) r.push("sensitive files + external net");
  else if (s.hasSensitiveFiles) r.push("sensitive file access");
  else if (s.hasExternalNet) r.push("external network");
  if (s.hasListener) r.push("listening socket");
  if (s.hasPtrace) r.push("ptrace");
  if ((s.denyCount ?? 0) > 0) r.push(`${s.denyCount} denied`);
  if ((s.auditCount ?? 0) > 0) r.push(`${s.auditCount} audited`);
  return r.join(" + ");
}
