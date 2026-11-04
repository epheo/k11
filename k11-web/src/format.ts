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
