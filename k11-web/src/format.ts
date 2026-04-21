/// Format a millis-since-epoch timestamp relative to now, e.g. "3s", "12m", "2h".
export function formatRelativeTime(ms: number | bigint): string {
  const v = typeof ms === "bigint" ? Number(ms) : ms;
  if (!v) return "";
  const delta = Math.max(0, Date.now() - v);
  const s = Math.floor(delta / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  return `${d}d`;
}

/// Sum errno counts from a map.
export function totalFailed(errors: Record<string, number>): number {
  return Object.values(errors).reduce((a, b) => a + b, 0);
}

/// Render errno counts as a compact string: "ENOENT:3 EACCES:1".
export function formatErrors(errors: Record<string, number>): string {
  return Object.entries(errors)
    .map(([k, v]) => (v > 1 ? `${k}:${v}` : k))
    .join(" ");
}

/// Convert a two-letter ISO country code to a regional-indicator flag emoji.
export function countryFlag(iso: string | undefined): string {
  if (!iso || iso.length !== 2) return "";
  const cc = iso.toUpperCase();
  const A = 0x1f1e6 - 0x41;
  return String.fromCodePoint(A + cc.charCodeAt(0), A + cc.charCodeAt(1));
}

/// Human-readable open flags decoder for O_* bits.
export function decodeOpenFlags(flags: number): string {
  const parts: string[] = [];
  const mode = flags & 0o3;
  parts.push(["RD", "WR", "RDWR"][mode] ?? "?");
  if (flags & 0o100) parts.push("CREAT");
  if (flags & 0o200) parts.push("EXCL");
  if (flags & 0o1000) parts.push("TRUNC");
  if (flags & 0o2000) parts.push("APPEND");
  if (flags & 0o4000) parts.push("NONBLOCK");
  if (flags & 0o400000) parts.push("DIRECTORY");
  if (flags & 0o200000) parts.push("NOFOLLOW");
  return parts.join(" ");
}
