/// Format a byte count as a compact human-readable string.
export function formatBytes(n: number | bigint): string {
  const v = typeof n === "bigint" ? Number(n) : n;
  if (v < 1024) return `${v}B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)}K`;
  if (v < 1024 * 1024 * 1024) return `${(v / 1024 / 1024).toFixed(1)}M`;
  return `${(v / 1024 / 1024 / 1024).toFixed(1)}G`;
}

/// Clamp a number into `[lo, hi]`.
export function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

/// Return a lowercase-safe substring match.
export function iIncludes(haystack: string, needle: string): boolean {
  if (!needle) return true;
  return haystack.toLowerCase().includes(needle.toLowerCase());
}
