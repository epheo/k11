/**
 * Return a new Set with `key` toggled (added if absent, removed if present).
 *
 * Svelte reactivity needs a fresh reference to re-track, so we always clone.
 * Prefer this over the `new Set(s); if (has) delete else add; return s;` pattern.
 */
export function toggleInSet<T>(set: ReadonlySet<T>, key: T): Set<T> {
  const next = new Set(set);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  return next;
}
