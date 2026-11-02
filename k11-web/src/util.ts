/** A new Set with `key` toggled: Svelte re-tracks on a fresh reference. */
export function toggleInSet<T>(set: ReadonlySet<T>, key: T): Set<T> {
  const next = new Set(set);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  return next;
}

/** Case-insensitive include/exclude match shared by every tab's filter row. */
export function textFilter(include: string, exclude: string): (text: string) => boolean {
  const inc = include.toLowerCase();
  const exc = exclude.toLowerCase();
  return (text) => {
    const t = text.toLowerCase();
    return (!inc || t.includes(inc)) && (!exc || !t.includes(exc));
  };
}
