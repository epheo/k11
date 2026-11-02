import { store } from "./store.svelte.ts";

/** True if `path` is covered by a current deny rule (prefix match). */
export function isPathDenied(path: string): boolean {
  if (!store.policy) return false;
  return store.policy.denyFilePaths.some(
    (p) => path.startsWith(p) || (path + "/").startsWith(p),
  );
}
