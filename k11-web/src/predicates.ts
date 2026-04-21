import { store } from "./store.svelte.ts";

/** True if `path` contains any substring from the server's sensitive-paths list. */
export function isSensitive(path: string): boolean {
  return store.sensitivePaths.some((s) => path.includes(s));
}

/** True if `addr` is not a loopback / unspecified address. */
export function isExternal(addr: string): boolean {
  return (
    !addr.startsWith("127.") &&
    !addr.startsWith("[::1]") &&
    !addr.startsWith("0.0.0.0")
  );
}

/** True if `path` is covered by a current deny rule (prefix match). */
export function isPathDenied(path: string): boolean {
  if (!store.policy) return false;
  return store.policy.denyFilePaths.some(
    (p) => path.startsWith(p) || (path + "/").startsWith(p),
  );
}
