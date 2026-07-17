import { store } from "./store.svelte.ts";

/** True if `path` contains any substring from the server's sensitive-paths list. */
export function isSensitive(path: string): boolean {
  return store.sensitivePaths.some((s) => path.includes(s));
}

/**
 * True if `addr` is routable beyond this machine and its private networks.
 * Mirrors the server's is_external_addr (store.rs) — keep in sync.
 */
export function isExternal(addr: string): boolean {
  const a = (addr.startsWith("[") && addr.endsWith("]") ? addr.slice(1, -1) : addr).toLowerCase();
  if (a === "0.0.0.0" || a === "::" || a === "::1") return false;
  if (a.startsWith("127.") || a.startsWith("10.") || a.startsWith("192.168.")) return false;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(a)) return false;
  if (a.startsWith("169.254.")) return false;
  if (/^fe[89ab]/.test(a)) return false;
  if (a.startsWith("fc") || a.startsWith("fd")) return false;
  return true;
}

/** True if `path` is covered by a current deny rule (prefix match). */
export function isPathDenied(path: string): boolean {
  if (!store.policy) return false;
  return store.policy.denyFilePaths.some(
    (p) => path.startsWith(p) || (path + "/").startsWith(p),
  );
}
