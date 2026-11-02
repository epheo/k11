import { store } from "./store.svelte.ts";

/**
 * The deny rule covering `path`, if any. Rules match whole path components,
 * as the kernel matcher does: `/a/b` covers `/a/b` and `/a/b/c`, not `/a/bc`.
 */
export function coveringRule(path: string): string | undefined {
  return store.policy?.denyFilePaths.find((r) => path === r || path.startsWith(r + "/"));
}
