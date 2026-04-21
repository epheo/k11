import { store } from "./store.svelte.ts";

/// Run a named RPC, mapping transport errors into the store. Returns the result
/// on success, or `null` on failure (with the error surfaced in `store.error`).
export async function rpc<T>(name: string, fn: () => Promise<T>): Promise<T | null> {
  try {
    const res = await fn();
    if (store.error) store.error = null;
    return res;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[rpc:${name}]`, err);
    store.error = `${name}: ${msg}`;
    return null;
  }
}
