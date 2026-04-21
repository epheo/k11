/**
 * Wraps a Connect/grpc-web call and logs failures instead of silently swallowing.
 * Returns null on error so callers can do `if (res) store.x = res`.
 */
export async function rpc<T>(label: string, fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn();
  } catch (e) {
    console.warn(`[k11] ${label} failed:`, e);
    return null;
  }
}
