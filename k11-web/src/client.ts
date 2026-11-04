import { createClient, type Interceptor } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import { K11 } from "./gen/k11_pb.ts";
import { mockTransport } from "./mock.ts";

/**
 * The control token arrives in the URL fragment, which browsers never send
 * to a server, and is removed from the address bar and history. It is kept
 * for this origin, so other tabs, bookmarks and the next daemon start keep
 * control in this browser.
 */
function takeToken(): string | null {
  const given = location.hash.match(/token=([0-9a-f]+)/)?.[1] ?? null;
  if (given) history.replaceState(null, "", location.pathname + location.search);
  try {
    if (given) localStorage.setItem("k11-token", given);
    return localStorage.getItem("k11-token");
  } catch {
    // Site data blocked: control for this page only.
    return given;
  }
}

const token = takeToken();

const auth: Interceptor = (next) => (req) => {
  if (token) req.header.set("authorization", `Bearer ${token}`);
  return next(req);
};

/** Dev builds only: production folds this to false and drops the mock. */
export const mocked = import.meta.env.DEV && new URLSearchParams(location.search).has("mock");

export const client = createClient(
  K11,
  mocked
    ? mockTransport()
    : createGrpcWebTransport({ baseUrl: window.location.origin, interceptors: [auth] }),
);
