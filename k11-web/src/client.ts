import { createClient, type Interceptor } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import { K11 } from "./gen/k11_pb.ts";
import { mockTransport } from "./mock.ts";

/**
 * The control token arrives in the URL fragment, which browsers never send
 * to a server. It is kept for this tab (reloads included) and removed from
 * the address bar and history.
 */
function takeToken(): string | null {
  const match = location.hash.match(/token=([0-9a-f]+)/);
  if (match) {
    sessionStorage.setItem("k11-token", match[1]);
    history.replaceState(null, "", location.pathname + location.search);
  }
  return sessionStorage.getItem("k11-token");
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
