import { createClient } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";

import { K11 } from "./gen/k11_pb.ts";

const transport = createGrpcWebTransport({
  baseUrl: location.origin,
});

export const client = createClient(K11, transport);
