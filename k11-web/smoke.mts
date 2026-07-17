// End-to-end smoke test against a running k11d on 127.0.0.1:1100.
// Run from k11-web/: node --experimental-transform-types smoke.mts
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { create } from "@bufbuild/protobuf";
import { createClient } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import {
  K11,
  GetAgentsRequestSchema,
  GetAgentDetailRequestSchema,
  StreamEventsRequestSchema,
} from "./src/gen/k11_pb.ts";

const transport = createGrpcWebTransport({ baseUrl: "http://127.0.0.1:1100" });
const client = createClient(K11, transport);

function ancestors(pid: number): number[] {
  const out: number[] = [];
  let p = pid;
  while (p > 1) {
    out.push(p);
    try {
      const stat = readFileSync(`/proc/${p}/stat`, "utf8");
      p = Number(stat.split(") ")[1].split(" ")[1]);
    } catch {
      break;
    }
  }
  return out;
}

const agents = await client.getAgents(create(GetAgentsRequestSchema, {}));
console.log(`== agents (${agents.agents.length}) ==`);
for (const a of agents.agents) {
  console.log(
    `  root=${a.rootPid} comm=${a.rootComm} procs=${a.processCount} ` +
    `files=${a.fileCount} net=${a.netCount} unix=${a.unixCount} dropped=${a.eventsDropped}`,
  );
}

const roots = new Set(agents.agents.map((a) => a.rootPid));
const myRoot = ancestors(process.pid).find((p) => roots.has(p));
if (!myRoot) {
  console.error("FAIL: this process is not inside any watched agent tree");
  process.exit(1);
}
console.log(`\n== streaming with root_pid filter = ${myRoot} (this session's tree) ==`);

const ac = new AbortController();
type Row = { kind: string; pid: number; comm: string; rootPid: number };
const collected: Row[] = [];
const streamDone = (async () => {
  try {
    const req = create(StreamEventsRequestSchema, { rootPid: myRoot });
    for await (const msg of client.streamEvents(req, { signal: ac.signal })) {
      if (msg.payload.case === "event" && msg.payload.value) {
        const ev = msg.payload.value;
        collected.push({
          kind: ev.payload.case ?? "?",
          pid: ev.pid,
          comm: ev.comm,
          rootPid: ev.rootPid,
        });
      }
    }
  } catch {
    // aborted below — expected
  }
})();

// Let the subscription establish, then generate distinctive kernel activity.
await new Promise((r) => setTimeout(r, 500));
const marker = `/tmp/k11-smoke-${process.pid}`;
const sh = spawn("bash", [
  "-c",
  `set -x
   echo hello > ${marker}.txt
   mv ${marker}.txt ${marker}.renamed
   chmod 600 ${marker}.renamed
   ln -s ${marker}.renamed ${marker}.link
   cat ${marker}.renamed > /dev/null
   rm -f ${marker}.renamed ${marker}.link
   exec 3<>/dev/tcp/127.0.0.1/1100 && exec 3>&-`,
], { stdio: "ignore" });
await new Promise((r) => sh.on("exit", r));
await new Promise((r) => setTimeout(r, 1500));
ac.abort();
await streamDone;

const byKind = new Map<string, number>();
for (const row of collected) byKind.set(row.kind, (byKind.get(row.kind) ?? 0) + 1);
console.log(`captured ${collected.length} events:`, Object.fromEntries(byKind));

const wrongRoot = collected.filter((r) => r.rootPid !== myRoot);
const nonProcess = collected.filter((r) => !["execve", "fork", "exit"].includes(r.kind));
const missingMeta = collected.filter((r) => !r.pid || !r.comm);
console.log(`meta present on all events: ${missingMeta.length === 0 ? "PASS" : "FAIL"}`);
console.log(`all events match filter root: ${wrongRoot.length === 0 ? "PASS" : "FAIL"}`);
console.log(`non-process events pass the filter (C1 fix): ${nonProcess.length > 0 ? "PASS" : "FAIL"}`);

const detail = await client.getAgentDetail(
  create(GetAgentDetailRequestSchema, { rootPid: myRoot }),
);
const smokeFiles = detail.files.filter((f) => f.path.includes("k11-smoke"));
console.log(`\n== detail for root ${myRoot} ==`);
console.log(
  `procs=${detail.processes.length} files=${detail.files.length} ` +
  `conns=${detail.connections.length} unix=${detail.unixSockets.length}`,
);
for (const f of smokeFiles) {
  const flags = [
    f.modified && "modified", f.deleted && "deleted", f.renamed && "renamed",
    f.permChanged && "perm", f.isSymlink && "symlink",
  ].filter(Boolean).join(",");
  console.log(`  smoke file: ${f.path} count=${f.count} [${flags}]`);
}
console.log(`smoke activity aggregated: ${smokeFiles.length > 0 ? "PASS" : "FAIL"}`);
const loopback = detail.connections.find((c) => c.addr.startsWith("127.") && c.port === 1100);
console.log(`loopback connect recorded, not external: ${loopback && !loopback.external ? "PASS" : "FAIL"}`);
