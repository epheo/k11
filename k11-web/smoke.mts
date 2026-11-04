// End-to-end smoke test against a running `k11 daemon` on 127.0.0.1:1100.
// Run from k11-web/: node --experimental-transform-types smoke.mts
//
// Run it inside a recorded tree: `k11 run -- npm run smoke`, or with
// watch.all. The tree under test is whichever one the daemon attributes this
// process to; everything the test spawns must land in the same tree.
import { existsSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { create } from "@bufbuild/protobuf";
import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import {
  K11,
  GetAgentsRequestSchema,
  GetAgentDetailRequestSchema,
  GetAgentEventsRequestSchema,
  GetPolicyRequestSchema,
  GetWatchRequestSchema,
  SetEnforceRequestSchema,
  SetWatchRequestSchema,
  StreamEventsRequestSchema,
  type Event,
} from "./src/gen/k11_pb.ts";

const transport = createGrpcWebTransport({ baseUrl: "http://127.0.0.1:1100" });
const client = createClient(K11, transport);
const me = process.pid;
const marker = `/tmp/k11-smoke-${me}`;

let failures = 0;
function check(label: string, ok: boolean, detail = "") {
  failures += ok ? 0 : 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` (${detail})` : ""}`);
}

function comm(pid: number): string {
  try {
    return readFileSync(`/proc/${pid}/comm`, "utf8").trim();
  } catch {
    return "?";
  }
}

function ancestors(pid: number): number[] {
  const out: number[] = [];
  let p = pid;
  while (p > 1) {
    out.push(p);
    try {
      // comm may itself contain ") ": the fields start after the last one.
      const stat = readFileSync(`/proc/${p}/stat`, "utf8");
      p = Number(stat.slice(stat.lastIndexOf(") ") + 2).split(" ")[1]);
    } catch {
      break;
    }
  }
  return out;
}

type Row = {
  seq: bigint;
  kind: string;
  pid: number;
  comm: string;
  rootPid: number;
  path: string;
  ret: number;
  tsNs: bigint;
};

function row(ev: Event): Row {
  const p = ev.payload;
  let path = "";
  if (p.case === "open" || p.case === "unlink" || p.case === "chmod" || p.case === "chown") {
    path = p.value.filename;
  } else if (p.case === "rename") {
    path = p.value.newPath;
  } else if (p.case === "connect" || p.case === "bind") {
    path = `${p.value.addr}:${p.value.port}`;
  }
  return {
    seq: ev.seq,
    kind: p.case ?? "?",
    pid: ev.pid,
    comm: ev.comm,
    rootPid: ev.rootPid,
    path,
    ret: ev.ret,
    tsNs: ev.timestampNs,
  };
}

/** Collect every event the stream delivers until `stop` resolves. */
function collect(rootPid: number | undefined): { rows: Row[]; stop: () => Promise<void> } {
  const rows: Row[] = [];
  const ac = new AbortController();
  const done = (async () => {
    try {
      const req = create(StreamEventsRequestSchema, rootPid === undefined ? {} : { rootPid });
      for await (const ev of client.streamEvents(req, { signal: ac.signal })) rows.push(row(ev));
    } catch {
      // aborted below
    }
  })();
  return {
    rows,
    stop: async () => {
      ac.abort();
      await done;
    },
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --- Where are we? ---

const agents = await client.getAgents(create(GetAgentsRequestSchema, {}));
const roots = new Set(agents.agents.map((a) => a.rootPid));
console.log(`== daemon tracks ${agents.agents.length} trees ==`);
console.log("this process and its ancestors (* = tree root according to the daemon):");
for (const p of ancestors(me)) {
  console.log(`  ${roots.has(p) ? "*" : " "} ${p} ${comm(p)}`);
}

// --- Generate activity while streaming everything ---

const all = collect(undefined);
await sleep(500);

const sh = spawn(
  "bash",
  [
    "-c",
    `set -x
     echo hello > ${marker}.txt
     mv ${marker}.txt ${marker}.renamed
     chmod 600 ${marker}.renamed
     ln -s ${marker}.renamed ${marker}.link
     cat ${marker}.renamed > /dev/null
     cd /tmp && cat k11-smoke-${me}-missing 2>/dev/null; rm -f k11-smoke-${me}-missing
     exec 3<>/dev/tcp/127.0.0.1/1100 && exec 3>&-`,
  ],
  { stdio: "ignore" },
);
await new Promise((r) => sh.on("exit", r));

// This process's own activity, so the daemon's attribution of `me` can be read
// straight off the stream.
writeFileSync(`${marker}.self`, "x");
readFileSync(`${marker}.self`);

// Legacy syscall variants (glibc on x86_64 uses rename, chmod, unlink, not
// the *at forms) and a worker thread that exits while its process lives.
const nodeChild = spawn(
  process.execPath,
  [
    "-e",
    `
  const fs = require("fs");
  const { Worker } = require("worker_threads");
  const m = ${JSON.stringify(marker)};
  fs.writeFileSync(m + ".legacy", "x");
  fs.renameSync(m + ".legacy", m + ".legacy2");
  fs.chmodSync(m + ".legacy2", 0o600);
  fs.unlinkSync(m + ".legacy2");
  new Worker("", { eval: true }).on("exit", () => {
    fs.writeFileSync(m + ".done", "x");
    setTimeout(() => {}, 4000);
  });
`,
  ],
  { stdio: "ignore" },
);

// The node child says when its work is done: a slow machine starts node slowly.
for (let waited = 0; !existsSync(`${marker}.done`) && waited < 30_000; waited += 100) await sleep(100);
await sleep(500);
await all.stop();

// --- Attribution: the tree is whatever the daemon says ours is ---

const mine = all.rows.filter((r) => r.pid === me);
if (mine.length === 0) {
  console.error(`FAIL  no events attributed to this process (pid ${me}): is the daemon watching this shell?`);
  console.error(`      ${all.rows.length} events were streamed in total`);
  process.exit(1);
}
const myRoots = [...new Set(mine.map((r) => r.rootPid))];
check("this process has one tree root", myRoots.length === 1, `roots ${myRoots.join(",")}`);
const root = myRoots[0];
console.log(`== tree root ${root} ${comm(root)}: ${all.rows.filter((r) => r.rootPid === root).length} of ${all.rows.length} streamed events ==`);

const ours = all.rows.filter((r) => r.rootPid === root);
const childPids = new Set([sh.pid!, nodeChild.pid!]);
const childRows = all.rows.filter((r) => childPids.has(r.pid));
check(
  "children attributed to the same tree",
  childRows.length > 0 && childRows.every((r) => r.rootPid === root),
  `${childRows.length} child events, roots ${[...new Set(childRows.map((r) => r.rootPid))].join(",")}`,
);

const byKind = new Map<string, number>();
for (const r of ours) byKind.set(r.kind, (byKind.get(r.kind) ?? 0) + 1);
console.log("   kinds:", Object.fromEntries(byKind));

check("meta present on all events", ours.every((r) => r.pid && r.comm));
check("file and network events present", ours.some((r) => !["execve", "fork", "exit"].includes(r.kind)));

// `echo hello > file` is one open; the LSM hook and the syscall exit must not
// both record it.
const txtOpens = ours.filter((r) => r.kind === "open" && r.path === `${marker}.txt`).length;
check("one record per open", txtOpens === 1, `${txtOpens} records for ${marker}.txt`);

// A failed open and an unlink of a relative path are recorded. Resolution to
// an absolute path is best-effort in userspace (it reads /proc/<pid>/cwd,
// which races the process), so accept either the resolved or the raw path.
const missingName = `k11-smoke-${me}-missing`;
const isMissing = (p: string) => p === missingName || p === `/tmp/${missingName}`;
check(
  "relative open and unlink recorded",
  ours.some((r) => r.kind === "open" && isMissing(r.path) && r.ret < 0) &&
    ours.some((r) => r.kind === "unlink" && isMissing(r.path)),
);

// CLOCK_BOOTTIME conversion: every event must land near now, not shifted by
// the machine's accumulated suspend time.
const skewMs = Math.max(...ours.map((r) => Math.abs(Number(r.tsNs / 1000000n) - Date.now())));
check("timestamps within a minute of wall clock", ours.length > 0 && skewMs < 60_000, `max skew ${skewMs} ms`);

// --- Aggregates for the tree ---

const detailRes = await client.getAgentDetail(create(GetAgentDetailRequestSchema, { rootPid: root }));
if (!detailRes.detail) {
  console.error("FAIL  getAgentDetail returned no detail");
  process.exit(1);
}
const detail = detailRes.detail;
console.log(
  `== detail: procs=${detail.processes.length} files=${detail.files.length} ` +
    `conns=${detail.connections.length} unix=${detail.unixSockets.length} ==`,
);
const smokeFiles = detail.files.filter((f) => f.path.startsWith(marker));
for (const f of smokeFiles) {
  const flags = [
    f.modified && "modified",
    f.deleted && "deleted",
    f.renamed && "renamed",
    f.permChanged && "perm",
    f.isSymlink && "symlink",
  ]
    .filter(Boolean)
    .join(",");
  console.log(`   ${f.path} count=${f.access?.count ?? 0} [${flags}]`);
}
check("smoke activity aggregated", smokeFiles.length > 0);

const loopback = detail.connections.find((c) => c.addr.startsWith("127.") && c.port === 1100);
check("loopback connect recorded, not external", !!loopback && !loopback.external);

const legacy = smokeFiles.filter((f) => f.path.includes(".legacy"));
check(
  "legacy syscall variants recorded (rename, chmod, unlink)",
  legacy.some((f) => f.renamed) && legacy.some((f) => f.permChanged) && legacy.some((f) => f.deleted),
);

const nodeProc = detail.processes.find((p) => p.pid === nodeChild.pid);
check("threaded process still running after a worker thread exited", !!nodeProc?.running);
check(
  "a process shows its command line",
  !!nodeProc?.cmdLine.startsWith(`${process.execPath} -e '`),
  nodeProc?.cmdLine.slice(0, 40),
);
const nodeThreads = readdirSync(`/proc/${nodeChild.pid}/task`)
  .map(Number)
  .filter((tid) => tid !== nodeChild.pid);
const phantoms = detail.processes.filter((p) => nodeThreads.includes(p.pid));
check(
  "threads not recorded as processes",
  nodeThreads.length > 0 && phantoms.length === 0,
  `${nodeThreads.length} threads, ${phantoms.length} listed as processes`,
);
nodeChild.kill();
await new Promise((r) => nodeChild.on("exit", r));

// --- Snapshot APIs ---

const tail = await client.getAgentEvents(create(GetAgentEventsRequestSchema, { rootPid: root, limit: 5 }));
const seqs = tail.events.map((e) => e.seq);
const newestStreamed = ours.reduce((max, r) => (r.seq > max ? r.seq : max), 0n);
check(
  "event tail is the newest events, oldest first",
  seqs.length === 5 && seqs.every((s, i) => i === 0 || s > seqs[i - 1]) && seqs[4] >= newestStreamed,
  `seqs ${seqs.join(",")}, newest streamed ${newestStreamed}`,
);

const delta = await client.getAgentDetail(
  create(GetAgentDetailRequestSchema, { rootPid: root, sinceVersion: detailRes.version }),
);
check(
  "detail delta holds only what changed",
  !delta.detail || delta.detail.files.length < detail.files.length,
  `${delta.detail?.files.length ?? 0} of ${detail.files.length} files resent`,
);

const policy = await client.getPolicy(create(GetPolicyRequestSchema, {}));
console.log(`   policy: enforce=${policy.enforce} rules=${policy.denyFilePaths.length} ${policy.unavailable}`);
check("policy is read-only without the control token", !policy.writable);
const setEnforce = (c: typeof client) =>
  c.setEnforce(create(SetEnforceRequestSchema, { enforce: policy.enforce })).then(
    () => "ok",
    (e) => Code[ConnectError.from(e).code],
  );
const anonymous = await setEnforce(client);
check("policy changes refused without the token", anonymous === "PermissionDenied", anonymous);
// The control URL is root-only; as a user this check is skipped.
let controlUrl = "";
try {
  controlUrl = readFileSync("/run/k11/dashboard", "utf8").trim();
} catch {
  console.log("   (control URL not readable: token check skipped)");
}
if (controlUrl) {
  const token = controlUrl.split("#token=")[1];
  const withToken = createClient(
    K11,
    createGrpcWebTransport({
      baseUrl: "http://127.0.0.1:1100",
      interceptors: [(next) => (req) => (req.header.set("authorization", `Bearer ${token}`), next(req))],
    }),
  );
  const accepted = await setEnforce(withToken);
  check("policy changes accepted with the token", accepted === "ok" || accepted === "FailedPrecondition", accepted);

  // --- Watch list, edited at runtime ---
  const setWatch = (c: typeof client, names: string[]) =>
    c.setWatch(create(SetWatchRequestSchema, { names })).then(
      (w) => w.names,
      (e) => Code[ConnectError.from(e).code],
    );
  const watch = await client.getWatch(create(GetWatchRequestSchema, {}));
  check("watch list is read-only without the token", !watch.writable);
  const refused = await setWatch(client, []);
  check("watch changes refused without the token", refused === "PermissionDenied", String(refused));
  // pid 1 is the test VM's init, an idle parent of this tree; on a host it
  // would be systemd and every process below it.
  if (readFileSync("/proc/1/comm", "utf8").trim() === "init") {
    const before = await client.getAgents(create(GetAgentsRequestSchema, {}));
    const added = await setWatch(withToken, [...watch.names, "init"]);
    check("a name added with the token", Array.isArray(added) && added.includes("init"), String(added));
    const after = await client.getAgents(create(GetAgentsRequestSchema, {}));
    const roots = after.agents.map((a) => a.rootPid);
    check("a running process is picked up when its name is watched", roots.includes(1), roots.join(","));
    check(
      "a recorded tree is not split by a watched parent",
      roots.includes(root) && roots.length === before.agents.length + 1,
      roots.join(","),
    );
    await setWatch(withToken, watch.names);
  }
}

// --- Server-side root filter ---

const filtered = collect(root);
await sleep(300);
writeFileSync(`${marker}.filtered`, "x");
unlinkSync(`${marker}.filtered`);
await sleep(700);
await filtered.stop();
check(
  "filtered stream delivers this tree only",
  filtered.rows.length > 0 && filtered.rows.every((r) => r.rootPid === root),
  `${filtered.rows.length} events`,
);

for (const suffix of [".renamed", ".link", ".self", ".done"]) {
  try {
    unlinkSync(`${marker}${suffix}`);
  } catch {
    // already gone
  }
}

console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
