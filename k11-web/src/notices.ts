/**
 * Notices, polled by id. Ids start over with each daemon, so what was read
 * is kept in this browser per daemon start. Desktop alerts are for notices
 * that arrive while a dashboard is open; older ones only count as unread.
 */
import { create } from "@bufbuild/protobuf";

import { client } from "./client.ts";
import { store } from "./store.svelte.ts";
import { select } from "./sync.ts";
import { MAX_NOTICES, NOTICE_BURST, POLL_INTERVAL_MS } from "./constants.ts";
import { ConnectError } from "@connectrpc/connect";
import {
  GetNoticesRequestSchema,
  QuietNoticesRequestSchema,
  type GetNoticesResponse,
  type Notice,
} from "./gen/k11_pb.ts";

const READ_KEY = "k11-notices-read";
const ALERTS_KEY = "k11-alerts";

let epoch = 0n;
let last = 0n;
/** Notices up to here were there before this page, or already alerted. */
let alerted: bigint | null = null;

export function startNotices() {
  store.alerts = keep(() => localStorage.getItem(ALERTS_KEY) === "1") === true && permitted();
  poll();
}

async function poll() {
  try {
    let res = await client.getNotices(create(GetNoticesRequestSchema, { afterId: last }));
    if (res.epoch !== epoch) {
      // A new daemon: ask again from its first notice.
      if (last > 0n) res = await client.getNotices(create(GetNoticesRequestSchema, {}));
      epoch = res.epoch;
      last = 0n;
      store.notices = [];
      const read = keep(() => JSON.parse(localStorage.getItem(READ_KEY) ?? "null"));
      store.readNoticeId = read?.epoch === String(epoch) ? BigInt(read.id) : 0n;
    }
    setQuiet(res);
    if (res.notices.length > 0) {
      last = res.notices[res.notices.length - 1].id;
      store.notices = [...store.notices, ...res.notices].slice(-MAX_NOTICES);
      if (alerted === null) alerted = last;
      else alert(res.notices.filter((n) => n.id > alerted!));
      alerted = last;
    } else if (alerted === null) {
      alerted = 0n;
    }
    if (store.noticesOpen) markRead();
  } catch {
    // The agent poll says when the daemon is unreachable.
  }
  setTimeout(poll, POLL_INTERVAL_MS);
}

function setQuiet(res: GetNoticesResponse) {
  store.quiet = res.quiet;
  store.quietWritable = res.writable;
  store.notices = store.notices.filter((n) => !n.quietKey || !res.quiet.includes(n.quietKey));
}

/** No more notices about `key`, here or in a tree that has not met it yet. */
export const quiet = (key: string) => changeQuiet({ add: [key] });
export const unquiet = (key: string) => changeQuiet({ remove: [key] });

async function changeQuiet(change: { add?: string[]; remove?: string[] }) {
  try {
    const res = await client.quietNotices(create(QuietNoticesRequestSchema, change));
    store.quietWritable = true;
    setQuiet(res);
  } catch (e) {
    store.error = `quiet: ${ConnectError.from(e).rawMessage}`;
  }
}

export function markRead() {
  const id = store.notices.at(-1)?.id ?? 0n;
  if (id <= store.readNoticeId) return;
  store.readNoticeId = id;
  keep(() => localStorage.setItem(READ_KEY, JSON.stringify({ epoch: String(epoch), id: String(id) })));
}

export async function toggleAlerts() {
  if (!store.alerts) {
    if (!("Notification" in window)) {
      store.error = "this browser has no desktop notifications";
      return;
    }
    if ((await Notification.requestPermission()) !== "granted") {
      store.error = "desktop notifications are blocked for this page in the browser's site settings";
      return;
    }
  }
  store.alerts = !store.alerts;
  keep(() => localStorage.setItem(ALERTS_KEY, store.alerts ? "1" : "0"));
}

function alert(fresh: Notice[]) {
  if (!store.alerts || !permitted() || fresh.length === 0) return;
  // A burst is one alert, not a wall of them.
  const notes =
    fresh.length > NOTICE_BURST
      ? [{ title: "k11", body: `${fresh.length} new notices`, notice: fresh[0] }]
      : fresh.map((n) => ({
          title: `k11: ${n.agent}`,
          body: n.peerName ? `${n.summary}\n${n.peerName}` : n.summary,
          notice: n,
        }));
  for (const { title, body, notice } of notes) {
    const note = new Notification(title, { body, tag: `k11-${notice.id}` });
    note.onclick = () => {
      window.focus();
      store.noticesOpen = true;
      select(notice.rootPid);
    };
  }
}

function permitted(): boolean {
  return "Notification" in window && Notification.permission === "granted";
}

/** Site data can be blocked; the page works without it. */
function keep<T>(f: () => T): T | undefined {
  try {
    return f();
  } catch {
    return undefined;
  }
}
