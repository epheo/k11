<script lang="ts">
  import { NoticeKind } from "./gen/k11_pb.ts";
  import { onMount } from "svelte";
  import { store } from "./store.svelte.ts";
  import { loadPast, openPast, select } from "./sync.ts";
  import { agentTitle, count, formatDateTime, lasted, sessionTitle } from "./format.ts";
  import NoticeRow from "./NoticeRow.svelte";

  /** The record grows while the page is open; reading it again is cheap. */
  const PAST_REFRESH_MS = 30_000;
  /** The newest; the rest on demand, so notices stay in view. */
  const PAST_SHOWN = 5;
  let allPast = $state(false);
  onMount(() => {
    loadPast();
    const timer = setInterval(loadPast, PAST_REFRESH_MS);
    return () => clearInterval(timer);
  });

  // The serious first: what a person would want to see before the rest.
  const GROUPS: { kind: NoticeKind; title: string }[] = [
    { kind: NoticeKind.RULE, title: "deny rules matched" },
    { kind: NoticeKind.PTRACE, title: "processes traced" },
    { kind: NoticeKind.SENSITIVE, title: "sensitive files" },
    { kind: NoticeKind.EXPOSED, title: "ports open to other hosts" },
    { kind: NoticeKind.HOST, title: "hosts reached" },
  ];

  let look = $derived(store.agents.filter((a) => a.risk !== "low"));
  let running = $derived(store.agents.filter((a) => a.runningCount > 0).length);
  let groups = $derived(
    GROUPS.map((g) => ({ ...g, notices: store.notices.filter((n) => n.kind === g.kind).reverse() })).filter(
      (g) => g.notices.length > 0,
    ),
  );
</script>

<div class="front">
  {#if store.agents.length === 0}
    <div class="empty-card">
      <div class="empty-title">k11</div>
      <div class="empty-desc">
        {store.past.length > 0 ? "no agent session now." : "nothing recorded yet."}<br />
        watch a program on the left, or record one command: <code>k11 run -- &lt;command&gt;</code>
      </div>
    </div>
  {:else}
    <h2>## what your agents did</h2>
    <p class="front-summary">
      {count(store.agents.length, "session")}, {running} running.
      {#if look.length > 0}
        <span class="warn">{look.length} {look.length === 1 ? "needs" : "need"} a look.</span>
      {:else}
        Nothing new needs a look.
      {/if}
    </p>

    {#if look.length > 0}
      <h3 class="listen-head">need a look</h3>
      {#each look as a (a.rootPid)}
        <button class="front-agent" onclick={() => select(a.rootPid)}>
          <span class="risk risk-{a.risk}">{a.risk}</span>
          <span class="front-agent-title">{agentTitle(a.rootPid, a.rootComm)}</span>
          <span class="why">{a.riskReasons.join(", ")}</span>
        </button>
      {/each}
    {/if}
  {/if}

  {#if store.past.length > 0 || store.pastNote}
    <h3 class="listen-head">past sessions{store.past.length > 0 ? ` (${store.past.length})` : ""}</h3>
    {#if store.pastNote}<p class="tab-hint">{store.pastNote}</p>{/if}
    {#each allPast ? store.past : store.past.slice(0, PAST_SHOWN) as p (p.id)}
      {@const s = p.summary!}
      <button class="front-agent" title={p.id} onclick={() => openPast(p.id)}>
        <span class="risk risk-{s.risk}">{s.risk}</span>
        <span class="front-agent-title">{sessionTitle(s)}</span>
        <span class="front-when">{formatDateTime(s.firstSeenMs)}, {lasted(s.firstSeenMs, s.lastSeenMs)}</span>
        {#if s.risk !== "low"}<span class="why">{s.riskReasons.join(", ")}</span>{/if}
      </button>
    {/each}
    {#if store.past.length > PAST_SHOWN}
      <button class="proc-show-all" onclick={() => (allPast = !allPast)}>
        {allPast ? "[show the newest]" : `[show all ${store.past.length}]`}
      </button>
    {/if}
  {/if}

  {#if store.agents.length > 0}
    {#each groups as g (g.kind)}
      <h3 class="listen-head">{g.title} ({g.notices.length})</h3>
      {#each g.notices as n (n.id)}
        <NoticeRow {n} />
      {/each}
    {/each}
    {#if groups.length === 0}
      <p class="tab-hint">
        no notices yet: k11 tells you when an agent reaches a host outside this machine's networks,
        opens a port to other hosts, touches a sensitive file, matches a deny rule or traces a process.
      </p>
    {/if}
  {/if}
</div>
