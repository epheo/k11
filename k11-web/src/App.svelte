<script lang="ts">
  import { onMount } from "svelte";
  import { store, dismissAgent, restoreDismissed } from "./store.svelte.ts";
  import { start, select, setEnforce } from "./sync.ts";
  import { startNotices, markRead } from "./notices.ts";
  import { mocked } from "./client.ts";
  import { agentTitle, compact, containerLabel, containerTitle, count, formatRelativeTime } from "./format.ts";
  import { IDLE_AFTER_MS } from "./constants.ts";
  import DetailView from "./DetailView.svelte";
  import WatchPanel from "./WatchPanel.svelte";
  import RawLogPanel from "./RawLogPanel.svelte";
  import NoticesPanel from "./NoticesPanel.svelte";
  import "./style.css";

  onMount(() => {
    start();
    startNotices();
    if (mocked) {
      const view = new URLSearchParams(location.search).get("mock");
      setTimeout(() => {
        select(store.agents[0]?.rootPid ?? null);
        store.noticesOpen = view === "notices";
      }, 300);
    }
  });

  let unread = $derived(store.notices.filter((n) => n.id > store.readNoticeId).length);
  $effect(() => {
    document.title = unread > 0 ? `(${unread}) k11` : "k11";
  });

  function toggleNotices() {
    store.noticesOpen = !store.noticesOpen;
    if (store.noticesOpen) markRead();
  }

  let shown = $derived(store.agents.filter((a) => !store.dismissed.has(a.rootPid)));
  let hidden = $derived(store.agents.length - shown.length);

  function toggleEnforce() {
    const on = !store.policy!.enforce;
    const ask = "Enforce deny rules? Matching opens by watched agents will fail with EPERM.";
    if (!on || confirm(ask)) setEnforce(on);
  }
</script>

<header class="topbar">
  <div class="prompt">
    <span class="host">k11</span>:~$ watch --agents<span class="cursor" aria-hidden="true"></span>
  </div>
  <div class="status">
    <span class="dot" class:off={!store.connected}></span>
    <span>
      {#if store.connected}
        live
      {:else if store.failures > 0}
        daemon unreachable, retrying
      {:else}
        connecting
      {/if}
    </span>
    {#if store.policy}
      {#if store.policy.unavailable}
        <span class="enforce-status off" title={store.policy.unavailable}>record only</span>
      {:else if !store.policy.writable}
        <span
          class="enforce-status off"
          title="changes need control: open the dashboard with `k11 dashboard`"
        >{store.policy.enforce ? "enforcing" : "audit"} &middot; read-only</span>
      {:else}
        <button
          class="enforce-status"
          class:on={store.policy.enforce}
          class:off={!store.policy.enforce}
          title="deny rules: {store.policy.enforce ? 'opens fail with EPERM' : 'matches are recorded, opens go ahead'}"
          onclick={toggleEnforce}
        >
          {store.policy.enforce ? "enforcing" : "audit"}
        </button>
      {/if}
    {/if}
    <button class="notices-toggle" class:unread={unread > 0} onclick={toggleNotices}>
      notices{#if unread > 0}&nbsp;<span class="badge">{unread}</span>{/if}
    </button>
  </div>
  {#if store.noticesOpen}
    <NoticesPanel />
  {/if}
</header>

{#if store.error}
  <div class="error-line">
    {store.error}
    <button onclick={() => (store.error = null)}>[x]</button>
  </div>
{/if}

<div class="main">
  <aside class="sidebar">
    <WatchPanel />
    <div class="sec-head">
      <h2>## agents</h2>
    </div>
    <div class="agent-list">
      {#if shown.length === 0}
        <div class="no-agents">
          no agent activity yet<br />
          watch a program above, or record one command:<br />
          <code>k11 run -- &lt;command&gt;</code>
        </div>
      {/if}
      {#each shown as a (a.rootPid)}
        {@const exited = a.runningCount === 0}
        {@const idle = !exited && a.lastSeenMs > 0n && store.now - Number(a.lastSeenMs) > IDLE_AFTER_MS}
        {@const counters = [
          { n: a.fileCount, text: count(a.fileCount, "file op"), cls: a.hasSensitiveFiles ? "warn" : "" },
          { n: a.netCount, text: count(a.netCount, "connection"), cls: a.hasExternalNet ? "warn" : "" },
          { n: a.unixCount, text: count(a.unixCount, "socket"), cls: "" },
          { n: a.execCount, text: count(a.execCount, "command"), cls: "" },
          { n: a.denyCount, text: `${compact(a.denyCount)} denied`, cls: "bad" },
          { n: a.auditCount, text: `${compact(a.auditCount)} audited`, cls: "warn" },
          { n: a.bindCount, text: count(a.bindCount, "bind"), cls: "warn" },
          { n: a.ptraceCount, text: `${compact(a.ptraceCount)} ptrace`, cls: "bad" },
        ].filter((c) => c.n > 0)}
        <div class="agent-root" class:active={store.selectedPid === a.rootPid} class:dim={exited} class:idle>
          <button class="agent-open" onclick={() => select(a.rootPid)}>
            <div class="name" title={a.rootCwd}>
              <span class="ind" class:idle={exited || idle}></span>
              <span class="project">{agentTitle(a.rootPid, a.rootComm)}</span>
              <span class="risk risk-{a.risk}" title={a.riskReasons.join(", ") || "nothing notable"}>
                {a.risk}
              </span>
            </div>
            <div class="cwd">
              {a.rootComm}
              {#if a.container}
                <span title={containerTitle(a.container)}>in {containerLabel(a.container)}</span>
              {/if}
              {#if idle}<span>(idle {formatRelativeTime(a.lastSeenMs).replace(" ago", "")})</span>{/if}
            </div>
            {#if a.risk !== "low" && a.riskReasons.length > 0}
              <div class="why risk-{a.risk}">{a.riskReasons.join(", ")}</div>
            {/if}
            <div class="counters">
              {#each counters as c, i (c.text)}
                {#if i > 0}{" \u00b7 "}{/if}<span class={c.cls}>{c.text}</span>
              {/each}
              {#if counters.length === 0}nothing yet{/if}
            </div>
          </button>
          <button class="dismiss" title="hide this agent" onclick={() => dismissAgent(a.rootPid)}>[x]</button>
        </div>
      {/each}
      {#if hidden > 0}
        <button class="restore" onclick={restoreDismissed}>{hidden} hidden [show]</button>
      {/if}
    </div>
  </aside>

  <div class="content">
    {#if store.detail}
      <DetailView detail={store.detail} />
    {:else}
      <div class="empty-state">
        <div class="empty-card">
          <div class="empty-title">k11</div>
          <div class="empty-desc">
            kernel-level agent monitor<br />
            select an agent from the sidebar to inspect<br />
            file access, network connections, and process trees
          </div>
          <div class="empty-hint">
            watching process / file / network / unix socket syscalls
          </div>
        </div>
      </div>
    {/if}
  </div>
</div>

{#if store.detail}
  <RawLogPanel />
{/if}
