<script lang="ts">
  import { onMount } from "svelte";
  import { store, dismissAgent, restoreDismissed } from "./store.svelte.ts";
  import { start, select, setEnforce } from "./sync.ts";
  import DetailView from "./DetailView.svelte";
  import RawLogPanel from "./RawLogPanel.svelte";
  import "./style.css";

  onMount(start);

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
          title="policy changes need control: open the dashboard with `sudo k11 dashboard`"
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
  </div>
</header>

{#if store.error}
  <div class="error-line">
    {store.error}
    <button onclick={() => (store.error = null)}>[x]</button>
  </div>
{/if}

<div class="main">
  <aside class="sidebar">
    <div class="sec-head">
      <h2>## agents</h2>
    </div>
    <div class="agent-list">
      {#if shown.length === 0}
        <div class="no-agents">no agent activity yet</div>
      {/if}
      {#each shown as a (a.rootPid)}
        <div class="agent-root" class:active={store.selectedPid === a.rootPid} class:dim={a.runningCount === 0}>
          <button class="agent-open" onclick={() => select(a.rootPid)}>
            <div class="name">
              <span class="ind" class:idle={a.runningCount === 0}></span>
              {a.rootComm}
              <span class="risk risk-{a.risk}" title={a.riskReasons.join(", ") || "nothing notable"}>
                {a.risk}
              </span>
            </div>
            {#if a.rootCwd}
              <div class="cwd" title={a.rootCwd}>{a.rootCwd.split("/").slice(-2).join("/")}</div>
            {/if}
            <div class="counters">
              <span class:warn={a.hasSensitiveFiles}>{a.fileCount} fs</span>
              &middot; <span class:warn={a.hasExternalNet}>{a.netCount} conn</span>
              &middot; {a.unixCount} unix
              &middot; {a.execCount} exec
              {#if a.denyCount > 0}
                &middot; <span class="bad">{a.denyCount} denied</span>
              {/if}
              {#if a.auditCount > 0}
                &middot; <span class="warn">{a.auditCount} audited</span>
              {/if}
              {#if a.bindCount > 0}
                &middot; <span class="warn">{a.bindCount} bind</span>
              {/if}
              {#if a.ptraceCount > 0}
                &middot; <span class="bad">{a.ptraceCount} ptrace</span>
              {/if}
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
