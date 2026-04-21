<script lang="ts">
  import { onMount } from "svelte";
  import { store, dismissAgent } from "./store.svelte.ts";
  import {
    loadConfig,
    loadPolicy,
    selectAgent,
    toggleEnforce,
  } from "./api.ts";
  import { startStream } from "./stream.ts";
  import { riskLevel, riskReasons } from "./format.ts";
  import DetailView from "./DetailView.svelte";
  import RawLogPanel from "./RawLogPanel.svelte";
  import "./style.css";

  onMount(() => {
    loadConfig();
    loadPolicy();
    startStream();
  });
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
      {:else if store.reconnectAttempts > 0}
        reconnecting ({store.reconnectAttempts})…
      {:else}
        connecting…
      {/if}
    </span>
    {#if store.policy}
      <button
        class="enforce-status"
        class:on={store.policy.enforce}
        class:off={!store.policy.enforce}
        onclick={toggleEnforce}
      >
        {store.policy.enforce ? "enforcing" : "audit"}
      </button>
    {/if}
  </div>
</header>

<div class="main">
  <aside class="sidebar">
    <div class="sec-head">
      <h2>## agents</h2>
    </div>
    <div class="agent-list">
      {#if store.agents.length === 0}
        <div class="no-agents">waiting for events...</div>
      {:else}
        {#each store.agents.filter((a) => !store.dismissedPids.has(a.rootPid)) as a (a.rootPid)}
          {@const risk = riskLevel(a)}
          {@const reasons = riskReasons(a)}
          {@const activity = a.fileCount + a.netCount + a.execCount}
          {@const allExited = a.processCount > 0 && a.runningCount === 0}
          <button
            class="agent-root"
            class:active={store.selectedPid === a.rootPid}
            class:dim={allExited}
            onclick={() => selectAgent(a.rootPid)}
          >
            <div class="name">
              <span class="ind" class:idle={activity === 0}></span>
              {a.rootComm}
              <span class="risk risk-{risk}" title={reasons || risk}>{risk}</span>
              <span
                class="dismiss"
                role="button"
                tabindex="-1"
                title="dismiss agent"
                onclick={(e) => { e.stopPropagation(); dismissAgent(a.rootPid); }}
                onkeydown={(e) => e.key === "Enter" && dismissAgent(a.rootPid)}
              >[x]</span>
            </div>
            <div class="counters">
              <span class:warn={a.hasSensitiveFiles}>{a.fileCount} fs</span>
              &middot; <span class:warn={a.hasExternalNet}>{a.netCount} conn</span>
              &middot; {a.unixCount} unix
              &middot; {a.execCount} exec
              {#if a.denyCount > 0}
                &middot; <span class="bad">{a.denyCount} denied</span>
              {/if}
              {#if a.bindCount > 0}
                &middot; <span class="warn">{a.bindCount} listen</span>
              {/if}
              {#if a.ptraceCount > 0}
                &middot; <span class="bad">{a.ptraceCount} ptrace</span>
              {/if}
            </div>
          </button>
        {/each}
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
            kernel-level agent monitor<br>
            select an agent from the sidebar to inspect<br>
            file access, network connections, and process trees
          </div>
          <div class="empty-hint">
            watching execve / openat / connect / fork / exit
          </div>
        </div>
      </div>
    {/if}
  </div>
</div>

{#if store.detail}
  <RawLogPanel />
{/if}
