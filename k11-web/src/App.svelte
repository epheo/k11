<script lang="ts">
  import { onMount } from "svelte";

  import { store } from "./store.svelte.ts";
  import { refreshAgents, selectAgent, toggleEnforce } from "./api.ts";
  import { formatRelativeTime } from "./format.ts";
  import DetailView from "./DetailView.svelte";
  import RawLogPanel from "./RawLogPanel.svelte";

  onMount(() => {
    const interval = setInterval(refreshAgents, 3000);
    return () => clearInterval(interval);
  });

  function pick(rootPid: number) {
    selectAgent(rootPid);
  }
</script>

<div class="topbar">
  <div>
    <span class="prompt">k11@</span><span class="host">{store.hostname}</span><span class="cursor"
    ></span>
    {#if store.policy}
      <span
        class="enforce-status"
        class:on={store.policy.enforce}
        class:off={!store.policy.enforce}
        onclick={toggleEnforce}
        onkeydown={(e) => e.key === "Enter" && toggleEnforce()}
        role="button"
        tabindex="0"
      >
        {store.policy.enforce ? "enforcing" : "audit"}
      </span>
    {/if}
  </div>
  <div class="status">
    <span class="dot" class:off={!store.streamConnected}></span>
    {store.streamConnected ? "stream live" : "stream offline"}
    {#if store.error}
      · <span class="bad">{store.error}</span>
    {/if}
  </div>
</div>

<div class="main">
  <aside class="sidebar">
    <div class="agent-list">
      {#if store.agents.length === 0}
        <div class="no-agents">no agents tracked yet</div>
      {:else}
        {#each store.agents as a (a.rootPid)}
          <div
            class="agent-root"
            class:active={a.rootPid === store.selectedPid}
            onclick={() => pick(a.rootPid)}
            onkeydown={(e) => e.key === "Enter" && pick(a.rootPid)}
            role="button"
            tabindex="0"
          >
            <div><span class="name">{a.rootComm}</span> <span class="pid">#{a.rootPid}</span></div>
            <div class="counters">
              {a.processCount} proc · {a.fileCount} files · {a.netCount} net
              {#if a.denyCount > 0}
                &middot; <span class="bad">{a.denyCount} denied</span>
              {/if}
              {#if a.hasSensitiveFiles}
                &middot; <span class="warn">sensitive</span>
              {/if}
              {#if a.hasExternalNet}
                &middot; <span class="warn">external</span>
              {/if}
            </div>
          </div>
        {/each}
      {/if}
    </div>
  </aside>

  <div class="content">
    {#if store.selectedPid !== null && store.detail}
      <DetailView />
    {:else}
      <div class="empty-state">
        <div class="empty-card">
          <div class="empty-title">no agent selected</div>
          <div class="empty-desc">
            select an agent from the sidebar to inspect its process tree, file
            accesses, and network activity.
          </div>
          <div class="empty-hint">
            {store.agents.length === 0
              ? "no agents are running that k11 is watching — start one to see events flow."
              : "agents appear on the left as they fork, open files, or connect."}
          </div>
        </div>
      </div>
    {/if}
    <RawLogPanel />
  </div>
</div>
