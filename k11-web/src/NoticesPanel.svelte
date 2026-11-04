<script lang="ts">
  import Ago from "./Ago.svelte";
  import { agentTitle } from "./format.ts";
  import { NoticeKind } from "./gen/k11_pb.ts";
  import { store } from "./store.svelte.ts";
  import { deny, select } from "./sync.ts";
  import { coveringRule } from "./deny.ts";
  import { quiet, toggleAlerts, unquiet } from "./notices.ts";
  
  const TAGS: Record<NoticeKind, string> = {
    [NoticeKind.UNSPECIFIED]: "",
    [NoticeKind.HOST]: "NET",
    [NoticeKind.EXPOSED]: "BIND",
    [NoticeKind.SENSITIVE]: "FILE",
    [NoticeKind.RULE]: "RULE",
    [NoticeKind.PTRACE]: "TRACE",
  };

  let shown = $derived([...store.notices].reverse());

  const close = () => (store.noticesOpen = false);
  // The toggle is outside the panel: let it close the panel itself.
  const outside = (e: PointerEvent) =>
    !(e.target as Element).closest?.(".notices, .notices-toggle") && close();
  let canDeny = $derived(!!store.policy?.writable && !store.policy.unavailable);
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && close()} onpointerdown={outside} />

<div class="notices" role="dialog" aria-label="notices">
  <div class="notices-head">
    <h2>## notices</h2>
    <button
      class="notices-alerts"
      class:on={store.alerts}
      title="a desktop notification for each new notice, while a dashboard is open"
      onclick={toggleAlerts}
    >[desktop alerts: {store.alerts ? "on" : "off"}]</button>
    <button title="close (Esc)" onclick={close}>[x]</button>
  </div>
  {#if shown.length === 0}
    <div class="notices-empty">
      nothing yet.<br />
      k11 tells you here when an agent reaches a host outside this machine's networks,
      opens a port to other hosts, touches a sensitive file, matches a deny rule or
      traces a process: once per agent and target.
    </div>
  {/if}
  {#each shown as n (n.id)}
    <div class="notice" class:unread={n.id > store.readNoticeId}>
      <div class="notice-meta">
        <span class="notice-tag" class:bad={n.kind === NoticeKind.RULE || n.kind === NoticeKind.PTRACE}>
          {TAGS[n.kind]}
        </span>
        <button class="notice-agent" title="show this agent ({n.agent})" onclick={() => select(n.rootPid)}>
          {agentTitle(n.rootPid, n.agent)}
        </button>
        <span class="notice-time"><Ago ms={n.timestampMs} /></span>
      </div>
      <div class="notice-text">{n.summary}</div>
      {#if n.peerName}
        <div class="notice-peer">{n.peerName}</div>
      {/if}
      <div class="notice-actions">
        {#if n.path && canDeny}
          {#if coveringRule(n.path)}
            <span class="deny-btn active" title="covered by the rule {coveringRule(n.path)}">[deny rule]</span>
          {:else}
            <button class="deny-btn" onclick={() => deny(n.path)}>[deny from now on]</button>
          {/if}
        {/if}
        {#if n.quietKey && store.quietWritable}
          <button class="quiet-btn" title="expected: no more notices about {n.quietKey}" onclick={() => quiet(n.quietKey)}>
            [quiet {n.quietKey}]
          </button>
        {/if}
      </div>
    </div>
  {/each}
  {#if store.quiet.length > 0}
    <div class="notices-quiet">
      quiet:
      {#each store.quiet as key (key)}
        <span class="quiet-key">
          {key}{#if store.quietWritable}<button title="tell me again" onclick={() => unquiet(key)}>&times;</button>{/if}
        </span>
      {/each}
    </div>
  {/if}
</div>
