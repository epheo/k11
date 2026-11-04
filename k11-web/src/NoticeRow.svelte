<script lang="ts">
  import Ago from "./Ago.svelte";
  import { agentTitle } from "./format.ts";
  import { knownHost } from "./known-hosts.ts";
  import { NoticeKind, type Notice } from "./gen/k11_pb.ts";
  import { store } from "./store.svelte.ts";
  import { deny, select } from "./sync.ts";
  import { coveringRule } from "./deny.ts";
  import { quiet } from "./notices.ts";

  let { n }: { n: Notice } = $props();

  const TAGS: Record<NoticeKind, string> = {
    [NoticeKind.UNSPECIFIED]: "",
    [NoticeKind.HOST]: "NET",
    [NoticeKind.EXPOSED]: "BIND",
    [NoticeKind.SENSITIVE]: "FILE",
    [NoticeKind.RULE]: "RULE",
    [NoticeKind.PTRACE]: "TRACE",
  };

  let known = $derived(n.kind === NoticeKind.HOST ? knownHost(n.quietKey) : undefined);
  let canDeny = $derived(!!store.policy?.writable && !store.policy.unavailable);
</script>

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
  {#if n.peerName || known}
    <div class="notice-peer">
      {n.peerName}{#if known}{n.peerName ? " \u00b7 " : ""}<span class="known">{known}</span>{/if}
    </div>
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
