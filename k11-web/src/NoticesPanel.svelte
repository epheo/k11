<script lang="ts">
  import { store } from "./store.svelte.ts";
  import { toggleAlerts, unquiet } from "./notices.ts";
  import NoticeRow from "./NoticeRow.svelte";

  let shown = $derived([...store.notices].reverse());

  const close = () => (store.noticesOpen = false);
  // The toggle is outside the panel: let it close the panel itself.
  const outside = (e: PointerEvent) =>
    !(e.target as Element).closest?.(".notices, .notices-toggle") && close();
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
    <NoticeRow {n} />
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
