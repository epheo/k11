<script lang="ts">
  import type { UnixSocketAccess } from "./gen/k11_pb.ts";
  import { access, formatRelativeTime, totalFailed, formatErrors } from "./format.ts";

  let { sockets }: { sockets: UnixSocketAccess[] } = $props();

  let include = $state("");
  let exclude = $state("");

  let filtered = $derived(
    sockets.filter((s) => {
      if (include && !s.path.toLowerCase().includes(include.toLowerCase())) return false;
      if (exclude && s.path.toLowerCase().includes(exclude.toLowerCase())) return false;
      return true;
    })
  );
</script>

<div class="filter-row">
  <span class="filter-label">find</span>
  <input class="filter-input" placeholder="filter by path..." bind:value={include} />
  <span class="filter-label">not</span>
  <input class="filter-input exclude" placeholder="exclude..." bind:value={exclude} />
</div>

{#if filtered.length === 0}
  <div class="tab-empty">no unix socket activity recorded</div>
{:else}
  <table class="net-table">
    <thead>
      <tr>
        <th class="col-addr">path</th>
        <th class="col-count">#</th>
        <th class="col-status">status</th>
        <th class="col-comms">process</th>
        <th class="col-time">last seen</th>
      </tr>
    </thead>
    <tbody>
      {#each filtered as s (s.path)}
        {@const a = access(s)}
        {@const fails = totalFailed(a.errors)}
        <tr>
          <td class="col-addr">{s.path}</td>
          <td class="col-count">{a.count}</td>
          <td class="col-status">
            {#if fails > 0}
              <span class="fail">{formatErrors(a.errors)}</span>
            {:else}
              <span class="ok">ok</span>
            {/if}
          </td>
          <td class="col-comms">{a.comms.join(", ")}</td>
          <td class="col-time">{formatRelativeTime(a.lastSeenMs)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
