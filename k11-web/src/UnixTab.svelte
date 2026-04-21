<script lang="ts">
  import type { UnixSocketAccess } from "./gen/k11_pb.ts";

  import { formatRelativeTime, totalFailed, formatErrors } from "./format.ts";

  let { sockets }: { sockets: UnixSocketAccess[] } = $props();

  let filter = $state("");
  let filtered = $derived(
    sockets.filter((s) => !filter || s.path.toLowerCase().includes(filter.toLowerCase())),
  );
</script>

<div class="filter-row">
  <span class="filter-label">find</span>
  <input class="filter-input" placeholder="filter by socket path..." bind:value={filter} />
</div>

{#if filtered.length === 0}
  <div class="tab-empty">no unix socket connections</div>
{:else}
  <table class="net-table">
    <thead>
      <tr>
        <th class="col-addr">socket</th>
        <th class="col-count">#</th>
        <th class="col-status">status</th>
        <th class="col-comms">process</th>
        <th class="col-time">last seen</th>
      </tr>
    </thead>
    <tbody>
      {#each filtered as s (s.path)}
        {@const fails = totalFailed(s.errors)}
        <tr>
          <td class="col-addr">{s.path}</td>
          <td class="col-count">{s.count}</td>
          <td class="col-status">
            {#if fails > 0}
              <span class="fail">{formatErrors(s.errors)}</span>
            {:else}
              <span class="ok">ok</span>
            {/if}
          </td>
          <td class="col-comms">{s.comms.join(", ")}</td>
          <td class="col-time">{formatRelativeTime(s.lastSeenMs)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
