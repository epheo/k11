<script lang="ts">
  import type { UnixSocketAccess } from "./gen/k11_pb.ts";
  import { access, formatRelativeTime } from "./format.ts";
  import { textFilter } from "./util.ts";
  import FilterRow from "./FilterRow.svelte";
  import ErrorsCell from "./ErrorsCell.svelte";

  let { sockets }: { sockets: UnixSocketAccess[] } = $props();

  let include = $state("");
  let exclude = $state("");
  let keep = $derived(textFilter(include, exclude));
  let shown = $derived(sockets.filter((s) => keep(s.path)));
</script>

<FilterRow bind:include bind:exclude placeholder="filter by path..." />

{#if shown.length === 0}
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
      {#each shown as s (s.path)}
        {@const a = access(s)}
        <tr>
          <td class="col-addr">{s.path}</td>
          <td class="col-count">{a.count}</td>
          <td class="col-status"><ErrorsCell errors={a.errors} /></td>
          <td class="col-comms">{a.comms.join(", ")}</td>
          <td class="col-time">{formatRelativeTime(a.lastSeenMs)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
