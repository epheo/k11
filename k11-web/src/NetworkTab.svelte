<script lang="ts">
  import type { ConnectionAccess } from "./gen/k11_pb.ts";
  import { access, formatRelativeTime, countryFlag } from "./format.ts";
  import { textFilter } from "./util.ts";
  import FilterRow from "./FilterRow.svelte";
  import ErrorsCell from "./ErrorsCell.svelte";

  let { connections, binds }: { connections: ConnectionAccess[]; binds: ConnectionAccess[] } =
    $props();

  let include = $state("");
  let exclude = $state("");

  let keep = $derived(textFilter(include, exclude));
  const matches = (c: ConnectionAccess) => keep(`${c.hostname ?? ""} ${c.addr} ${c.port}`);
  let shownConns = $derived(connections.filter(matches));
  let shownBinds = $derived(binds.filter(matches));
  const hostPort = (c: ConnectionAccess) =>
    c.addr.includes(":") ? `[${c.addr}]:${c.port}` : `${c.addr}:${c.port}`;
</script>

<FilterRow bind:include bind:exclude placeholder="filter by host, addr, port..." />

{#snippet table(rows: ConnectionAccess[], remote: boolean)}
  <table class="net-table">
    <thead>
      <tr>
        <th class="col-ext" title={remote ? "leaves this machine's networks" : "reachable from other hosts"}></th>
        <th class="col-addr">address</th>
        <th class="col-count">#</th>
        <th class="col-status">status</th>
        {#if remote}
          <th class="col-asn">asn</th>
          <th class="col-location">location</th>
        {/if}
        <th class="col-comms">process</th>
        <th class="col-time">last seen</th>
      </tr>
    </thead>
    <tbody>
      {#each rows as c (`${c.addr} ${c.port}`)}
        {@const a = access(c)}
        <tr class:external={c.external}>
          <td class="col-ext">{#if c.external}<span class="dot"></span>{/if}</td>
          <td class="col-addr">
            {#if c.hostname}<span class="col-hostname">{c.hostname}</span>{/if}
            <span class:col-ip={!!c.hostname}>{hostPort(c)}</span>
          </td>
          <td class="col-count">{a.count}</td>
          <td class="col-status"><ErrorsCell errors={a.errors} /></td>
          {#if remote}
            <td class="col-asn">{c.asn ?? ""}</td>
            <td class="col-location">
              {countryFlag(c.country ?? "")}
              {[c.city, c.country].filter(Boolean).join(", ")}
            </td>
          {/if}
          <td class="col-comms">{a.comms.join(", ")}</td>
          <td class="col-time">{formatRelativeTime(a.lastSeenMs)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/snippet}

{#if shownConns.length === 0 && shownBinds.length === 0}
  <div class="tab-empty">no network activity recorded</div>
{/if}
{#if shownConns.length > 0}
  {@render table(shownConns, true)}
{/if}
{#if shownBinds.length > 0}
  <h3 class="listen-head">&#9675; bound</h3>
  {@render table(shownBinds, false)}
{/if}
