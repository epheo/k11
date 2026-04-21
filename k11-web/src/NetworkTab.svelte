<script lang="ts">
  import type { ConnectionAccess } from "./gen/k11_pb.ts";
  import { formatRelativeTime, totalFailed, formatErrors, countryFlag } from "./format.ts";
  import { isExternal } from "./predicates.ts";

  let { connections, binds }: { connections: ConnectionAccess[]; binds: ConnectionAccess[] } = $props();

  let include = $state("");
  let exclude = $state("");

  function filterConns(list: ConnectionAccess[]): ConnectionAccess[] {
    return list.filter((c) => {
      const text = `${c.hostname ?? ""} ${c.addr} ${c.port}`;
      if (include && !text.toLowerCase().includes(include.toLowerCase())) return false;
      if (exclude && text.toLowerCase().includes(exclude.toLowerCase())) return false;
      return true;
    });
  }

  let filteredConns = $derived(filterConns(connections));
  let filteredBinds = $derived(filterConns(binds));
</script>

<div class="filter-row">
  <span class="filter-label">find</span>
  <input class="filter-input" placeholder="filter by host, addr, port..." bind:value={include} />
  <span class="filter-label">not</span>
  <input class="filter-input exclude" placeholder="exclude..." bind:value={exclude} />
</div>

{#if filteredConns.length === 0 && filteredBinds.length === 0}
  <div class="tab-empty">no network activity recorded</div>
{:else}
  {#if filteredConns.length > 0}
    <table class="net-table">
      <thead>
        <tr>
          <th class="col-ext"></th>
          <th class="col-addr">address</th>
          <th class="col-port">port</th>
          <th class="col-count">#</th>
          <th class="col-status">status</th>
          <th class="col-asn">asn</th>
          <th class="col-location">location</th>
          <th class="col-comms">process</th>
          <th class="col-time">last seen</th>
        </tr>
      </thead>
      <tbody>
        {#each filteredConns as c (`${c.addr}:${c.port}`)}
          {@const ext = isExternal(c.addr)}
          {@const fails = totalFailed(c.errors)}
          <tr class:external={ext}>
            <td class="col-ext">{#if ext}<span class="dot"></span>{/if}</td>
            <td class="col-addr">
              {#if c.hostname}
                <span class="col-hostname">{c.hostname}</span>
                <span class="col-ip"> {c.addr}</span>
              {:else}
                {c.addr}
              {/if}
            </td>
            <td class="col-port">{c.port}</td>
            <td class="col-count">{c.count}</td>
            <td class="col-status">
              {#if fails > 0}
                <span class="fail">{formatErrors(c.errors)}</span>
              {:else}
                <span class="ok">ok</span>
              {/if}
            </td>
            <td class="col-asn">{c.asn ?? ""}</td>
            <td class="col-location">
              {#if c.country}{countryFlag(c.country)}{/if}
              {c.city ?? ""}{#if c.country && c.city}, {/if}{c.country ?? ""}
            </td>
            <td class="col-comms">{c.comms.join(", ")}</td>
            <td class="col-time">{formatRelativeTime(c.lastSeenMs)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  {#if filteredBinds.length > 0}
    <h3 class="listen-head">&#9675; listening</h3>
    <table class="net-table">
      <thead>
        <tr>
          <th class="col-ext"></th>
          <th class="col-addr">address</th>
          <th class="col-port">port</th>
          <th class="col-count">#</th>
          <th class="col-status">status</th>
          <th class="col-comms">process</th>
          <th class="col-time">last seen</th>
        </tr>
      </thead>
      <tbody>
        {#each filteredBinds as b (`${b.addr}:${b.port}`)}
          {@const ext = isExternal(b.addr)}
          {@const fails = totalFailed(b.errors)}
          <tr class:external={ext}>
            <td class="col-ext">{#if ext}<span class="dot"></span>{/if}</td>
            <td class="col-addr">{b.addr}</td>
            <td class="col-port">{b.port}</td>
            <td class="col-count">{b.count}</td>
            <td class="col-status">
              {#if fails > 0}
                <span class="fail">{formatErrors(b.errors)}</span>
              {:else}
                <span class="ok">ok</span>
              {/if}
            </td>
            <td class="col-comms">{b.comms.join(", ")}</td>
            <td class="col-time">{formatRelativeTime(b.lastSeenMs)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{/if}
