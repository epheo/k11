<script lang="ts">
  import Ago from "./Ago.svelte";
  import type { ConnectionAccess } from "./gen/k11_pb.ts";
  import { access, countryFlag, type AccessFields } from "./format.ts";
  import { textFilter } from "./util.ts";
  import FilterRow from "./FilterRow.svelte";
  import ErrorsCell from "./ErrorsCell.svelte";
  import { knownHost } from "./known-hosts.ts";

  let { connections, binds }: { connections: ConnectionAccess[]; binds: ConnectionAccess[] } =
    $props();

  let include = $state("");
  let exclude = $state("");

  let keep = $derived(textFilter(include, exclude));
  const matches = (c: ConnectionAccess) => keep(`${c.hostname ?? ""} ${c.addr} ${c.port}`);
  let shownConns = $derived(byHost(connections.filter(matches)));
  let shownBinds = $derived(byHost(binds.filter(matches)));
  // Without the GeoIP databases every row would show two empty columns.
  let geo = $derived(connections.some((c) => c.asn || c.country));
  let external = $derived(connections.some((c) => c.external));
  const hostPort = (c: ConnectionAccess) =>
    c.addr.includes(":") ? `[${c.addr}]:${c.port}` : `${c.addr}:${c.port}`;

  interface Row {
    key: string;
    hostname?: string;
    addrs: string[];
    access: AccessFields;
    external: boolean;
    asn?: string;
    country?: string;
    city?: string;
  }

  /**
   * One row per host and port: a name answers from several addresses, and
   * an IPv6 one fails where there is no IPv6 route.
   */
  function byHost(list: ConnectionAccess[]): Row[] {
    const rows = new Map<string, Row>();
    for (const c of list) {
      const a = access(c);
      const key = c.hostname ? `${c.hostname} ${c.port}` : hostPort(c);
      const row = rows.get(key);
      if (!row) {
        rows.set(key, {
          key,
          hostname: c.hostname,
          addrs: [hostPort(c)],
          access: { ...a, errors: { ...a.errors }, comms: [...a.comms] },
          external: c.external,
          asn: c.asn,
          country: c.country,
          city: c.city,
        });
        continue;
      }
      row.addrs.push(hostPort(c));
      row.access.count += a.count;
      for (const [e, n] of Object.entries(a.errors)) row.access.errors[e] = (row.access.errors[e] ?? 0) + n;
      for (const comm of a.comms) if (!row.access.comms.includes(comm)) row.access.comms.push(comm);
      if (a.lastSeenMs > row.access.lastSeenMs) row.access.lastSeenMs = a.lastSeenMs;
      row.external ||= c.external;
      row.asn ??= c.asn;
      row.country ??= c.country;
      row.city ??= c.city;
    }
    return [...rows.values()];
  }
</script>

<FilterRow bind:include bind:exclude placeholder="filter by host, addr, port..." />

{#snippet table(rows: Row[], remote: boolean)}
  <table class="net-table">
    <thead>
      <tr>
        <th class="col-ext" title={remote ? "leaves this machine's networks" : "reachable from other hosts"}></th>
        <th class="col-addr">address</th>
        <th class="col-count">#</th>
        <th class="col-status">status</th>
        {#if remote && geo}
          <th class="col-asn">asn</th>
          <th class="col-location">location</th>
        {/if}
        <th class="col-comms">process</th>
        <th class="col-time">last seen</th>
      </tr>
    </thead>
    <tbody>
      {#each rows as c (c.key)}
        {@const a = c.access}
        <tr class:external={c.external}>
          <td class="col-ext">{#if c.external}<span class="dot"></span>{/if}</td>
          <td class="col-addr" title={c.addrs.join("\n")}>
            {#if c.hostname}<span class="col-hostname">{c.hostname}</span>{/if}
            {#if knownHost(c.hostname)}<span class="known">{knownHost(c.hostname)}</span>{/if}
            <span class:col-ip={!!c.hostname}>{c.addrs.join(" ")}</span>
          </td>
          <td class="col-count">{a.count}</td>
          <td class="col-status"><ErrorsCell errors={a.errors} count={a.count} /></td>
          {#if remote && geo}
            <td class="col-asn">{c.asn ?? ""}</td>
            <td class="col-location">
              {countryFlag(c.country ?? "")}
              {[c.city, c.country].filter(Boolean).join(", ")}
            </td>
          {/if}
          <td class="col-comms">{a.comms.join(", ")}</td>
          <td class="col-time"><Ago ms={a.lastSeenMs} /></td>
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
{#if external && !geo}
  <div class="tab-hint">
    no owner or location for these addresses: k11 reads them from the GeoLite2 City and ASN
    databases in /usr/share/GeoIP, or where <code>[geoip]</code> in k11.toml says.
  </div>
{/if}
{#if shownBinds.length > 0}
  <h3 class="listen-head">&#9675; bound</h3>
  {@render table(shownBinds, false)}
{/if}
