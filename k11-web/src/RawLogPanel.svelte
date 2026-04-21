<script lang="ts">
  import { store } from "./store.svelte.ts";
  import { eventToRawLine } from "./rawlog.ts";
  import { formatRelativeTime } from "./format.ts";

  let include = $state("");

  let filtered = $derived.by(() => {
    const lines = store.rawLog.map(eventToRawLine);
    const pidFilter = store.rawPidFilter;
    return lines.filter((line) => {
      if (pidFilter !== null && line.pid !== pidFilter) return false;
      if (include) {
        const q = include.toLowerCase();
        if (
          !line.tag.includes(q) &&
          !line.summary.toLowerCase().includes(q) &&
          !String(line.pid).includes(q)
        ) {
          return false;
        }
      }
      return true;
    });
  });

  function toggleRawCollapsed() {
    store.rawCollapsed = !store.rawCollapsed;
  }
</script>

<div class="raw-panel" class:collapsed={store.rawCollapsed}>
  <div
    class="raw-header"
    onclick={toggleRawCollapsed}
    onkeydown={(e) => e.key === "Enter" && toggleRawCollapsed()}
    role="button"
    tabindex="0"
  >
    <span>## raw_log ({filtered.length})</span>
    <span class="raw-filters" onclick={(e) => e.stopPropagation()} role="toolbar" tabindex="-1">
      <button
        class="filter-btn"
        onclick={(e) => {
          e.stopPropagation();
          store.rawLog = [];
        }}
      >
        clear
      </button>
      <input
        class="filter-input"
        placeholder="filter..."
        bind:value={include}
        onclick={(e) => e.stopPropagation()}
      />
      {#if store.rawPidFilter !== null}
        <span class="pid-filter">
          pid={store.rawPidFilter}
          <span
            class="dismiss"
            onclick={(e) => {
              e.stopPropagation();
              store.rawPidFilter = null;
            }}
            onkeydown={(e) => e.key === "Enter" && (store.rawPidFilter = null)}
            role="button"
            tabindex="0"
          >
            ×
          </span>
        </span>
      {/if}
    </span>
  </div>
  {#if !store.rawCollapsed}
    <div class="raw-feed">
      {#each filtered.slice(-300) as line, i (i)}
        <div class="raw-line">
          <span class="ts">{formatRelativeTime(line.tsMs)}</span>
          <span class="tag">{line.tag}</span>
          <span class="pid">#{line.pid}</span>
          <span>{line.summary}</span>
        </div>
      {/each}
      {#if filtered.length > 300}
        <div class="raw-truncated">… {filtered.length - 300} older lines hidden</div>
      {/if}
    </div>
  {/if}
</div>
