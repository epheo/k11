<script lang="ts">
  import { store, toggleRawCollapsed, setRawPidFilter } from "./store.svelte.ts";
  import { ALL_TAGS, type RawTag } from "./rawlog.ts";
  import { formatTime, formatRelativeTime } from "./format.ts";
  import { RAW_LOG_RENDER_CAP as MAX_RENDER } from "./constants.ts";
  import { toggleInSet } from "./util.ts";

  let activeTags = $state<Set<RawTag>>(new Set(ALL_TAGS));
  let failOnly = $state(false);
  let feedEl: HTMLDivElement | undefined = $state();
  let autoScroll = $state(true);

  const toggleTag = (t: RawTag) => (activeTags = toggleInSet(activeTags, t));
  const toggleAll = () =>
    (activeTags = activeTags.size === ALL_TAGS.length ? new Set() : new Set(ALL_TAGS));

  let filtered = $derived(
    store.events.filter(
      (e) =>
        activeTags.has(e.tag) &&
        (!failOnly || e.failed) &&
        (store.rawPidFilter === null || e.pid === store.rawPidFilter),
    ),
  );
  let visible = $derived(filtered.slice(-MAX_RENDER));

  $effect(() => {
    // Follow new rows while the user sits at the bottom.
    void visible;
    if (autoScroll && !store.rawCollapsed && feedEl) {
      queueMicrotask(() => feedEl && (feedEl.scrollTop = feedEl.scrollHeight));
    }
  });

  function onScroll() {
    if (feedEl) {
      autoScroll = feedEl.scrollTop + feedEl.clientHeight >= feedEl.scrollHeight - 40;
    }
  }
</script>

<div class="raw-panel" class:collapsed={store.rawCollapsed}>
  <div class="raw-header">
    <span>
      <button class="raw-title" onclick={toggleRawCollapsed}>## raw_log ({filtered.length})</button>
      <span class="raw-filters" role="toolbar">
        <button class="filter-btn" class:active={activeTags.size === ALL_TAGS.length} onclick={toggleAll}>
          ALL
        </button>
        {#each ALL_TAGS as t (t)}
          <button class="filter-btn" class:active={activeTags.has(t)} onclick={() => toggleTag(t)}>{t}</button>
        {/each}
        <button class="filter-btn fail" class:active={failOnly} onclick={() => (failOnly = !failOnly)}>
          FAIL
        </button>
      </span>
      {#if store.rawPidFilter !== null}
        <button class="pid-filter" onclick={() => setRawPidFilter(null)}>pid:{store.rawPidFilter} [x]</button>
      {/if}
    </span>
    <button class="toggle" onclick={toggleRawCollapsed}>
      {store.rawCollapsed ? "[expand]" : "[collapse]"}
    </button>
  </div>
  <div class="raw-feed" bind:this={feedEl} onscroll={onScroll}>
    {#if filtered.length > MAX_RENDER}
      <div class="raw-truncated">showing last {MAX_RENDER} of {filtered.length} events</div>
    {/if}
    {#each visible as e (e.seq)}
      <div class="raw-line" class:flash={e.flagged || e.failed || e.denied || e.audited}>
        <span
          class="tag"
          class:sensitive={e.flagged}
          class:fail-tag={e.failed}
          class:denied={e.denied}
          class:audited={e.audited}
        >{e.tag}</span>
        <span class="comm">{e.pid}</span>
        <span class="detail" class:sensitive={e.flagged} class:fail-tag={e.failed}>{e.text}</span>
        <span class="ts" title={formatRelativeTime(Number(e.tsNs / 1000000n))}>{formatTime(e.tsNs)}</span>
      </div>
    {/each}
  </div>
</div>
