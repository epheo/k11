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
    store.events.filter((e) => {
      if (!e.tag) return false;
      if (!activeTags.has(e.tag)) return false;
      if (failOnly && !e.failed) return false;
      if (store.rawPidFilter !== null && e.pid !== store.rawPidFilter) return false;
      return true;
    })
  );

  let visible = $derived(
    filtered.length > MAX_RENDER ? filtered.slice(filtered.length - MAX_RENDER) : filtered
  );

  $effect(() => {
    // re-run on filtered change; if user is at bottom, keep them there
    visible;
    if (autoScroll && !store.rawCollapsed && feedEl) {
      queueMicrotask(() => {
        if (feedEl) feedEl.scrollTop = feedEl.scrollHeight;
      });
    }
  });

  function onScroll() {
    if (!feedEl) return;
    const atBottom = feedEl.scrollTop + feedEl.clientHeight >= feedEl.scrollHeight - 40;
    autoScroll = atBottom;
  }
</script>

<div class="raw-panel" class:collapsed={store.rawCollapsed}>
  <div class="raw-header">
    <span>
      <span
        role="button"
        tabindex="0"
        onclick={toggleRawCollapsed}
        onkeydown={(e) => e.key === "Enter" && toggleRawCollapsed()}
      >## raw_log ({filtered.length})</span>
      <span class="raw-filters" onclick={(e) => e.stopPropagation()} role="toolbar" tabindex="-1">
        <button
          class="filter-btn"
          class:active={activeTags.size === ALL_TAGS.length}
          onclick={toggleAll}
        >ALL</button>
        {#each ALL_TAGS as t (t)}
          <button
            class="filter-btn"
            class:active={activeTags.has(t)}
            onclick={() => toggleTag(t)}
          >{t}</button>
        {/each}
        <button
          class="filter-btn fail"
          class:active={failOnly}
          onclick={() => (failOnly = !failOnly)}
        >FAIL</button>
      </span>
      {#if store.rawPidFilter !== null}
        <button
          class="pid-filter"
          onclick={(e) => { e.stopPropagation(); setRawPidFilter(null); }}
        >pid:{store.rawPidFilter} [x]</button>
      {/if}
    </span>
    <button class="toggle" onclick={toggleRawCollapsed}>
      {store.rawCollapsed ? "[expand]" : "[collapse]"}
    </button>
  </div>
  <div class="raw-feed" bind:this={feedEl} onscroll={onScroll}>
    {#if filtered.length > MAX_RENDER}
      <div class="raw-truncated">
        showing last {MAX_RENDER} of {filtered.length} events
      </div>
    {/if}
    {#each visible as e (e.id)}
      <div class="raw-line" class:flash={e.sens || e.failed || e.denied || e.audited}>
        <span
          class="tag"
          class:sensitive={e.sens}
          class:fail-tag={e.failed}
          class:denied={e.denied}
          class:audited={e.audited}
        >{e.tag}</span>
        <span class="comm" title="pid {e.pid}">{e.comm}</span>
        <span class="detail" class:sensitive={e.sens} class:fail-tag={e.failed}>
          {e.detail}
        </span>
        {#if e.audited}
          <span class="audit-badge">AUDIT</span>
        {/if}
        <span class="ts" title={formatRelativeTime(Number(e.tsNs / 1000000n))}>
          {formatTime(e.tsNs)}
        </span>
      </div>
    {/each}
  </div>
</div>
