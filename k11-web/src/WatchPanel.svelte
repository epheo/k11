<script lang="ts">
  import { AGENT_PRESETS } from "./constants.ts";
  import { store } from "./store.svelte.ts";
  import { setWatch } from "./sync.ts";

  let draft = $state("");

  let names = $derived(store.watch?.names ?? []);
  let editable = $derived(!!store.watch?.writable && !store.watch.all);
  let presets = $derived(AGENT_PRESETS.filter((p) => !names.includes(p.name)));

  function add(name: string) {
    name = name.trim();
    if (name && !names.includes(name)) setWatch([...names, name]);
  }

  function submit(e: SubmitEvent) {
    e.preventDefault();
    add(draft);
    draft = "";
  }
</script>

<div class="sec-head">
  <h2>## watching</h2>
</div>
<div class="watch">
  {#if store.watch?.all}
    <div class="watch-note">every process (watch.all)</div>
  {:else}
    <div class="watch-names">
      {#each names as name (name)}
        <span class="watch-name">
          {name}
          {#if editable}
            <button
              title="stop starting new trees for {name}; recorded ones finish"
              onclick={() => setWatch(names.filter((n) => n !== name))}
            >&times;</button>
          {/if}
        </span>
      {:else}
        <span class="watch-note">nothing yet</span>
      {/each}
    </div>
    {#if editable}
      <form onsubmit={submit}>
        <input
          bind:value={draft}
          placeholder="program name, e.g. claude"
          maxlength="15"
          spellcheck="false"
        />
      </form>
      {#if presets.length}
        <div class="watch-presets">
          {#each presets as p (p.name)}
            <button title="watch programs named {p.name}" onclick={() => add(p.name)}>+ {p.label}</button>
          {/each}
        </div>
      {/if}
    {:else if store.watch}
      <div class="watch-note">read-only: `k11 dashboard` to change</div>
    {/if}
  {/if}
</div>
