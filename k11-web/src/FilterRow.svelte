<script lang="ts">
  let {
    include = $bindable(""),
    exclude = $bindable(""),
    placeholder,
  }: { include: string; exclude: string; placeholder: string } = $props();
</script>

<div class="filter-row">
  <span class="filter-label">find</span>
  <input class="filter-input" {placeholder} bind:value={include} />
  <span class="filter-label">not</span>
  <input class="filter-input exclude" placeholder="exclude..." bind:value={exclude} />
</div>
