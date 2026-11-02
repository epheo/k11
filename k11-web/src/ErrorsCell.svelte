<script lang="ts">
  import { formatErrors } from "./format.ts";

  let { errors }: { errors: { [k: string]: number } } = $props();
  let text = $derived(formatErrors(errors));
</script>

<span class={text ? "fail" : "ok"}>{text || "ok"}</span>
