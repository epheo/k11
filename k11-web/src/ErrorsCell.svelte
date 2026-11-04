<script lang="ts">
  import { formatErrors, totalFailed } from "./format.ts";

  // With `count`, failures among successes read as partial, not as a failure.
  let { errors, count }: { errors: { [k: string]: number }; count?: number } = $props();
  let text = $derived(formatErrors(errors));
  let partial = $derived(count !== undefined && totalFailed(errors) < count);
</script>

<span class={text ? (partial ? "partial" : "fail") : "ok"}>{text || "ok"}</span>
