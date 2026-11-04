<script lang="ts">
  import { formatDateTime, formatRelativeTime } from "./format.ts";

  let { ms }: { ms: bigint | number } = $props();
</script>

<span title={formatDateTime(ms)}>{formatRelativeTime(ms)}</span>
