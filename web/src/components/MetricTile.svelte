<script lang="ts">
  interface Props {
    label: string;
    value: string;
    hint?: string;
  }
  let { label, value, hint }: Props = $props();
</script>

<div
  class="flex flex-col gap-1 rounded-lg border border-slate-200 bg-white p-4"
  data-testid="metric-tile"
>
  <span class="text-xs uppercase tracking-wide text-slate-500">{label}</span>
  <span class="text-2xl font-semibold text-slate-900">{value}</span>
  {#if hint}<span class="text-xs text-slate-400">{hint}</span>{/if}
</div>
