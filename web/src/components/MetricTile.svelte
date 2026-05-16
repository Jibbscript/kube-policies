<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    label: string;
    value: string;
    hint?: string;
    sparkline?: Snippet;
  }
  let { label, value, hint, sparkline }: Props = $props();
</script>

<div
  class="flex flex-col gap-1 rounded-lg border border-slate-200 bg-white p-4 shadow-sm"
  data-testid="metric-tile"
>
  <span class="text-xs uppercase tracking-wide text-slate-500">{label}</span>
  <span class="text-2xl font-semibold text-slate-900">{value}</span>
  {#if hint}<span class="text-xs text-slate-400">{hint}</span>{/if}
  {#if sparkline}
    <div class="mt-1 h-8 w-full">{@render sparkline()}</div>
  {/if}
</div>
