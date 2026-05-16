<script lang="ts">
  import { onMount } from 'svelte';
  import { getMetricsSummary } from '$lib/api';
  import type { MetricsSummary } from '$lib/types';
  import MetricTile from '$components/MetricTile.svelte';
  import { metricsToTiles, sparklinePath } from '$lib/metrics';

  let summary = $state<MetricsSummary | null>(null);
  let err = $state<string | null>(null);

  // Tiny rolling buffers for the two sparklines.
  let rpsHist = $state<number[]>([]);
  let p95Hist = $state<number[]>([]);

  const tiles = $derived(summary ? metricsToTiles(summary) : []);
  const rpsPath = $derived(sparklinePath(rpsHist, 120, 32));
  const p95Path = $derived(sparklinePath(p95Hist, 120, 32));

  async function refresh(): Promise<void> {
    try {
      const m = await getMetricsSummary();
      summary = m;
      rpsHist = [...rpsHist, m.admission_rps].slice(-30);
      p95Hist = [...p95Hist, m.eval_p95_ms].slice(-30);
      err = null;
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(() => {
    void refresh();
    const id = setInterval(refresh, 3_000);
    return () => clearInterval(id);
  });
</script>

<section class="space-y-4">
  <header class="flex items-center justify-between">
    <h1 class="text-2xl font-semibold">Metrics</h1>
    {#if summary?.policy_manager_degraded || summary?.admission_webhook_degraded}
      <span class="rounded badge-degraded px-2 py-1 text-xs font-semibold">Some sources degraded</span>
    {/if}
  </header>

  {#if err}<p class="text-sm text-amber-700">{err}</p>{/if}

  <div class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4" data-testid="metric-grid">
    {#each tiles as tile (tile.key)}
      <MetricTile label={tile.label} value={tile.value} hint={tile.hint} />
    {/each}
  </div>

  <div class="grid grid-cols-1 gap-3 lg:grid-cols-2">
    <div class="rounded-lg border border-slate-200 bg-white p-3">
      <div class="mb-1 text-xs uppercase text-slate-500">Admission RPS (30 samples)</div>
      <svg viewBox="0 0 120 32" class="h-12 w-full">
        <path d={rpsPath} fill="none" stroke="currentColor" stroke-width="1.5" />
      </svg>
    </div>
    <div class="rounded-lg border border-slate-200 bg-white p-3">
      <div class="mb-1 text-xs uppercase text-slate-500">Eval p95 ms (30 samples)</div>
      <svg viewBox="0 0 120 32" class="h-12 w-full">
        <path d={p95Path} fill="none" stroke="currentColor" stroke-width="1.5" />
      </svg>
    </div>
  </div>

  {#if summary?.top_violating_rules?.length}
    <div class="rounded-lg border border-slate-200 bg-white p-3">
      <h2 class="mb-2 text-sm font-semibold">Top violating rules</h2>
      <ol class="space-y-1 text-sm">
        {#each summary.top_violating_rules as r (r.rule_id)}
          <li class="flex justify-between"><span class="font-mono">{r.rule_id}</span><span>{r.count}</span></li>
        {/each}
      </ol>
    </div>
  {/if}
</section>
