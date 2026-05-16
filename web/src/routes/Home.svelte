<script lang="ts">
  import { onMount } from 'svelte';
  import { link } from 'svelte-spa-router';
  import { getMetricsSummary, getRecentDecisions } from '$lib/api';
  import type { MetricsSummary, PublicEvent } from '$lib/types';
  import DecisionRow from '$components/DecisionRow.svelte';

  let summary = $state<MetricsSummary | null>(null);
  let recent = $state<PublicEvent[]>([]);
  let err = $state<string | null>(null);

  async function refresh(): Promise<void> {
    try {
      const [m, r] = await Promise.all([getMetricsSummary(), getRecentDecisions(10)]);
      summary = m;
      recent = r.events ?? [];
      err = null;
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(() => {
    void refresh();
    const id = setInterval(refresh, 5_000);
    return () => clearInterval(id);
  });
</script>

<section class="space-y-6">
  <div class="rounded-xl border border-slate-200 bg-white p-6">
    <h1 class="text-3xl font-semibold">kube-policies</h1>
    <p class="mt-2 max-w-prose text-slate-600">
      A Kubernetes admission policy engine with bundled rules, exception management, and
      transparent decision auditing. This dashboard reads-only by default; writes are gated
      by the BFF (<code>ALLOW_WRITES=true</code>).
    </p>
    <a
      href="/playground"
      use:link
      class="mt-4 inline-flex rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800"
      data-testid="cta-playground"
    >
      Try the Playground →
    </a>
  </div>

  <div class="grid grid-cols-1 gap-4 sm:grid-cols-3" data-testid="home-counters">
    <div class="rounded-lg border border-slate-200 bg-white p-4">
      <div class="text-xs uppercase text-slate-500">Admission RPS</div>
      <div class="text-3xl font-semibold">{summary?.admission_rps.toFixed(2) ?? '—'}</div>
    </div>
    <div class="rounded-lg border border-slate-200 bg-white p-4">
      <div class="text-xs uppercase text-slate-500">Denials / min</div>
      <div class="text-3xl font-semibold">{summary?.denials_per_min.toFixed(1) ?? '—'}</div>
    </div>
    <div class="rounded-lg border border-slate-200 bg-white p-4">
      <div class="text-xs uppercase text-slate-500">Policies loaded</div>
      <div class="text-3xl font-semibold">{summary?.policies_loaded ?? '—'}</div>
    </div>
  </div>

  <div class="rounded-lg border border-slate-200 bg-white">
    <header class="border-b border-slate-200 px-4 py-2">
      <h2 class="text-sm font-semibold">Last 10 decisions</h2>
    </header>
    {#if err}
      <p class="px-4 py-3 text-sm text-amber-700">No live data: {err}</p>
    {:else if recent.length === 0}
      <p class="px-4 py-3 text-sm text-slate-500" data-testid="ticker-empty">
        No decisions yet — try the Playground.
      </p>
    {:else}
      <table class="w-full">
        <tbody>
          {#each recent as e (e.timestamp + e.namespace + (e.name ?? ''))}
            <DecisionRow event={e} />
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</section>
