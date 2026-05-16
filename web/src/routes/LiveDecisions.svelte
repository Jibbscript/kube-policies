<script lang="ts">
  import { onMount } from 'svelte';
  import { getRecentDecisions } from '$lib/api';
  import type { PublicEvent } from '$lib/types';
  import DecisionRow from '$components/DecisionRow.svelte';

  let events = $state<PublicEvent[]>([]);
  let err = $state<string | null>(null);

  let filterDecision = $state<'ALL' | 'ALLOW' | 'DENY'>('ALL');
  let filterNamespace = $state<string>('');

  const filtered = $derived(
    events.filter(
      (e) =>
        (filterDecision === 'ALL' || e.decision === filterDecision) &&
        (filterNamespace === '' ||
          e.namespace.toLowerCase().includes(filterNamespace.toLowerCase())),
    ),
  );

  async function refresh(): Promise<void> {
    try {
      const r = await getRecentDecisions(50);
      events = r.events ?? [];
      err = null;
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(() => {
    void refresh();
    const id = setInterval(refresh, 2_000);
    return () => clearInterval(id);
  });
</script>

<section class="space-y-3">
  <h1 class="text-2xl font-semibold">Live decisions</h1>
  <p class="text-sm text-slate-500">M1 polls <code>/api/decisions/recent</code> every 2 s. M2 will switch to SSE.</p>

  <div class="flex flex-wrap gap-2 text-sm">
    {#each ['ALL', 'ALLOW', 'DENY'] as opt (opt)}
      <button
        type="button"
        class="rounded-full px-3 py-1 {filterDecision === opt ? 'bg-slate-900 text-white' : 'bg-slate-200 text-slate-700'}"
        onclick={() => (filterDecision = opt as 'ALL' | 'ALLOW' | 'DENY')}
        data-testid={`filter-${opt.toLowerCase()}`}
      >
        {opt}
      </button>
    {/each}
    <input
      type="text"
      placeholder="namespace contains…"
      bind:value={filterNamespace}
      class="rounded border border-slate-300 px-2 py-1"
      data-testid="filter-namespace"
    />
  </div>

  {#if err}<p class="text-sm text-amber-700">{err}</p>{/if}

  <table class="w-full rounded-lg border border-slate-200 bg-white text-sm">
    <thead class="border-b border-slate-200 text-left text-xs uppercase text-slate-500">
      <tr>
        <th class="px-3 py-2">Time</th>
        <th class="px-3 py-2">Namespace</th>
        <th class="px-3 py-2">Kind/Name</th>
        <th class="px-3 py-2">Decision</th>
        <th class="px-3 py-2">Rule</th>
        <th class="px-3 py-2 text-right">Latency</th>
      </tr>
    </thead>
    <tbody data-testid="decisions-tbody">
      {#each filtered as e (e.timestamp + e.namespace + (e.name ?? ''))}
        <DecisionRow event={e} />
      {/each}
      {#if filtered.length === 0}
        <tr><td colspan="6" class="px-3 py-4 text-slate-500">No matching decisions.</td></tr>
      {/if}
    </tbody>
  </table>
</section>
