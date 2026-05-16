<script lang="ts">
  import { onMount } from 'svelte';
  import { getMetricsSummary, getRecentDecisions } from '$lib/api';

  let degraded = $state(false);
  let emptyTickerSince: number | null = null;
  let lastReason = $state<string | null>(null);

  async function poll(): Promise<void> {
    try {
      const m = await getMetricsSummary();
      if (m.policy_manager_degraded || m.admission_webhook_degraded) {
        degraded = true;
        lastReason = 'metrics source unavailable';
        return;
      }
    } catch {
      degraded = true;
      lastReason = 'metrics endpoint error';
      return;
    }

    try {
      const r = await getRecentDecisions(10);
      if (!r.events || r.events.length === 0) {
        if (emptyTickerSince === null) emptyTickerSince = Date.now();
        if (Date.now() - emptyTickerSince >= 60_000) {
          degraded = true;
          lastReason = 'no cluster traffic in 60s';
          return;
        }
      } else {
        emptyTickerSince = null;
        degraded = false;
        lastReason = null;
      }
    } catch {
      // Recent endpoint failure isn't enough on its own to flip the banner.
    }
  }

  onMount(() => {
    void poll();
    const id = setInterval(poll, 5_000);
    return () => clearInterval(id);
  });
</script>

{#if degraded}
  <div
    role="alert"
    data-testid="mode-banner"
    class="bg-amber-100 px-4 py-2 text-center text-sm text-amber-900"
  >
    Synthetic mode: no cluster traffic observed; counters and ticker may be empty.
    {#if lastReason}<span class="ml-2 text-amber-800">({lastReason})</span>{/if}
  </div>
{/if}
