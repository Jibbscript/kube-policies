<script lang="ts">
  import { onMount } from 'svelte';
  import { listPolicies, testPolicy } from '$lib/api';
  import type { EvaluationResult, Policy } from '$lib/types';
  import VerdictPanel from '$components/VerdictPanel.svelte';
  import privileged from '$fixtures/sample-pod-privileged.json';
  import hostpath from '$fixtures/sample-pod-hostpath.json';
  import latestTag from '$fixtures/sample-pod-latest-tag.json';
  import compliant from '$fixtures/sample-pod-compliant.json';

  type SampleKey = 'privileged' | 'hostpath' | 'latest-tag' | 'compliant' | 'custom';
  const samples: Record<Exclude<SampleKey, 'custom'>, unknown> = {
    privileged,
    hostpath,
    'latest-tag': latestTag,
    compliant,
  };

  let policies = $state<Policy[]>([]);
  let policyId = $state<string>('security-baseline');
  let sampleKey = $state<SampleKey>('privileged');
  let bodyText = $state<string>(JSON.stringify(privileged, null, 2));
  let verdict = $state<EvaluationResult | null>(null);
  let loading = $state(false);
  let err = $state<string | null>(null);

  $effect(() => {
    if (sampleKey === 'custom') return;
    bodyText = JSON.stringify(samples[sampleKey], null, 2);
  });

  async function loadPolicies(): Promise<void> {
    try {
      policies = await listPolicies();
      if (policies.length > 0 && !policies.some((p) => p.id === policyId)) {
        policyId = policies[0].id;
      }
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  }

  async function evaluate(): Promise<void> {
    loading = true;
    err = null;
    verdict = null;
    try {
      const body = JSON.parse(bodyText) as unknown;
      verdict = await testPolicy(policyId, body);
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void loadPolicies();
  });
</script>

<section class="grid grid-cols-1 gap-4 lg:grid-cols-2">
  <div class="space-y-3 rounded-lg border border-slate-200 bg-white p-4">
    <h2 class="text-lg font-semibold">Manifest</h2>

    <label class="block text-xs font-semibold uppercase text-slate-500" for="policy-picker">
      Policy
    </label>
    <select
      id="policy-picker"
      bind:value={policyId}
      data-testid="policy-picker"
      class="w-full rounded border border-slate-300 px-2 py-1 text-sm"
    >
      <option value="security-baseline">security-baseline (bundled)</option>
      {#each policies as p (p.id)}
        {#if p.id !== 'security-baseline'}
          <option value={p.id}>{p.name} ({p.id})</option>
        {/if}
      {/each}
    </select>

    <label class="block text-xs font-semibold uppercase text-slate-500" for="sample-picker">
      Sample
    </label>
    <select
      id="sample-picker"
      bind:value={sampleKey}
      data-testid="sample-picker"
      class="w-full rounded border border-slate-300 px-2 py-1 text-sm"
    >
      <option value="privileged">Pod (privileged)</option>
      <option value="hostpath">Pod (hostPath volume)</option>
      <option value="latest-tag">Pod (image: latest)</option>
      <option value="compliant">Pod (compliant)</option>
      <option value="custom">Paste your own…</option>
    </select>

    <label class="block text-xs font-semibold uppercase text-slate-500" for="body-textarea">
      Body
    </label>
    <textarea
      id="body-textarea"
      bind:value={bodyText}
      onfocus={() => (sampleKey = 'custom')}
      data-testid="body-textarea"
      class="h-80 w-full rounded border border-slate-300 p-2 font-mono text-xs"
    ></textarea>

    <button
      type="button"
      onclick={evaluate}
      disabled={loading}
      data-testid="evaluate-button"
      class="rounded bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
    >
      {loading ? 'Evaluating…' : 'Evaluate'}
    </button>
  </div>

  <div>
    <h2 class="mb-2 text-lg font-semibold">Verdict</h2>
    <VerdictPanel {verdict} error={err} {loading} />
  </div>
</section>
