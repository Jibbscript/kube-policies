<script lang="ts">
  import type { EvaluationResult } from '$lib/types';
  import { prettyJson } from '$lib/format';
  import RuleBadge from './RuleBadge.svelte';

  interface Props {
    verdict: EvaluationResult | null;
    error?: string | null;
    loading?: boolean;
  }
  let { verdict, error = null, loading = false }: Props = $props();

  let isDeny = $derived(verdict?.Decision === 'DENY');
</script>

<section data-testid="verdict-panel" class="rounded-lg border border-slate-200 bg-white p-4">
  {#if loading}
    <p class="text-sm text-slate-500">Evaluating…</p>
  {:else if error}
    <p class="text-sm text-red-700" data-testid="verdict-error">Error: {error}</p>
  {:else if !verdict}
    <p class="text-sm text-slate-500">Submit a manifest to see the verdict.</p>
  {:else}
    <header class="mb-3 flex items-center justify-between">
      <span
        data-testid="decision-badge"
        class="rounded px-3 py-1 text-sm font-bold {isDeny ? 'badge-deny' : 'badge-allow'}"
      >
        {verdict.Decision}
      </span>
      {#if verdict.Reason}
        <span class="text-xs text-slate-500">{verdict.Reason}</span>
      {/if}
    </header>

    {#if verdict.Message}
      <p class="mb-3 text-sm text-slate-700" data-testid="verdict-message">{verdict.Message}</p>
    {/if}

    {#if verdict.Violations?.length}
      <h3 class="mb-1 text-xs font-semibold uppercase text-slate-500">Violations</h3>
      <ul class="mb-3 space-y-2" data-testid="violation-list">
        {#each verdict.Violations as v (v.rule_id + '|' + v.path)}
          <li class="rounded border border-red-100 bg-red-50 p-2">
            <div class="flex items-center gap-2 text-xs">
              <RuleBadge ruleId={v.rule_id} name={v.rule_name} />
              {#if v.path}<code class="text-slate-500">{v.path}</code>{/if}
            </div>
            <p class="mt-1 text-sm text-slate-800">{v.message}</p>
            {#if v.frameworks?.length}
              <div class="mt-1 flex flex-wrap gap-1">
                {#each v.frameworks as f (f)}
                  <span class="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600">{f}</span>
                {/each}
              </div>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}

    {#if verdict.Patches?.length}
      <h3 class="mb-1 text-xs font-semibold uppercase text-slate-500">Patches</h3>
      <pre class="mb-3 overflow-x-auto rounded bg-slate-50 p-2 text-xs">{prettyJson(verdict.Patches)}</pre>
    {/if}

    {#if verdict.Metadata && Object.keys(verdict.Metadata).length > 0}
      <details class="text-xs">
        <summary class="cursor-pointer text-slate-500">Metadata</summary>
        <pre class="mt-1 overflow-x-auto rounded bg-slate-50 p-2">{prettyJson(verdict.Metadata)}</pre>
      </details>
    {/if}
  {/if}
</section>
