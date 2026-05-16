<script lang="ts">
  import { onMount } from 'svelte';
  import { link } from 'svelte-spa-router';
  import { getPolicy } from '$lib/api';
  import type { Policy } from '$lib/types';
  import SeverityChip from '$components/SeverityChip.svelte';
  import RuleBadge from '$components/RuleBadge.svelte';

  interface Props {
    params?: { id?: string };
  }
  let { params }: Props = $props();
  const id = $derived(params?.id ?? '');

  let policy = $state<Policy | null>(null);
  let err = $state<string | null>(null);

  const allowWrites = import.meta.env.VITE_ALLOW_WRITES === 'true';

  onMount(async () => {
    if (!id) return;
    try {
      policy = await getPolicy(id);
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  });
</script>

<section class="space-y-4">
  <a class="text-sm text-blue-700 hover:underline" href="/policies" use:link>← Back to policies</a>

  {#if err}
    <p class="text-sm text-amber-700">{err}</p>
  {:else if !policy}
    <p class="text-sm text-slate-500">Loading…</p>
  {:else}
    <header class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold">{policy.name}</h1>
        <p class="text-sm text-slate-500">{policy.description ?? '—'}</p>
      </div>
      {#if allowWrites}
        <div class="flex gap-2">
          <button class="rounded bg-slate-200 px-3 py-1 text-sm" data-testid="edit-btn">Edit</button>
          <button class="rounded bg-red-100 px-3 py-1 text-sm text-red-800" data-testid="delete-btn">Delete</button>
        </div>
      {/if}
    </header>

    <ul class="space-y-2">
      {#each policy.rules as rule (rule.id)}
        <li class="rounded border border-slate-200 bg-white p-3">
          <div class="flex items-center gap-2">
            <RuleBadge ruleId={rule.id} name={rule.name} />
            <SeverityChip severity={rule.severity} />
            <span class="text-sm font-semibold">{rule.name}</span>
          </div>
          {#if rule.description}<p class="mt-1 text-sm text-slate-600">{rule.description}</p>{/if}
          {#if rule.rego}
            <details class="mt-2 text-xs">
              <summary class="cursor-pointer text-slate-500">Rego excerpt</summary>
              <pre class="mt-1 overflow-x-auto rounded bg-slate-50 p-2">{rule.rego}</pre>
            </details>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>
