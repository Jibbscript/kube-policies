<script lang="ts">
  import { onMount } from 'svelte';
  import { link } from 'svelte-spa-router';
  import { listExceptions } from '$lib/api';
  import type { Exception } from '$lib/types';

  let items = $state<Exception[]>([]);
  let err = $state<string | null>(null);

  const allowWrites = import.meta.env.VITE_ALLOW_WRITES === 'true';

  onMount(async () => {
    try {
      items = await listExceptions();
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  });
</script>

<section class="space-y-4">
  <header class="flex items-center justify-between">
    <h1 class="text-2xl font-semibold">Exceptions</h1>
    {#if allowWrites}
      <button class="rounded bg-slate-900 px-3 py-1.5 text-sm text-white" data-testid="new-exception-btn">
        + New exception
      </button>
    {/if}
  </header>

  {#if err}<p class="text-sm text-amber-700">{err}</p>{/if}

  <table class="w-full rounded-lg border border-slate-200 bg-white text-sm">
    <thead class="border-b border-slate-200 text-left text-xs uppercase text-slate-500">
      <tr>
        <th class="px-3 py-2">ID</th>
        <th class="px-3 py-2">Policy</th>
        <th class="px-3 py-2">Rule</th>
        <th class="px-3 py-2">Namespace</th>
        <th class="px-3 py-2">Expires</th>
      </tr>
    </thead>
    <tbody data-testid="exceptions-table">
      {#each items as e (e.id)}
        <tr class="border-b border-slate-100">
          <td class="px-3 py-2 font-mono">
            <a class="text-blue-700 hover:underline" href={`/exceptions/${e.id}`} use:link>{e.id}</a>
          </td>
          <td class="px-3 py-2 font-mono">{e.policy_id}</td>
          <td class="px-3 py-2 font-mono">{e.rule_id ?? '—'}</td>
          <td class="px-3 py-2 font-mono">{e.namespace ?? '*'}</td>
          <td class="px-3 py-2">{e.expires_at ?? '—'}</td>
        </tr>
      {/each}
      {#if items.length === 0 && !err}
        <tr><td colspan="5" class="px-3 py-4 text-slate-500">No exceptions configured.</td></tr>
      {/if}
    </tbody>
  </table>
</section>
