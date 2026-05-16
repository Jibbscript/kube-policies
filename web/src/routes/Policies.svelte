<script lang="ts">
  import { onMount } from 'svelte';
  import { link } from 'svelte-spa-router';
  import { listPolicies } from '$lib/api';
  import type { Policy } from '$lib/types';

  let policies = $state<Policy[]>([]);
  let err = $state<string | null>(null);

  onMount(async () => {
    try {
      policies = await listPolicies();
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  });
</script>

<section class="space-y-4">
  <header>
    <h1 class="text-2xl font-semibold">Policies</h1>
  </header>

  {#if err}
    <p class="text-sm text-amber-700">Couldn't load policies: {err}</p>
  {/if}

  <table class="w-full rounded-lg border border-slate-200 bg-white text-sm">
    <thead class="border-b border-slate-200 text-left text-xs uppercase text-slate-500">
      <tr>
        <th class="px-3 py-2">ID</th>
        <th class="px-3 py-2">Name</th>
        <th class="px-3 py-2">Rules</th>
        <th class="px-3 py-2">Enabled</th>
      </tr>
    </thead>
    <tbody data-testid="policies-table">
      {#each policies as p (p.id)}
        <tr class="border-b border-slate-100">
          <td class="px-3 py-2 font-mono">
            <a class="text-blue-700 hover:underline" href={`/policies/${p.id}`} use:link>{p.id}</a>
          </td>
          <td class="px-3 py-2">{p.name}</td>
          <td class="px-3 py-2">{p.rules?.length ?? 0}</td>
          <td class="px-3 py-2">{p.enabled ? 'yes' : 'no'}</td>
        </tr>
      {/each}
      {#if policies.length === 0 && !err}
        <tr><td colspan="4" class="px-3 py-4 text-slate-500">No policies loaded.</td></tr>
      {/if}
    </tbody>
  </table>
</section>
