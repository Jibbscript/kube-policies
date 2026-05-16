<script lang="ts">
  import { onMount } from 'svelte';
  import { link } from 'svelte-spa-router';
  import { listExceptions } from '$lib/api';
  import type { Exception } from '$lib/types';
  import { prettyJson } from '$lib/format';

  interface Props {
    params?: { id?: string };
  }
  let { params }: Props = $props();
  const id = $derived(params?.id ?? '');

  let item = $state<Exception | null>(null);
  let err = $state<string | null>(null);

  onMount(async () => {
    if (!id) return;
    try {
      const all = await listExceptions();
      item = all.find((e) => e.id === id) ?? null;
      if (!item) err = `Exception ${id} not found`;
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  });
</script>

<section class="space-y-3">
  <a class="text-sm text-blue-700 hover:underline" href="/exceptions" use:link>← Back</a>
  {#if err}
    <p class="text-sm text-amber-700">{err}</p>
  {:else if !item}
    <p class="text-sm text-slate-500">Loading…</p>
  {:else}
    <div class="rounded border border-slate-200 bg-white p-4">
      <h1 class="text-xl font-semibold">{item.id}</h1>
      <p class="mt-2 text-sm text-slate-600">{item.reason}</p>
      <pre class="mt-3 overflow-x-auto rounded bg-slate-50 p-2 text-xs">{prettyJson(item)}</pre>
    </div>
  {/if}
</section>
