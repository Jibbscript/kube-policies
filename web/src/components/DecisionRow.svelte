<script lang="ts">
  import type { PublicEvent } from '$lib/types';
  import { relativeTime } from '$lib/format';
  import RuleBadge from './RuleBadge.svelte';

  interface Props {
    event: PublicEvent;
  }
  let { event }: Props = $props();
</script>

<tr data-testid="decision-row" class="border-b border-slate-100 text-sm">
  <td class="px-3 py-2 text-slate-500">{relativeTime(event.timestamp)}</td>
  <td class="px-3 py-2 font-mono">{event.namespace ?? '—'}</td>
  <td class="px-3 py-2">
    <span class="font-mono">{event.kind}</span>
    {#if event.name}<span class="text-slate-500">/{event.name}</span>{/if}
  </td>
  <td class="px-3 py-2">
    <span
      class="inline-flex rounded px-2 py-0.5 text-xs font-semibold {event.decision === 'DENY'
        ? 'badge-deny'
        : 'badge-allow'}"
    >
      {event.decision}
    </span>
  </td>
  <td class="px-3 py-2">
    {#if event.rule_id}<RuleBadge ruleId={event.rule_id} />{:else}<span class="text-slate-400">—</span>{/if}
  </td>
</tr>
