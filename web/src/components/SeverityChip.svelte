<script lang="ts">
  interface Props {
    severity?: 'low' | 'medium' | 'high' | 'critical';
  }
  let { severity }: Props = $props();

  const colors: Record<NonNullable<Props['severity']>, string> = {
    low: 'bg-slate-100 text-slate-700',
    medium: 'bg-yellow-100 text-yellow-800',
    high: 'bg-orange-100 text-orange-800',
    critical: 'bg-red-100 text-red-800',
  };

  let cls = $derived(severity ? colors[severity] : 'bg-slate-100 text-slate-500');
  let label = $derived(severity ? severity.toUpperCase() : 'N/A');
</script>

<span
  class="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium {cls}"
  data-testid="severity-chip"
>
  {label}
</span>
