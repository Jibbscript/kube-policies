<script lang="ts">
  interface Props {
    ruleId: string;
    name?: string;
  }
  let { ruleId, name }: Props = $props();
</script>

<span
  class="inline-flex items-center rounded-md bg-slate-100 px-2 py-0.5 text-xs font-mono text-slate-700"
  title={name ?? ruleId}
  data-testid="rule-badge"
>
  {ruleId}
</span>
