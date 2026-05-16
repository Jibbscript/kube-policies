<script lang="ts">
  import Router, { link } from 'svelte-spa-router';
  import Home from '$routes/Home.svelte';
  import Playground from '$routes/Playground.svelte';
  import Policies from '$routes/Policies.svelte';
  import PolicyDetail from '$routes/PolicyDetail.svelte';
  import Exceptions from '$routes/Exceptions.svelte';
  import ExceptionDetail from '$routes/ExceptionDetail.svelte';
  import LiveDecisions from '$routes/LiveDecisions.svelte';
  import Metrics from '$routes/Metrics.svelte';
  import ModeBanner from '$components/ModeBanner.svelte';

  const routes = {
    '/': Home,
    '/playground': Playground,
    '/policies': Policies,
    '/policies/:id': PolicyDetail,
    '/exceptions': Exceptions,
    '/exceptions/:id': ExceptionDetail,
    '/live': LiveDecisions,
    '/metrics': Metrics,
    '*': Home,
  };
</script>

<div class="min-h-screen flex flex-col">
  <ModeBanner />
  <header class="border-b border-slate-200 bg-white">
    <nav class="mx-auto flex max-w-6xl items-center gap-4 px-4 py-3 text-sm" data-testid="nav">
      <a href="/" use:link class="font-semibold text-slate-900">kube-policies</a>
      <a href="/playground" use:link class="text-slate-600 hover:text-slate-900">Playground</a>
      <a href="/policies" use:link class="text-slate-600 hover:text-slate-900">Policies</a>
      <a href="/exceptions" use:link class="text-slate-600 hover:text-slate-900">Exceptions</a>
      <a href="/live" use:link class="text-slate-600 hover:text-slate-900">Live</a>
      <a href="/metrics" use:link class="text-slate-600 hover:text-slate-900">Metrics</a>
    </nav>
  </header>
  <main class="mx-auto w-full max-w-6xl flex-1 px-4 py-6">
    <Router {routes} />
  </main>
  <footer class="border-t border-slate-200 bg-white px-4 py-3 text-xs text-slate-500">
    v{__APP_VERSION__} · read-only when write-mode disabled by BFF
  </footer>
</div>
