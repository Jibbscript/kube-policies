# CSP Verdict (M1 empirical test per plan §3)

Result: **PASS** (no inline `<style>` tags in `dist/index.html`).

Decision: commit option **(a)** — CSP `style-src 'self'` (no `'unsafe-inline'`).

## Evidence

`dist/index.html` after `pnpm build`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="theme-color" content="#0f172a" />
    <title>kube-policies dashboard</title>
    <script type="module" crossorigin src="/assets/index-<hash>.js"></script>
    <link rel="stylesheet" crossorigin href="/assets/index-<hash>.css">
  </head>
  <body class="min-h-screen bg-slate-50 text-slate-900 antialiased">
    <div id="app"></div>
  </body>
</html>
```

The Tailwind v4 CSS-only setup (`@import "tailwindcss"` in `src/app.css` plus
the `@tailwindcss/vite` plugin) emits all styles into the external
`/assets/index-*.css` stylesheet. No inline `<style>` tag, no inline `style=""`
attribute is present in the built HTML.

Decision applied in: `cmd/dashboard/main.go` CSP header — `style-src 'self'`.

## Stack

- Tailwind CSS: ^4.0.0 (`@tailwindcss/vite` ^4.0.0)
- Vite: ^5.4.11
- Svelte: ^5.16.0 with `@sveltejs/vite-plugin-svelte` ^4.0.4
