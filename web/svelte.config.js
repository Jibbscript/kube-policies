import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
  preprocess: vitePreprocess(),
  // Note: runes mode is auto-detected per .svelte file based on $state/$derived
  // usage. We do NOT force global runes mode because some third-party libraries
  // (e.g., svelte-spa-router) still use legacy lifecycle imports.
};
