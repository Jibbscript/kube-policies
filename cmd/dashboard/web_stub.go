//go:build no_ui

package main

import "net/http"

// spaHandler returns a stub handler used when the binary is built with
// -tags=no_ui. The default (no tag) build embeds the real SPA via
// web_embed.go. This stub exists so the dashboard binary can still be
// compiled and exercised in CI before the SPA has been built.
func spaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html>
<html><head><title>kube-policies dashboard</title></head>
<body style="font-family:system-ui;padding:2rem;max-width:42rem;margin:0 auto">
<h1>UI not built</h1>
<p>This dashboard binary was compiled with <code>-tags=no_ui</code>. The Single
Page Application assets are not embedded. Rebuild without the tag, or run
<code>make ui-build &amp;&amp; make build-dashboard</code> to produce a binary
with the SPA included.</p>
<p>The JSON API endpoints (<code>/api/metrics/summary</code>,
<code>/api/decisions/recent</code>, <code>/api/decisions/stream</code>,
<code>/api/v1/*</code>, <code>/healthz</code>, <code>/readyz</code>) are
served normally.</p>
</body></html>`))
	})
}
