//go:build !no_ui

package main

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"strings"
)

// webEmbedFS embeds the built SPA assets that the Makefile populates into
// cmd/dashboard/web_dist/ from web/dist/ at build time. The placeholder file
// (.placeholder) keeps //go:embed happy when the copy step has not yet
// produced real assets — without at least one matching file the directive
// would fail to compile.
//
//go:embed all:web_dist
var webEmbedFS embed.FS

// spaHandler returns an http.Handler that serves the embedded SPA. Missing
// paths fall back to index.html so client-side hash routing keeps working
// even if a viewer reloads on a deep route (the hash fragment is invisible
// to the server anyway, but the same handler answers HTML asset requests
// like /favicon.ico cleanly).
func spaHandler() http.Handler {
	sub, err := fs.Sub(webEmbedFS, "web_dist")
	if err != nil {
		// Should never happen — the path is a compile-time constant.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "SPA sub-fs unavailable: "+err.Error(), http.StatusInternalServerError)
		})
	}
	return http.FileServer(spaFS{fs: http.FS(sub)})
}

// spaFS wraps an http.FileSystem so unknown paths fall back to index.html.
type spaFS struct {
	fs http.FileSystem
}

func (s spaFS) Open(name string) (http.File, error) {
	// Strip leading slash already done by http.FileServer.
	f, err := s.fs.Open(name)
	if err == nil {
		return f, nil
	}
	if os.IsNotExist(err) || strings.HasSuffix(err.Error(), "file does not exist") {
		// Try index.html for SPA fallback. If that also fails the original
		// error is more informative.
		if idx, ierr := s.fs.Open("index.html"); ierr == nil {
			return idx, nil
		}
	}
	return nil, err
}
