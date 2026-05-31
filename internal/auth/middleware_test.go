package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireBearer(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("metrics"))
	})

	cases := []struct {
		name     string
		verifier *TokenVerifier
		header   string
		want     int
	}{
		{"valid token", NewTokenVerifier("s3cret"), "Bearer s3cret", http.StatusOK},
		{"wrong token", NewTokenVerifier("s3cret"), "Bearer nope", http.StatusUnauthorized},
		{"no header", NewTokenVerifier("s3cret"), "", http.StatusUnauthorized},
		{"missing scheme", NewTokenVerifier("s3cret"), "s3cret", http.StatusUnauthorized},
		{"unconfigured verifier fails closed", NewTokenVerifier(""), "Bearer anything", http.StatusUnauthorized},
		{"rotation: previous token accepted", NewTokenVerifier("new", "old"), "Bearer old", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := RequireBearer(tc.verifier, ok)
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}
