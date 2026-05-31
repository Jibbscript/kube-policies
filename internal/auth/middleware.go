package auth

import "net/http"

// RequireBearer wraps next with constant-time bearer-token authentication
// (CRY-WU-08). It returns 401 when the verifier is unconfigured (no token set —
// fail closed, never a wildcard) or when the request's Authorization header does
// not carry an accepted token. On success it delegates to next.
//
// Intended for the /metrics handler so Prometheus scrapes are authenticated;
// health endpoints (/healthz, /readyz) must NOT be wrapped — kubelet probes send
// no Authorization header.
func RequireBearer(v *TokenVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !v.Configured() || !v.VerifyHeader(r.Header.Get("Authorization")) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
