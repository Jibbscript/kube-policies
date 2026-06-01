package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
)

// upstreamTokenKeyType is the private context key under which the proxy handler
// stashes the authenticated user's bearer token for the Director to forward
// upstream (IAM-WU-05). A distinct type avoids collisions with other context
// values.
type upstreamTokenKeyType struct{}

var upstreamTokenKey upstreamTokenKeyType

// writeMethods is the set of HTTP verbs gated by ALLOW_WRITES.
var writeMethods = map[string]struct{}{
	http.MethodPost:   {},
	http.MethodPut:    {},
	http.MethodPatch:  {},
	http.MethodDelete: {},
}

// isWriteMethod reports whether m is a write verb requiring AllowWrites=true.
func isWriteMethod(m string) bool {
	_, ok := writeMethods[strings.ToUpper(m)]
	return ok
}

// isReadOnlyRPC reports whether the given proxied subpath (i.e. the suffix
// after /api/v1) is a POST endpoint that performs no server-side mutation —
// only RPC-style read evaluation. These bypass the AllowWrites gate so the
// Playground UX (`POST /policies/:id/test`) works in the default read-only
// deployment without operators having to flip `allowWrites=true`.
//
// Currently recognized:
//   - /policies/<id>/test    — evaluates a candidate object against a policy
//   - /policies/validate     — validates a policy spec without persisting it
//   - /policies/evaluate     — ad-hoc evaluation: inline policy + resource,
//     nothing persisted (used by CI hooks and future "diff this manifest"
//     UX before a policy is saved).
func isReadOnlyRPC(method, proxyPath string) bool {
	if strings.ToUpper(method) != http.MethodPost {
		return false
	}
	// Normalise: proxyPath always starts with "/" because Gin captures the
	// suffix beginning at the slash.
	if proxyPath == "/policies/validate" || proxyPath == "/policies/evaluate" {
		return true
	}
	if strings.HasPrefix(proxyPath, "/policies/") && strings.HasSuffix(proxyPath, "/test") {
		// Guard against /policies/test (zero-length id). Note: previously
		// this also forbade slashes inside the id, which broke CRD-derived
		// IDs originally minted as "crd/<ns>/<name>". The CRD ID format
		// has since been changed to "crd:<ns>:<name>" so the slash guard
		// was redundant, but kept the mid-empty check because that one
		// still matters (otherwise /policies//test sneaks through).
		mid := strings.TrimSuffix(strings.TrimPrefix(proxyPath, "/policies/"), "/test")
		return mid != ""
	}
	return false
}

type unwrapResponseWriter interface {
	Unwrap() http.ResponseWriter
}

type proxyResponseWriter struct {
	gin.ResponseWriter
	closeNotifySource http.ResponseWriter
}

type closeNotifier interface {
	CloseNotify() <-chan bool
}

var neverCloseNotify = make(chan bool)

func (w proxyResponseWriter) CloseNotify() <-chan bool {
	if notifier, ok := w.closeNotifySource.(closeNotifier); ok {
		return notifier.CloseNotify()
	}
	return neverCloseNotify
}

func newProxyResponseWriter(w gin.ResponseWriter) http.ResponseWriter {
	source := http.ResponseWriter(w)
	if unwrapper, ok := w.(unwrapResponseWriter); ok {
		source = unwrapper.Unwrap()
	}
	return proxyResponseWriter{
		ResponseWriter:    w,
		closeNotifySource: source,
	}
}

// NewProxyHandler returns a Gin handler that reverse-proxies /api/v1/* to
// cfg.PolicyManagerURL.
//
// Authorization is layered (IAM-WU-05):
//   - PRIMARY: per-user authorization is enforced UPSTREAM by the policy-manager.
//     The handler forwards the authenticated user's bearer token (set by the auth
//     middleware) so the policy-manager's own OIDC+RBAC decides what the real user
//     may do — e.g. a viewer's mutation is rejected 403 by the policy-manager even
//     when ALLOW_WRITES=true.
//   - KILL-SWITCH / defense-in-depth: when cfg.AllowWrites is false, write verbs
//     are rejected with 403 BEFORE the proxy runs (no upstream contact). This is a
//     coarse cluster-wide off switch, NOT a substitute for per-user authZ; it is
//     deliberately retained so writes can be globally disabled regardless of role.
//     isReadOnlyRPC exempts non-mutating RPC POSTs (validate/evaluate/test) from
//     the verb gate only — they are still authenticated and authorized upstream.
//
// auditLog receives a DashboardWriteAttempt record for every mutating request
// (AUD-WU-13), including denied attempts (ALLOW_WRITES=false → 403). It may be
// nil or a no-op logger when auditing is disabled. Read-only RPC POSTs
// (validate/evaluate/test) and GET/HEAD requests are never audited.
//
// The handler expects to be mounted with a wildcard route capturing the
// upstream subpath in the "proxyPath" parameter (e.g. /api/v1/*proxyPath).
func NewProxyHandler(cfg *Config, clientTLS *tls.Config, log *zap.Logger, auditLog *audit.Logger) (gin.HandlerFunc, error) {
	target, err := url.Parse(cfg.PolicyManagerURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// When the policy-manager serves TLS (CRY-WU-05), reverse-proxy upstream
	// connections must verify its certificate (CRY-WU-07). Use an explicit
	// Transport with the verified TLS config; never mutate http.DefaultTransport
	// (process-global). nil clientTLS keeps the default transport (system roots
	// / plaintext upstream for non-TLS deployments).
	if clientTLS != nil {
		proxy.Transport = &http.Transport{TLSClientConfig: clientTLS}
	}

	// Customize Director: rewrite host header to the target and tag the
	// request so upstream logs can attribute it to the dashboard.
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
		req.Header.Set("X-Forwarded-By", "kube-policies-dashboard")
		// Per-user authorization (IAM-WU-05): forward the authenticated user's
		// bearer token so the policy-manager authenticates the REAL user and
		// enforces its own OIDC+RBAC, rather than acting on the dashboard's
		// service identity. Always strip any client-supplied Authorization first
		// so a browser cannot smuggle a credential of its choosing to the PM; the
		// dashboard is the sole authority for what token reaches the upstream.
		req.Header.Del("Authorization")
		if tok, _ := req.Context().Value(upstreamTokenKey).(string); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Warn("reverse proxy error",
			zap.String("path", r.URL.Path),
			zap.Error(err),
		)
		http.Error(w, `{"error":"upstream unavailable"}`, http.StatusBadGateway)
	}

	return func(c *gin.Context) {
		suffix := c.Param("proxyPath")
		if suffix == "" {
			suffix = "/"
		}

		// Audit mutating requests at the boundary (AUD-WU-13). The audit set
		// equals the mutation set: isWriteMethod && !isReadOnlyRPC. Read-only
		// RPC POSTs (validate/evaluate/test) and GET/HEAD are never audited.
		// The record is emitted BEFORE the gate so denied attempts (ALLOW_WRITES=
		// false → 403) are captured — only a dashboard-side record can log them.
		isWrite := isWriteMethod(c.Request.Method) && !isReadOnlyRPC(c.Request.Method, suffix)
		if isWrite && auditLog != nil {
			// IDENTITY: derive the user from the authenticated principal.
			// In authModeDisabled principalFromContext returns false → degrade to
			// "system:unauthenticated" (mirrors policymanager.userInfoFromContext).
			// In forward-auth mode IDToken may be empty but Username IS set; we
			// audit on Username. NEVER gate the emit on IDToken != "".
			// NEVER log p.IDToken (raw OIDC bearer token).
			username := "system:unauthenticated"
			if p, ok := principalFromContext(c); ok {
				username = p.Username
			}
			meta := map[string]interface{}{
				"user":         username,
				"method":       c.Request.Method,
				"path":         suffix,
				"allow_writes": cfg.AllowWrites,
			}
			if rid := c.GetHeader("X-Request-Id"); rid != "" {
				meta["correlation_id"] = rid
			}
			auditLog.LogSystemEvent("DashboardWriteAttempt", "dashboard write attempt", meta)
		}

		if !cfg.AllowWrites && isWrite {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "writes disabled (ALLOW_WRITES=false)",
			})
			return
		}

		// Carry the authenticated user's token to the Director (IAM-WU-05) so it
		// is forwarded upstream as the bearer credential. The Director only sees
		// the *http.Request, so the token rides on the request context. Empty in
		// disabled auth mode (no principal) — the Director then sends no token.
		if p, ok := principalFromContext(c); ok && p.IDToken != "" {
			c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), upstreamTokenKey, p.IDToken))
		}

		// Rewrite the request path: Gin's *proxyPath captures the suffix
		// including a leading slash, so we reconstruct /api/v1{suffix}.
		c.Request.URL.Path = "/api/v1" + suffix
		// Clear RawPath so Go re-encodes from Path; keep RawQuery as-is.
		c.Request.URL.RawPath = ""

		proxy.ServeHTTP(newProxyResponseWriter(c.Writer), c.Request)
	}, nil
}
