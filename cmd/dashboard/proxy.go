package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// writeMethods is the set of HTTP verbs gated by ALLOW_WRITES.
var writeMethods = map[string]struct{}{
	http.MethodPost:   {},
	http.MethodPut:    {},
	http.MethodPatch: {},
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
// Currently recognised:
//   - /policies/<id>/test    — evaluates a candidate object against a policy
//   - /policies/validate     — validates a policy spec without persisting it
func isReadOnlyRPC(method, proxyPath string) bool {
	if strings.ToUpper(method) != http.MethodPost {
		return false
	}
	// Normalise: proxyPath always starts with "/" because Gin captures the
	// suffix beginning at the slash.
	if proxyPath == "/policies/validate" {
		return true
	}
	if strings.HasPrefix(proxyPath, "/policies/") && strings.HasSuffix(proxyPath, "/test") {
		// Guard against /policies/test (zero-length id) and the validate
		// case above.
		mid := strings.TrimSuffix(strings.TrimPrefix(proxyPath, "/policies/"), "/test")
		return mid != "" && !strings.Contains(mid, "/")
	}
	return false
}

// NewProxyHandler returns a Gin handler that reverse-proxies /api/v1/* to
// cfg.PolicyManagerURL. When cfg.AllowWrites is false, write verbs are
// rejected with 403 BEFORE the proxy runs — there is no upstream contact for
// disallowed requests.
//
// The handler expects to be mounted with a wildcard route capturing the
// upstream subpath in the "proxyPath" parameter (e.g. /api/v1/*proxyPath).
func NewProxyHandler(cfg *Config, log *zap.Logger) (gin.HandlerFunc, error) {
	target, err := url.Parse(cfg.PolicyManagerURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize Director: rewrite host header to the target and tag the
	// request so upstream logs can attribute it to the dashboard.
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
		req.Header.Set("X-Forwarded-By", "kube-policies-dashboard")
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

		if !cfg.AllowWrites && isWriteMethod(c.Request.Method) && !isReadOnlyRPC(c.Request.Method, suffix) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "writes disabled (ALLOW_WRITES=false)",
			})
			return
		}

		// Rewrite the request path: Gin's *proxyPath captures the suffix
		// including a leading slash, so we reconstruct /api/v1{suffix}.
		c.Request.URL.Path = "/api/v1" + suffix
		// Clear RawPath so Go re-encodes from Path; keep RawQuery as-is.
		c.Request.URL.RawPath = ""

		proxy.ServeHTTP(c.Writer, c.Request)
	}, nil
}
