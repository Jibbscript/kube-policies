package policymanager

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// Role is an ordered API authorization level. Higher integer values are
// strictly more privileged, so an "allowed if role >= required" comparison is
// just an integer comparison.
type Role int

const (
	// RoleNone is the absence of any granted role: every protected route is denied.
	RoleNone Role = 0
	// RoleViewer may read management resources and run read-only evaluation RPCs.
	RoleViewer Role = 1
	// RoleEditor adds create/update/delete of policies, bundles, and exceptions.
	RoleEditor Role = 2
	// RoleAdmin adds privileged operations (deploy, compliance report generation).
	RoleAdmin Role = 3
)

// parseRole maps a config role name to a Role. The bool is false for an empty
// or unrecognized name, in which case the caller treats it as RoleNone.
func parseRole(name string) (Role, bool) {
	switch name {
	case "viewer":
		return RoleViewer, true
	case "editor":
		return RoleEditor, true
	case "admin":
		return RoleAdmin, true
	default:
		return RoleNone, false
	}
}

// roleForPrincipal resolves the effective Role for an authenticated principal:
// the highest role among RoleBindings whose Groups intersect the principal's
// groups, or the configured DefaultRole when no binding matches (RoleNone if
// DefaultRole is empty or unparseable). A nil principal yields RoleNone.
func roleForPrincipal(p *Principal, rbac config.RBACConfig) Role {
	if p == nil {
		return RoleNone
	}
	best := RoleNone
	matched := false
	for _, rb := range rbac.RoleBindings {
		if !groupsIntersect(rb.Groups, p.Groups) {
			continue
		}
		if r, ok := parseRole(rb.Role); ok {
			matched = true
			if r > best {
				best = r
			}
		}
	}
	if matched {
		return best
	}
	if r, ok := parseRole(rbac.DefaultRole); ok {
		return r
	}
	return RoleNone
}

// groupsIntersect reports whether the two group lists share at least one value.
func groupsIntersect(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// routeKey identifies a management route by HTTP method and gin's matched route
// template (c.FullPath()), e.g. {POST, "/api/v1/policies/:id/deploy"}.
type routeKey struct {
	method   string
	fullPath string
}

// requiredRoles is the explicit, deny-by-default authorization table for the
// management plane. A route absent from this table is denied (403) regardless
// of role. The decisions machine-plane (/api/v1/decisions/*) is intentionally
// absent: it is OIDC-exempt and authenticated separately (see router.go).
var requiredRoles = map[routeKey]Role{
	// Read-only management routes (viewer).
	{http.MethodGet, "/api/v1/policies"}:              RoleViewer,
	{http.MethodGet, "/api/v1/policies/:id"}:          RoleViewer,
	{http.MethodGet, "/api/v1/policies/:id/status"}:   RoleViewer,
	{http.MethodGet, "/api/v1/bundles"}:               RoleViewer,
	{http.MethodGet, "/api/v1/bundles/:id"}:           RoleViewer,
	{http.MethodGet, "/api/v1/exceptions"}:            RoleViewer,
	{http.MethodGet, "/api/v1/compliance/reports"}:    RoleViewer,
	{http.MethodGet, "/api/v1/compliance/frameworks"}: RoleViewer,
	// Read-only evaluation RPCs: no persistence, so viewer-level.
	{http.MethodPost, "/api/v1/policies/:id/test"}: RoleViewer,
	{http.MethodPost, "/api/v1/policies/validate"}: RoleViewer,
	{http.MethodPost, "/api/v1/policies/evaluate"}: RoleViewer,
	// Mutating management routes (editor).
	{http.MethodPost, "/api/v1/policies"}:         RoleEditor,
	{http.MethodPut, "/api/v1/policies/:id"}:      RoleEditor,
	{http.MethodDelete, "/api/v1/policies/:id"}:   RoleEditor,
	{http.MethodPost, "/api/v1/bundles"}:          RoleEditor,
	{http.MethodPost, "/api/v1/exceptions"}:       RoleEditor,
	{http.MethodPut, "/api/v1/exceptions/:id"}:    RoleEditor,
	{http.MethodDelete, "/api/v1/exceptions/:id"}: RoleEditor,
	// Privileged operations (admin).
	{http.MethodPost, "/api/v1/policies/:id/deploy"}: RoleAdmin,
	{http.MethodPost, "/api/v1/compliance/reports"}:  RoleAdmin,
}

// requiredRole returns the minimum Role required for (method, fullPath) and
// whether the route is in the table at all. A route not in the table is denied
// by default (ok=false).
func requiredRole(method, fullPath string) (Role, bool) {
	r, ok := requiredRoles[routeKey{method: method, fullPath: fullPath}]
	return r, ok
}

// RBACMiddleware enforces the requiredRoles table (IAM-WU-02). It must run
// after OIDCAuthMiddleware so a Principal is present. A route absent from the
// table is denied by default. The principal's effective role must be at least
// the route's required role.
func RBACMiddleware(rbac config.RBACConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := PrincipalFrom(c)
		if !ok {
			// Defensive: should not happen if authN ran first.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		needed, known := requiredRole(c.Request.Method, c.FullPath())
		if !known {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if roleForPrincipal(p, rbac) < needed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}
