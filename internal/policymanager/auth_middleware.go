package policymanager

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	authenticationv1 "k8s.io/api/authentication/v1"

	"github.com/Jibbscript/kube-policies/internal/auth"
	"github.com/Jibbscript/kube-policies/internal/config"
)

// principalContextKey is the gin context key under which the authenticated
// Principal is stored after OIDCAuthMiddleware succeeds.
const principalContextKey = "kp_principal"

// Principal is the authenticated caller derived from a verified OIDC ID token.
type Principal struct {
	Subject  string
	Username string
	Groups   []string
}

// oidcVerifier is the narrow seam OIDCAuthMiddleware depends on. It is
// satisfied by *oidc.IDTokenVerifier in production and by an offline verifier
// built over oidc.StaticKeySet in tests, so authN can be exercised without any
// network round-trip.
type oidcVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

// OIDCVerifier is the exported alias for the verifier seam so callers in other
// packages (cmd/policy-manager) can hold a nil-or-value of this type and pass
// it into NewAPIRouter.
type OIDCVerifier = oidcVerifier

// newVerifierWithKeySet assembles an *oidc.IDTokenVerifier over the given
// oidc.KeySet using the auth config. It is the single point where the verifier
// options are set: SkipClientIDCheck (audience is enforced manually in
// OIDCAuthMiddleware to support multiple accepted audiences) and
// SupportedSigningAlgs restricted to cfg.SupportedAlgs — the FIPS-approved
// asymmetric allow-list (IAM-WU-13). Both NewOIDCVerifier (production, remote
// key set) and tests (static key set) route through here so the allow-list
// propagation is exercised by the same code path that ships.
func newVerifierWithKeySet(ks oidc.KeySet, cfg config.AuthConfig) *oidc.IDTokenVerifier {
	return oidc.NewVerifier(cfg.Issuer, ks, &oidc.Config{
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: cfg.SupportedAlgs,
	})
}

// NewOIDCVerifier builds the production verifier from the auth config. It wires
// a lazy oidc.RemoteKeySet against cfg.JWKSURL (no blocking network call here;
// keys are fetched on first verification and cached) and delegates the verifier
// assembly — including the FIPS-approved signing-algorithm allow-list — to
// newVerifierWithKeySet (IAM-WU-13).
func NewOIDCVerifier(ctx context.Context, cfg config.AuthConfig) (oidcVerifier, error) {
	keySet := oidc.NewRemoteKeySet(ctx, cfg.JWKSURL)
	return newVerifierWithKeySet(keySet, cfg), nil
}

// OIDCAuthMiddleware authenticates each request with a bearer OIDC ID token
// (IAM-WU-01). On success it stores the derived Principal in the gin context
// and calls the next handler; on any failure it aborts with 401 and a generic
// message — verification error details are never returned to the client.
func OIDCAuthMiddleware(v oidcVerifier, cfg config.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := auth.BearerToken(c.GetHeader("Authorization"))
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}

		idToken, err := v.Verify(c.Request.Context(), raw)
		if err != nil {
			// Do not leak err to the client; it may carry issuer/key detail.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		// Enforce audience ourselves (SkipClientIDCheck is set on the verifier)
		// so multiple accepted audiences are supported: the token's aud set must
		// intersect the configured allow-list.
		if !audienceIntersects(idToken.Audience, cfg.Audience) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		p := &Principal{
			Subject:  idToken.Subject,
			Username: usernameFromClaims(claims, cfg.UsernameClaim, idToken.Subject),
			Groups:   groupsFromClaims(claims, cfg.GroupsClaim),
		}
		c.Set(principalContextKey, p)
		c.Next()
	}
}

// userInfoFromContext maps the authenticated caller in the gin context to the
// authenticationv1.UserInfo recorded on audit events (IAM-WU-14). When a
// verified Principal is present it carries the OIDC username (UserInfo.Username),
// subject (UserInfo.UID), and groups; this is always the case in production,
// where all seven persisting mutation routes sit behind OIDC+RBAC. When no
// Principal is present — which only happens when authentication is disabled
// (a dev/test posture, see NewAPIRouter) — it returns an honest
// "system:unauthenticated" label rather than fabricating an identity.
func userInfoFromContext(c *gin.Context) authenticationv1.UserInfo {
	if p, ok := PrincipalFrom(c); ok && p != nil {
		return authenticationv1.UserInfo{
			Username: p.Username,
			UID:      p.Subject,
			Groups:   p.Groups,
		}
	}
	return authenticationv1.UserInfo{
		Username: "system:unauthenticated",
		Groups:   []string{"system:unauthenticated"},
	}
}

// PrincipalFrom returns the authenticated Principal stored by
// OIDCAuthMiddleware, or (nil, false) when none is present.
func PrincipalFrom(c *gin.Context) (*Principal, bool) {
	v, ok := c.Get(principalContextKey)
	if !ok {
		return nil, false
	}
	p, ok := v.(*Principal)
	return p, ok
}

// audienceIntersects reports whether the token's audience set shares at least
// one value with the configured accepted audiences.
func audienceIntersects(tokenAud, accepted []string) bool {
	for _, a := range accepted {
		for _, t := range tokenAud {
			if a == t {
				return true
			}
		}
	}
	return false
}

// usernameFromClaims reads the configured username claim as a string, falling
// back to the token subject when the claim is absent or not a string.
func usernameFromClaims(claims map[string]any, claimName, fallback string) string {
	if claimName != "" {
		if v, ok := claims[claimName].(string); ok && v != "" {
			return v
		}
	}
	return fallback
}

// groupsFromClaims reads the configured groups claim. It accepts either a JSON
// array of strings or a single JSON string (some IdPs emit a scalar when there
// is exactly one group); any other shape yields nil (no groups). Non-string and
// empty entries within an array are skipped.
func groupsFromClaims(claims map[string]any, claimName string) []string {
	if claimName == "" {
		return nil
	}
	switch v := claims[claimName].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		groups := make([]string, 0, len(v))
		for _, g := range v {
			if s, ok := g.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
		return groups
	default:
		return nil
	}
}
