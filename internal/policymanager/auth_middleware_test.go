package policymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// Hermetic OIDC test fixtures. No network: tokens are minted with go-jose and
// verified offline against an oidc.StaticKeySet holding the matching public
// keys, with a fixed clock so exp/iat/nbf checks are deterministic.

const (
	testIssuer   = "https://issuer.test.example.com"
	testAudience = "kube-policies-api"
)

// approvedAlgs mirrors the production FIPS asymmetric allow-list.
var approvedAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// fixedNow is the deterministic verification clock. Test token exp/iat are set
// relative to it so verification never depends on wall-clock time.
var fixedNow = time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)

var (
	testRSAPriv   *rsa.PrivateKey
	testECDSAPriv *ecdsa.PrivateKey
	// testUntrustedRSAPriv is a second RSA key that is deliberately NOT placed in
	// the StaticKeySet, so a token signed with it must fail signature
	// verification (FIX F).
	testUntrustedRSAPriv *rsa.PrivateKey
	// testHMACKey is a fresh symmetric key used to mint HS256 tokens that the
	// asymmetric-only allow-list must reject (FIX E).
	testHMACKey []byte
)

func init() {
	var err error
	testRSAPriv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testECDSAPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	testUntrustedRSAPriv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testHMACKey = make([]byte, 32)
	if _, err = rand.Read(testHMACKey); err != nil {
		panic(err)
	}
}

// newHermeticVerifier builds an offline verifier over the test public keys.
func newHermeticVerifier(t *testing.T) oidcVerifier {
	t.Helper()
	keySet := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{
		testRSAPriv.Public(),
		testECDSAPriv.Public(),
	}}
	return oidc.NewVerifier(testIssuer, keySet, &oidc.Config{
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: approvedAlgs,
		Now:                  func() time.Time { return fixedNow },
	})
}

// testAuthConfig is the AuthConfig the middleware reads in tests.
func testAuthConfig() config.AuthConfig {
	return config.AuthConfig{
		Enabled:       true,
		Issuer:        testIssuer,
		Audience:      []string{testAudience},
		UsernameClaim: "sub",
		GroupsClaim:   "groups",
		SupportedAlgs: approvedAlgs,
	}
}

// mintToken signs the given claims with the requested algorithm using the
// matching test private key and returns the compact JWS.
func mintToken(t *testing.T, alg jose.SignatureAlgorithm, claims map[string]any) string {
	t.Helper()
	var key any
	switch alg {
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key = testRSAPriv
	case jose.ES256, jose.ES384, jose.ES512:
		key = testECDSAPriv
	default:
		t.Fatalf("unsupported test alg %q", alg)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	compact, err := jws.CompactSerialize()
	require.NoError(t, err)
	return compact
}

// mintTokenWithKey signs claims with an explicit key/alg pair. It is used to
// forge a token from an untrusted signer (FIX F) and to mint a symmetric HS256
// token (FIX E) — neither of which goes through mintToken's trusted-key switch.
func mintTokenWithKey(t *testing.T, alg jose.SignatureAlgorithm, key any, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	compact, err := jws.CompactSerialize()
	require.NoError(t, err)
	return compact
}

// mintNoneToken forges an RFC 7519 unsecured JWS ({"alg":"none"} with an empty
// signature segment). go-jose refuses to produce one, so it is assembled by
// hand from base64url(header).base64url(payload). (FIX E.)
func mintNoneToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	body := base64.RawURLEncoding.EncodeToString(payload)
	// Trailing dot with an empty signature segment is the unsecured-JWS form.
	return header + "." + body + "."
}

// validClaims returns a claims map that passes verification under fixedNow.
func validClaims() map[string]any {
	return map[string]any{
		"iss":    testIssuer,
		"aud":    testAudience,
		"sub":    "alice",
		"groups": []string{"platform", "sre"},
		"iat":    fixedNow.Add(-1 * time.Minute).Unix(),
		"nbf":    fixedNow.Add(-1 * time.Minute).Unix(),
		"exp":    fixedNow.Add(1 * time.Hour).Unix(),
	}
}

// serveWithAuth runs the OIDC middleware in a tiny engine and returns the
// recorder plus the captured Principal (if the request reached the handler).
func serveWithAuth(t *testing.T, v oidcVerifier, cfg config.AuthConfig, authHeader string) (*httptest.ResponseRecorder, *Principal) {
	t.Helper()
	var captured *Principal
	r := gin.New()
	r.GET("/probe", OIDCAuthMiddleware(v, cfg), func(c *gin.Context) {
		if p, ok := PrincipalFrom(c); ok {
			captured = p
		}
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	r.ServeHTTP(w, req)
	return w, captured
}

func TestOIDCAuthMiddleware(t *testing.T) {
	v := newHermeticVerifier(t)
	cfg := testAuthConfig()

	tests := []struct {
		name       string
		authHeader string
		wantCode   int
	}{
		{
			name:       "missing token",
			authHeader: "",
			wantCode:   http.StatusUnauthorized,
		},
		{
			name:       "malformed token",
			authHeader: "Bearer not-a-jwt",
			wantCode:   http.StatusUnauthorized,
		},
		{
			name: "wrong issuer",
			authHeader: "Bearer " + mintToken(t, jose.RS256, func() map[string]interface{} {
				c := validClaims()
				c["iss"] = "https://evil.example.com"
				return c
			}()),
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "wrong audience",
			authHeader: "Bearer " + mintToken(t, jose.RS256, func() map[string]interface{} {
				c := validClaims()
				c["aud"] = "some-other-api"
				return c
			}()),
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "expired token",
			authHeader: "Bearer " + mintToken(t, jose.RS256, func() map[string]interface{} {
				c := validClaims()
				c["exp"] = fixedNow.Add(-1 * time.Hour).Unix()
				c["iat"] = fixedNow.Add(-2 * time.Hour).Unix()
				return c
			}()),
			wantCode: http.StatusUnauthorized,
		},
		{
			// FIX E: a symmetric HS256 token, otherwise structurally valid (right
			// issuer/aud/exp), must be rejected by the FIPS asymmetric allow-list.
			// The rejection therefore proves the alg gate fired, not a parse error.
			name:       "HS256 rejected by alg allow-list",
			authHeader: "Bearer " + mintTokenWithKey(t, jose.HS256, testHMACKey, validClaims()),
			wantCode:   http.StatusUnauthorized,
		},
		{
			// FIX E: an alg=none unsecured JWS must be rejected.
			name:       "alg=none rejected",
			authHeader: "Bearer " + mintNoneToken(t, validClaims()),
			wantCode:   http.StatusUnauthorized,
		},
		{
			// FIX F: a valid RS256 token signed by a key NOT in the StaticKeySet
			// must fail signature verification (proves we verify signatures, not
			// just claims).
			name:       "RS256 signed by untrusted key rejected",
			authHeader: "Bearer " + mintTokenWithKey(t, jose.RS256, testUntrustedRSAPriv, validClaims()),
			wantCode:   http.StatusUnauthorized,
		},
		{
			name:       "valid RS256",
			authHeader: "Bearer " + mintToken(t, jose.RS256, validClaims()),
			wantCode:   http.StatusOK,
		},
		{
			name:       "valid ES256",
			authHeader: "Bearer " + mintToken(t, jose.ES256, validClaims()),
			wantCode:   http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := serveWithAuth(t, v, cfg, tc.authHeader)
			assert.Equal(t, tc.wantCode, w.Code)
		})
	}
}

func TestOIDCAuthMiddleware_PopulatesPrincipal(t *testing.T) {
	v := newHermeticVerifier(t)
	cfg := testAuthConfig()

	w, p := serveWithAuth(t, v, cfg, "Bearer "+mintToken(t, jose.RS256, validClaims()))
	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, p)
	assert.Equal(t, "alice", p.Subject)
	assert.Equal(t, "alice", p.Username)
	assert.ElementsMatch(t, []string{"platform", "sre"}, p.Groups)
}

func TestOIDCAuthMiddleware_AbsentGroupsTolerated(t *testing.T) {
	v := newHermeticVerifier(t)
	cfg := testAuthConfig()

	claims := validClaims()
	delete(claims, "groups")
	w, p := serveWithAuth(t, v, cfg, "Bearer "+mintToken(t, jose.RS256, claims))
	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, p)
	assert.Empty(t, p.Groups)
}

// TestOIDCAuthMiddleware_SingleStringGroupsClaim covers FIX A/G: an IdP that
// emits the groups claim as a scalar string (rather than an array) must yield a
// single-element Principal.Groups, not an empty/dropped set (which would
// fail-closed and lock the user out of every RBAC-gated route).
func TestOIDCAuthMiddleware_SingleStringGroupsClaim(t *testing.T) {
	v := newHermeticVerifier(t)
	cfg := testAuthConfig()

	claims := validClaims()
	claims["groups"] = "platform"
	w, p := serveWithAuth(t, v, cfg, "Bearer "+mintToken(t, jose.RS256, claims))
	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, p)
	assert.Equal(t, []string{"platform"}, p.Groups)
}

// TestNewVerifierWithKeySet_PropagatesAllowList covers FIX H: the PRODUCTION
// verifier-assembly helper (the same one NewOIDCVerifier calls) must propagate
// cfg.SupportedAlgs into oidc.Config.SupportedSigningAlgs. Here the allow-list
// is ES256-only and the token is RS256 signed by a key that IS in the key set —
// so a passing result would mean the alg gate was bypassed. Asserting rejection
// proves the production line `SupportedSigningAlgs: cfg.SupportedAlgs` is live;
// deleting it would let this RS256 token through and fail the test.
func TestNewVerifierWithKeySet_PropagatesAllowList(t *testing.T) {
	keySet := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{
		testRSAPriv.Public(),
		testECDSAPriv.Public(),
	}}
	cfg := testAuthConfig()
	cfg.SupportedAlgs = []string{"ES256"}

	// The production helper does not pin a clock, so mint a token whose exp/iat
	// are valid under wall-clock time. The signing key (testRSAPriv) IS in the
	// key set and the issuer matches, so the ONLY reason verification can fail is
	// the RS256-vs-ES256 allow-list — which is exactly what this asserts.
	now := time.Now()
	claims := validClaims()
	claims["iat"] = now.Add(-1 * time.Minute).Unix()
	claims["nbf"] = now.Add(-1 * time.Minute).Unix()
	claims["exp"] = now.Add(1 * time.Hour).Unix()

	v := newVerifierWithKeySet(keySet, cfg)
	_, err := v.Verify(context.Background(), mintToken(t, jose.RS256, claims))
	require.Error(t, err, "RS256 must be rejected when the allow-list is ES256-only")
}
