package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	jose "github.com/go-jose/go-jose/v4"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func init() { gin.SetMode(gin.TestMode) }

// --- cookie sealer ---

func testKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestCookieSealer_RoundTripAndTamper(t *testing.T) {
	s, err := newCookieSealer(testKey(1))
	if err != nil {
		t.Fatalf("newCookieSealer: %v", err)
	}
	sealed, err := s.seal(sessionPurpose, []byte("hello-session"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := s.open(sessionPurpose, sealed)
	if err != nil || string(got) != "hello-session" {
		t.Fatalf("open round-trip = (%q, %v), want hello-session", got, err)
	}
	// Flip a byte in the base64 payload → authentication tag fails.
	raw, _ := base64.RawURLEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := s.open(sessionPurpose, tampered); err == nil {
		t.Fatal("tampered ciphertext must fail to open")
	}
}

func TestCookieSealer_WrongPurposeRejected(t *testing.T) {
	s, _ := newCookieSealer(testKey(2))
	sealed, _ := s.seal(oauthPurpose, []byte("tx"))
	// A value sealed for the oauth purpose must not open under the session purpose.
	if _, err := s.open(sessionPurpose, sealed); err == nil {
		t.Fatal("AAD purpose binding must prevent cross-purpose open")
	}
}

func TestCookieSealer_KeyRotation(t *testing.T) {
	old, _ := newCookieSealer(testKey(3))
	sealedWithOld, _ := old.seal(sessionPurpose, []byte("rotate-me"))

	// New ring: current key is new (4), previous key is old (3).
	rotated, err := newCookieSealer(testKey(4), testKey(3))
	if err != nil {
		t.Fatalf("newCookieSealer: %v", err)
	}
	got, err := rotated.open(sessionPurpose, sealedWithOld)
	if err != nil || string(got) != "rotate-me" {
		t.Fatalf("rotated ring must open a value sealed with the previous key: (%q, %v)", got, err)
	}
	// And it seals with the NEW key — a ring holding only the new key opens it.
	fresh, _ := rotated.seal(sessionPurpose, []byte("fresh"))
	newOnly, _ := newCookieSealer(testKey(4))
	if _, err := newOnly.open(sessionPurpose, fresh); err != nil {
		t.Fatalf("value must be sealed with the current (new) key: %v", err)
	}
	// A ring holding only the rotated-out key cannot open the fresh value.
	oldOnly, _ := newCookieSealer(testKey(3))
	if _, err := oldOnly.open(sessionPurpose, fresh); err == nil {
		t.Fatal("rotated-out key must not open a value sealed with the new key")
	}
}

func TestCookieSealer_KeySizeValidation(t *testing.T) {
	if _, err := newCookieSealer(make([]byte, 16)); err == nil {
		t.Fatal("a 16-byte key must be rejected (AES-256 requires 32)")
	}
	if _, err := newCookieSealer(); err == nil {
		t.Fatal("no keys must be rejected")
	}
}

func TestDecodeSessionKeys(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(testKey(9))
	keys, err := decodeSessionKeys(good, "")
	if err != nil || len(keys) != 1 {
		t.Fatalf("decodeSessionKeys(good,\"\") = (%v,%v)", keys, err)
	}
	// URL-safe base64 keys (containing - or _) must also decode (review NIT). An
	// all-0xFF key encodes to "____...==" under the URL alphabet.
	allFF := make([]byte, 32)
	for i := range allFF {
		allFF[i] = 0xFF
	}
	if _, err := decodeSessionKeys(base64.URLEncoding.EncodeToString(allFF), ""); err != nil {
		t.Fatalf("URL-safe base64 key must decode: %v", err)
	}
	if _, err := decodeSessionKeys("", ""); err == nil {
		t.Fatal("empty current key must error")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := decodeSessionKeys(short, ""); err == nil {
		t.Fatal("a key that decodes to 16 bytes must error")
	}
}

// --- middleware ---

func oidcTestAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	sealer, err := newCookieSealer(testKey(7))
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{
		mode:          authModeOIDC,
		log:           zap.NewNop(),
		secure:        false, // base cookie names (no __Host-) so tests read them over http
		sealer:        sealer,
		usernameClaim: "sub",
		groupsClaim:   "groups",
		idleTimeout:   15 * time.Minute,
		absTimeout:    12 * time.Hour,
	}
}

func (a *authenticator) sealSessionCookie(t *testing.T, sess session) *http.Cookie {
	t.Helper()
	raw, _ := json.Marshal(sess)
	sealed, err := a.sealer.seal(sessionPurpose, raw)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: a.sessionCookieName(), Value: sealed}
}

func runMiddleware(a *authenticator, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := gin.New()
	g := r.Group("")
	g.Use(a.middleware())
	g.GET("/api/decisions/recent", func(c *gin.Context) {
		p, ok := principalFromContext(c)
		if !ok {
			c.String(http.StatusOK, "no-principal")
			return
		}
		c.String(http.StatusOK, "user="+p.Username)
	})
	r.ServeHTTP(w, req)
	return w
}

func TestSessionMiddleware_NoCookie(t *testing.T) {
	a := oidcTestAuthenticator(t)

	t.Run("XHR gets 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/decisions/recent", nil)
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		w := runMiddleware(a, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if w.Header().Get("X-Login-URL") == "" {
			t.Fatal("401 should carry an X-Login-URL hint")
		}
	})

	t.Run("top-level navigation gets 302 to login", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/decisions/recent", nil)
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		w := runMiddleware(a, req)
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", w.Code)
		}
		if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/auth/login") {
			t.Fatalf("Location = %q, want /auth/login redirect", loc)
		}
	})
}

func TestSessionMiddleware_ValidSession(t *testing.T) {
	a := oidcTestAuthenticator(t)
	now := time.Now()
	sess := session{
		Subject:  "u-1",
		Username: "alice",
		Groups:   []string{"platform-admins"},
		AuthTime: now.Unix(),
		IdleExp:  now.Add(10 * time.Minute).Unix(),
		AbsExp:   now.Add(6 * time.Hour).Unix(),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/decisions/recent", nil)
	req.AddCookie(a.sealSessionCookie(t, sess))
	w := runMiddleware(a, req)
	if w.Code != http.StatusOK || w.Body.String() != "user=alice" {
		t.Fatalf("valid session: code=%d body=%q, want 200 user=alice", w.Code, w.Body.String())
	}
	// The middleware slides the idle window and re-issues the cookie.
	var reissued bool
	for _, ck := range w.Result().Cookies() {
		if ck.Name == a.sessionCookieName() && ck.Value != "" {
			reissued = true
		}
	}
	if !reissued {
		t.Fatal("a valid request should re-issue (slide) the session cookie")
	}
}

func TestSessionMiddleware_Expired(t *testing.T) {
	a := oidcTestAuthenticator(t)
	now := time.Now()

	cases := map[string]session{
		"idle expired": {Subject: "u", Username: "x", IdleExp: now.Add(-time.Minute).Unix(), AbsExp: now.Add(time.Hour).Unix()},
		"abs expired":  {Subject: "u", Username: "x", IdleExp: now.Add(time.Hour).Unix(), AbsExp: now.Add(-time.Minute).Unix()},
	}
	for name, sess := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/decisions/recent", nil)
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
			req.AddCookie(a.sealSessionCookie(t, sess))
			w := runMiddleware(a, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 for %s", w.Code, name)
			}
			// The stale cookie is cleared (Max-Age<0).
			var cleared bool
			for _, ck := range w.Result().Cookies() {
				if ck.Name == a.sessionCookieName() && ck.MaxAge < 0 {
					cleared = true
				}
			}
			if !cleared {
				t.Fatal("an expired session must clear the cookie")
			}
		})
	}
}

func TestSessionMiddleware_TamperedCookieRejected(t *testing.T) {
	a := oidcTestAuthenticator(t)
	// A cookie sealed with a DIFFERENT key must not authenticate.
	other := &authenticator{sealer: mustSealer(t, testKey(99)), secure: false}
	forged := other.sealSessionCookie(t, session{Username: "mallory", IdleExp: time.Now().Add(time.Hour).Unix(), AbsExp: time.Now().Add(time.Hour).Unix()})
	forged.Name = a.sessionCookieName()
	req := httptest.NewRequest(http.MethodGet, "/api/decisions/recent", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.AddCookie(forged)
	w := runMiddleware(a, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("forged cookie sealed by an unknown key must be rejected, got %d", w.Code)
	}
}

func mustSealer(t *testing.T, key []byte) *cookieSealer {
	t.Helper()
	s, err := newCookieSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestForwardAuthMiddleware(t *testing.T) {
	a := &authenticator{
		mode:            authModeForwardAuth,
		log:             zap.NewNop(),
		fwdUserHeader:   "X-Forwarded-User",
		fwdEmailHeader:  "X-Forwarded-Email",
		fwdGroupsHeader: "X-Forwarded-Groups",
		fwdTokenHeader:  "X-Forwarded-Access-Token",
	}

	t.Run("trusts forwarded identity", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/decisions/recent", nil)
		req.Header.Set("X-Forwarded-User", "bob")
		req.Header.Set("X-Forwarded-Groups", "policy-authors, platform-admins")
		w := runMiddleware(a, req)
		if w.Code != http.StatusOK || w.Body.String() != "user=bob" {
			t.Fatalf("forward-auth: code=%d body=%q", w.Code, w.Body.String())
		}
	})

	t.Run("missing identity header is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/decisions/recent", nil)
		w := runMiddleware(a, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("missing forwarded user must 401, got %d", w.Code)
		}
	})
}

func TestDisabledMiddleware_PassesThrough(t *testing.T) {
	a := &authenticator{mode: authModeDisabled, log: zap.NewNop()}
	req := httptest.NewRequest(http.MethodGet, "/api/decisions/recent", nil)
	w := runMiddleware(a, req)
	if w.Code != http.StatusOK {
		t.Fatalf("disabled mode must pass through, got %d", w.Code)
	}
}

// --- OIDC login + callback (hermetic, offline-signed ID token) ---

func newOIDCTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signIDToken(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

const testClientID = "kube-policies-dashboard"
const testIssuer = "https://issuer.test.example.com"

// oidcFlowAuthenticator wires an authenticator whose token endpoint is a local
// httptest server returning idToken, and whose verifier trusts key's public half.
func oidcFlowAuthenticator(t *testing.T, key *ecdsa.PrivateKey, idToken string) (*authenticator, *httptest.Server) {
	t.Helper()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	keySet := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key.Public()}}
	verifier := oidc.NewVerifier(testIssuer, keySet, &oidc.Config{
		ClientID:             testClientID,
		SupportedSigningAlgs: fipsSigningAlgs,
	})
	a := oidcTestAuthenticator(t)
	a.verifier = verifier
	a.oauth2Cfg = &oauth2.Config{
		ClientID:     testClientID,
		ClientSecret: "secret",
		Endpoint:     oauth2.Endpoint{AuthURL: "https://issuer.test.example.com/authorize", TokenURL: tokenSrv.URL},
		RedirectURL:  "https://dash.example.com/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "groups"},
	}
	return a, tokenSrv
}

func TestLogin_SetsTempCookieAndRedirects(t *testing.T) {
	a, _ := oidcFlowAuthenticator(t, newOIDCTestKey(t), "")
	r := gin.New()
	a.registerRoutes(r)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/policies", nil))

	if w.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	q := loc.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("login must send a PKCE S256 challenge, got %v", loc.RawQuery)
	}
	if q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatal("login must send state + nonce")
	}
	var hasTemp bool
	for _, ck := range w.Result().Cookies() {
		if ck.Name == a.oauthCookieName() && ck.Value != "" && ck.HttpOnly {
			hasTemp = true
		}
	}
	if !hasTemp {
		t.Fatal("login must set an HttpOnly temp cookie")
	}
}

// callbackFixture drives login (to obtain a valid temp cookie) then crafts the
// matching ID token and returns the callback response. tamper lets a test mutate
// the returned state / nonce to assert rejections.
func runCallback(t *testing.T, mutate func(state *string, nonce *string)) *httptest.ResponseRecorder {
	t.Helper()
	key := newOIDCTestKey(t)
	// First do /auth/login with a placeholder authenticator to mint a temp cookie.
	pre, _ := oidcFlowAuthenticator(t, key, "")
	rl := gin.New()
	pre.registerRoutes(rl)
	lw := httptest.NewRecorder()
	rl.ServeHTTP(lw, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/metrics", nil))
	var tempCookie *http.Cookie
	for _, ck := range lw.Result().Cookies() {
		if ck.Name == pre.oauthCookieName() {
			tempCookie = ck
		}
	}
	if tempCookie == nil {
		t.Fatal("no temp cookie from login")
	}
	// Recover the sealed state/nonce so the ID token can carry the right nonce.
	opened, err := pre.sealer.open(oauthPurpose, tempCookie.Value)
	if err != nil {
		t.Fatalf("open temp cookie: %v", err)
	}
	var tx oauthTx
	_ = json.Unmarshal(opened, &tx)

	state, nonce := tx.State, tx.Nonce
	if mutate != nil {
		mutate(&state, &nonce)
	}
	idToken := signIDToken(t, key, map[string]any{
		"iss":    testIssuer,
		"aud":    testClientID,
		"sub":    "user-123",
		"email":  "user@example.com",
		"groups": []string{"platform-admins"},
		"nonce":  nonce,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	a, _ := oidcFlowAuthenticator(t, key, idToken)

	r := gin.New()
	a.registerRoutes(r)
	cbURL := "/auth/callback?code=abc&state=" + url.QueryEscape(state)
	req := httptest.NewRequest(http.MethodGet, cbURL, nil)
	req.AddCookie(tempCookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestCallback_HappyPath(t *testing.T) {
	w := runCallback(t, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d (%s), want 302", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/metrics" {
		t.Fatalf("callback should redirect to return_to=/metrics, got %q", loc)
	}
	var gotSession bool
	for _, ck := range w.Result().Cookies() {
		if strings.Contains(ck.Name, sessionCookieBase) && ck.Value != "" && ck.HttpOnly {
			gotSession = true
		}
	}
	if !gotSession {
		t.Fatal("happy-path callback must establish a session cookie")
	}
}

func TestCallback_NonceMismatchRejected(t *testing.T) {
	// Sign the ID token with a nonce that does NOT match the sealed transaction.
	w := runCallback(t, func(_ *string, nonce *string) { *nonce = "attacker-controlled-nonce" })
	if w.Code != http.StatusForbidden {
		t.Fatalf("nonce mismatch must be 403 (go-oidc does not check nonce), got %d", w.Code)
	}
}

func TestCallback_StateMismatchRejected(t *testing.T) {
	w := runCallback(t, func(state *string, _ *string) { *state = "wrong-state" })
	if w.Code != http.StatusForbidden {
		t.Fatalf("state (CSRF) mismatch must be 403, got %d", w.Code)
	}
}

// --- config validation + helpers ---

func TestConfigValidateAuth(t *testing.T) {
	t.Run("disabled ok", func(t *testing.T) {
		if err := (&Config{AuthMode: "disabled"}).validateAuth(); err != nil {
			t.Fatalf("disabled must validate: %v", err)
		}
	})
	t.Run("oidc missing fields fails closed", func(t *testing.T) {
		err := (&Config{AuthMode: "oidc"}).validateAuth()
		if err == nil {
			t.Fatal("oidc with no issuer/client/key must error")
		}
		for _, want := range []string{"DASHBOARD_OIDC_ISSUER", "DASHBOARD_OIDC_CLIENT_ID", "DASHBOARD_SESSION_KEY"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error must name %s, got: %v", want, err)
			}
		}
	})
	t.Run("oidc complete ok", func(t *testing.T) {
		c := &Config{
			AuthMode:         "oidc",
			OIDCIssuer:       "https://idp",
			OIDCClientID:     "id",
			OIDCClientSecret: "sec",
			OIDCRedirectURL:  "https://d/auth/callback",
			SessionKey:       "k",
		}
		if err := c.validateAuth(); err != nil {
			t.Fatalf("complete oidc must validate: %v", err)
		}
	})
	t.Run("unknown mode errors", func(t *testing.T) {
		if err := (&Config{AuthMode: "magic"}).validateAuth(); err == nil {
			t.Fatal("unknown auth mode must error")
		}
	})
}

func TestSanitizeReturnTo(t *testing.T) {
	cases := map[string]string{
		"/policies":               "/policies",
		"/policies?id=1#frag":     "/policies?id=1#frag",
		"":                        "/",
		"relative":                "/",
		"//evil.com":              "/",
		"https://evil.com":        "/",
		"javascript:alert(1)":     "/",
		"/\\evil.com":             "/", // browser normalizes \ to / -> //evil.com (MAJOR finding)
		"/\\/evil.com":            "/",
		"/\\\\evil.com":           "/",
		"/foo\r\nSet-Cookie: x=y": "/", // CRLF header splitting
		"/foo\x00bar":             "/", // NUL / control char
	}
	for in, want := range cases {
		if got := sanitizeReturnTo(in); got != want {
			t.Errorf("sanitizeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteSession_SizeGuard(t *testing.T) {
	a := oidcTestAuthenticator(t)

	// An over-size session (e.g. a giant ID token) must NOT be written — the
	// browser would silently drop it and strand the user in a re-login loop.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	huge := session{Subject: "u", IDToken: strings.Repeat("x", 6000), IdleExp: time.Now().Add(time.Hour).Unix(), AbsExp: time.Now().Add(time.Hour).Unix()}
	if a.writeSession(c, huge) {
		t.Fatal("an over-size session must return false")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("no cookie may be emitted when over the size limit")
	}

	// A normal session writes fine.
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	if !a.writeSession(c2, session{Subject: "u", Username: "alice", IdleExp: time.Now().Add(time.Hour).Unix(), AbsExp: time.Now().Add(time.Hour).Unix()}) {
		t.Fatal("a normal session must be written")
	}
}

func TestIsNavigation(t *testing.T) {
	nav := httptest.NewRequest(http.MethodGet, "/", nil)
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	if !isNavigation(nav) {
		t.Error("Sec-Fetch-Mode: navigate should be a navigation")
	}
	xhr := httptest.NewRequest(http.MethodGet, "/", nil)
	xhr.Header.Set("Sec-Fetch-Mode", "cors")
	if isNavigation(xhr) {
		t.Error("Sec-Fetch-Mode: cors must NOT be a navigation")
	}
	reqXHR := httptest.NewRequest(http.MethodGet, "/", nil)
	reqXHR.Header.Set("X-Requested-With", "XMLHttpRequest")
	if isNavigation(reqXHR) {
		t.Error("X-Requested-With must NOT be a navigation")
	}
}

func TestSplitGroups(t *testing.T) {
	got := splitGroups(" a, b ,, c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("splitGroups = %v, want [a b c]", got)
	}
	if splitGroups("") != nil {
		t.Fatal("empty groups must be nil")
	}
}

func TestClaimStrings(t *testing.T) {
	claims := map[string]any{
		"groups":  []any{"a", "b"},
		"single":  "solo",
		"numbers": []any{1, 2},
	}
	if got := claimStrings(claims, "groups"); len(got) != 2 || got[0] != "a" {
		t.Fatalf("claimStrings(groups) = %v", got)
	}
	if got := claimStrings(claims, "single"); len(got) != 1 || got[0] != "solo" {
		t.Fatalf("claimStrings(single) = %v", got)
	}
	if got := claimStrings(claims, "missing"); got != nil {
		t.Fatalf("missing claim must be nil, got %v", got)
	}
}
