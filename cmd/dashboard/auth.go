package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/Jibbscript/kube-policies/internal/auth"
)

// auth.go implements the dashboard's user authentication (IAM-WU-04), session
// lifecycle (IAM-WU-16), and the gate that protects the read/proxy endpoints
// (NET-WU-18). Three modes, selected by DASHBOARD_AUTH_MODE:
//
//   - "disabled" (default): no user auth — the legacy dev posture, loudly warned.
//   - "oidc": full OpenID Connect Authorization Code + PKCE login in the BFF,
//     with a stateless AES-256-GCM-sealed session cookie so any replica serves
//     any request (no sticky sessions / shared store).
//   - "forward-auth": trust identity headers set by an upstream identity-aware
//     proxy (oauth2-proxy / IAP / Traefik forwardAuth). ONLY safe when the
//     dashboard is not directly reachable — the proxy must strip client-supplied
//     identity headers at the trust boundary.
//
// Per-user authorization is enforced UPSTREAM by the policy-manager: the user's
// ID token is carried in the session and forwarded on proxied calls (IAM-WU-05),
// so the policy-manager's own OIDC+RBAC decides what the real user may do.

// fipsSigningAlgs is the FIPS-approved asymmetric JWS allow-list for ID-token
// verification, mirroring the policy-manager (config.fipsAsymmetricAlgs, which is
// package-private). HMAC and "none" are intentionally excluded so a token cannot
// be downgraded to an unapproved/unsigned algorithm.
var fipsSigningAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

type authMode string

const (
	authModeDisabled    authMode = "disabled"
	authModeOIDC        authMode = "oidc"
	authModeForwardAuth authMode = "forward-auth"
)

// Cookie purposes are used as AES-GCM additional authenticated data so a value
// sealed for one cookie cannot be replayed as the other.
const (
	sessionPurpose = "kp-dashboard-session-v1"
	oauthPurpose   = "kp-dashboard-oauthtx-v1"

	sessionCookieBase = "kp_dash_session"
	oauthCookieBase   = "kp_dash_oauthtx"

	// principalContextKey holds the authenticated *principal on the gin context.
	principalContextKey = "kp_principal"

	// oauthTxTTL bounds how long the in-flight login transaction (state, nonce,
	// PKCE verifier) is valid — it only needs to survive the IdP round-trip.
	oauthTxTTL = 10 * time.Minute
)

// principal is the authenticated user as seen by the dashboard. IDToken is the
// raw OIDC ID token forwarded upstream to the policy-manager (IAM-WU-05); it is
// empty in forward-auth mode unless the proxy passes an access-token header.
type principal struct {
	Subject  string
	Username string
	Email    string
	Groups   []string
	IDToken  string
}

// session is the JSON payload sealed into the session cookie. Field names are
// short to keep the sealed+base64 cookie within the ~4KB browser limit.
type session struct {
	Subject  string   `json:"sub"`
	Username string   `json:"usr"`
	Email    string   `json:"eml"`
	Groups   []string `json:"grp"`
	IDToken  string   `json:"idt"`
	AuthTime int64    `json:"iat"` // unix seconds at login; anchors the absolute timeout
	IdleExp  int64    `json:"iex"` // unix seconds; sliding inactivity deadline (AC-11/AC-12)
	AbsExp   int64    `json:"aex"` // unix seconds; hard maximum-lifetime deadline (AC-12)
}

// oauthTx is the short-lived login-transaction state sealed into the temp cookie
// across the IdP redirect.
type oauthTx struct {
	State    string `json:"st"`
	Nonce    string `json:"no"`
	Verifier string `json:"vf"` // PKCE code_verifier
	ReturnTo string `json:"rt"`
	Created  int64  `json:"ct"`
}

// authenticator carries the resolved auth configuration for the process.
type authenticator struct {
	mode   authMode
	log    *zap.Logger
	secure bool // session cookies are Secure + __Host- prefixed; false only for plaintext dev

	// oidc mode
	oauth2Cfg     *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	sealer        *cookieSealer
	usernameClaim string
	groupsClaim   string
	idleTimeout   time.Duration
	absTimeout    time.Duration

	// forward-auth mode
	fwdUserHeader   string
	fwdEmailHeader  string
	fwdGroupsHeader string
	fwdTokenHeader  string
}

// newAuthenticator resolves the auth configuration. For oidc mode it performs
// OIDC discovery against the issuer and builds the OAuth2 + verifier objects;
// a discovery or key failure is returned as an error so the caller fails closed
// rather than serving an unprotected dashboard while claiming auth is on.
func newAuthenticator(ctx context.Context, cfg *Config, log *zap.Logger) (*authenticator, error) {
	a := &authenticator{mode: authMode(cfg.AuthMode), log: log}
	switch a.mode {
	case authModeDisabled, "":
		a.mode = authModeDisabled
		return a, nil

	case authModeForwardAuth:
		a.fwdUserHeader = cfg.ForwardAuthUserHeader
		a.fwdEmailHeader = cfg.ForwardAuthEmailHeader
		a.fwdGroupsHeader = cfg.ForwardAuthGroupsHeader
		a.fwdTokenHeader = cfg.ForwardAuthTokenHeader
		return a, nil

	case authModeOIDC:
		keys, err := decodeSessionKeys(cfg.SessionKey, cfg.SessionKeyPrevious)
		if err != nil {
			return nil, fmt.Errorf("oidc auth: %w", err)
		}
		sealer, err := newCookieSealer(keys...)
		if err != nil {
			return nil, fmt.Errorf("oidc auth: %w", err)
		}
		provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
		if err != nil {
			return nil, fmt.Errorf("oidc auth: discover issuer %q: %w", cfg.OIDCIssuer, err)
		}
		a.secure = !cfg.SessionCookieInsecure
		a.sealer = sealer
		a.verifier = provider.Verifier(&oidc.Config{
			ClientID:             cfg.OIDCClientID,
			SupportedSigningAlgs: fipsSigningAlgs,
		})
		a.oauth2Cfg = &oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.OIDCRedirectURL,
			Scopes:       cfg.OIDCScopes,
		}
		a.usernameClaim = cfg.OIDCUsernameClaim
		a.groupsClaim = cfg.OIDCGroupsClaim
		a.idleTimeout = cfg.SessionIdleTimeout
		a.absTimeout = cfg.SessionAbsoluteTimeout
		return a, nil

	default:
		return nil, fmt.Errorf("unknown DASHBOARD_AUTH_MODE %q (want disabled|oidc|forward-auth)", cfg.AuthMode)
	}
}

func (a *authenticator) sessionCookieName() string { return cookieName(sessionCookieBase, a.secure) }
func (a *authenticator) oauthCookieName() string   { return cookieName(oauthCookieBase, a.secure) }

// principalFromContext returns the authenticated user stored by the auth
// middleware, if any. Used by the reverse proxy to forward the user's identity
// to the policy-manager (IAM-WU-05).
func principalFromContext(c *gin.Context) (*principal, bool) {
	v, ok := c.Get(principalContextKey)
	if !ok {
		return nil, false
	}
	p, ok := v.(*principal)
	return p, ok
}

// cookieName applies the __Host- prefix only when the cookie is Secure: the
// prefix REQUIRES Secure + Path=/ + no Domain, so a plaintext-dev cookie cannot
// use it.
func cookieName(base string, secure bool) string {
	if secure {
		return "__Host-" + base
	}
	return base
}

// registerRoutes adds the auth endpoints. In disabled/forward-auth mode the OIDC
// login endpoints are not served (there is nothing for the BFF to drive).
func (a *authenticator) registerRoutes(r *gin.Engine) {
	// /auth/userinfo works in every mode so the SPA can ask "who am I?" without
	// being challenged; it returns authenticated:false rather than 401.
	r.GET("/auth/userinfo", a.userinfo)
	if a.mode == authModeOIDC {
		r.GET("/auth/login", a.login)
		r.GET("/auth/callback", a.callback)
		r.POST("/auth/logout", a.logout)
	}
}

// middleware returns the gate applied to the protected read/proxy routes.
func (a *authenticator) middleware() gin.HandlerFunc {
	switch a.mode {
	case authModeForwardAuth:
		return a.forwardAuthMiddleware()
	case authModeOIDC:
		return a.sessionMiddleware()
	default: // disabled
		return func(c *gin.Context) { c.Next() }
	}
}

// sessionMiddleware enforces the OIDC session cookie: it rejects requests with no
// valid session, enforces the idle + absolute timeouts (AC-11/AC-12), and slides
// the idle window forward on each authenticated request.
func (a *authenticator) sessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sess, ok := a.readSession(c)
		if !ok {
			a.challenge(c)
			return
		}
		now := time.Now().Unix()
		if now >= sess.AbsExp || now >= sess.IdleExp {
			a.clearSession(c)
			a.challenge(c)
			return
		}
		// Slide the inactivity window and re-issue the cookie (AC-11/AC-12).
		// Best-effort: the session already opened (so it fit once); a failed
		// re-issue is logged but does not reject this already-authenticated request.
		sess.IdleExp = time.Now().Add(a.idleTimeout).Unix()
		_ = a.writeSession(c, sess)
		c.Set(principalContextKey, &principal{
			Subject:  sess.Subject,
			Username: sess.Username,
			Email:    sess.Email,
			Groups:   sess.Groups,
			IDToken:  sess.IDToken,
		})
		c.Next()
	}
}

// forwardAuthMiddleware trusts identity headers set by an upstream identity-aware
// proxy. A missing user header means the request did not pass through the proxy
// (or the proxy is misconfigured) → reject. SECURITY: these headers are spoofable
// if the dashboard is directly reachable; the proxy MUST strip client-supplied
// copies and the dashboard MUST only be reachable via the proxy.
func (a *authenticator) forwardAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := strings.TrimSpace(c.GetHeader(a.fwdUserHeader))
		if user == "" {
			a.challenge(c)
			return
		}
		c.Set(principalContextKey, &principal{
			Subject:  user,
			Username: user,
			Email:    strings.TrimSpace(c.GetHeader(a.fwdEmailHeader)),
			Groups:   splitGroups(c.GetHeader(a.fwdGroupsHeader)),
			IDToken:  strings.TrimSpace(c.GetHeader(a.fwdTokenHeader)),
		})
		c.Next()
	}
}

// challenge ends an unauthenticated request: a 302 to /auth/login for a top-level
// browser navigation, or a 401 (with an X-Login-URL hint) for an XHR/fetch/SSE
// request, which a 302 cannot drive (fetch follows it opaquely into a cross-origin
// CORS error; EventSource just errors).
func (a *authenticator) challenge(c *gin.Context) {
	loginURL := "/auth/login?return_to=" + url.QueryEscape(c.Request.URL.RequestURI())
	if a.mode == authModeOIDC && isNavigation(c.Request) {
		c.Redirect(http.StatusFound, loginURL)
		c.Abort()
		return
	}
	if a.mode == authModeOIDC {
		c.Header("X-Login-URL", loginURL)
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
}

// login starts the Authorization Code + PKCE flow: it mints state (CSRF), nonce
// (replay), and a PKCE verifier, seals them into the short-lived temp cookie, and
// redirects to the IdP with the S256 challenge.
func (a *authenticator) login(c *gin.Context) {
	state, err1 := auth.GenerateToken(auth.DefaultTokenBytes)
	nonce, err2 := auth.GenerateToken(auth.DefaultTokenBytes)
	if err1 != nil || err2 != nil {
		a.log.Error("failed to mint login state", zap.Error(errors.Join(err1, err2)))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "login unavailable"})
		return
	}
	verifier := oauth2.GenerateVerifier()
	tx := oauthTx{
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		ReturnTo: sanitizeReturnTo(c.Query("return_to")),
		Created:  time.Now().Unix(),
	}
	raw, _ := json.Marshal(tx)
	sealed, err := a.sealer.seal(oauthPurpose, raw)
	if err != nil {
		a.log.Error("failed to seal login transaction", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "login unavailable"})
		return
	}
	a.writeCookie(c, a.oauthCookieName(), sealed, int(oauthTxTTL.Seconds()))
	authURL := a.oauth2Cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	c.Redirect(http.StatusFound, authURL)
}

// callback completes the flow: verify state (CSRF), exchange the code with the
// PKCE verifier, verify the ID token, check the nonce (go-oidc does NOT), then
// establish the session and redirect back into the SPA.
func (a *authenticator) callback(c *gin.Context) {
	txRaw, err := c.Cookie(a.oauthCookieName())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "no login in progress"})
		return
	}
	// The transaction is single-use: clear the temp cookie regardless of outcome.
	a.clearCookie(c, a.oauthCookieName())

	opened, err := a.sealer.open(oauthPurpose, txRaw)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid login transaction"})
		return
	}
	var tx oauthTx
	if err = json.Unmarshal(opened, &tx); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid login transaction"})
		return
	}
	if time.Since(time.Unix(tx.Created, 0)) > oauthTxTTL {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "login expired, please retry"})
		return
	}
	if oidcErr := c.Query("error"); oidcErr != "" {
		a.log.Warn("oidc callback returned an error", zap.String("error", oidcErr))
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		return
	}
	// CSRF: the returned state must equal the sealed state.
	if !subtleConstEq(c.Query("state"), tx.State) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "state mismatch"})
		return
	}

	token, err := a.oauth2Cfg.Exchange(c.Request.Context(), c.Query("code"), oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		a.log.Warn("oidc code exchange failed", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no id_token in response"})
		return
	}
	idt, err := a.verifier.Verify(c.Request.Context(), rawID)
	if err != nil {
		a.log.Warn("id_token verification failed", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid id_token"})
		return
	}
	// CRITICAL: go-oidc's Verify does NOT validate the nonce — the caller must.
	if !subtleConstEq(idt.Nonce, tx.Nonce) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "nonce mismatch"})
		return
	}

	var claims map[string]any
	_ = idt.Claims(&claims)
	now := time.Now()
	sess := session{
		Subject:  idt.Subject,
		Username: claimString(claims, a.usernameClaim, idt.Subject),
		Email:    claimString(claims, "email", ""),
		Groups:   claimStrings(claims, a.groupsClaim),
		IDToken:  rawID,
		AuthTime: now.Unix(),
		IdleExp:  now.Add(a.idleTimeout).Unix(),
		AbsExp:   now.Add(a.absTimeout).Unix(),
	}
	if !a.writeSession(c, sess) {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "session too large; the identity token exceeds the cookie size limit (reduce group claims or token size)"})
		return
	}
	a.log.Info("dashboard user authenticated",
		zap.String("subject", sess.Subject),
		zap.String("username", sess.Username),
		zap.Int("groups", len(sess.Groups)),
	)
	c.Redirect(http.StatusFound, tx.ReturnTo)
}

// logout clears the session cookie (AC-12 user-initiated termination). Single
// logout at the IdP (end_session_endpoint) is left to the deployment.
func (a *authenticator) logout(c *gin.Context) {
	a.clearSession(c)
	c.Status(http.StatusNoContent)
}

// userinfo reports the current identity for the SPA. It never challenges: an
// unauthenticated caller gets {authenticated:false} so the SPA can render a login
// affordance rather than erroring.
func (a *authenticator) userinfo(c *gin.Context) {
	if a.mode == authModeDisabled {
		c.JSON(http.StatusOK, gin.H{"authenticated": true, "auth_mode": "disabled"})
		return
	}
	var p *principal
	switch a.mode {
	case authModeOIDC:
		if sess, ok := a.readSession(c); ok && time.Now().Unix() < sess.IdleExp && time.Now().Unix() < sess.AbsExp {
			p = &principal{Subject: sess.Subject, Username: sess.Username, Email: sess.Email, Groups: sess.Groups}
		}
	case authModeForwardAuth:
		if user := strings.TrimSpace(c.GetHeader(a.fwdUserHeader)); user != "" {
			p = &principal{Subject: user, Username: user, Email: strings.TrimSpace(c.GetHeader(a.fwdEmailHeader)), Groups: splitGroups(c.GetHeader(a.fwdGroupsHeader))}
		}
	}
	if p == nil {
		c.JSON(http.StatusOK, gin.H{"authenticated": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"username":      p.Username,
		"email":         p.Email,
		"groups":        p.Groups,
	})
}

// readSession decodes and validates the session cookie. It returns ok=false for a
// missing, malformed, or tampered cookie (callers treat that as no session).
func (a *authenticator) readSession(c *gin.Context) (session, bool) {
	raw, err := c.Cookie(a.sessionCookieName())
	if err != nil || raw == "" {
		return session{}, false
	}
	opened, err := a.sealer.open(sessionPurpose, raw)
	if err != nil {
		return session{}, false
	}
	var sess session
	if err := json.Unmarshal(opened, &sess); err != nil {
		return session{}, false
	}
	return sess, true
}

// maxSessionCookieBytes is a conservative ceiling (name+value) for the sealed
// session cookie. Browsers cap a single cookie at ~4096 bytes and SILENTLY DROP
// an over-limit Set-Cookie, which would strand the user in an invisible re-login
// loop. We fail loudly instead; the headroom below 4096 leaves room for other
// cookies. A raw ID token with very many group claims is the realistic trigger.
const maxSessionCookieBytes = 3800

// writeSession seals and emits the session cookie. It returns false (and logs)
// without emitting a cookie when the sealed value would exceed the browser size
// limit, so the caller can surface an explicit error rather than a silent loop.
func (a *authenticator) writeSession(c *gin.Context, sess session) bool {
	raw, _ := json.Marshal(sess)
	sealed, err := a.sealer.seal(sessionPurpose, raw)
	if err != nil {
		a.log.Error("failed to seal session", zap.Error(err))
		return false
	}
	if len(a.sessionCookieName())+len(sealed) > maxSessionCookieBytes {
		a.log.Error("session cookie exceeds the browser size limit; the identity token is too large for a cookie session",
			zap.Int("sealed_bytes", len(sealed)),
			zap.Int("limit_bytes", maxSessionCookieBytes),
			zap.Int("id_token_bytes", len(sess.IDToken)),
		)
		return false
	}
	// Cookie Max-Age tracks the idle window so the browser drops it on inactivity.
	a.writeCookie(c, a.sessionCookieName(), sealed, int(a.idleTimeout.Seconds()))
	return true
}

func (a *authenticator) clearSession(c *gin.Context) { a.clearCookie(c, a.sessionCookieName()) }

func (a *authenticator) writeCookie(c *gin.Context, name, value string, maxAgeSeconds int) {
	//nolint:gosec // G124 false positive: HttpOnly and SameSite=Lax are set unconditionally; Secure tracks a.secure, which is true by default and only false when an operator explicitly opts into plaintext-dev (SessionCookieInsecure), where the __Host- cookie-name prefix is also dropped (forcing Secure:true here would silently break that documented mode). SameSite=Lax is correct because the OIDC redirect lands as a top-level GET, on which the browser DOES send Lax cookies, so the temp oauth cookie is readable on the callback without needing SameSite=None.
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *authenticator) clearCookie(c *gin.Context, name string) {
	//nolint:gosec // G124 false positive: HttpOnly and SameSite=Lax are set unconditionally; Secure tracks a.secure (true by default, false only for the documented plaintext-dev opt-in). This is a deletion (MaxAge:-1, empty value), so the attribute set mirrors writeCookie exactly.
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- cookie sealing (AES-256-GCM, FIPS-approved AEAD) ---

// cookieSealer seals/opens opaque cookie values with AES-256-GCM. It holds a key
// ring so keys rotate without invalidating live sessions: values are sealed with
// the FIRST (current) key and opened by trying each key in order. AES-GCM is an
// AEAD, so confidentiality and integrity come in one pass with no separate HMAC.
type cookieSealer struct {
	aeads []cipher.AEAD
}

func newCookieSealer(keys ...[]byte) (*cookieSealer, error) {
	if len(keys) == 0 {
		return nil, errors.New("cookieSealer: at least one 32-byte key is required")
	}
	s := &cookieSealer{}
	for i, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("cookieSealer: key %d must be 32 bytes (AES-256), got %d", i, len(k))
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("cookieSealer: aes.NewCipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("cookieSealer: cipher.NewGCM: %w", err)
		}
		s.aeads = append(s.aeads, gcm)
	}
	return s, nil
}

// seal encrypts plaintext with the current key, binding purpose as AAD. The
// output is base64url(nonce || ciphertext||tag) with a fresh random 96-bit nonce.
func (s *cookieSealer) seal(purpose string, plaintext []byte) (string, error) {
	gcm := s.aeads[0]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("cookieSealer: read nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(purpose))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open decrypts a sealed value, trying each key (current then previous) so a
// rotated-out key still opens live cookies. Any tamper, wrong key, or wrong
// purpose yields an error.
func (s *cookieSealer) open(purpose, value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("cookieSealer: malformed value")
	}
	for _, gcm := range s.aeads {
		ns := gcm.NonceSize()
		if len(raw) < ns {
			continue
		}
		if pt, err := gcm.Open(nil, raw[:ns], raw[ns:], []byte(purpose)); err == nil {
			return pt, nil
		}
	}
	return nil, errors.New("cookieSealer: cannot open value (tampered, rotated-out key, or wrong purpose)")
}

// decodeSessionKeys decodes the base64 session keys. The current key is required;
// the previous key is optional (rotation). Each must decode to 32 bytes.
func decodeSessionKeys(current, previous string) ([][]byte, error) {
	if current == "" {
		return nil, errors.New("DASHBOARD_SESSION_KEY is required in oidc mode (base64 of 32 random bytes)")
	}
	out := make([][]byte, 0, 2)
	cur, err := decodeKey(current)
	if err != nil {
		return nil, fmt.Errorf("DASHBOARD_SESSION_KEY: %w", err)
	}
	out = append(out, cur)
	if previous != "" {
		prev, err := decodeKey(previous)
		if err != nil {
			return nil, fmt.Errorf("DASHBOARD_SESSION_KEY_PREVIOUS: %w", err)
		}
		out = append(out, prev)
	}
	return out, nil
}

func decodeKey(s string) ([]byte, error) {
	// Accept standard or URL-safe base64, padded or raw, for operator convenience
	// (the cookie payload itself uses base64url, so a URL-safe key is a natural
	// thing for an operator to supply).
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != 32 {
				return nil, fmt.Errorf("key must decode to 32 bytes (AES-256), got %d", len(b))
			}
			return b, nil
		}
	}
	return nil, errors.New("not valid base64")
}

// --- helpers ---

// sanitizeReturnTo permits only a same-origin absolute path, defeating open
// redirects. It rejects anything that could escape the origin: a non-"/" start,
// "//" (protocol-relative), a backslash (browsers normalize "\" to "/", so
// "/\evil.com" navigates as protocol-relative "//evil.com" — a post-login open
// redirect), CR/LF/control characters (header splitting), and anything net/url
// parses as absolute or host-bearing.
func sanitizeReturnTo(raw string) string {
	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") {
		return "/"
	}
	if strings.ContainsAny(raw, "\\\r\n") {
		return "/"
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "/"
		}
	}
	if u, err := url.Parse(raw); err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	return raw
}

// isNavigation reports whether the request is a top-level browser navigation (so
// a 302 to the IdP is appropriate) versus an XHR/fetch/EventSource (which needs a
// 401). Sec-Fetch-Mode is the reliable modern signal; the Accept/X-Requested-With
// pair is the fallback.
func isNavigation(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Mode") {
	case "navigate":
		return true
	case "cors", "no-cors", "same-origin", "websocket":
		return false
	}
	if r.Header.Get("X-Requested-With") != "" {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// splitGroups parses a comma-separated forwarded-groups header into a slice.
func splitGroups(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func claimString(claims map[string]any, key, fallback string) string {
	if key == "" {
		return fallback
	}
	if v, ok := claims[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

func claimStrings(claims map[string]any, key string) []string {
	if key == "" {
		return nil
	}
	v, ok := claims[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}

// subtleConstEq compares two strings in constant time (avoids leaking the state /
// nonce via early-exit timing). ConstantTimeCompare returns 0 on a length
// mismatch, so empty-vs-empty (both unset) is handled by the callers requiring a
// non-empty sealed value first.
func subtleConstEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
