package auth

import (
	"strings"
	"testing"
)

func TestBearerToken(t *testing.T) {
	cases := map[string]struct {
		header string
		want   string
	}{
		"valid":          {"Bearer abc123", "abc123"},
		"empty token":    {"Bearer ", ""},
		"no scheme":      {"abc123", ""},
		"wrong scheme":   {"Basic abc123", ""},
		"wrong case":     {"bearer abc123", ""},
		"empty header":   {"", ""},
		"prefix only":    {"Bearer", ""},
		"token w spaces": {"Bearer a b c", "a b c"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := BearerToken(tc.header); got != tc.want {
				t.Fatalf("BearerToken(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestTokenVerifier_Configured(t *testing.T) {
	if NewTokenVerifier().Configured() {
		t.Fatal("verifier with no tokens must be unconfigured")
	}
	if NewTokenVerifier("", "").Configured() {
		t.Fatal("verifier with only empty tokens must be unconfigured")
	}
	if !NewTokenVerifier("real").Configured() {
		t.Fatal("verifier with a real token must be configured")
	}
	var nilV *TokenVerifier
	if nilV.Configured() {
		t.Fatal("nil verifier must be unconfigured")
	}
}

func TestTokenVerifier_Verify(t *testing.T) {
	v := NewTokenVerifier("s3cret-current")
	if !v.Verify("s3cret-current") {
		t.Fatal("matching token must verify")
	}
	if v.Verify("s3cret-wrong") {
		t.Fatal("non-matching token must be rejected")
	}
	if v.Verify("") {
		t.Fatal("empty presented token must be rejected")
	}
	// Length must not be leaked: a prefix of the real token is rejected.
	if v.Verify("s3cret") {
		t.Fatal("token prefix must be rejected")
	}
}

func TestTokenVerifier_Unconfigured_RejectsEverything(t *testing.T) {
	v := NewTokenVerifier("")
	if v.Verify("") || v.Verify("anything") {
		t.Fatal("unconfigured verifier must reject every token (no wildcard)")
	}
}

// TestTokenVerifier_RotationWindow proves CRY-WU-14: during rotation both the
// current and the previous token are accepted, while an unrelated token is
// still rejected.
func TestTokenVerifier_RotationWindow(t *testing.T) {
	v := NewTokenVerifier("new-token", "old-token")
	if !v.Verify("new-token") {
		t.Fatal("current token must verify during rotation")
	}
	if !v.Verify("old-token") {
		t.Fatal("previous token must verify during rotation")
	}
	if v.Verify("retired-token") {
		t.Fatal("a token outside the rotation window must be rejected")
	}
}

func TestTokenVerifier_VerifyHeader(t *testing.T) {
	v := NewTokenVerifier("hdr-token")
	if !v.VerifyHeader("Bearer hdr-token") {
		t.Fatal("valid bearer header must verify")
	}
	if v.VerifyHeader("Bearer wrong") {
		t.Fatal("wrong bearer header must be rejected")
	}
	if v.VerifyHeader("hdr-token") {
		t.Fatal("missing Bearer scheme must be rejected")
	}
}

func TestGenerateToken(t *testing.T) {
	a, err := GenerateToken(DefaultTokenBytes)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	b, err := GenerateToken(DefaultTokenBytes)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if a == b {
		t.Fatal("two generated tokens must differ")
	}
	if a == "" {
		t.Fatal("generated token must be non-empty")
	}
	// RawURLEncoding must not contain padding or URL-unsafe characters.
	if strings.ContainsAny(a, "+/=") {
		t.Fatalf("token %q must be URL-safe and unpadded", a)
	}
	// A freshly generated token round-trips through the verifier.
	if !NewTokenVerifier(a).Verify(a) {
		t.Fatal("generated token must verify against itself")
	}
}

func TestGenerateToken_NonPositiveNormalizes(t *testing.T) {
	tok, err := GenerateToken(0)
	if err != nil {
		t.Fatalf("GenerateToken(0): %v", err)
	}
	// 32 bytes -> ceil(32/3)*4 - padding = 43 RawURLEncoding chars.
	if len(tok) != 43 {
		t.Fatalf("GenerateToken(0) length = %d, want 43 (32 bytes RawURLEncoding)", len(tok))
	}
}
