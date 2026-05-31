package config

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTLSConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     TLSConfig
		wantErr bool
	}{
		{"tls13 no ciphers", TLSConfig{MinVersion: "1.3", ClientAuth: "require"}, false},
		{"tls13 approved cipher", TLSConfig{MinVersion: "1.3", CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}, ClientAuth: "none"}, false},
		{"tls13 native suite names accepted", TLSConfig{MinVersion: "1.3", CipherSuites: []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"}, ClientAuth: "none"}, false},
		{"empty client_auth ok", TLSConfig{MinVersion: "1.3", ClientAuth: ""}, false},
		{"tls12 below floor", TLSConfig{MinVersion: "1.2", ClientAuth: "require"}, true},
		{"bad min_version 1.1", TLSConfig{MinVersion: "1.1", ClientAuth: "require"}, true},
		{"bad min_version junk", TLSConfig{MinVersion: "tls1.3", ClientAuth: "require"}, true},
		{"unknown cipher", TLSConfig{MinVersion: "1.3", CipherSuites: []string{"TLS_RSA_WITH_RC4_128_SHA"}, ClientAuth: "none"}, true},
		{"weak cbc cipher rejected", TLSConfig{MinVersion: "1.3", CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}, ClientAuth: "none"}, true},
		{"unknown client_auth", TLSConfig{MinVersion: "1.3", ClientAuth: "maybe"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestBuildServerTLSConfig_MapsFields(t *testing.T) {
	cfg := TLSConfig{
		MinVersion:   "1.3",
		CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		ClientAuth:   "require",
	}
	pool := x509.NewCertPool()
	c, err := BuildServerTLSConfig(cfg, pool)
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}
	if c.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS1.3", c.MinVersion)
	}
	if len(c.CipherSuites) != 1 || c.CipherSuites[0] != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {
		t.Errorf("CipherSuites = %v, want [ECDHE_RSA_AES256_GCM]", c.CipherSuites)
	}
	if c.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert (CA pool supplied)", c.ClientAuth)
	}
}

// TestBuildServerTLSConfig_RequireWithoutCADowngrades proves the guard that
// prevents CRY-WU-03 from breaking handshakes before CRY-WU-04 mounts a CA
// bundle: client_auth=require with a nil CA pool falls back to NoClientCert.
func TestBuildServerTLSConfig_RequireWithoutCADowngrades(t *testing.T) {
	c, err := BuildServerTLSConfig(TLSConfig{MinVersion: "1.3", ClientAuth: "require"}, nil)
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}
	if c.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v, want NoClientCert when no CA pool supplied", c.ClientAuth)
	}
}

func TestBuildServerTLSConfig_RejectsInvalid(t *testing.T) {
	if _, err := BuildServerTLSConfig(TLSConfig{MinVersion: "1.1"}, nil); err == nil {
		t.Fatal("expected error for min_version 1.1")
	}
}

// TestServedHandshake_MinVersionEnforced is the integration proof for CRY-WU-03:
// a server built with min_version 1.3 from config completes a TLS 1.3 handshake
// and refuses a client capped at TLS 1.2.
func TestServedHandshake_MinVersionEnforced(t *testing.T) {
	serverCfg, err := BuildServerTLSConfig(TLSConfig{MinVersion: "1.3", ClientAuth: "none"}, nil)
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = serverCfg
	srv.StartTLS()
	defer srv.Close()

	// A TLS 1.3-capable client (trusting the test cert) must succeed.
	okClient := srv.Client()
	resp, err := okClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("TLS 1.3 client should connect: %v", err)
	}
	_ = resp.Body.Close()
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated version = %x, want TLS 1.3", func() uint16 {
			if resp.TLS == nil {
				return 0
			}
			return resp.TLS.Version
		}())
	}

	// A client capped at TLS 1.2 must be refused at handshake.
	downgrade := srv.Client()
	tr, ok := downgrade.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport from srv.Client()")
	}
	tr.TLSClientConfig.MaxVersion = tls.VersionTLS12
	if _, err := downgrade.Get(srv.URL); err == nil {
		t.Fatal("TLS 1.2 client must be refused by a min_version=1.3 listener")
	}
}
