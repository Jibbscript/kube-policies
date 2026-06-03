package config

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestBuildClientTLSConfig_ReturnShape covers the three early-return shapes of
// the IAM-WU-03 signature: nil when neither a trust root nor a client identity
// is supplied, RootCAs-only when just a CA is given, and a client-identity
// config (system roots) when only getClientCert is given.
func TestBuildClientTLSConfig_ReturnShape(t *testing.T) {
	ca := newTestCA(t)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	clientLeaf := ca.leaf(t, "client", true)
	getCert := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientLeaf, nil }

	t.Run("empty path and nil cert returns nil config", func(t *testing.T) {
		cfg, err := BuildClientTLSConfig("", nil)
		if err != nil || cfg != nil {
			t.Fatalf("BuildClientTLSConfig(\"\", nil) = (%v, %v), want (nil, nil)", cfg, err)
		}
	})

	t.Run("CA only sets RootCAs and no client cert", func(t *testing.T) {
		cfg, err := BuildClientTLSConfig(caFile, nil)
		if err != nil {
			t.Fatalf("BuildClientTLSConfig: %v", err)
		}
		if cfg == nil || cfg.RootCAs == nil {
			t.Fatalf("expected non-nil config with RootCAs, got %+v", cfg)
		}
		if cfg.GetClientCertificate != nil {
			t.Fatal("GetClientCertificate must be nil when no client identity is supplied")
		}
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
		}
		if cfg.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify must never be set")
		}
	})

	t.Run("client cert only uses system roots", func(t *testing.T) {
		cfg, err := BuildClientTLSConfig("", getCert)
		if err != nil {
			t.Fatalf("BuildClientTLSConfig: %v", err)
		}
		if cfg == nil || cfg.GetClientCertificate == nil {
			t.Fatalf("expected non-nil config with GetClientCertificate, got %+v", cfg)
		}
		if cfg.RootCAs != nil {
			t.Fatal("RootCAs must be nil (system roots) when only a client identity is supplied")
		}
	})

	t.Run("bad CA path propagates the load error", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "nope.crt")
		if _, err := BuildClientTLSConfig(bad, getCert); err == nil {
			t.Fatal("a missing CA bundle must surface an error")
		}
	})
}

// TestBuildClientTLSConfig_MutualRoundTrip is the end-to-end proof for IAM-WU-03:
// a server that RequireAndVerifyClientCert accepts a client built by
// BuildClientTLSConfig that presents a CA-signed cert, and rejects one that
// presents none.
func TestBuildClientTLSConfig_MutualRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	serverLeaf := ca.leaf(t, "policy-manager", false)
	clientLeaf := ca.leaf(t, "admission-webhook", true)

	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}

	// Server enforces client-cert verification against the CA pool (mirrors the
	// policy-manager listener under --require-client-cert).
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca.cert)
	serverCfg, err := BuildServerTLSConfig(TLSConfig{MinVersion: "1.3", ClientAuth: "require"}, clientCAs)
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}
	serverCfg.Certificates = []tls.Certificate{serverLeaf}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = serverCfg
	srv.StartTLS()
	defer srv.Close()

	t.Run("client presenting a CA-signed cert is accepted", func(t *testing.T) {
		getCert := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientLeaf, nil }
		cfg, err := BuildClientTLSConfig(caFile, getCert)
		if err != nil {
			t.Fatalf("BuildClientTLSConfig: %v", err)
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("mTLS client must be accepted: %v", err)
		}
		_ = resp.Body.Close()
	})

	t.Run("client presenting no cert is rejected at the TLS layer", func(t *testing.T) {
		cfg, err := BuildClientTLSConfig(caFile, nil)
		if err != nil {
			t.Fatalf("BuildClientTLSConfig: %v", err)
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		if resp, err := client.Get(srv.URL); err == nil {
			resp.Body.Close()
			t.Fatal("a client presenting no certificate must be rejected by a require-client-cert listener")
		}
	})
}
