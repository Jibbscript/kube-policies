package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA is a self-signed CA used to mint server and client leaf certs in mTLS tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// leaf mints a CA-signed leaf certificate. isClient toggles client vs server EKU.
func (ca *testCA) leaf(t *testing.T, cn string, isClient bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if isClient {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestLoadClientCAPool(t *testing.T) {
	t.Run("empty path returns nil pool", func(t *testing.T) {
		pool, err := LoadClientCAPool("")
		if err != nil || pool != nil {
			t.Fatalf("LoadClientCAPool(\"\") = (%v, %v), want (nil, nil)", pool, err)
		}
	})
	t.Run("valid PEM returns pool", func(t *testing.T) {
		ca := newTestCA(t)
		f := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(f, ca.pem, 0o600); err != nil {
			t.Fatal(err)
		}
		pool, err := LoadClientCAPool(f)
		if err != nil || pool == nil {
			t.Fatalf("LoadClientCAPool(valid) = (%v, %v), want non-nil pool", pool, err)
		}
	})
	t.Run("garbage file is a hard error (empty-pool footgun)", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "junk.crt")
		if err := os.WriteFile(f, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadClientCAPool(f); err == nil {
			t.Fatal("garbage PEM must return an error, not an empty pool")
		}
	})
	t.Run("missing file errors", func(t *testing.T) {
		if _, err := LoadClientCAPool(filepath.Join(t.TempDir(), "nope.crt")); err == nil {
			t.Fatal("missing file must error")
		}
	})
}

// TestMTLSHandshake proves CRY-WU-04: require + CA pool rejects a client with no
// cert and accepts a CA-signed client; nil pool stays permissive.
func TestMTLSHandshake(t *testing.T) {
	ca := newTestCA(t)
	serverLeaf := ca.leaf(t, "server", false)
	clientLeaf := ca.leaf(t, "client", true)

	startServer := func(t *testing.T, clientCAs *x509.CertPool) *httptest.Server {
		cfg, err := BuildServerTLSConfig(TLSConfig{MinVersion: "1.3", ClientAuth: "require"}, clientCAs)
		if err != nil {
			t.Fatalf("BuildServerTLSConfig: %v", err)
		}
		cfg.Certificates = []tls.Certificate{serverLeaf}
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}))
		srv.TLS = cfg
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}

	// Trust pool for clients to verify the server leaf.
	serverTrust := x509.NewCertPool()
	serverTrust.AddCert(ca.cert)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)

	t.Run("require+CA rejects client without cert", func(t *testing.T) {
		srv := startServer(t, caPool)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: serverTrust, MinVersion: tls.VersionTLS13,
		}}}
		if _, err := client.Get(srv.URL); err == nil {
			t.Fatal("client without a cert must be rejected when client_auth=require + CA pool")
		}
	})

	t.Run("require+CA accepts CA-signed client", func(t *testing.T) {
		srv := startServer(t, caPool)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      serverTrust,
			Certificates: []tls.Certificate{clientLeaf},
			MinVersion:   tls.VersionTLS13,
		}}}
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("CA-signed client must be accepted: %v", err)
		}
		_ = resp.Body.Close()
	})

	t.Run("nil pool stays permissive (no client cert needed)", func(t *testing.T) {
		srv := startServer(t, nil) // downgrades to NoClientCert
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: serverTrust, MinVersion: tls.VersionTLS13,
		}}}
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("permissive server must accept a client with no cert: %v", err)
		}
		_ = resp.Body.Close()
	})
}

// TestBuildServerTLSConfig_EmptyPoolFootgun documents why LoadClientCAPool must
// reject an empty bundle: an empty-but-non-nil pool keeps ClientAuth at
// RequireAndVerifyClientCert (no downgrade), which would reject every client.
func TestBuildServerTLSConfig_EmptyPoolFootgun(t *testing.T) {
	empty := x509.NewCertPool()
	cfg, err := BuildServerTLSConfig(TLSConfig{MinVersion: "1.3", ClientAuth: "require"}, empty)
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("empty non-nil pool should NOT downgrade (got %v); the loader must reject empty bundles", cfg.ClientAuth)
	}
}
