package main

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/Jibbscript/kube-policies/internal/admission"
	"github.com/Jibbscript/kube-policies/internal/config"
)

// webhookTestCA is a self-signed CA used to mint server + client leaf certs for
// the webhook mTLS enforcement tests (IAM-WU-06). Mirrors the helper pattern in
// internal/config/mtls_test.go but local to package main.
type webhookTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newWebhookTestCA(t *testing.T) *webhookTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "ca key")
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "webhook-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err, "ca cert")
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err, "parse ca cert")
	return &webhookTestCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// leaf mints a CA-signed leaf certificate. isClient toggles client vs server EKU.
func (ca *webhookTestCA) leaf(t *testing.T, cn string, isClient bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "leaf key")
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
	require.NoError(t, err, "leaf cert")
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// writeCAFile writes the CA PEM bundle to a temp file and returns its path.
func (ca *webhookTestCA) writeCAFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client-ca.crt")
	require.NoError(t, os.WriteFile(p, ca.pem, 0o600))
	return p
}

// startWebhookTLS wires the *tls.Config produced by setupWebhookServer onto an
// httptest TLS server and serves the controller's gin handler (so /healthz is
// real). It installs the test server leaf so clients can verify the server.
func startWebhookTLS(t *testing.T, srvCfg *http.Server, serverLeaf tls.Certificate) *httptest.Server {
	t.Helper()
	tlsConf := srvCfg.TLSConfig.Clone()
	tlsConf.Certificates = []tls.Certificate{serverLeaf}
	ts := httptest.NewUnstartedServer(srvCfg.Handler)
	ts.TLS = tlsConf
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// TestSetupWebhookServer_MTLSEnforce proves IAM-WU-06: with --require-client-cert
// (default) and a client-CA bundle, the webhook requires + verifies the apiserver
// client certificate. A client presenting NO cert is rejected at the TLS
// handshake; a client presenting the CA-signed cert is accepted.
func TestSetupWebhookServer_MTLSEnforce(t *testing.T) {
	log := zaptest.NewLogger(t)
	ca := newWebhookTestCA(t)
	serverLeaf := ca.leaf(t, "webhook-server", false)
	clientLeaf := ca.leaf(t, "apiserver-client", true)
	caPath := ca.writeCAFile(t)

	tlsCfg := &config.TLSConfig{MinVersion: "1.3", ClientAuth: "require", ClientCAPath: caPath}
	srv, err := setupWebhookServer(admission.NewController(nil, nil, nil, log, nil), tlsCfg, true, config.RateLimitConfig{}, nil, log)
	require.NoError(t, err, "enforce + CA bundle must build successfully")
	require.NotNil(t, srv)
	require.Equal(t, tls.RequireAndVerifyClientCert, srv.TLSConfig.ClientAuth,
		"enforce path must set RequireAndVerifyClientCert")

	ts := startWebhookTLS(t, srv, serverLeaf)

	// Trust pool so clients can verify the server leaf.
	serverTrust := x509.NewCertPool()
	serverTrust.AddCert(ca.cert)

	t.Run("client without cert is rejected at handshake", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    serverTrust,
			MinVersion: tls.VersionTLS13,
		}}}
		resp, err := client.Get(ts.URL + "/healthz")
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err, "a client presenting no cert MUST be rejected when mTLS is enforced")
	})

	t.Run("CA-signed client is accepted", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      serverTrust,
			Certificates: []tls.Certificate{clientLeaf},
			MinVersion:   tls.VersionTLS13,
		}}}
		resp, err := client.Get(ts.URL + "/healthz")
		require.NoError(t, err, "a CA-signed client MUST be accepted")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestSetupWebhookServer_EnforceWithoutCAFailsClosed proves the fail-closed
// boundary: --require-client-cert=true with no client-CA bundle must refuse to
// build a server rather than silently downgrade to a permissive listener.
func TestSetupWebhookServer_EnforceWithoutCAFailsClosed(t *testing.T) {
	log := zaptest.NewLogger(t)
	tlsCfg := &config.TLSConfig{MinVersion: "1.3", ClientAuth: "require", ClientCAPath: ""}
	srv, err := setupWebhookServer(admission.NewController(nil, nil, nil, log, nil), tlsCfg, true, config.RateLimitConfig{}, nil, log)
	require.Error(t, err, "enforce with no client-CA bundle MUST fail closed")
	assert.Nil(t, srv, "no server should be returned on the fail-closed path")
	assert.Contains(t, err.Error(), "require-client-cert",
		"the fail-closed error must name the break-glass switch so operators can act")
}

// TestSetupWebhookServer_BreakGlassPermissive proves the documented break-glass:
// --require-client-cert=false with no client-CA bundle builds successfully and
// accepts a client presenting no certificate (permissive, server-auth-only).
func TestSetupWebhookServer_BreakGlassPermissive(t *testing.T) {
	log := zaptest.NewLogger(t)
	ca := newWebhookTestCA(t)
	serverLeaf := ca.leaf(t, "webhook-server", false)

	tlsCfg := &config.TLSConfig{MinVersion: "1.3", ClientAuth: "require", ClientCAPath: ""}
	srv, err := setupWebhookServer(admission.NewController(nil, nil, nil, log, nil), tlsCfg, false, config.RateLimitConfig{}, nil, log)
	require.NoError(t, err, "break-glass with no CA bundle must build successfully")
	require.NotNil(t, srv)
	require.Equal(t, tls.NoClientCert, srv.TLSConfig.ClientAuth,
		"break-glass path must leave the listener permissive (NoClientCert)")

	ts := startWebhookTLS(t, srv, serverLeaf)

	serverTrust := x509.NewCertPool()
	serverTrust.AddCert(ca.cert)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    serverTrust,
		MinVersion: tls.VersionTLS13,
	}}}
	resp, err := client.Get(ts.URL + "/healthz")
	require.NoError(t, err, "break-glass listener must accept a client presenting no cert")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_, _ = io.Copy(io.Discard, resp.Body)
}
