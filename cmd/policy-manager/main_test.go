package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// writeTestClientCA writes a self-signed CA PEM to a temp file and returns its
// path, for exercising the policy-manager's client-CA load path.
func writeTestClientCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-client-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	p := filepath.Join(t.TempDir(), "client-ca.crt")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestBuildAPITLSConfig covers the three mTLS branches of the policy-manager API
// listener (IAM-WU-03), mirroring the admission-webhook's setupWebhookServer
// tests (IAM-WU-06). The config deliberately uses client_auth="require" — the
// shipped viper default — to prove --require-client-cert is authoritative over it.
func TestBuildAPITLSConfig(t *testing.T) {
	caPath := writeTestClientCA(t)
	base := func(caP string) config.TLSConfig {
		return config.TLSConfig{MinVersion: "1.3", ClientAuth: "require", ClientCAPath: caP}
	}

	t.Run("require + CA enforces RequireAndVerifyClientCert", func(t *testing.T) {
		c, err := buildAPITLSConfig(base(caPath), true)
		if err != nil {
			t.Fatalf("buildAPITLSConfig: %v", err)
		}
		if c.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", c.ClientAuth)
		}
		if c.ClientCAs == nil {
			t.Fatal("ClientCAs must be set when enforcing")
		}
	})

	t.Run("require without CA fails closed", func(t *testing.T) {
		_, err := buildAPITLSConfig(base(""), true)
		if err == nil {
			t.Fatal("require-client-cert with no CA bundle must return an error (fail closed)")
		}
		if !strings.Contains(err.Error(), "require-client-cert") {
			t.Fatalf("error should name the --require-client-cert switch, got: %v", err)
		}
	})

	// Regression guard for the "optional mTLS silently enforces" defect: with the
	// shipped default client_auth="require" and --require-client-cert=false but a
	// CA present, the listener must be VerifyClientCertIfGiven (verify if given,
	// admit if absent) — NOT RequireAndVerifyClientCert, which would lock out the
	// cert-less operators that optional mode is meant to keep serving.
	t.Run("optional + CA verifies-if-given (does not enforce)", func(t *testing.T) {
		c, err := buildAPITLSConfig(base(caPath), false)
		if err != nil {
			t.Fatalf("buildAPITLSConfig: %v", err)
		}
		if c.ClientAuth != tls.VerifyClientCertIfGiven {
			t.Fatalf("ClientAuth = %v, want VerifyClientCertIfGiven (optional must not enforce despite client_auth=require default)", c.ClientAuth)
		}
	})

	t.Run("no require + no CA is server-auth only", func(t *testing.T) {
		c, err := buildAPITLSConfig(base(""), false)
		if err != nil {
			t.Fatalf("buildAPITLSConfig: %v", err)
		}
		if c.ClientAuth != tls.NoClientCert {
			t.Fatalf("ClientAuth = %v, want NoClientCert", c.ClientAuth)
		}
	})
}
