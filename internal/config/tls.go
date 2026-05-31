package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sort"
	"strings"
)

// tlsVersions maps the configured min_version string to a crypto/tls version
// constant. Only TLS 1.2 and 1.3 are accepted; 1.0/1.1 are obsolete and are
// rejected at load so a weak floor can never be configured (SC-8, SC-23).
var tlsVersions = map[string]uint16{
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

// approvedCipherSuites is the allow-list of TLS 1.2 AEAD/PFS cipher suites the
// product permits, keyed by IANA name. TLS 1.3 cipher suites are fixed by the
// Go runtime and are not configurable, so they are intentionally absent here;
// for a TLS-1.3-only listener (the secure default) the cipher_suites setting
// has no handshake effect but is still validated. Any suite not in this map is
// rejected at load, which excludes all CBC, RC4, 3DES, and non-PFS suites
// (SC-8, SC-13).
var approvedCipherSuites = map[string]uint16{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// clientAuthTypes maps the configured client_auth string to a crypto/tls
// ClientAuthType. "require" maps to RequireAndVerifyClientCert so honoring the
// declared intent enforces mutual TLS once a client CA bundle is supplied
// (IA-3, SC-8(1)); see BuildServerTLSConfig for the CA-bundle dependency.
var clientAuthTypes = map[string]tls.ClientAuthType{
	"":                   tls.NoClientCert,
	"none":               tls.NoClientCert,
	"request":            tls.RequestClientCert,
	"require_any":        tls.RequireAnyClientCert,
	"verify_if_given":    tls.VerifyClientCertIfGiven,
	"require":            tls.RequireAndVerifyClientCert,
	"require_and_verify": tls.RequireAndVerifyClientCert,
}

// ValidateTLS validates the TLS stanza without building a *tls.Config. It is
// called from validateConfig so a malformed min_version, an unknown cipher
// suite name, or an unknown client_auth mode fails fast at load time rather
// than at first handshake.
func (c TLSConfig) Validate() error {
	v, ok := tlsVersions[c.MinVersion]
	if !ok {
		return fmt.Errorf("invalid TLS min version: %q (supported: %s)", c.MinVersion, sortedKeys(tlsVersions))
	}
	// The product mandates a TLS 1.3 floor (SC-8/SC-23 secure baseline);
	// configuring a lower version is rejected at load.
	if v < tls.VersionTLS13 {
		return fmt.Errorf("invalid TLS min version: %q is below the mandated TLS 1.3 floor", c.MinVersion)
	}
	for _, name := range c.CipherSuites {
		if _, ok := approvedCipherSuites[name]; !ok {
			return fmt.Errorf("unknown or non-approved tls cipher_suite %q (approved: %s)", name, sortedCipherKeys())
		}
	}
	if _, ok := clientAuthTypes[strings.ToLower(c.ClientAuth)]; !ok {
		return fmt.Errorf("unknown tls client_auth %q (supported: none, request, require_any, verify_if_given, require)", c.ClientAuth)
	}
	return nil
}

// ClientAuthType returns the crypto/tls ClientAuthType for the configured
// client_auth string. It assumes Validate has already accepted the value.
func (c TLSConfig) ClientAuthType() tls.ClientAuthType {
	return clientAuthTypes[strings.ToLower(c.ClientAuth)]
}

// BuildClientTLSConfig builds a *tls.Config for an outbound client that
// verifies the server certificate against the CA bundle at caPath (CRY-WU-06,
// CRY-WU-07). An empty caPath returns (nil, nil) so the caller falls back to
// the system root pool. MinVersion is pinned to TLS 1.3; InsecureSkipVerify is
// never set.
func BuildClientTLSConfig(caPath string) (*tls.Config, error) {
	pool, err := LoadClientCAPool(caPath)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, nil
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}, nil
}

// LoadClientCAPool loads a PEM bundle of client-certificate CAs from path
// (CRY-WU-04). An empty path returns (nil, nil) so callers fall back to the
// permissive (no client-cert verification) mode. A file that parses to zero
// certificates is treated as a hard error: an empty-but-non-nil pool would
// silently reject every client under RequireAndVerifyClientCert.
func LoadClientCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client CA bundle %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates parsed from client CA bundle %q", path)
	}
	return pool, nil
}

// BuildServerTLSConfig builds a *tls.Config for a server listener from the
// validated TLS stanza (CRY-WU-03). MinVersion and CipherSuites are driven
// entirely by configuration, replacing hardcoded literals.
//
// Client-certificate authentication is only enforced when clientCAs is
// non-nil: requiring and verifying a client certificate without a CA pool
// would reject every handshake, so when no CA bundle is supplied the listener
// falls back to tls.NoClientCert regardless of the configured client_auth.
// The full mutual-TLS path (mounting and loading the apiserver CA bundle) is
// completed in CRY-WU-04, which passes a non-nil pool here.
func BuildServerTLSConfig(c TLSConfig, clientCAs *x509.CertPool) (*tls.Config, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	minVersion := tlsVersions[c.MinVersion]

	var suites []uint16
	for _, name := range c.CipherSuites {
		suites = append(suites, approvedCipherSuites[name])
	}

	clientAuth := c.ClientAuthType()
	if clientCAs == nil && (clientAuth == tls.RequireAndVerifyClientCert || clientAuth == tls.VerifyClientCertIfGiven) {
		// No CA bundle yet (CRY-WU-04 supplies it); do not break handshakes by
		// demanding verification we cannot perform.
		clientAuth = tls.NoClientCert
	}

	return &tls.Config{
		MinVersion: minVersion,
		// Go ignores CipherSuites for TLS 1.3 (suites are fixed by the runtime).
		// With the mandated 1.3 floor this field has no handshake effect today;
		// it is still populated and validated so the configured suites are
		// recorded and any non-approved name fails at load (SC-8/SC-13).
		CipherSuites: suites,
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,
	}, nil
}

func sortedKeys(m map[string]uint16) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func sortedCipherKeys() string {
	keys := make([]string, 0, len(approvedCipherSuites))
	for k := range approvedCipherSuites {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
