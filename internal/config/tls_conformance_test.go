package config

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
)

// TestConformance_ProtocolFloor is the build-gating TLS conformance test
// (CRY-WU-17): a server built from BuildServerTLSConfig must REFUSE TLS 1.0/1.1/1.2
// and complete a TLS 1.3 handshake. It is hermetic (in-process, no cluster) and
// lives in package config so it is covered by `go test ./internal/...` in CI and
// `make test-unit` — a test placed under ./test/tls would be silently skipped.
func TestConformance_ProtocolFloor(t *testing.T) {
	ca := newTestCA(t)
	serverLeaf := ca.leaf(t, "server", false)

	cfg, err := BuildServerTLSConfig(TLSConfig{MinVersion: "1.3", ClientAuth: "none"}, nil)
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}
	cfg.Certificates = []tls.Certificate{serverLeaf}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept loop: handshake each connection so a rejected protocol surfaces as
	// a clean dial error rather than a client hang.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = c.Close()
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	weak := []struct {
		name string
		max  uint16
	}{
		{"TLS 1.0", tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12},
	}
	for _, w := range weak {
		t.Run("reject "+w.name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", addr, &tls.Config{
				RootCAs:    roots,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS10,
				MaxVersion: w.max,
			})
			if err == nil {
				_ = conn.Close()
				t.Fatalf("handshake with MaxVersion=%s must be REJECTED by a TLS 1.3 listener", w.name)
			}
		})
	}

	t.Run("accept TLS 1.3", func(t *testing.T) {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			RootCAs:    roots,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("TLS 1.3 handshake must succeed: %v", err)
		}
		defer conn.Close()
		if v := conn.ConnectionState().Version; v != tls.VersionTLS13 {
			t.Fatalf("negotiated version = %x, want TLS 1.3", v)
		}
	})
}

// TestConformance_NoWeakCiphersInAllowList is a self-auditing guard: every entry
// in approvedCipherSuites must be a non-insecure AEAD suite. If someone adds a
// CBC/RC4/3DES suite to the allow-list, Go's InsecureCipherSuites() catches it
// here and fails the build (CRY-WU-17).
func TestConformance_NoWeakCiphersInAllowList(t *testing.T) {
	insecure := map[uint16]string{}
	for _, c := range tls.InsecureCipherSuites() {
		insecure[c.ID] = c.Name
	}
	for name, id := range approvedCipherSuites {
		if n, bad := insecure[id]; bad {
			t.Fatalf("approved cipher %q (id %#x) is in Go's INSECURE set (%s); remove it", name, id, n)
		}
	}
	if len(approvedCipherSuites) == 0 {
		t.Fatal("approvedCipherSuites must not be empty")
	}
}

// TestConformance_FloorIsTLS13 guards that the validated version floor never
// regresses below TLS 1.3.
func TestConformance_FloorIsTLS13(t *testing.T) {
	for _, mv := range []string{"1.0", "1.1", "1.2"} {
		if err := (TLSConfig{MinVersion: mv, ClientAuth: "none"}).Validate(); err == nil {
			t.Fatalf("min_version %q must be rejected (TLS 1.3 floor)", mv)
		}
	}
	if err := (TLSConfig{MinVersion: "1.3", ClientAuth: "none"}).Validate(); err != nil {
		t.Fatalf("min_version 1.3 must be accepted: %v", err)
	}
}
