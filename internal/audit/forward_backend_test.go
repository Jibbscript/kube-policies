package audit

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// selfSignedCert returns an in-memory TLS cert valid for 127.0.0.1, for the
// mock SIEM receiver. The client side uses forward_tls_insecure=true.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// startReceiver runs a TLS line-receiver over the given (already-listening) TCP
// listener, pushing each received line onto lines. It returns when the listener
// is closed.
func startReceiver(ln net.Listener, serverCfg *tls.Config, lines chan<- string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			tlsConn := tls.Server(c, serverCfg)
			scanner := bufio.NewScanner(tlsConn)
			scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
			for scanner.Scan() {
				lines <- scanner.Text()
			}
		}(conn)
	}
}

func forwardCfg(addr, spoolDir string) *config.AuditConfig {
	return &config.AuditConfig{
		Enabled: true,
		Backend: "forward",
		Config: map[string]string{
			"forward_address":      addr,
			"forward_spool_dir":    spoolDir,
			"forward_tls_insecure": "true",
			"forward_dial_timeout": "300ms",
		},
	}
}

// AUD-WU-09: an event is delivered byte-for-byte to a TLS receiver.
func TestForwardBackend_DeliversOverTLS(t *testing.T) {
	cert := selfSignedCert(t)
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lines := make(chan string, 4)
	go startReceiver(ln, serverCfg, lines)

	b, err := NewForwardBackend(forwardCfg(ln.Addr().String(), t.TempDir()), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ev := &Event{RequestID: "fwd-1", EventType: "PolicyDecision",
		Kind: metav1.GroupVersionKind{Kind: "Pod"}, Decision: "deny"}
	if err := b.Write(ev); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	select {
	case got := <-lines:
		// The receiver line must equal the marshaled event exactly.
		want := mustMarshal(t, ev)
		if got != want {
			t.Errorf("byte mismatch:\n got=%s\nwant=%s", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for forwarded event")
	}
}

// AUD-WU-09: when the receiver is unavailable the record is spooled to disk and
// replayed on recovery — never silently dropped.
func TestForwardBackend_SpoolsAndReplays(t *testing.T) {
	cert := selfSignedCert(t)
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	// Bind the listener (reserves the port) but DO NOT accept yet → the client's
	// TLS handshake times out and the record is spooled.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	spoolDir := t.TempDir()

	b, err := NewForwardBackend(forwardCfg(ln.Addr().String(), spoolDir), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ev := &Event{RequestID: "spooled-1", EventType: "PolicyDecision", Decision: "allow"}
	if err := b.Write(ev); err != nil {
		t.Fatalf("Write (down) returned error: %v", err)
	}

	spoolFile := filepath.Join(spoolDir, "audit-forward.spool")
	data, err := os.ReadFile(spoolFile)
	if err != nil || len(data) == 0 {
		t.Fatalf("expected record spooled to disk, got err=%v len=%d", err, len(data))
	}

	// Recovery: start accepting, then drive a replay.
	lines := make(chan string, 4)
	go startReceiver(ln, serverCfg, lines)
	b.replaySpool()

	select {
	case got := <-lines:
		if got != mustMarshal(t, ev) {
			t.Errorf("replayed record mismatch: %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for replayed event")
	}

	// Spool must be drained after a successful replay.
	if _, err := os.Stat(spoolFile); !os.IsNotExist(err) {
		remaining, _ := os.ReadFile(spoolFile)
		t.Errorf("spool not drained after replay: %s", remaining)
	}
}

// AUD-WU-09 ordering: after a flap, a record that arrives while the spool is
// non-empty must NOT be delivered ahead of the older spooled record. Spool R1
// (receiver down), recover, send R2 — R2 must spool behind R1, and replay must
// deliver R1 then R2 in order.
func TestForwardBackend_SpoolCoherentOrdering(t *testing.T) {
	cert := selfSignedCert(t)
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	spoolDir := t.TempDir()

	b, err := NewForwardBackend(forwardCfg(ln.Addr().String(), spoolDir), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// Receiver down: R1 spools.
	r1 := &Event{RequestID: "r1", EventType: "PolicyDecision", Decision: "allow"}
	if err := b.Write(r1); err != nil {
		t.Fatal(err)
	}

	// Receiver up, but R2 arrives BEFORE a replay tick: it must spool behind R1.
	lines := make(chan string, 8)
	go startReceiver(ln, serverCfg, lines)
	r2 := &Event{RequestID: "r2", EventType: "PolicyDecision", Decision: "deny"}
	if err := b.Write(r2); err != nil {
		t.Fatal(err)
	}

	// Drain in order.
	b.replaySpool()

	want := []string{mustMarshal(t, r1), mustMarshal(t, r2)}
	for i, w := range want {
		select {
		case got := <-lines:
			if got != w {
				t.Errorf("record %d out of order:\n got=%s\nwant=%s", i, got, w)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for record %d (ordering)", i)
		}
	}
}

func mustMarshal(t *testing.T, ev *Event) string {
	t.Helper()
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
