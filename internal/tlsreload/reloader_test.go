package tlsreload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// writePair writes a self-signed ECDSA cert/key with the given serial+CN to
// certPath/keyPath. The serial makes "which cert is served" observable.
func writePair(t *testing.T, certPath, keyPath string, serial int64, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// servedSerial returns the serial of the leaf currently served by the reloader.
func servedSerial(t *testing.T, r *Reloader) int64 {
	t.Helper()
	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.SerialNumber.Int64()
}

func eventually(t *testing.T, want int64, get func() int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if get() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for served serial %d (last=%d)", want, get())
}

func TestNew_InitialLoadAndGetCertificate(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, cp, kp, 1, "cert-A")

	r, err := New(cp, kp, zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := servedSerial(t, r); got != 1 {
		t.Fatalf("served serial = %d, want 1", got)
	}
}

func TestNew_FailsWhenMissing(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"), zap.NewNop()); err == nil {
		t.Fatal("New must fail when the key pair is absent")
	}
}

// TestReload_DirectOverwrite proves a plain in-place file rotation is served
// without restart.
func TestReload_DirectOverwrite(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, cp, kp, 1, "cert-A")

	r, err := New(cp, kp, zap.NewNop(), WithReloadInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = r.Start(ctx) }()

	writePair(t, cp, kp, 2, "cert-B")
	eventually(t, 2, func() int64 { return servedSerial(t, r) })
}

// TestReload_SymlinkDirSwap mimics the Kubernetes Secret "..data" atomic swap:
// the leaf files are symlinks into a timestamped dir, and rotation re-points
// the "..data" symlink. A leaf-file-only watcher would miss this; the
// directory watch must catch it.
func TestReload_SymlinkDirSwap(t *testing.T) {
	dir := t.TempDir()

	dataA := filepath.Join(dir, "..2026_a")
	if err := os.Mkdir(dataA, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writePair(t, filepath.Join(dataA, "tls.crt"), filepath.Join(dataA, "tls.key"), 1, "cert-A")
	// ..data -> ..2026_a
	dataLink := filepath.Join(dir, "..data")
	if err := os.Symlink(dataA, dataLink); err != nil {
		t.Fatalf("symlink ..data: %v", err)
	}
	// leaf symlinks -> ..data/tls.crt|key
	cp, kp := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.Symlink(filepath.Join("..data", "tls.crt"), cp); err != nil {
		t.Fatalf("symlink crt: %v", err)
	}
	if err := os.Symlink(filepath.Join("..data", "tls.key"), kp); err != nil {
		t.Fatalf("symlink key: %v", err)
	}

	r, err := New(cp, kp, zap.NewNop(), WithReloadInterval(time.Hour)) // rely on fs events, not the ticker
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := servedSerial(t, r); got != 1 {
		t.Fatalf("initial served serial = %d, want 1", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = r.Start(ctx) }()

	// Rotate the k8s way: new timestamped dir, then atomically swap ..data.
	dataB := filepath.Join(dir, "..2026_b")
	if err := os.Mkdir(dataB, 0o755); err != nil {
		t.Fatalf("mkdir B: %v", err)
	}
	writePair(t, filepath.Join(dataB, "tls.crt"), filepath.Join(dataB, "tls.key"), 2, "cert-B")
	tmpLink := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink(dataB, tmpLink); err != nil {
		t.Fatalf("symlink tmp: %v", err)
	}
	if err := os.Rename(tmpLink, dataLink); err != nil { // atomic swap
		t.Fatalf("rename swap: %v", err)
	}
	_ = os.RemoveAll(dataA)

	eventually(t, 2, func() int64 { return servedSerial(t, r) })
}

// TestReload_HalfWriteKeepsPrevious proves a mismatched/garbage pair never
// replaces the cached good certificate.
func TestReload_HalfWriteKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, cp, kp, 1, "cert-A")

	r, err := New(cp, kp, zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Corrupt only the cert file: LoadX509KeyPair must fail and the cache stays.
	if err := os.WriteFile(cp, []byte("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	r.reload()
	if got := servedSerial(t, r); got != 1 {
		t.Fatalf("served serial = %d after bad reload, want 1 (last-known-good preserved)", got)
	}
}

// TestServedHandshake proves the served certificate changes on the next
// handshake after an on-disk rotation, with no server restart.
func TestServedHandshake(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, cp, kp, 1, "cert-A")

	r, err := New(cp, kp, zap.NewNop(), WithReloadInterval(50*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = r.Start(ctx) }()

	srv := &http.Server{
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: r.GetCertificate},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLSConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = srv.Serve(ln) }()

	dial := func() int64 {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}

	if got := dial(); got != 1 {
		t.Fatalf("first handshake serial = %d, want 1", got)
	}
	writePair(t, cp, kp, 2, "cert-B")
	eventually(t, 2, dial)
}
