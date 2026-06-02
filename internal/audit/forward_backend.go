package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// ForwardBackend ships audit records off-host to a SIEM/log pipeline over TLS
// (AUD-WU-09, NIST AU-6 / AU-6(3) / AU-4(1)). Each record is sent as one
// newline-delimited JSON line over a persistent TLS connection. When the
// receiver is unavailable the record is appended to a local disk SPOOL instead
// of being dropped (the failure mode that got the original webhook/elasticsearch
// stubs removed); a background goroutine reconnects and replays the spool on
// recovery.
//
// Delivery semantics: AT-LEAST-ONCE, ordered. The spool is the local-durability
// guarantee — forwarding failure never silently loses a record. ORDER is
// preserved across a receiver flap: once ANY record is spooled, every subsequent
// record is also spooled (spool-coherent send) so a newer record can never be
// delivered ahead of an older spooled one; live sending resumes only after the
// spool fully drains. A record may be DUPLICATED at the receiver if delivery
// succeeds but the post-delivery spool rewrite then fails (a stream has no
// per-record ack); such events are logged + observable, not lost. The receiver
// is expected to de-duplicate on the record's request_id/sequence.
type ForwardBackend struct {
	address      string
	tlsConfig    *tls.Config
	spoolPath    string
	dialer       *net.Dialer
	retryEvery   time.Duration
	writeTimeout time.Duration
	log          *zap.Logger

	mu      sync.Mutex // guards conn + spool file mutations + spooled
	conn    net.Conn   // current connection; nil when disconnected
	spooled bool       // true while the spool holds undelivered records

	stop   chan struct{}
	stopWG sync.WaitGroup
	closed bool
}

// NewForwardBackend builds a ForwardBackend from AuditConfig.Config keys:
//
//	forward_address       host:port of the TLS receiver (required)
//	forward_spool_dir     directory for the disk spool (default <log dir>/spool)
//	forward_ca_file       PEM CA bundle to trust (default: system roots)
//	forward_tls_insecure  "true" disables verification — TESTING ONLY
//	forward_server_name   TLS SNI/verification name (default: host of address)
func NewForwardBackend(cfg *config.AuditConfig, log *zap.Logger) (*ForwardBackend, error) {
	if log == nil {
		log = zap.NewNop()
	}
	addr := cfg.Config["forward_address"]
	if addr == "" {
		return nil, fmt.Errorf("audit forward backend: forward_address is required")
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("audit forward backend: invalid forward_address %q: %w", addr, err)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if sn := cfg.Config["forward_server_name"]; sn != "" {
		tlsCfg.ServerName = sn
	} else {
		tlsCfg.ServerName = host
	}
	if cfg.Config["forward_tls_insecure"] == "true" {
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- test/dev only, gated by explicit opt-in
	} else if caFile := cfg.Config["forward_ca_file"]; caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("audit forward backend: read CA %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("audit forward backend: no certificates parsed from CA %q", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	spoolDir := cfg.Config["forward_spool_dir"]
	if spoolDir == "" {
		base := cfg.Config["filename"]
		if base == "" {
			base = "/var/log/kube-policies/audit.log"
		}
		spoolDir = filepath.Join(filepath.Dir(base), "spool")
	}
	if err := os.MkdirAll(spoolDir, 0o750); err != nil {
		return nil, fmt.Errorf("audit forward backend: create spool dir: %w", err)
	}

	dialTimeout := 5 * time.Second
	if v := cfg.Config["forward_dial_timeout"]; v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			dialTimeout = d
		}
	}
	writeTimeout := 10 * time.Second
	if v := cfg.Config["forward_write_timeout"]; v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			writeTimeout = d
		}
	}

	spoolPath := filepath.Join(spoolDir, "audit-forward.spool")
	b := &ForwardBackend{
		address:      addr,
		tlsConfig:    tlsCfg,
		spoolPath:    spoolPath,
		dialer:       &net.Dialer{Timeout: dialTimeout},
		retryEvery:   5 * time.Second,
		writeTimeout: writeTimeout,
		log:          log,
		stop:         make(chan struct{}),
	}
	// A non-empty spool left over from a previous run must be drained in order
	// before any live send, so mark spooled=true at startup.
	if fi, err := os.Stat(spoolPath); err == nil && fi.Size() > 0 {
		b.spooled = true
	}

	b.stopWG.Add(1)
	go b.replayLoop()
	return b, nil
}

// Write sends a marshaled event.
func (b *ForwardBackend) Write(event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit forward backend: marshal event: %w", err)
	}
	return b.send(data)
}

// WriteRaw sends pre-serialized (sealed integrity-envelope) bytes verbatim.
func (b *ForwardBackend) WriteRaw(data []byte) error {
	return b.send(data)
}

// send delivers a record. It is SPOOL-COHERENT: while any record is spooled,
// every new record is also spooled (and ordered) so the receiver never sees a
// newer record ahead of an older spooled one. Otherwise it attempts a live
// delivery and, on failure, spools (marking the backend spooled so subsequent
// records queue behind this one until replay drains them). A transient receiver
// outage therefore never propagates as a write error nor reorders the stream.
func (b *ForwardBackend) send(payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.spooled {
		return b.spoolLocked(payload)
	}
	if err := b.writeLocked(payload); err != nil {
		b.spooled = true
		return b.spoolLocked(payload)
	}
	return nil
}

// writeLocked lazily dials and writes one framed line under a bounded write
// deadline (so a hung-but-connected receiver cannot block the audit flush
// goroutine indefinitely while holding b.mu). Caller holds b.mu.
func (b *ForwardBackend) writeLocked(payload []byte) error {
	if b.conn == nil {
		conn, err := (&tls.Dialer{NetDialer: b.dialer, Config: b.tlsConfig}).DialContext(context.Background(), "tcp", b.address)
		if err != nil {
			return err
		}
		b.conn = conn
	}
	if err := b.conn.SetWriteDeadline(time.Now().Add(b.writeTimeout)); err != nil {
		_ = b.conn.Close()
		b.conn = nil
		return err
	}
	line := append(append([]byte{}, payload...), '\n')
	if _, err := b.conn.Write(line); err != nil {
		_ = b.conn.Close()
		b.conn = nil
		return err
	}
	return nil
}

// spoolLocked appends a record to the disk spool. Caller holds b.mu.
func (b *ForwardBackend) spoolLocked(payload []byte) error {
	f, err := os.OpenFile(b.spoolPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("audit forward backend: open spool: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(append([]byte{}, payload...), '\n')); err != nil {
		return fmt.Errorf("audit forward backend: write spool: %w", err)
	}
	return nil
}

// replayLoop periodically attempts to drain the spool to the receiver.
func (b *ForwardBackend) replayLoop() {
	defer b.stopWG.Done()
	ticker := time.NewTicker(b.retryEvery)
	defer ticker.Stop()
	for {
		select {
		case <-b.stop:
			b.replaySpool() // best-effort final drain
			return
		case <-ticker.C:
			b.replaySpool()
		}
	}
}

// replaySpool sends every spooled record in order, rewriting the spool with only
// the records that still could not be delivered (preserving order). A delivery
// failure stops the pass so ordering is never violated.
func (b *ForwardBackend) replaySpool() {
	b.mu.Lock()
	defer b.mu.Unlock()

	data, err := os.ReadFile(b.spoolPath)
	if err != nil || len(data) == 0 {
		b.spooled = false // nothing spooled; resume live sends
		return
	}

	lines := splitLines(data)
	remaining := make([][]byte, 0, len(lines))
	delivered := 0
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		if err := b.writeLocked(line); err != nil {
			// Receiver down again: keep this and all subsequent records spooled.
			remaining = append(remaining, lines[i:]...)
			break
		}
		delivered++
	}
	if delivered == 0 {
		return // could not deliver anything; leave spool + spooled flag intact
	}
	if err := b.rewriteSpoolLocked(remaining); err != nil {
		// Records were delivered but the spool could not be shrunk: they remain
		// on disk and WILL be re-delivered next tick (at-least-once). Surface it
		// so the duplication is observable rather than silent.
		b.log.Warn("audit forward: spool rewrite failed; delivered records may be re-sent",
			zap.Int("delivered", delivered), zap.Error(err))
		return // keep spooled=true; retry next tick
	}
	if len(remaining) == 0 {
		b.spooled = false // spool fully drained; resume live sends
	}
}

// rewriteSpoolLocked replaces the spool file with the remaining records, or
// removes it when empty. Returns an error so the caller can react to a failed
// truncate (which otherwise leaves already-delivered records to be re-sent).
// Caller holds b.mu.
func (b *ForwardBackend) rewriteSpoolLocked(remaining [][]byte) error {
	if len(remaining) == 0 {
		if err := os.Remove(b.spoolPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	var buf []byte
	for _, line := range remaining {
		if len(line) == 0 {
			continue
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	tmp := b.spoolPath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.spoolPath)
}

// Close stops the replay loop (after a final drain attempt) and closes the
// connection. Any still-undelivered records remain in the spool for next start.
func (b *ForwardBackend) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.mu.Unlock()

	close(b.stop)
	b.stopWG.Wait()

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		err := b.conn.Close()
		b.conn = nil
		return err
	}
	return nil
}

// splitLines splits on '\n' without allocating substrings beyond the slices.
func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			out = append(out, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}
