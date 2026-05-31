package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// Tamper-evidence for the audit log (AUD-WU-04, NIST AU-9 / AU-9(3)).
//
// Each persisted line is a sealed envelope {"record":<event-json>,"hmac":<hex>}
// where the event carries a strictly-increasing Sequence and the PrevHash of
// the preceding record's HMAC. The HMAC is computed over the EXACT record bytes
// that are persisted (json.RawMessage), and VerifyChain recomputes it over those
// same bytes verbatim — it never re-marshals a decoded struct. That is
// deliberate: re-marshaling map[string]interface{} (Event.Metadata) is lossy
// (JSON numbers decode to float64, dropping precision above 2^53) and would
// raise false tamper alarms. Signing the verbatim bytes makes the chain robust
// against any representational drift. The HMAC key is loaded from an injected
// source (a mounted Secret, AUD-WU-05), never hard-coded.

// maxAuditLine bounds a single audit record when verifying. Audit events embed
// the admitted object (RawExtension), so the default 64 KiB scanner buffer is
// too small; 8 MiB comfortably exceeds the apiserver's request size.
const maxAuditLine = 8 << 20

// sealedRecord is the on-disk envelope written for each event when audit
// integrity is enabled. Record holds the verbatim event JSON the HMAC covers.
type sealedRecord struct {
	Record json.RawMessage `json:"record"`
	HMAC   string          `json:"hmac"`
}

// Chainer seals events into the hash chain as they are persisted. It is safe
// for concurrent use (flushEvents is single-threaded today, but the lock makes
// the invariant explicit and future-proof).
type Chainer struct {
	mu       sync.Mutex
	key      []byte
	seq      uint64
	prevHash string
}

// NewChainer returns a Chainer keyed by key. key must be non-empty.
func NewChainer(key []byte) (*Chainer, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("audit integrity: HMAC key is empty")
	}
	// Copy so a caller mutating the backing array cannot change the key.
	k := make([]byte, len(key))
	copy(k, key)
	return &Chainer{key: k}, nil
}

// LoadKeyFromFile reads an HMAC key from path (a mounted Secret). Surrounding
// whitespace/newlines are trimmed. An empty file is an error.
func LoadKeyFromFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit integrity: read key %q: %w", path, err)
	}
	key := bytes.TrimSpace(raw)
	if len(key) == 0 {
		return nil, fmt.Errorf("audit integrity: key file %q is empty", path)
	}
	return key, nil
}

// Seal assigns the next Sequence and the running PrevHash to e, then returns the
// sealed envelope bytes ({"record":<event>,"hmac":<hex>}) to persist verbatim.
// It advances the chain; call it exactly once per persisted event, in order.
func (c *Chainer) Seal(e *Event) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	e.Sequence = c.seq
	e.PrevHash = c.prevHash
	record, err := json.Marshal(e)
	if err != nil {
		c.seq-- // roll back so a transient marshal error doesn't gap the chain
		return nil, fmt.Errorf("audit integrity: marshal record: %w", err)
	}
	mac := computeHMAC(c.key, record)
	envelope, err := json.Marshal(sealedRecord{Record: record, HMAC: mac})
	if err != nil {
		c.seq--
		return nil, fmt.Errorf("audit integrity: marshal envelope: %w", err)
	}
	c.prevHash = mac
	return envelope, nil
}

func computeHMAC(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyChain reads newline-delimited sealed envelopes from r and verifies the
// sequence + HMAC chain under key. It returns nil for an untampered log and a
// descriptive error identifying the first record whose sequence, prev-hash, or
// HMAC does not match. The HMAC is recomputed over the verbatim record bytes,
// so no re-marshal/round-trip can cause a false mismatch.
func VerifyChain(r io.Reader, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("audit integrity: HMAC key is empty")
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxAuditLine)

	var (
		prevHash    string
		expectedSeq uint64
	)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var env sealedRecord
		if err := json.Unmarshal(line, &env); err != nil {
			return fmt.Errorf("audit integrity: parse envelope after seq %d: %w", expectedSeq, err)
		}
		want := computeHMAC(key, env.Record)
		if !hmac.Equal([]byte(want), []byte(env.HMAC)) {
			return fmt.Errorf("audit integrity: record HMAC mismatch after seq %d (record tampered)", expectedSeq)
		}
		// HMAC verified over verbatim bytes; only NOW decode for chain metadata.
		var e Event
		if err := json.Unmarshal(env.Record, &e); err != nil {
			return fmt.Errorf("audit integrity: parse record after seq %d: %w", expectedSeq, err)
		}
		expectedSeq++
		if e.Sequence != expectedSeq {
			return fmt.Errorf("audit integrity: sequence gap: record has %d, expected %d", e.Sequence, expectedSeq)
		}
		if e.PrevHash != prevHash {
			return fmt.Errorf("audit integrity: prev-hash mismatch at seq %d (chain broken)", e.Sequence)
		}
		prevHash = env.HMAC
	}
	return scanner.Err()
}
