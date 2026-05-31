package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sealLog seals n events under key and returns the newline-delimited envelope
// log exactly as the file backend would persist it.
func sealLog(t *testing.T, key []byte, n int) []byte {
	t.Helper()
	c, err := NewChainer(key)
	if err != nil {
		t.Fatalf("NewChainer: %v", err)
	}
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		e := &Event{
			Timestamp: time.Unix(int64(1700000000+i), 0).UTC(),
			RequestID: "req-" + string(rune('a'+i)),
			EventType: "admission",
			Decision:  "deny",
			Operation: "CREATE",
		}
		sealed, err := c.Seal(e)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		buf.Write(append(sealed, '\n'))
	}
	return buf.Bytes()
}

// recordSequences extracts the Sequence of every record in an envelope log.
func recordSequences(t *testing.T, log []byte) []uint64 {
	t.Helper()
	var seqs []uint64
	for _, line := range bytes.Split(bytes.TrimSpace(log), []byte("\n")) {
		var env sealedRecord
		if err := json.Unmarshal(line, &env); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		var e Event
		if err := json.Unmarshal(env.Record, &e); err != nil {
			t.Fatalf("unmarshal record: %v", err)
		}
		seqs = append(seqs, e.Sequence)
	}
	return seqs
}

func TestVerifyChain_Untampered(t *testing.T) {
	key := []byte("super-secret-hmac-key")
	log := sealLog(t, key, 5)
	if err := VerifyChain(bytes.NewReader(log), key); err != nil {
		t.Fatalf("untampered log must verify: %v", err)
	}
}

func TestChain_SequenceMonotonicNoGaps(t *testing.T) {
	seqs := recordSequences(t, sealLog(t, []byte("k"), 4))
	want := []uint64{1, 2, 3, 4}
	if len(seqs) != len(want) {
		t.Fatalf("got %d records, want %d", len(seqs), len(want))
	}
	for i := range want {
		if seqs[i] != want[i] {
			t.Fatalf("sequence[%d] = %d, want %d", i, seqs[i], want[i])
		}
	}
}

// TestVerifyChain_DetectsByteFlip flips a byte of a record's payload and asserts
// VerifyChain reports an HMAC mismatch (AUD-WU-04 done-when).
func TestVerifyChain_DetectsByteFlip(t *testing.T) {
	key := []byte("k")
	log := sealLog(t, key, 3)
	// The record is embedded verbatim (json.RawMessage) in the envelope, so the
	// decision value appears unescaped; mutate it in the first record.
	tampered := bytes.Replace(log, []byte(`"decision":"deny"`), []byte(`"decision":"allw"`), 1)
	if bytes.Equal(tampered, log) {
		t.Fatal("test setup: nothing was mutated")
	}
	err := VerifyChain(bytes.NewReader(tampered), key)
	if err == nil {
		t.Fatal("VerifyChain must detect a mutated record")
	}
	if !strings.Contains(err.Error(), "HMAC mismatch") {
		t.Fatalf("expected HMAC mismatch error, got: %v", err)
	}
}

func TestVerifyChain_DetectsDeletedRecord(t *testing.T) {
	key := []byte("k")
	log := sealLog(t, key, 4)
	lines := bytes.Split(bytes.TrimSpace(log), []byte("\n"))
	kept := append([][]byte{lines[0]}, lines[2:]...) // drop record 2 -> seq gap
	mangled := bytes.Join(kept, []byte("\n"))
	err := VerifyChain(bytes.NewReader(mangled), key)
	if err == nil {
		t.Fatal("VerifyChain must detect a deleted record")
	}
	if !strings.Contains(err.Error(), "sequence gap") {
		t.Fatalf("expected sequence gap error, got: %v", err)
	}
}

func TestVerifyChain_WrongKey(t *testing.T) {
	log := sealLog(t, []byte("right-key"), 3)
	if err := VerifyChain(bytes.NewReader(log), []byte("wrong-key")); err == nil {
		t.Fatal("VerifyChain with the wrong key must fail")
	}
}

// TestVerifyChain_LargeMetadataInteger is the regression test for the
// in-memory-vs-JSON-round-trip BLOCKER: an audit record whose Metadata carries
// an integer > 2^53 must still verify. Signing the verbatim persisted bytes (an
// envelope) — not a re-marshaled struct — is what makes this pass; a re-marshal
// approach would decode the int to float64 and raise a false tamper alarm.
func TestVerifyChain_LargeMetadataInteger(t *testing.T) {
	key := []byte("k")
	c, err := NewChainer(key)
	if err != nil {
		t.Fatal(err)
	}
	e := &Event{
		Decision: "deny",
		Metadata: map[string]interface{}{
			"generation": int64(9007199254740993), // 2^53 + 1
			"note":       "large-int round-trip",
			"nested":     map[string]interface{}{"count": int64(9223372036854775807)},
		},
	}
	sealed, err := c.Seal(e)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	log := append(sealed, '\n')
	if err := VerifyChain(bytes.NewReader(log), key); err != nil {
		t.Fatalf("record with a large-integer Metadata value must verify (no false tamper alarm): %v", err)
	}
}

func TestVerifyChain_EmptyKey(t *testing.T) {
	if err := VerifyChain(bytes.NewReader([]byte("")), nil); err == nil {
		t.Fatal("VerifyChain with an empty key must error")
	}
}

func TestNewChainer_EmptyKey(t *testing.T) {
	if _, err := NewChainer(nil); err == nil {
		t.Fatal("NewChainer with an empty key must error")
	}
}

func TestLoadKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "key")
	if err := os.WriteFile(good, []byte("  secret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadKeyFromFile(good)
	if err != nil {
		t.Fatalf("LoadKeyFromFile: %v", err)
	}
	if string(key) != "secret-key" {
		t.Fatalf("key = %q, want %q (trimmed)", key, "secret-key")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFromFile(empty); err == nil {
		t.Fatal("empty key file must error")
	}
	if _, err := LoadKeyFromFile(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("missing key file must error")
	}
}

// TestChainerKeyIsCopied proves mutating the caller's key slice does not change
// the chainer's key (defensive copy): a record sealed before mutation still
// verifies under the original key bytes.
func TestChainerKeyIsCopied(t *testing.T) {
	key := []byte("original-key")
	c, err := NewChainer(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Seal(&Event{Decision: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	copy(key, []byte("zzzzzzzzzzzz"))
	if err := VerifyChain(bytes.NewReader(append(sealed, '\n')), []byte("original-key")); err != nil {
		t.Fatalf("record must verify under the original key despite caller mutation: %v", err)
	}
}
