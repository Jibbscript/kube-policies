package audit

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// auditFilesOldestFirst lists the audit log + its rotated backups, ordered
// oldest-first (by mtime), so VerifyChainFiles sees the chain in write order.
func auditFilesOldestFirst(t *testing.T, dir, base string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	type fi struct {
		path  string
		mtime int64
	}
	var files []fi
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, strings.TrimSuffix(base, ".log")) || !strings.HasSuffix(name, ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, fi{filepath.Join(dir, name), info.ModTime().UnixNano()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mtime < files[j].mtime })
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.path
	}
	return out
}

// AUD-WU-06 (AU-4): the file backend rotates at the size cap and the integrity
// chain remains verifiable ACROSS rotated files via VerifyChainFiles. Exercises
// the FileBackend + Chainer directly (deterministic, no async buffer).
func TestFileBackend_RotationPreservesChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	key := []byte("rotation-hmac-key-abcdef")
	cfg := &config.AuditConfig{
		Enabled:   true,
		Backend:   "file",
		Retention: "90d",
		MaxSizeMB: 1, // 1 MiB — smallest lumberjack size cap
		Config:    map[string]string{"filename": logPath},
	}
	b, err := NewFileBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := NewChainer(key)
	if err != nil {
		t.Fatal(err)
	}

	// ~300 KiB filler per record; a handful exceeds 1 MiB and forces >=1 rotation
	// while keeping rotations sparse enough to avoid filename collisions.
	filler := strings.Repeat("x", 300*1024)
	for i := 0; i < 20; i++ {
		ev := &Event{
			RequestID: "rot-req",
			EventType: "PolicyDecision",
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "ConfigMap"},
			Decision:  "allow",
			Object:    &runtime.RawExtension{Raw: []byte(`{"kind":"ConfigMap","data":{"blob":"` + filler + `"}}`)},
		}
		sealed, err := ch.Seal(ev)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.WriteRaw(sealed); err != nil {
			t.Fatal(err)
		}
		if len(auditFilesOldestFirst(t, dir, "audit.log")) >= 2 {
			break
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	files := auditFilesOldestFirst(t, dir, "audit.log")
	if len(files) < 2 {
		t.Fatalf("expected rotation to produce >1 file, got %d: %v", len(files), files)
	}

	// A single rotated tail file fails standalone (its first Sequence != 1), but
	// the whole set in oldest-first order verifies end-to-end.
	if err := VerifyChainFiles(key, files...); err != nil {
		t.Errorf("VerifyChainFiles across %d rotated files failed: %v", len(files), err)
	}
}

// AUD-WU-07 (AU-11): Retention="90d" maps to a 90-day max-age on the writer.
func TestFileBackend_RetentionMapsToMaxAge(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AuditConfig{
		Enabled:   true,
		Backend:   "file",
		Retention: "90d",
		MaxSizeMB: 50,
		Config:    map[string]string{"filename": filepath.Join(dir, "audit.log")},
	}
	b, err := NewFileBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.w.MaxAge != 90 {
		t.Errorf("Retention 90d should map to MaxAge=90 days, got %d", b.w.MaxAge)
	}
	if b.w.MaxSize != 50 {
		t.Errorf("MaxSizeMB 50 should map to MaxSize=50, got %d", b.w.MaxSize)
	}

	cfg.Retention = "180d"
	b2, err := NewFileBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	if b2.w.MaxAge != 180 {
		t.Errorf("Retention 180d should map to MaxAge=180, got %d", b2.w.MaxAge)
	}
}
