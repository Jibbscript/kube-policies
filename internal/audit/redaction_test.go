package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/Jibbscript/kube-policies/internal/config"
)

func rawExt(s string) *runtime.RawExtension { return &runtime.RawExtension{Raw: []byte(s)} }

// AUD-WU-17: a Secret's data/stringData are fully redacted before persistence.
func TestMaybeRedact_SecretData(t *testing.T) {
	l := &Logger{config: &config.AuditConfig{RedactObjects: true}}
	secret := `{"kind":"Secret","apiVersion":"v1","metadata":{"name":"db"},` +
		`"data":{"password":"c2VjcmV0","username":"YWRtaW4="},"stringData":{"token":"plain-tok"}}`
	ev := &Event{
		Kind:   metav1.GroupVersionKind{Version: "v1", Kind: "Secret"},
		Object: rawExt(secret),
	}
	out := l.maybeRedact(ev)
	got := string(out.Object.Raw)
	for _, leak := range []string{"c2VjcmV0", "YWRtaW4=", "plain-tok"} {
		if strings.Contains(got, leak) {
			t.Errorf("redacted output still contains secret material %q: %s", leak, got)
		}
	}
	if !strings.Contains(got, redactedPlaceholder) {
		t.Errorf("expected %q placeholder in output: %s", redactedPlaceholder, got)
	}
	// Original event must be untouched (maybeRedact returns a copy).
	if strings.Contains(string(ev.Object.Raw), redactedPlaceholder) {
		t.Error("maybeRedact mutated the original event's Object")
	}
}

// AUD-WU-17: credential-like keys are redacted even in non-Secret kinds.
func TestMaybeRedact_SensitiveKeys(t *testing.T) {
	l := &Logger{config: &config.AuditConfig{RedactObjects: true}}
	cm := `{"kind":"ConfigMap","data":{"db_password":"hunter2","host":"db.local","api_token":"abc"}}`
	ev := &Event{Object: rawExt(cm)}
	got := string(l.maybeRedact(ev).Object.Raw)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "abc") {
		t.Errorf("sensitive values not redacted: %s", got)
	}
	if !strings.Contains(got, "db.local") {
		t.Errorf("non-sensitive value host should be preserved: %s", got)
	}
}

// Redaction disabled -> payload preserved verbatim.
func TestMaybeRedact_DisabledPreserves(t *testing.T) {
	l := &Logger{config: &config.AuditConfig{RedactObjects: false}}
	secret := `{"kind":"Secret","data":{"password":"c2VjcmV0"}}`
	ev := &Event{Kind: metav1.GroupVersionKind{Kind: "Secret"}, Object: rawExt(secret)}
	if got := string(l.maybeRedact(ev).Object.Raw); !strings.Contains(got, "c2VjcmV0") {
		t.Errorf("redaction disabled must preserve payload, got %s", got)
	}
}

// AUD-WU-17 + AUD-WU-04: redaction happens BEFORE sealing, so the on-disk sealed
// record (under a valid HMAC) contains the placeholder, not the secret — and the
// integrity chain still verifies.
func TestFileBackend_RedactionBeforeSeal(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte("test-hmac-key-0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.AuditConfig{
		Enabled:       true,
		Backend:       "file",
		BufferSize:    16,
		FlushInterval: "10s",
		Retention:     "90d",
		RedactObjects: true,
		Config: map[string]string{
			"filename":           logPath,
			"integrity_key_path": keyPath,
		},
	}
	l, err := NewLogger(cfg)
	if err != nil {
		t.Fatal(err)
	}

	l.LogDecision(&Context{
		RequestID: "req-1",
		Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Secret"},
		Decision:  "allow",
		Object:    rawExt(`{"kind":"Secret","data":{"password":"c2VjcmV0LXZhbHVl"}}`),
	})
	if err := l.Close(); err != nil { // flushes
		t.Fatal(err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("c2VjcmV0LXZhbHVl")) {
		t.Errorf("sealed on-disk record leaked the secret: %s", data)
	}
	if !bytes.Contains(data, []byte(redactedPlaceholder)) {
		t.Errorf("expected redaction placeholder in sealed record: %s", data)
	}
	// The chain over the redacted bytes must verify.
	key, _ := LoadKeyFromFile(keyPath)
	if err := VerifyChain(bytes.NewReader(data), key); err != nil {
		t.Errorf("VerifyChain failed over redacted sealed log: %v", err)
	}
	// schema_version stamped (AUD-WU-17).
	if !bytes.Contains(data, []byte(`"schema_version":"`+AuditSchemaVersion+`"`)) {
		t.Errorf("expected schema_version in record: %s", data)
	}
}

// Sanity: a non-object payload is replaced wholesale (fail-safe).
func TestMaybeRedact_NonObjectFailSafe(t *testing.T) {
	l := &Logger{config: &config.AuditConfig{RedactObjects: true}}
	ev := &Event{Kind: metav1.GroupVersionKind{Kind: "Secret"}, Object: rawExt(`"just-a-string"`)}
	got := l.maybeRedact(ev).Object.Raw
	var decoded string
	if err := json.Unmarshal(got, &decoded); err != nil || decoded != redactedPlaceholder {
		t.Errorf("non-object secret payload should be replaced wholesale, got %s", got)
	}
}
