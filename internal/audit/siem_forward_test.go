package audit_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/config"
)

// TestSIEMForwarding_AuditEventDeliveredOverTLS is the IRM-WU-13 SIEM-pipeline
// integration test (NIST AU-6, AU-9(3), SI-4). It proves the end-to-end delivery
// CONTRACT the production forwarder relies on: a real audit PolicyDecision,
// written by the file backend (internal/audit), is shippable to a SIEM endpoint
// over TLS and arrives intact.
//
// The production forwarder is the opt-in Fluent Bit DaemonSet (Helm
// `audit.forwarder.*`) tailing audit.log and shipping to a TLS SIEM output; this
// test exercises the same path with a mock TLS receiver standing in for the SIEM,
// so the audit-record shape + TLS delivery are verified in CI without requiring a
// running Fluent Bit. Do NOT reintroduce an in-process forwarding backend — the
// removed silent-drop Elasticsearch stub is exactly what this file backend +
// external forwarder model replaces.
func TestSIEMForwarding_AuditEventDeliveredOverTLS(t *testing.T) {
	// 1. Mock TLS SIEM receiver (HTTPS-only).
	var (
		mu       sync.Mutex
		received [][]byte
	)
	siem := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer siem.Close()

	// 2. Real audit logger writing to a file backend (the forwarder's source).
	logfile := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.NewLogger(&config.AuditConfig{
		Enabled:       true,
		Backend:       "file",
		Config:        map[string]string{"filename": logfile},
		BufferSize:    16,
		FlushInterval: "50ms",
		Retention:     "90d",
		RedactObjects: true,
	})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	// 3. Emit a PolicyDecision (a denied privileged pod).
	logger.LogDecision(&audit.Context{
		RequestID: "siem-test-1",
		Namespace: "default",
		Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
		Name:      "privileged-pod",
		Operation: "CREATE",
		Decision:  "DENY",
		Reason:    "PolicyViolation",
		Message:   "privileged containers are not allowed",
		Timestamp: time.Now().UTC(),
	})

	// Close drains the buffer to the file backend (AU-9: no silent loss).
	if err = logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 4. Tail the audit file and forward each JSON record to the SIEM over TLS,
	//    exactly as the Fluent Bit http/TLS output does in production. The
	//    httptest client trusts only the mock receiver's cert, so a successful
	//    POST proves a real TLS handshake occurred.
	f, err := os.Open(logfile)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()

	client := siem.Client()
	forwarded := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		resp, err := client.Post(siem.URL, "application/json", bytes.NewReader(line))
		if err != nil {
			t.Fatalf("forward over TLS: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("SIEM returned %d", resp.StatusCode)
		}
		forwarded++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	if forwarded == 0 {
		t.Fatal("no audit records were written to the file backend to forward")
	}

	// 5. Assert the SIEM received the PolicyDecision intact.
	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("mock SIEM received no events over TLS")
	}
	var sawDecision bool
	for _, body := range received {
		var ev struct {
			EventType string `json:"event_type"`
			RequestID string `json:"request_id"`
			Decision  string `json:"decision"`
		}
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Fatalf("SIEM payload is not a valid audit JSON record: %v", err)
		}
		if ev.EventType == "PolicyDecision" && ev.RequestID == "siem-test-1" {
			if ev.Decision != "DENY" {
				t.Fatalf("forwarded decision = %q, want DENY", ev.Decision)
			}
			sawDecision = true
		}
	}
	if !sawDecision {
		t.Fatal("the PolicyDecision audit event did not arrive at the mock SIEM over TLS")
	}
}
