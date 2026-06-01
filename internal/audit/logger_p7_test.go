package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// recordingBackend captures emitted events for assertions; an optional per-write
// delay simulates a slow sink to exercise buffer backpressure.
type recordingBackend struct {
	mu     sync.Mutex
	events []*Event
	delay  time.Duration
}

func (b *recordingBackend) Write(e *Event) error {
	if b.delay > 0 {
		time.Sleep(b.delay)
	}
	b.mu.Lock()
	b.events = append(b.events, e)
	b.mu.Unlock()
	return nil
}
func (b *recordingBackend) WriteRaw([]byte) error { return nil }
func (b *recordingBackend) Close() error          { return nil }
func (b *recordingBackend) count() int            { b.mu.Lock(); defer b.mu.Unlock(); return len(b.events) }
func (b *recordingBackend) all() []*Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*Event, len(b.events))
	copy(out, b.events)
	return out
}

// newTestLogger wires a Logger around an injected backend (NewLogger only knows
// file/stdout/forward), running the same background processor.
func newTestLogger(cfg *config.AuditConfig, backend Backend) *Logger {
	ctx, cancel := context.WithCancel(context.Background())
	l := &Logger{
		config:  cfg,
		backend: backend,
		buffer:  make(chan *Event, cfg.BufferSize),
		ctx:     ctx,
		cancel:  cancel,
		logger:  zap.NewNop(),
		metrics: NopMetrics{},
	}
	l.wg.Add(1)
	go l.processEvents()
	return l
}

// AUD-WU-01/02/20: a decision record carries source attribution, dual UTC
// timestamps (received <= stage), a correlation id, and a schema version.
func TestLogDecision_AttributionTimestampsCorrelation(t *testing.T) {
	rb := &recordingBackend{}
	cfg := &config.AuditConfig{Enabled: true, Backend: "stdout", BufferSize: 16, FlushInterval: "10s"}
	l := newTestLogger(cfg, rb)

	received := time.Now().Add(-50 * time.Millisecond)
	stage := time.Now()
	l.LogDecision(&Context{
		RequestID:                "uid-123",
		UserInfo:                 authenticationv1.UserInfo{Username: "alice"},
		Kind:                     metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
		Decision:                 "deny",
		SourceIP:                 "10.0.0.5",
		UserAgent:                "kube-apiserver/v1.31",
		RequestURI:               "/validate",
		APIServerID:              "apiserver-0",
		AdmissionWebhookConfig:   "kube-policies-validating",
		RequestReceivedTimestamp: received,
		StageTimestamp:           stage,
		CorrelationID:            "corr-xyz",
		Timestamp:                received,
	})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	if rb.count() != 1 {
		t.Fatalf("expected 1 event, got %d", rb.count())
	}
	e := rb.all()[0]
	if e.SourceIP != "10.0.0.5" || e.UserAgent != "kube-apiserver/v1.31" ||
		e.RequestURI != "/validate" || e.APIServerID != "apiserver-0" ||
		e.AdmissionWebhookConfig != "kube-policies-validating" {
		t.Errorf("attribution fields not propagated: %+v", e)
	}
	if e.CorrelationID != "corr-xyz" {
		t.Errorf("correlation_id = %q, want corr-xyz", e.CorrelationID)
	}
	if e.SchemaVersion != AuditSchemaVersion {
		t.Errorf("schema_version = %q, want %q", e.SchemaVersion, AuditSchemaVersion)
	}
	if e.RequestReceivedTimestamp == nil || e.StageTimestamp == nil {
		t.Fatal("dual timestamps must be set")
	}
	if e.RequestReceivedTimestamp.Location() != time.UTC || e.StageTimestamp.Location() != time.UTC {
		t.Errorf("timestamps must be UTC: rrt=%v st=%v", e.RequestReceivedTimestamp.Location(), e.StageTimestamp.Location())
	}
	if e.RequestReceivedTimestamp.After(*e.StageTimestamp) {
		t.Errorf("request_received_timestamp must be <= stage_timestamp")
	}
}

// AUD-WU-02/20 fallbacks: with no explicit dual timestamps / correlation id, the
// record still gets UTC timestamps and a non-empty correlation id (the request
// id), so every record is attributable.
func TestLogDecision_TimestampCorrelationFallbacks(t *testing.T) {
	rb := &recordingBackend{}
	l := newTestLogger(&config.AuditConfig{Enabled: true, Backend: "stdout", BufferSize: 4, FlushInterval: "10s"}, rb)
	l.LogDecision(&Context{RequestID: "uid-fallback", Decision: "allow", Timestamp: time.Now()})
	_ = l.Close()
	e := rb.all()[0]
	if e.CorrelationID != "uid-fallback" {
		t.Errorf("correlation_id should fall back to request id, got %q", e.CorrelationID)
	}
	if e.RequestReceivedTimestamp == nil || e.StageTimestamp == nil {
		t.Fatal("fallback timestamps must still be set")
	}
}

// AUD-WU-20/17: config and system events carry a correlation id and schema
// version; a caller-supplied correlation id propagates.
func TestConfigAndSystemEvents_CorrelationSchema(t *testing.T) {
	rb := &recordingBackend{}
	l := newTestLogger(&config.AuditConfig{Enabled: true, Backend: "stdout", BufferSize: 8, FlushInterval: "10s"}, rb)
	l.LogConfigChange(authenticationv1.UserInfo{Username: "admin"}, "UPDATE", "policy", "p1",
		map[string]interface{}{"correlation_id": "cid-propagated"})
	l.LogSystemEvent("Reconcile", "reconciled", map[string]interface{}{"correlation_id": "cid-sys"})
	_ = l.Close()

	for _, e := range rb.all() {
		if e.SchemaVersion != AuditSchemaVersion {
			t.Errorf("%s event missing schema_version", e.EventType)
		}
		if e.CorrelationID == "" {
			t.Errorf("%s event missing correlation_id", e.EventType)
		}
	}
	byType := map[string]*Event{}
	for _, e := range rb.all() {
		byType[e.EventType] = e
	}
	if byType["ConfigurationChange"].CorrelationID != "cid-propagated" {
		t.Errorf("config-change correlation id not propagated: %q", byType["ConfigurationChange"].CorrelationID)
	}
	if byType["Reconcile"].CorrelationID != "cid-sys" {
		t.Errorf("system-event correlation id not propagated: %q", byType["Reconcile"].CorrelationID)
	}
}

// AUD-WU-14: in block (fail-closed) overflow mode no record is lost even when the
// sink is slow and the buffer is tiny — backpressure holds every producer.
func TestOverflowBlock_NoLoss(t *testing.T) {
	rb := &recordingBackend{delay: 1 * time.Millisecond}
	cfg := &config.AuditConfig{Enabled: true, Backend: "stdout", BufferSize: 1, FlushInterval: "10s", OverflowPolicy: "block"}
	l := newTestLogger(cfg, rb)

	const n = 250 // > the 100-event flush batch, so the slow flush forces backpressure
	for i := 0; i < n; i++ {
		l.LogSystemEvent("Load", "x", nil)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := rb.count(); got != n {
		t.Errorf("block overflow policy lost records: recorded %d of %d", got, n)
	}
}

// AUD-WU-14: a graceful Close flushes everything still buffered (the SIGTERM
// shutdown path) — no loss on shutdown.
func TestGracefulClose_FlushesBuffer(t *testing.T) {
	rb := &recordingBackend{delay: 2 * time.Millisecond}
	cfg := &config.AuditConfig{Enabled: true, Backend: "stdout", BufferSize: 64, FlushInterval: "1h"}
	l := newTestLogger(cfg, rb)
	const n = 40
	for i := 0; i < n; i++ {
		l.LogSystemEvent("Shutdown", "x", nil)
	}
	// Records are buffered (flush interval is 1h, batch threshold 100) — only
	// Close()'s drain flushes them.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := rb.count(); got != n {
		t.Errorf("graceful close lost buffered records: recorded %d of %d", got, n)
	}
	// Close is idempotent.
	if err := l.Close(); err != nil {
		t.Errorf("second Close should be a no-op, got %v", err)
	}
}
