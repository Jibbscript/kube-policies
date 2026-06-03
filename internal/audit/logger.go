package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/policy"
)

// AuditSchemaVersion is the version stamped on every emitted audit record
// (AUD-WU-17, AU-3(1)). Bump on any breaking change to the Event JSON shape;
// the published schema lives at internal/audit/schema.json.
const AuditSchemaVersion = "1.0.0"

// Metrics is the minimal metrics surface the audit logger uses.
// Defined here to avoid importing internal/metrics from pkg/.
type Metrics interface {
	IncAuditEvents(eventType, status string)
	SetAuditBufferSize(size float64)
}

// NopMetrics is a no-op Metrics implementation suitable for tests or
// configurations where metrics are not collected.
type NopMetrics struct{}

func (NopMetrics) IncAuditEvents(string, string) {}
func (NopMetrics) SetAuditBufferSize(float64)    {}

// Logger handles audit logging
type Logger struct {
	config    *config.AuditConfig
	backend   Backend
	buffer    chan *Event
	ctx       context.Context
	cancel    context.CancelFunc
	logger    *zap.Logger
	metrics   Metrics
	wg        sync.WaitGroup
	closeOnce sync.Once
	// chainer adds the tamper-evidence HMAC chain to each persisted event when
	// audit integrity is enabled (AUD-WU-04); nil disables chaining.
	chainer *Chainer
}

// Backend represents an audit backend
type Backend interface {
	Write(event *Event) error
	// WriteRaw persists pre-serialized bytes verbatim (one record per call).
	// Used for the sealed integrity envelope so the HMAC covers exactly the
	// bytes on disk (AUD-WU-04).
	WriteRaw(data []byte) error
	Close() error
}

// Event represents an audit event
type Event struct {
	Timestamp        time.Time                 `json:"timestamp"`
	RequestID        string                    `json:"request_id"`
	EventType        string                    `json:"event_type"`
	UserInfo         authenticationv1.UserInfo `json:"user_info"`
	Namespace        string                    `json:"namespace,omitempty"`
	Kind             metav1.GroupVersionKind   `json:"kind"`
	Name             string                    `json:"name,omitempty"`
	Operation        string                    `json:"operation"`
	Decision         string                    `json:"decision"`
	Reason           string                    `json:"reason,omitempty"`
	Message          string                    `json:"message,omitempty"`
	PolicyViolations []policy.PolicyViolation  `json:"policy_violations,omitempty"`
	Mutations        []policy.JSONPatch        `json:"mutations,omitempty"`
	ProcessingTime   time.Duration             `json:"processing_time"`
	Object           *runtime.RawExtension     `json:"object,omitempty"`
	OldObject        *runtime.RawExtension     `json:"old_object,omitempty"`
	Metadata         map[string]interface{}    `json:"metadata,omitempty"`
	// SuppressedBy carries the full per-violation attribution (ID, Name, PolicyID,
	// RuleID, Justification) for any violations the engine suppressed via a
	// matching PolicyException. The Prometheus `exception_suppressions_total`
	// counter intentionally drops exception_id from labels to bound cardinality
	// (plan §5.9.a / OQ-4); operators correlating a metric spike with a specific
	// exception query this audit field, not the metric.
	SuppressedBy []policy.ExceptionRef `json:"suppressed_by,omitempty"`

	// SchemaVersion (AUD-WU-17, AU-3(1)) stamps the record shape. omitempty keeps
	// hand-built Event literals in existing integrity tests byte-identical.
	SchemaVersion string `json:"schema_version,omitempty"`

	// CorrelationID (AUD-WU-20, AU-12(1)) ties together every record emitted for
	// one logical request across components (admission UID -> policy-manager API
	// -> dashboard). Propagated, never regenerated per hop.
	CorrelationID string `json:"correlation_id,omitempty"`

	// Source/network attribution (AUD-WU-01, AU-3 where/source). SourceIP is the
	// webhook's direct HTTP peer (the apiserver/proxy hop), NOT necessarily the
	// originating client — the apiserver does not forward the original caller IP
	// to admission webhooks. See docs/compliance/AU-controls.md.
	SourceIP               string `json:"source_ip,omitempty"`
	UserAgent              string `json:"user_agent,omitempty"`
	RequestURI             string `json:"request_uri,omitempty"`
	APIServerID            string `json:"apiserver_id,omitempty"`
	AdmissionWebhookConfig string `json:"admission_webhook_config,omitempty"`

	// Dual timestamps (AUD-WU-02, AU-8). RequestReceivedTimestamp is when the
	// controller received the request; StageTimestamp is when this audit record
	// was emitted. Both UTC. Pointers + omitempty so non-decision events (config/
	// system) and existing test literals stay byte-identical.
	RequestReceivedTimestamp *time.Time `json:"request_received_timestamp,omitempty"`
	StageTimestamp           *time.Time `json:"stage_timestamp,omitempty"`

	// Tamper-evidence chain fields (AUD-WU-04, AU-9). Populated only when audit
	// integrity is enabled; omitempty keeps integrity-off logs byte-identical to
	// before. Sequence is strictly increasing (>=1); PrevHash is the prior
	// record's HMAC. The HMAC itself lives in the sealing envelope written to
	// disk (see integrity.go sealedRecord / Chainer.Seal / VerifyChain), not on
	// the event, so it is never part of the bytes it signs.
	Sequence uint64 `json:"sequence,omitempty"`
	PrevHash string `json:"prev_hash,omitempty"`
}

// Context represents the context for audit logging
type Context struct {
	RequestID        string
	UserInfo         authenticationv1.UserInfo
	Namespace        string
	Kind             metav1.GroupVersionKind
	Name             string
	Operation        string
	Decision         string
	Reason           string
	Message          string
	PolicyViolations []policy.PolicyViolation
	Mutations        []policy.JSONPatch
	ProcessingTime   time.Duration
	Object           *runtime.RawExtension
	OldObject        *runtime.RawExtension
	Timestamp        time.Time
	Metadata         map[string]interface{}

	// AUD-WU-01 source/network attribution, populated by the admission controller
	// from the inbound *http.Request (gin Context), not from the AdmissionRequest.
	SourceIP               string
	UserAgent              string
	RequestURI             string
	APIServerID            string
	AdmissionWebhookConfig string
	// AUD-WU-02 dual timestamps (both UTC). RequestReceived = controller entry.
	RequestReceivedTimestamp time.Time
	StageTimestamp           time.Time
	// AUD-WU-20 correlation id (for admission this is the AdmissionRequest UID).
	CorrelationID string
	// SuppressedBy carries the ExceptionRefs attached to the EvaluationResult
	// for any violations waived by a matching PolicyException. Populated by
	// the admission controller from policy.EvaluationResult.SuppressedBy.
	SuppressedBy []policy.ExceptionRef
}

// NewLogger creates a new audit logger.
// log and metrics may be nil; nil is treated as a no-op so legacy callers
// continue to work, but new code should always pass real implementations.
func NewLogger(cfg *config.AuditConfig, opts ...Option) (*Logger, error) {
	o := loggerOptions{logger: zap.NewNop(), metrics: NopMetrics{}}
	for _, apply := range opts {
		apply(&o)
	}

	if !cfg.Enabled {
		return &Logger{config: cfg, logger: o.logger, metrics: o.metrics}, nil
	}

	backend, err := createBackend(cfg, o.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit backend: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	l := &Logger{
		config:  cfg,
		backend: backend,
		buffer:  make(chan *Event, cfg.BufferSize),
		ctx:     ctx,
		cancel:  cancel,
		logger:  o.logger,
		metrics: o.metrics,
	}

	// Audit integrity (AUD-WU-04/05, AU-9): when integrity_key_path is set, load
	// the HMAC key from the mounted Secret and chain every persisted record.
	if keyPath := cfg.Config["integrity_key_path"]; keyPath != "" {
		key, err := LoadKeyFromFile(keyPath)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("audit integrity: %w", err)
		}
		chainer, err := NewChainer(key)
		if err != nil {
			cancel()
			return nil, err
		}
		l.chainer = chainer
		o.logger.Info("audit integrity enabled (tamper-evident HMAC chain)")
	}

	// Start background processor
	l.wg.Add(1)
	go l.processEvents()

	return l, nil
}

// Option configures a Logger at construction time.
type Option func(*loggerOptions)

type loggerOptions struct {
	logger  *zap.Logger
	metrics Metrics
}

// WithLogger attaches a zap.Logger for diagnostic output.
func WithLogger(z *zap.Logger) Option {
	return func(o *loggerOptions) {
		if z != nil {
			o.logger = z
		}
	}
}

// WithMetrics attaches a Metrics implementation for buffer/drop telemetry.
func WithMetrics(m Metrics) Option {
	return func(o *loggerOptions) {
		if m != nil {
			o.metrics = m
		}
	}
}

// LogDecision logs a policy decision
func (l *Logger) LogDecision(ctx *Context) {
	if !l.config.Enabled {
		return
	}

	// Dual timestamps (AUD-WU-02, AU-8), both UTC. Fall back to the handler-entry
	// Timestamp / now when the caller did not populate them.
	rrt := ctx.RequestReceivedTimestamp
	if rrt.IsZero() {
		rrt = ctx.Timestamp
	}
	rrt = rrt.UTC()
	st := ctx.StageTimestamp
	if st.IsZero() {
		st = time.Now()
	}
	st = st.UTC()

	// Correlation id (AUD-WU-20) defaults to the request id (the AdmissionRequest
	// UID for admission), so a record always carries a non-empty correlation key.
	correlationID := ctx.CorrelationID
	if correlationID == "" {
		correlationID = ctx.RequestID
	}

	event := &Event{
		Timestamp:                ctx.Timestamp,
		RequestID:                ctx.RequestID,
		EventType:                "PolicyDecision",
		UserInfo:                 ctx.UserInfo,
		Namespace:                ctx.Namespace,
		Kind:                     ctx.Kind,
		Name:                     ctx.Name,
		Operation:                ctx.Operation,
		Decision:                 ctx.Decision,
		Reason:                   ctx.Reason,
		Message:                  ctx.Message,
		PolicyViolations:         ctx.PolicyViolations,
		Mutations:                ctx.Mutations,
		ProcessingTime:           ctx.ProcessingTime,
		Object:                   ctx.Object,
		OldObject:                ctx.OldObject,
		Metadata:                 ctx.Metadata,
		SuppressedBy:             ctx.SuppressedBy,
		SchemaVersion:            AuditSchemaVersion,
		CorrelationID:            correlationID,
		SourceIP:                 ctx.SourceIP,
		UserAgent:                ctx.UserAgent,
		RequestURI:               ctx.RequestURI,
		APIServerID:              ctx.APIServerID,
		AdmissionWebhookConfig:   ctx.AdmissionWebhookConfig,
		RequestReceivedTimestamp: &rrt,
		StageTimestamp:           &st,
	}

	l.enqueue(event)
}

// LogConfigChange logs a configuration change
func (l *Logger) LogConfigChange(userInfo authenticationv1.UserInfo, changeType, resource, resourceID string, changes map[string]interface{}) {
	if !l.config.Enabled {
		return
	}

	now := time.Now().UTC()
	// Correlation id (AUD-WU-20): callers propagate one via changes["correlation_id"];
	// otherwise synthesize a per-record id so every event still carries one.
	correlationID, _ := changes["correlation_id"].(string)
	if correlationID == "" {
		correlationID = fmt.Sprintf("corr-%d", now.UnixNano())
	}

	event := &Event{
		Timestamp:      now,
		RequestID:      fmt.Sprintf("config-%d", now.UnixNano()),
		EventType:      "ConfigurationChange",
		UserInfo:       userInfo,
		Operation:      changeType,
		Message:        fmt.Sprintf("%s %s %s", changeType, resource, resourceID),
		SchemaVersion:  AuditSchemaVersion,
		CorrelationID:  correlationID,
		StageTimestamp: func() *time.Time { t := now; return &t }(),
		Metadata: map[string]interface{}{
			"resource":    resource,
			"resource_id": resourceID,
			"changes":     changes,
		},
	}

	l.enqueue(event)
}

// LogSystemEvent logs a system event
func (l *Logger) LogSystemEvent(eventType, message string, metadata map[string]interface{}) {
	if !l.config.Enabled {
		return
	}

	now := time.Now().UTC()
	correlationID, _ := metadata["correlation_id"].(string)
	if correlationID == "" {
		correlationID = fmt.Sprintf("corr-%d", now.UnixNano())
	}

	event := &Event{
		Timestamp:      now,
		RequestID:      fmt.Sprintf("system-%d", now.UnixNano()),
		EventType:      eventType,
		Message:        message,
		Metadata:       metadata,
		SchemaVersion:  AuditSchemaVersion,
		CorrelationID:  correlationID,
		StageTimestamp: func() *time.Time { t := now; return &t }(),
	}

	l.enqueue(event)
}

// enqueue offers the event to the buffer. Overflow behavior is governed by
// config.Audit.OverflowPolicy (AUD-WU-14, AU-5/AU-9):
//   - "drop" (default): never blocks the hot path; on a full buffer it warns and
//     increments the dropped-event metric so operators can alert on loss.
//   - "block": fail-closed — apply backpressure until the consumer drains the
//     buffer, so no audit record is silently lost. The blocking send also selects
//     on ctx.Done() so a shutting-down logger (whose processEvents has exited)
//     can never deadlock a producer.
func (l *Logger) enqueue(event *Event) {
	// Fast path: non-blocking offer succeeds whenever there is room, for both
	// policies.
	select {
	case l.buffer <- event:
		return
	default:
	}

	if l.config.OverflowPolicy == "block" {
		select {
		case l.buffer <- event:
		case <-l.ctx.Done():
			// Logger is shutting down; the consumer may already be gone. Record
			// the loss rather than block forever.
			l.metrics.IncAuditEvents(event.EventType, "dropped")
		}
		return
	}

	l.logger.Warn("audit buffer full, dropping event",
		zap.String("event_type", event.EventType),
		zap.String("request_id", event.RequestID),
	)
	l.metrics.IncAuditEvents(event.EventType, "dropped")
}

// processEvents processes audit events in the background
func (l *Logger) processEvents() {
	defer l.wg.Done()

	flushInterval, _ := time.ParseDuration(l.config.FlushInterval)
	if flushInterval == 0 {
		flushInterval = 10 * time.Second
	}

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	events := make([]*Event, 0, 100)

	for {
		select {
		case <-l.ctx.Done():
			// Drain any queued events before shutdown. Cancel can race with
			// enqueue, so flushing only the local batch would lose records
			// still sitting in l.buffer.
			for {
				select {
				case event := <-l.buffer:
					events = append(events, event)
				default:
					l.flushEvents(events)
					return
				}
			}

		case event := <-l.buffer:
			events = append(events, event)
			if len(events) >= 100 {
				l.flushEvents(events)
				events = events[:0]
			}

		case <-ticker.C:
			l.metrics.SetAuditBufferSize(float64(len(l.buffer)))
			if len(events) > 0 {
				l.flushEvents(events)
				events = events[:0]
			}
		}
	}
}

// flushEvents writes events to the backend
func (l *Logger) flushEvents(events []*Event) {
	if l.backend == nil {
		return
	}

	for _, event := range events {
		// Redact Secret/PII payloads (AUD-WU-17, AU-3(1)/SI-12) BEFORE sealing or
		// writing. This MUST precede Chainer.Seal — sealing signs the verbatim
		// event bytes, so redacting after sealing would leave unredacted payload
		// on disk under a valid HMAC. maybeRedact returns the same event when
		// redaction is disabled or there is nothing sensitive to redact.
		event = l.maybeRedact(event)

		// When integrity is enabled (AUD-WU-04), seal the event into the hash
		// chain and persist the verbatim sealed bytes. Done here
		// (single-threaded flush) so Sequence is gap-free and ordered. On a
		// sealing error we do NOT fall back to an unchained Write — that would
		// insert a gap an auditor would read as tampering.
		if l.chainer != nil {
			sealed, err := l.chainer.Seal(event)
			if err != nil {
				l.logger.Error("failed to seal audit event for integrity",
					zap.String("request_id", event.RequestID), zap.Error(err))
				l.metrics.IncAuditEvents(event.EventType, "chain_error")
				continue
			}
			if err := l.backend.WriteRaw(sealed); err != nil {
				l.logger.Error("failed to write sealed audit event",
					zap.String("request_id", event.RequestID), zap.Error(err))
				l.metrics.IncAuditEvents(event.EventType, "write_error")
			} else {
				l.metrics.IncAuditEvents(event.EventType, "written")
			}
			continue
		}
		if err := l.backend.Write(event); err != nil {
			l.logger.Error("failed to write audit event",
				zap.String("event_type", event.EventType),
				zap.String("request_id", event.RequestID),
				zap.Error(err),
			)
			l.metrics.IncAuditEvents(event.EventType, "write_error")
		} else {
			l.metrics.IncAuditEvents(event.EventType, "written")
		}
	}
}

// Close flushes and closes the audit logger. It is idempotent (safe to call
// from both a SIGTERM handler and a deferred cleanup, AUD-WU-14): cancel()
// triggers processEvents to drain the buffer and flush every queued record
// before wg.Wait() returns, then the backend is closed.
func (l *Logger) Close() error {
	if !l.config.Enabled {
		return nil
	}

	var err error
	l.closeOnce.Do(func() {
		l.cancel()
		l.wg.Wait() // blocks until processEvents drains l.buffer and flushes
		if l.backend != nil {
			err = l.backend.Close()
		}
	})
	return err
}

// createBackend creates an audit backend based on configuration
func createBackend(config *config.AuditConfig, log *zap.Logger) (Backend, error) {
	switch config.Backend {
	case "file":
		return NewFileBackend(config)
	case "stdout":
		return NewStdoutBackend(), nil
	case "forward":
		return NewForwardBackend(config, log)
	default:
		return nil, fmt.Errorf("unsupported audit backend: %s", config.Backend)
	}
}

// FileBackend writes audit events to a size- and age-rotated file
// (AUD-WU-06/07, AU-4 capacity / AU-11 retention). Rotation is provided by
// lumberjack; the integrity hash-chain (integrity.go) is unaffected by rotation
// because its sequence/prev-hash state lives in the in-memory Chainer, not in
// the file — verification across a rotated set uses VerifyChainFiles, which
// concatenates the files oldest-first.
type FileBackend struct {
	w        *lumberjack.Logger
	filename string
}

// NewFileBackend creates a new rotating file backend. Rotation parameters come
// from AuditConfig: max_size_mb (size cap), max_backups (file count cap), and
// retention (max age; '90d' supported). A non-positive max_size_mb falls back
// to lumberjack's 100 MiB default.
func NewFileBackend(cfg *config.AuditConfig) (*FileBackend, error) {
	filename := cfg.Config["filename"]
	if filename == "" {
		filename = "/var/log/kube-policies/audit.log"
	}

	// Audit logs can contain sensitive request context, so the directory is
	// created 0750. lumberjack creates the log file (and rotated files) 0600.
	if err := os.MkdirAll(filepath.Dir(filename), 0o750); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	maxAgeDays := 0 // 0 = no age-based deletion
	if cfg.Retention != "" {
		d, err := config.ParseRetention(cfg.Retention)
		if err != nil {
			return nil, fmt.Errorf("audit file backend: %w", err)
		}
		maxAgeDays = int(d.Hours() / 24)
	}

	w := &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    cfg.MaxSizeMB, // MiB; <=0 -> lumberjack default 100
		MaxBackups: cfg.MaxBackups,
		MaxAge:     maxAgeDays, // days
		Compress:   false,      // keep rotated files plaintext so VerifyChain can read them
	}

	// Touch the file so a freshly-created log exists at 0600 immediately (and so
	// startup fails fast on an unwritable mount rather than at first event).
	if _, err := w.Write([]byte{}); err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &FileBackend{w: w, filename: filename}, nil
}

// Write writes an audit event to the rotating file.
func (b *FileBackend) Write(event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}
	_, err = b.w.Write(append(data, '\n'))
	return err
}

// WriteRaw appends pre-serialized bytes (a sealed integrity envelope) followed
// by a newline, verbatim.
func (b *FileBackend) WriteRaw(data []byte) error {
	_, err := b.w.Write(append(data, '\n'))
	return err
}

// Close closes the file backend.
func (b *FileBackend) Close() error {
	return b.w.Close()
}

// StdoutBackend writes audit events to stdout
type StdoutBackend struct{}

// NewStdoutBackend creates a new stdout backend
func NewStdoutBackend() *StdoutBackend {
	return &StdoutBackend{}
}

// Write writes an audit event to stdout
func (b *StdoutBackend) Write(event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// WriteRaw prints pre-serialized bytes (a sealed integrity envelope) verbatim.
func (b *StdoutBackend) WriteRaw(data []byte) error {
	fmt.Println(string(data))
	return nil
}

// Close closes the stdout backend
func (b *StdoutBackend) Close() error {
	return nil
}
