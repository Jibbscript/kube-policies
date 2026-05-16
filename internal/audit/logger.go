package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/policy"
)

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
	config  *config.AuditConfig
	backend Backend
	buffer  chan *Event
	ctx     context.Context
	cancel  context.CancelFunc
	logger  *zap.Logger
	metrics Metrics
}

// Backend represents an audit backend
type Backend interface {
	Write(event *Event) error
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

	backend, err := createBackend(cfg)
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

	// Start background processor
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

	event := &Event{
		Timestamp:        ctx.Timestamp,
		RequestID:        ctx.RequestID,
		EventType:        "PolicyDecision",
		UserInfo:         ctx.UserInfo,
		Namespace:        ctx.Namespace,
		Kind:             ctx.Kind,
		Name:             ctx.Name,
		Operation:        ctx.Operation,
		Decision:         ctx.Decision,
		Reason:           ctx.Reason,
		Message:          ctx.Message,
		PolicyViolations: ctx.PolicyViolations,
		Mutations:        ctx.Mutations,
		ProcessingTime:   ctx.ProcessingTime,
		Object:           ctx.Object,
		OldObject:        ctx.OldObject,
		Metadata:         ctx.Metadata,
	}

	l.enqueue(event)
}

// LogConfigChange logs a configuration change
func (l *Logger) LogConfigChange(userInfo authenticationv1.UserInfo, changeType, resource, resourceID string, changes map[string]interface{}) {
	if !l.config.Enabled {
		return
	}

	event := &Event{
		Timestamp: time.Now(),
		RequestID: fmt.Sprintf("config-%d", time.Now().UnixNano()),
		EventType: "ConfigurationChange",
		UserInfo:  userInfo,
		Operation: changeType,
		Message:   fmt.Sprintf("%s %s %s", changeType, resource, resourceID),
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

	event := &Event{
		Timestamp: time.Now(),
		RequestID: fmt.Sprintf("system-%d", time.Now().UnixNano()),
		EventType: eventType,
		Message:   message,
		Metadata:  metadata,
	}

	l.enqueue(event)
}

// enqueue offers the event to the buffer; on overflow it logs structured-warn
// and increments the dropped-event metric so operators can alert on it.
func (l *Logger) enqueue(event *Event) {
	select {
	case l.buffer <- event:
	default:
		l.logger.Warn("audit buffer full, dropping event",
			zap.String("event_type", event.EventType),
			zap.String("request_id", event.RequestID),
		)
		l.metrics.IncAuditEvents(event.EventType, "dropped")
	}
}

// processEvents processes audit events in the background
func (l *Logger) processEvents() {
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
			// Flush remaining events before shutdown
			l.flushEvents(events)
			return

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

// Close closes the audit logger
func (l *Logger) Close() error {
	if !l.config.Enabled {
		return nil
	}

	l.cancel()

	if l.backend != nil {
		return l.backend.Close()
	}

	return nil
}

// createBackend creates an audit backend based on configuration
func createBackend(config *config.AuditConfig) (Backend, error) {
	switch config.Backend {
	case "file":
		return NewFileBackend(config)
	case "stdout":
		return NewStdoutBackend(), nil
	default:
		return nil, fmt.Errorf("unsupported audit backend: %s", config.Backend)
	}
}

// FileBackend writes audit events to a file
type FileBackend struct {
	file *os.File
}

// NewFileBackend creates a new file backend
func NewFileBackend(config *config.AuditConfig) (*FileBackend, error) {
	filename := config.Config["filename"]
	if filename == "" {
		filename = "/var/log/kube-policies/audit.log"
	}

	// Audit logs can contain sensitive request context, so the directory and
	// file are created with restrictive perms: 0750 dir, 0600 file.
	if err := os.MkdirAll(filepath.Dir(filename), 0o750); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &FileBackend{file: file}, nil
}

// Write writes an audit event to the file
func (b *FileBackend) Write(event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	_, err = b.file.Write(append(data, '\n'))
	return err
}

// Close closes the file backend
func (b *FileBackend) Close() error {
	return b.file.Close()
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

// Close closes the stdout backend
func (b *StdoutBackend) Close() error {
	return nil
}
