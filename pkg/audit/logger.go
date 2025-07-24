package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/policy"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Logger handles audit logging
type Logger struct {
	config  *config.AuditConfig
	backend Backend
	buffer  chan *Event
	mutex   sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// Backend represents an audit backend
type Backend interface {
	Write(event *Event) error
	Close() error
}

// Event represents an audit event
type Event struct {
	Timestamp       time.Time                      `json:"timestamp"`
	RequestID       string                         `json:"request_id"`
	EventType       string                         `json:"event_type"`
	UserInfo        authenticationv1.UserInfo      `json:"user_info"`
	Namespace       string                         `json:"namespace,omitempty"`
	Kind            metav1.GroupVersionKind        `json:"kind"`
	Name            string                         `json:"name,omitempty"`
	Operation       string                         `json:"operation"`
	Decision        string                         `json:"decision"`
	Reason          string                         `json:"reason,omitempty"`
	Message         string                         `json:"message,omitempty"`
	PolicyViolations []policy.PolicyViolation      `json:"policy_violations,omitempty"`
	Mutations       []policy.JSONPatch             `json:"mutations,omitempty"`
	ProcessingTime  time.Duration                  `json:"processing_time"`
	Object          *runtime.RawExtension          `json:"object,omitempty"`
	OldObject       *runtime.RawExtension          `json:"old_object,omitempty"`
	Metadata        map[string]interface{}         `json:"metadata,omitempty"`
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

// NewLogger creates a new audit logger
func NewLogger(config *config.AuditConfig) (*Logger, error) {
	if !config.Enabled {
		return &Logger{config: config}, nil
	}

	backend, err := createBackend(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit backend: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	logger := &Logger{
		config:  config,
		backend: backend,
		buffer:  make(chan *Event, config.BufferSize),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start background processor
	go logger.processEvents()

	return logger, nil
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

	select {
	case l.buffer <- event:
	default:
		// Buffer is full, drop the event (or implement overflow handling)
		fmt.Printf("Audit buffer full, dropping event: %s\n", event.RequestID)
	}
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

	select {
	case l.buffer <- event:
	default:
		fmt.Printf("Audit buffer full, dropping config change event\n")
	}
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

	select {
	case l.buffer <- event:
	default:
		fmt.Printf("Audit buffer full, dropping system event\n")
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
			fmt.Printf("Failed to write audit event: %v\n", err)
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
	case "elasticsearch":
		return NewElasticsearchBackend(config)
	case "webhook":
		return NewWebhookBackend(config)
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

	// Create directory if it doesn't exist
	if err := os.MkdirAll("/var/log/kube-policies", 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

// ElasticsearchBackend writes audit events to Elasticsearch
type ElasticsearchBackend struct {
	// Implementation would include Elasticsearch client
}

// NewElasticsearchBackend creates a new Elasticsearch backend
func NewElasticsearchBackend(config *config.AuditConfig) (*ElasticsearchBackend, error) {
	// Implementation would initialize Elasticsearch client
	return &ElasticsearchBackend{}, nil
}

// Write writes an audit event to Elasticsearch
func (b *ElasticsearchBackend) Write(event *Event) error {
	// Implementation would write to Elasticsearch
	return nil
}

// Close closes the Elasticsearch backend
func (b *ElasticsearchBackend) Close() error {
	// Implementation would close Elasticsearch client
	return nil
}

// WebhookBackend sends audit events to a webhook
type WebhookBackend struct {
	// Implementation would include HTTP client and webhook URL
}

// NewWebhookBackend creates a new webhook backend
func NewWebhookBackend(config *config.AuditConfig) (*WebhookBackend, error) {
	// Implementation would initialize HTTP client
	return &WebhookBackend{}, nil
}

// Write sends an audit event to the webhook
func (b *WebhookBackend) Write(event *Event) error {
	// Implementation would send HTTP POST to webhook
	return nil
}

// Close closes the webhook backend
func (b *WebhookBackend) Close() error {
	// Implementation would cleanup HTTP client
	return nil
}

