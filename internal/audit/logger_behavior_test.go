package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// captureStdout swaps os.Stdout for a pipe, runs fn, then returns whatever fn wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	fn()

	require.NoError(t, w.Close())
	os.Stdout = orig
	<-done
	return buf.String()
}

// TestLogDecision_StdoutFlush verifies that the audit pipeline actually flushes a
// LogDecision call to the stdout backend within the configured flush interval.
// This locks the contract that audit records are not silently buffered forever.
func TestLogDecision_StdoutFlush(t *testing.T) {
	cfg := &config.AuditConfig{
		Enabled:       true,
		Backend:       "stdout",
		BufferSize:    10,
		FlushInterval: "50ms",
	}

	out := captureStdout(t, func() {
		logger, err := NewLogger(cfg)
		require.NoError(t, err)

		logger.LogDecision(&Context{
			RequestID: "req-flush-1",
			UserInfo:  authenticationv1.UserInfo{Username: "alice"},
			Namespace: "default",
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Name:      "p",
			Operation: "CREATE",
			Decision:  "ALLOW",
			Reason:    "PolicyCompliant",
			Timestamp: time.Now(),
		})

		// Allow at least two flush ticks before tearing the logger down so the
		// background processor has a chance to drain the buffer.
		time.Sleep(200 * time.Millisecond)
		require.NoError(t, logger.Close())
	})

	require.NotEmpty(t, out, "stdout backend produced no output")
	// The stdout backend writes one JSON object per event, separated by newlines.
	line := strings.TrimSpace(strings.Split(out, "\n")[0])
	require.NotEmpty(t, line)

	var event map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &event))
	assert.Equal(t, "req-flush-1", event["request_id"])
	assert.Equal(t, "PolicyDecision", event["event_type"])
	assert.Equal(t, "ALLOW", event["decision"])
}

func TestCloseFlushesQueuedDecision(t *testing.T) {
	cfg := &config.AuditConfig{
		Enabled:       true,
		Backend:       "stdout",
		BufferSize:    10,
		FlushInterval: "1h",
	}

	out := captureStdout(t, func() {
		logger, err := NewLogger(cfg)
		require.NoError(t, err)

		logger.LogDecision(&Context{
			RequestID: "req-close-flush-1",
			UserInfo:  authenticationv1.UserInfo{Username: "alice"},
			Namespace: "default",
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Name:      "p",
			Operation: "CREATE",
			Decision:  "DENY",
			Reason:    "PolicyViolation",
			Timestamp: time.Now(),
		})

		require.NoError(t, logger.Close())
	})

	line := strings.TrimSpace(strings.Split(out, "\n")[0])
	require.NotEmpty(t, line, "Close must flush queued audit event without waiting for the ticker")

	var event map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &event))
	assert.Equal(t, "req-close-flush-1", event["request_id"])
	assert.Equal(t, "DENY", event["decision"])
}
