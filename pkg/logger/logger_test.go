package logger

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"k8s.io/klog/v2"
	ctrlruntimelog "sigs.k8s.io/controller-runtime/pkg/log"
)

// resetCtrlLogStateForTest resets package-level wiring state between tests.
// Must only be called from within tests in this package.
func resetCtrlLogStateForTest() {
	ctrlLogMu.Lock()
	defer ctrlLogMu.Unlock()
	ctrlLogFirst = nil
	ctrlLogFirstCaller = ""
}

// TestNewLogger_ProductionKeys verifies that a production logger emits the
// expected JSON keys and that the service field matches the constructor arg.
func TestNewLogger_ProductionKeys(t *testing.T) {
	// Redirect os.Stdout before building the logger so zap's "stdout" path
	// captures output through our pipe.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	log := NewLogger("svc", "info")
	log.Info("hello", zap.String("k", "v"))
	_ = log.Sync()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("reading pipe: %v", err)
	}

	var entry map[string]interface{}
	line := strings.TrimSpace(buf.String())
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("JSON unmarshal failed (%q): %v", line, err)
	}

	for _, key := range []string{"timestamp", "level", "caller", "message", "service"} {
		if _, ok := entry[key]; !ok {
			t.Errorf("missing key %q in log output: %v", key, entry)
		}
	}
	if got, ok := entry["service"].(string); !ok || got != "svc" {
		t.Errorf("service = %q, want %q", entry["service"], "svc")
	}
}

// TestSetControllerRuntimeLogger_KeysAndCaller verifies that after wiring,
// controller-runtime log entries are captured by the observer and have a
// correctly formatted caller field.
func TestSetControllerRuntimeLogger_KeysAndCaller(t *testing.T) {
	resetCtrlLogStateForTest()
	t.Cleanup(resetCtrlLogStateForTest)

	core, obsLogs := observer.New(zap.DebugLevel)
	obsLogger := zap.New(core, zap.AddCaller())

	SetControllerRuntimeLogger(obsLogger)

	ctrlruntimelog.Log.WithName("x").Info("msg")

	entries := obsLogs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 observed entry, got %d", len(entries))
	}

	caller := entries[0].Caller
	callerStr := caller.String() // "file.go:42" format
	callerRe := regexp.MustCompile(`^[^:\s]+\.go:\d+$`)
	if !callerRe.MatchString(callerStr) {
		t.Errorf("caller %q does not match ^[^:\\s]+\\.go:\\d+$", callerStr)
	}
}

// TestSetControllerRuntimeLogger_IdempotentSamePointer verifies that calling
// the helper twice with the same *zap.Logger pointer does not panic.
func TestSetControllerRuntimeLogger_IdempotentSamePointer(t *testing.T) {
	resetCtrlLogStateForTest()
	t.Cleanup(resetCtrlLogStateForTest)

	core, _ := observer.New(zap.DebugLevel)
	obsLogger := zap.New(core)

	// Both calls must not panic.
	SetControllerRuntimeLogger(obsLogger)
	SetControllerRuntimeLogger(obsLogger) // same pointer: silent no-op
}

// TestSetControllerRuntimeLogger_PanicsOnDifferentPointer verifies that a
// second call with a different *zap.Logger panics with a message naming both
// call sites.
func TestSetControllerRuntimeLogger_PanicsOnDifferentPointer(t *testing.T) {
	resetCtrlLogStateForTest()
	t.Cleanup(resetCtrlLogStateForTest)

	coreA, _ := observer.New(zap.DebugLevel)
	loggerA := zap.New(coreA)

	coreB, _ := observer.New(zap.DebugLevel)
	loggerB := zap.New(coreB)

	SetControllerRuntimeLogger(loggerA)

	var panicVal interface{}
	func() {
		defer func() { panicVal = recover() }()
		SetControllerRuntimeLogger(loggerB)
	}()

	if panicVal == nil {
		t.Fatal("expected panic on second call with different *zap.Logger, got none")
	}
	msg, ok := panicVal.(string)
	if !ok {
		t.Fatalf("panic value is not a string: %T %v", panicVal, panicVal)
	}
	if !strings.Contains(msg, "already wired") {
		t.Errorf("panic message missing %q: %s", "already wired", msg)
	}
	fileLine := regexp.MustCompile(`[^:\s]+\.go:\d+`)
	if !fileLine.MatchString(msg) {
		t.Errorf("panic message missing file:line pair: %s", msg)
	}
}

// TestSetKlogLogger_RoutesThroughZap verifies that after wiring, klog entries
// are captured by the observer and that structured key-value pairs survive.
func TestSetKlogLogger_RoutesThroughZap(t *testing.T) {
	resetCtrlLogStateForTest()
	t.Cleanup(resetCtrlLogStateForTest)

	core, obsLogs := observer.New(zap.DebugLevel)
	obsLogger := zap.New(core)

	SetControllerRuntimeLogger(obsLogger)

	klog.InfoS("klog-hello", "k", "v")

	entries := obsLogs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 observed entry, got %d", len(entries))
	}

	// Verify the k=v pair survived the klog → zapr → observer pipeline.
	found := false
	for _, f := range entries[0].Context {
		if f.Key == "k" && f.String == "v" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("k=v field not found in observed entry context: %v", entries[0].Context)
	}
}
