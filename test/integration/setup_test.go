package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"

	"github.com/Jibbscript/kube-policies/pkg/logger"
)

// dynamicStdoutSyncer is a zapcore.WriteSyncer that resolves os.Stdout at
// write time rather than capturing its value at logger-construction time.
// zap's built-in "stdout" output-path sink captures the *os.File value during
// config.Build(); a subsequent os.Stdout = pipeWriter assignment in a test
// would be invisible to that captured file. By deferring the lookup to each
// Write call, tests can redirect os.Stdout to an os.Pipe and still capture
// every byte zap emits.
type dynamicStdoutSyncer struct{}

func (dynamicStdoutSyncer) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (dynamicStdoutSyncer) Sync() error                 { return os.Stdout.Sync() }

// sharedLogger is the JSON-encoded logger wired into controller-runtime / klog
// once per integration test binary via TestMain. Test suites continue to build
// their own per-suite *zap.Logger instances (zap.NewNop()) for their in-process
// binaries — those loggers are NOT used to call SetControllerRuntimeLogger.
// This sidesteps the "first SetupSuite wins, others get a stale global" failure
// mode that would arise if wiring happened inside each suite.
var sharedLogger *zap.Logger

func TestMain(m *testing.M) {
	// Build a production-style JSON logger with the same encoder configuration
	// as logger.NewLogger, but backed by dynamicStdoutSyncer so that
	// TestControllerRuntimeWarningAbsent can redirect os.Stdout to a pipe and
	// capture zap's output during the test.
	enc := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})
	core := zapcore.NewCore(enc, zapcore.AddSync(dynamicStdoutSyncer{}), zap.NewAtomicLevelAt(zap.InfoLevel))
	sharedLogger = zap.New(core, zap.AddCaller()).With(zap.String("service", "integration"))

	// Wire controller-runtime and klog to our zap pipeline BEFORE m.Run() so
	// no suite's SetupSuite can race on the global logger state.
	logger.SetControllerRuntimeLogger(sharedLogger)
	os.Exit(m.Run())
}

// TestControllerRuntimeWarningAbsent captures stderr and stdout while emitting
// one klog line through the bridged logger. It asserts:
//
//  1. The controller-runtime "log.SetLogger(...) was never called" warning is
//     absent from stderr (literal substring match).
//  2. At least one captured stdout line is valid JSON with `service` and
//     `caller` keys.
//  3. A deliberately-emitted klog.InfoS line appears as JSON with the
//     `marker=via-zap` field — proves klog is routed through zap.
//  4. Captured stdout contains zero lines in klog's default human-readable
//     format `^[EWIF]\d{4} HH:MM:SS.uuuuuu ...`.
//
// Honors OMC_SKIP_STDERR_CAPTURE=1 to skip the stderr check (CI does not set
// this; escape hatch for local platforms that flake on os.Pipe).
func TestControllerRuntimeWarningAbsent(t *testing.T) {
	// 1. Capture stderr (optional) and stdout.
	stderrBuf, restoreStderr := captureStderr(t)
	defer restoreStderr()

	stdoutBuf, restoreStdout := captureStdout(t)
	defer restoreStdout()

	// 2. Emit one klog line that exercises the bridge.
	klog.InfoS("smoke-test-klog", "marker", "via-zap")
	// Flush the zap core before draining pipes.
	_ = sharedLogger.Sync()

	restoreStderr() // close write-end; goroutine drains remainder then exits
	restoreStdout()

	// 3. Assertions.
	if os.Getenv("OMC_SKIP_STDERR_CAPTURE") != "1" {
		warn := "[controller-runtime] log.SetLogger(...) was never called; logs will not be displayed"
		if strings.Contains(stderrBuf.String(), warn) {
			t.Fatalf("controller-runtime warning leaked to stderr; got: %q", stderrBuf.String())
		}
	}

	stdoutText := stdoutBuf.String()

	// Build a list of parsed JSON records and collect non-JSON lines.
	var records []map[string]any
	var nonJSONLines []string
	scanner := bufio.NewScanner(strings.NewReader(stdoutText))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			nonJSONLines = append(nonJSONLines, string(line))
			continue
		}
		records = append(records, rec)
	}

	if len(records) == 0 {
		t.Fatalf("expected >=1 JSON log line on stdout; got %d records, %d non-JSON lines. Raw:\n%s",
			len(records), len(nonJSONLines), stdoutText)
	}

	// 3a. At least one JSON record must have both `service` and `caller`.
	sawJSON := false
	for _, rec := range records {
		if rec["service"] != nil && rec["caller"] != nil {
			sawJSON = true
			break
		}
	}
	if !sawJSON {
		t.Fatalf("no JSON record contained both `service` and `caller` keys; records: %+v", records)
	}

	// 3b. The klog smoke-test line must appear with marker=via-zap.
	sawKlog := false
	for _, rec := range records {
		if msg, _ := rec["message"].(string); msg != "smoke-test-klog" {
			continue
		}
		if marker, _ := rec["marker"].(string); marker == "via-zap" {
			sawKlog = true
			break
		}
	}
	if !sawKlog {
		t.Fatalf("klog.InfoS smoke-test line did not appear as JSON with marker=via-zap; records: %+v", records)
	}

	// 4. Zero lines in klog's default human-readable format.
	klogDefault := regexp.MustCompile(`^[EWIF]\d{4} \d{2}:\d{2}:\d{2}\.\d{6}`)
	for _, line := range nonJSONLines {
		if klogDefault.MatchString(line) {
			t.Fatalf("klog default-format line escaped the JSON pipeline: %q", line)
		}
	}
}

// captureStdout swaps os.Stdout for an os.Pipe and drains it into a buffer
// in a goroutine for the duration of the test. The returned restore func is
// idempotent — calling it more than once is safe.
func captureStdout(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	return capturePipe(t, &os.Stdout)
}

// captureStderr swaps os.Stderr for an os.Pipe and drains it into a buffer.
// Same shape as captureStdout.
func captureStderr(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	return capturePipe(t, &os.Stderr)
}

func capturePipe(t *testing.T, target **os.File) (*bytes.Buffer, func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	original := *target
	*target = w

	buf := &bytes.Buffer{}
	var bufMu sync.Mutex
	done := make(chan struct{})

	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, readErr := r.Read(b)
			if n > 0 {
				bufMu.Lock()
				buf.Write(b[:n])
				bufMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()

	var (
		restored  bool
		restoreMu sync.Mutex
	)
	restore := func() {
		restoreMu.Lock()
		defer restoreMu.Unlock()
		if restored {
			return
		}
		restored = true
		_ = w.Close()
		<-done
		_ = r.Close()
		*target = original
	}
	return buf, restore
}

// Compile-time assertions: suppress "imported and not used" warnings for
// packages referenced only via type assertions or variable declarations.
var (
	_           = fmt.Sprintf
	_ io.Reader = (*bytes.Buffer)(nil)
)
