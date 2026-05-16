package logger

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
	ctrlruntimelog "sigs.k8s.io/controller-runtime/pkg/log"
)

// Package-level state for SetControllerRuntimeLogger idempotency guard.
var (
	ctrlLogMu          sync.Mutex
	ctrlLogFirst       *zap.Logger
	ctrlLogFirstCaller string
)

// NewLogger creates a new structured logger
func NewLogger(service, level string) *zap.Logger {
	config := zap.NewProductionConfig()

	// Set log level
	switch level {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	// Configure encoder
	config.EncoderConfig = zapcore.EncoderConfig{
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
	}

	// Use JSON encoder for production
	config.Encoding = "json"

	// Configure output paths
	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}

	logger, err := config.Build()
	if err != nil {
		// Fallback to basic logger if configuration fails
		logger = zap.NewNop()
	}

	// Add service name as a field
	logger = logger.With(zap.String("service", service))

	return logger
}

// NewDevelopmentLogger creates a logger suitable for development
func NewDevelopmentLogger(service string) *zap.Logger {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	logger, err := config.Build()
	if err != nil {
		logger = zap.NewNop()
	}

	return logger.With(zap.String("service", service))
}

// NewLoggerFromEnv creates a logger based on environment variables
func NewLoggerFromEnv(service string) *zap.Logger {
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = "info"
	}

	env := os.Getenv("ENVIRONMENT")
	if env == "development" || env == "dev" {
		return NewDevelopmentLogger(service)
	}

	return NewLogger(service, level)
}

// SetControllerRuntimeLogger wires the global controller-runtime and klog v2
// loggers to route through the supplied zap logger via go-logr/zapr. Call this
// once from main() AFTER constructing the zap logger and BEFORE any
// controller-runtime / client-go / klog code path runs (otherwise
// controller-runtime emits "[controller-runtime] log.SetLogger(...) was never
// called; logs will not be displayed" and routes everything to a no-op).
//
// Idempotent for repeat calls with the SAME *zap.Logger pointer (silent
// no-op). Panics on a second call with a DIFFERENT pointer, naming both
// call sites — the genuine misuse case (two binaries fighting over the
// global root) must fail loud at boot.
//
// Note on JSON keys: zapr adds additive structured fields to log lines
// originating from controller-runtime (controller, reconciler group/kind,
// name, namespace). The base schema documented in NewLogger above
// (timestamp/level/caller/message/stacktrace/service) is preserved.
func SetControllerRuntimeLogger(log *zap.Logger) {
	ctrlLogMu.Lock()
	defer ctrlLogMu.Unlock()

	if ctrlLogFirst == nil {
		// First call: record caller, wire both global loggers.
		_, file, line, _ := runtime.Caller(1)
		ctrlLogFirstCaller = fmt.Sprintf("%s:%d", file, line)
		ctrlLogFirst = log

		zlogr := zapr.NewLogger(log)
		ctrlruntimelog.SetLogger(zlogr)
		klog.SetLogger(zlogr)
		return
	}

	if ctrlLogFirst == log {
		// Same pointer — silent no-op.
		return
	}

	// Different pointer — fail loud with both call sites named.
	_, file, line, _ := runtime.Caller(1)
	secondCaller := fmt.Sprintf("%s:%d", file, line)
	panic(fmt.Sprintf(
		"logger.SetControllerRuntimeLogger: already wired from %s with a different *zap.Logger; second call from %s",
		ctrlLogFirstCaller, secondCaller,
	))
}
