package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
