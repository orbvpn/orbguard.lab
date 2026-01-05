package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

// Logger wraps zerolog.Logger with additional functionality
type Logger struct {
	zerolog.Logger
}

// Config holds logger configuration
type Config struct {
	Level      string
	Format     string // "console" or "json"
	TimeFormat string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Level:      "info",
		Format:     "console",
		TimeFormat: time.RFC3339,
	}
}

// New creates a new logger with the given configuration
func New(cfg Config) *Logger {
	// Enable stack traces on errors
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	// Set time format
	if cfg.TimeFormat != "" {
		zerolog.TimeFieldFormat = cfg.TimeFormat
	} else {
		zerolog.TimeFieldFormat = time.RFC3339
	}

	// Parse level
	level := parseLevel(cfg.Level)

	// Create output writer
	var output io.Writer
	if cfg.Format == "console" {
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: cfg.TimeFormat,
		}
	} else {
		output = os.Stdout
	}

	// Create logger
	logger := zerolog.New(output).
		Level(level).
		With().
		Timestamp().
		Logger()

	return &Logger{Logger: logger}
}

// NewDefault creates a logger with default configuration
func NewDefault() *Logger {
	return New(DefaultConfig())
}

// NewDevelopment creates a logger optimized for development
func NewDevelopment() *Logger {
	return New(Config{
		Level:      "debug",
		Format:     "console",
		TimeFormat: "15:04:05",
	})
}

// NewProduction creates a logger optimized for production
func NewProduction() *Logger {
	return New(Config{
		Level:      "info",
		Format:     "json",
		TimeFormat: time.RFC3339,
	})
}

// WithComponent returns a new logger with the component field set
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		Logger: l.With().Str("component", component).Logger(),
	}
}

// WithRequestID returns a new logger with the request ID field set
func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{
		Logger: l.With().Str("request_id", requestID).Logger(),
	}
}

// WithSourceID returns a new logger with the source ID field set
func (l *Logger) WithSourceID(sourceID string) *Logger {
	return &Logger{
		Logger: l.With().Str("source_id", sourceID).Logger(),
	}
}

// WithError returns a new logger with the error attached
func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		Logger: l.With().Err(err).Logger(),
	}
}

// WithFields returns a new logger with the given fields attached
func (l *Logger) WithFields(fields map[string]any) *Logger {
	ctx := l.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return &Logger{Logger: ctx.Logger()}
}

// parseLevel converts a string level to zerolog.Level
func parseLevel(level string) zerolog.Level {
	switch level {
	case "trace":
		return zerolog.TraceLevel
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}

// Global logger instance
var global *Logger

func init() {
	global = NewDefault()
}

// SetGlobal sets the global logger instance
func SetGlobal(l *Logger) {
	global = l
}

// Global returns the global logger instance
func Global() *Logger {
	return global
}

// Convenience methods for global logger
func Debug() *zerolog.Event { return global.Debug() }
func Info() *zerolog.Event  { return global.Info() }
func Warn() *zerolog.Event  { return global.Warn() }
func Error() *zerolog.Event { return global.Error() }
func Fatal() *zerolog.Event { return global.Fatal() }
