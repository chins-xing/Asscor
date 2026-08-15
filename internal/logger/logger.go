package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
)

type contextKey struct{}

var traceKey = contextKey{}

type switchWriter struct {
	mu sync.RWMutex
	w  io.Writer
}

func newSwitchWriter(w io.Writer) *switchWriter {
	return &switchWriter{w: w}
}

func (sw *switchWriter) Write(p []byte) (n int, err error) {
	sw.mu.RLock()
	defer sw.mu.RUnlock()
	return sw.w.Write(p)
}

func (sw *switchWriter) Switch(w io.Writer) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.w = w
}

func (sw *switchWriter) Current() io.Writer {
	sw.mu.RLock()
	defer sw.mu.RUnlock()
	return sw.w
}

var (
	globalHandler  slog.Handler
	globalLogger   *slog.Logger
	globalFile     *os.File
	globalSwitcher *switchWriter
	handlerOpts    *slog.HandlerOptions
	handlerFormat  string
	once           sync.Once
)

type Config struct {
	Format    string
	Level     string
	Output    string
	AddSource bool
}

func DefaultConfig() Config {
	return Config{
		Format:    "json",
		Level:     "info",
		Output:    "stderr",
		AddSource: false,
	}
}

func Init(cfg Config) {
	once.Do(func() {
		handlerOpts = &slog.HandlerOptions{
			Level:     parseLevel(cfg.Level),
			AddSource: cfg.AddSource,
		}
		handlerFormat = cfg.Format

		var w io.Writer
		switch cfg.Output {
		case "stdout":
			w = os.Stdout
		case "stderr", "":
			w = os.Stderr
		default:
			f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				globalHandler = slog.NewJSONHandler(os.Stderr, handlerOpts)
				globalLogger = slog.New(globalHandler)
				globalLogger.Error("logger: cannot open log file, falling back to stderr", "path", cfg.Output, "error", err)
				return
			}
			globalFile = f
			w = f
		}

		globalSwitcher = newSwitchWriter(w)
		globalHandler = newHandler(globalSwitcher, handlerFormat, handlerOpts)

		globalLogger = slog.New(globalHandler)
		slog.SetDefault(globalLogger)
	})
}

func newHandler(w io.Writer, format string, opts *slog.HandlerOptions) slog.Handler {
	switch format {
	case "text":
		return slog.NewTextHandler(w, opts)
	default:
		return slog.NewJSONHandler(w, opts)
	}
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "info", "INFO", "":
		return slog.LevelInfo
	case "warn", "WARN", "warning", "WARNING":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func L() *slog.Logger {
	if globalLogger == nil {
		Init(DefaultConfig())
	}
	return globalLogger
}

func With(component string, extra ...any) *slog.Logger {
	l := L().With("component", component)
	if len(extra) > 0 {
		l = l.With(extra...)
	}
	return l
}

func WithComponent(component string) *slog.Logger {
	return L().With("component", component)
}

func WithTrace(ctx context.Context) *slog.Logger {
	if traceID, ok := ctx.Value(traceKey).(string); ok && traceID != "" {
		return L().With("trace_id", traceID)
	}
	return L()
}

func WithComponentAndTrace(component string, ctx context.Context) *slog.Logger {
	l := With(component)
	if traceID, ok := ctx.Value(traceKey).(string); ok && traceID != "" {
		l = l.With("trace_id", traceID)
	}
	return l
}

func NewContext(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceKey, traceID)
}

func TraceID(ctx context.Context) string {
	if v, ok := ctx.Value(traceKey).(string); ok {
		return v
	}
	return ""
}

func Debug(msg string, args ...any) { L().Debug(msg, args...) }
func Info(msg string, args ...any)  { L().Info(msg, args...) }
func Warn(msg string, args ...any)  { L().Warn(msg, args...) }
func Error(msg string, args ...any) { L().Error(msg, args...) }

func DebugCtx(ctx context.Context, msg string, args ...any) { L().DebugContext(ctx, msg, args...) }
func InfoCtx(ctx context.Context, msg string, args ...any)  { L().InfoContext(ctx, msg, args...) }
func WarnCtx(ctx context.Context, msg string, args ...any)  { L().WarnContext(ctx, msg, args...) }
func ErrorCtx(ctx context.Context, msg string, args ...any) { L().ErrorContext(ctx, msg, args...) }

func RedirectToFile(path string) error {
	if globalSwitcher == nil {
		return nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	prevFile := globalFile
	globalFile = f
	globalSwitcher.Switch(f)

	if prevFile != nil {
		prevFile.Close()
	}

	return nil
}

func RedirectToStderr() {
	if globalSwitcher == nil {
		return
	}

	prevFile := globalFile
	globalFile = nil
	globalSwitcher.Switch(os.Stderr)

	if prevFile != nil {
		prevFile.Close()
	}
}

func CurrentOutput() string {
	if globalSwitcher == nil {
		return "stderr"
	}
	w := globalSwitcher.Current()
	switch w {
	case os.Stdout:
		return "stdout"
	case os.Stderr:
		return "stderr"
	default:
		if globalFile != nil {
			return globalFile.Name()
		}
		return "file"
	}
}

func ResetForTesting() {
	if globalFile != nil {
		globalFile.Close()
		globalFile = nil
	}
	globalHandler = nil
	globalLogger = nil
	globalSwitcher = nil
	handlerOpts = nil
	handlerFormat = ""
	once = sync.Once{}
}
