package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type HistoryEntry struct {
	Index     int           `json:"index"`
	Command   string        `json:"command"`
	ExitCode  ExitCode      `json:"exit_code"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

type History struct {
	mu      sync.RWMutex
	entries []HistoryEntry
	maxSize int
	counter int
}

func NewHistory(maxSize int) *History {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &History{
		entries: make([]HistoryEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

func (h *History) Add(command string, exitCode ExitCode, duration time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.counter++
	entry := HistoryEntry{
		Index:     h.counter,
		Command:   command,
		ExitCode:  exitCode,
		Duration:  duration,
		Timestamp: time.Now(),
	}

	h.entries = append(h.entries, entry)
	if len(h.entries) > h.maxSize {
		h.entries = h.entries[len(h.entries)-h.maxSize:]
	}
}

func (h *History) Recent(n int) []HistoryEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if n <= 0 || n > len(h.entries) {
		n = len(h.entries)
	}

	result := make([]HistoryEntry, n)
	copy(result, h.entries[len(h.entries)-n:])
	return result
}

func (h *History) Search(pattern string) []HistoryEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var matches []HistoryEntry
	for _, e := range h.entries {
		if strings.Contains(e.Command, pattern) {
			matches = append(matches, e)
		}
	}
	return matches
}

func (h *History) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = h.entries[:0]
	h.counter = 0
}

func (h *History) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries)
}

type ColorScheme struct {
	Reset   string
	Red     string
	Green   string
	Yellow  string
	Blue    string
	Magenta string
	Cyan    string
	Gray    string
	Bold    string
}

var Colors = ColorScheme{
	Reset:   "\033[0m",
	Red:     "\033[31m",
	Green:   "\033[32m",
	Yellow:  "\033[33m",
	Blue:    "\033[34m",
	Magenta: "\033[35m",
	Cyan:    "\033[36m",
	Gray:    "\033[90m",
	Bold:    "\033[1m",
}

var NoColors = ColorScheme{
	Reset:   "",
	Red:     "",
	Green:   "",
	Yellow:  "",
	Blue:    "",
	Magenta: "",
	Cyan:    "",
	Gray:    "",
	Bold:    "",
}

type Output struct {
	stdout io.Writer
	stderr io.Writer
	colors ColorScheme
	color  bool
}

func NewOutput(stdout, stderr io.Writer) *Output {
	colorEnabled := isTerminal(stdout)
	colors := NoColors
	if colorEnabled {
		colors = Colors
	}
	return &Output{
		stdout: stdout,
		stderr: stderr,
		colors: colors,
		color:  colorEnabled,
	}
}

func (o *Output) SetColor(enabled bool) {
	o.color = enabled
	if enabled {
		o.colors = Colors
	} else {
		o.colors = NoColors
	}
}

func (o *Output) Write(format string, args ...interface{}) {
	fmt.Fprintf(o.stdout, format, args...)
}

func (o *Output) WriteErr(format string, args ...interface{}) {
	fmt.Fprintf(o.stderr, format, args...)
}

func (o *Output) Info(msg string) {
	fmt.Fprintf(o.stdout, "%s%s%s\n", o.colors.Cyan, msg, o.colors.Reset)
}

func (o *Output) Success(msg string) {
	fmt.Fprintf(o.stdout, "%s✓ %s%s\n", o.colors.Green, msg, o.colors.Reset)
}

func (o *Output) Warn(msg string) {
	fmt.Fprintf(o.stderr, "%s⚠ %s%s\n", o.colors.Yellow, msg, o.colors.Reset)
}

func (o *Output) Error(msg string) {
	fmt.Fprintf(o.stderr, "%s✗ %s%s\n", o.colors.Red, msg, o.colors.Reset)
}

func (o *Output) Header(title string) {
	fmt.Fprintf(o.stdout, "\n%s%s%s\n", o.colors.Bold, title, o.colors.Reset)
	fmt.Fprintf(o.stdout, "%s─────────────────────────────────────────────────%s\n", o.colors.Gray, o.colors.Reset)
}

func (o *Output) KeyValue(key, value string) {
	fmt.Fprintf(o.stdout, "  %s%-20s%s %s\n", o.colors.Cyan, key, o.colors.Reset, value)
}

func (o *Output) Prompt() string {
	return fmt.Sprintf("%sasscor>%s ", o.colors.Bold+o.colors.Green, o.colors.Reset)
}

type Completer struct {
	engine *Engine
}

func NewCompleter(engine *Engine) *Completer {
	return &Completer{engine: engine}
}

func (c *Completer) Complete(line string) []string {
	return c.engine.Completions(line)
}

type Terminal struct {
	engine    *Engine
	completer *Completer
	reader    *bufio.Reader
	output    *Output
}

func NewTerminal(engine *Engine) *Terminal {
	return &Terminal{
		engine:    engine,
		completer: NewCompleter(engine),
		reader:    bufio.NewReader(os.Stdin),
		output:    engine.Output(),
	}
}

func (t *Terminal) Run() error {
	t.output.Info("ASSCOR \u00b5Kernel CLI — type 'help' for commands, 'exit' to quit")
	fmt.Fprintln(t.output.stdout)

	for {
		select {
		case <-t.engine.ctx.Done():
			return nil
		default:
		}

		fmt.Fprint(t.output.stdout, t.output.Prompt())

		line, err := t.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Fprintln(t.output.stdout)
				return nil
			}
			t.output.Error(fmt.Sprintf("read error: %v", err))
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" {
			t.output.Info("Goodbye.")
			return nil
		}

		result := t.engine.Execute(line)

		if result.Output != "" {
			fmt.Fprint(t.output.stdout, result.Output)
		}

		if result.Err != nil && !t.isQuietResult(result) {
			t.output.Error(result.Err.Error())
		}
	}
}

func (t *Terminal) isQuietResult(r *CommandResult) bool {
	return r.ExitCode == ExitOK || r.ExitCode == ExitUsage
}

func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		fi, err := f.Stat()
		if err != nil {
			return false
		}
		return (fi.Mode() & os.ModeCharDevice) != 0
	}
	return false
}
