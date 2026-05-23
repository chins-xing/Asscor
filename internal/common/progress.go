package common

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type ProgressStyle int

const (
	StyleBar     ProgressStyle = iota
	StyleSpinner               = 1
	StyleQuiet                 = 2
)

type ProgressBar struct {
	mu          sync.Mutex
	total       int64
	current     int64
	style       ProgressStyle
	width       int
	desc        string
	out         io.Writer
	started     time.Time
	lastDraw    time.Duration
	done        bool
	firstRender bool

	spinnerFrames []string
	spinnerIdx    int

	enableCR bool
}

func NewProgressBar(total int64, desc string) *ProgressBar {
	return &ProgressBar{
		total:         total,
		current:       0,
		style:         StyleBar,
		width:         30,
		desc:          desc,
		out:           os.Stderr,
		started:       time.Now(),
		firstRender:   true,
		spinnerFrames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		enableCR:      isTerminal(os.Stderr),
	}
}

func NewSpinner(desc string) *ProgressBar {
	p := NewProgressBar(-1, desc)
	p.style = StyleSpinner
	return p
}

func NewQuietProgress(total int64, desc string) *ProgressBar {
	p := NewProgressBar(total, desc)
	p.style = StyleQuiet
	return p
}

func (p *ProgressBar) SetStyle(style ProgressStyle) *ProgressBar {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.style = style
	return p
}

func (p *ProgressBar) SetWidth(width int) *ProgressBar {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.width = width
	return p
}

func (p *ProgressBar) SetOutput(w io.Writer) *ProgressBar {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.out = w
	return p
}

func (p *ProgressBar) Add(n int64) *ProgressBar {
	p.mu.Lock()
	p.current += n
	if p.current > p.total && p.total > 0 {
		p.current = p.total
	}
	p.mu.Unlock()
	p.render()
	return p
}

func (p *ProgressBar) Increment() *ProgressBar {
	return p.Add(1)
}

func (p *ProgressBar) SetCurrent(n int64) *ProgressBar {
	p.mu.Lock()
	p.current = n
	if p.current > p.total && p.total > 0 {
		p.current = p.total
	}
	p.mu.Unlock()
	p.render()
	return p
}

func (p *ProgressBar) SetTotal(total int64) *ProgressBar {
	p.mu.Lock()
	p.total = total
	p.mu.Unlock()
	p.render()
	return p
}

func (p *ProgressBar) SetDesc(desc string) *ProgressBar {
	p.mu.Lock()
	p.desc = desc
	p.mu.Unlock()
	p.render()
	return p
}

func (p *ProgressBar) Finish() {
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		return
	}
	p.done = true
	p.current = p.total
	p.mu.Unlock()
	p.render()
}

func (p *ProgressBar) Elapsed() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return time.Since(p.started)
}

func (p *ProgressBar) render() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done {
		p.drawFinal()
		return
	}

	switch p.style {
	case StyleBar:
		p.drawBar()
	case StyleSpinner:
		p.drawSpinner()
	case StyleQuiet:
		p.drawQuiet()
	}
}

func (p *ProgressBar) drawBar() {
	if p.total <= 0 {
		p.drawSpinner()
		return
	}

	pct := float64(p.current) / float64(p.total)
	if pct > 1.0 {
		pct = 1.0
	}
	pctInt := int(pct * 100)

	filled := int(pct * float64(p.width))
	if filled > p.width {
		filled = p.width
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)

	elapsed := time.Since(p.started)
	var eta string
	if p.current > 0 && pct < 1.0 {
		remaining := time.Duration(float64(elapsed) / pct * (1.0 - pct))
		eta = fmt.Sprintf(" ETA: %s", formatDuration(remaining))
	}

	line := fmt.Sprintf("%s [%s] %d%% (%d/%d)%s",
		p.desc, bar, pctInt, p.current, p.total, eta)

	p.writeProgressLine(line)
}

func (p *ProgressBar) drawSpinner() {
	frame := p.spinnerFrames[p.spinnerIdx%len(p.spinnerFrames)]
	p.spinnerIdx++

	elapsed := time.Since(p.started)
	line := fmt.Sprintf("%s %s (%s, %d items)",
		frame, p.desc, formatDuration(elapsed), p.current)

	p.writeProgressLine(line)
}

func (p *ProgressBar) writeProgressLine(line string) {
	if !p.enableCR {
		return
	}

	if p.firstRender {
		fmt.Fprint(p.out, "\n")
		p.firstRender = false
	}

	truncated := line
	if len(truncated) > 120 {
		truncated = truncated[:120]
	}

	fmt.Fprintf(p.out, "\r\x1b[K%s", truncated)
}

func (p *ProgressBar) drawQuiet() {
	if p.total <= 0 {
		return
	}
	pct := float64(p.current) / float64(p.total)
	pctInt := int(pct * 100)
	if pctInt%10 == 0 && pctInt > 0 {
		threshold := pctInt
		lastThreshold := int(p.lastDraw.Minutes()) * 10
		if threshold != lastThreshold {
			p.lastDraw = time.Since(p.started)
			fmt.Fprintf(p.out, "%s: %d%% (%d/%d)\n", p.desc, pctInt, p.current, p.total)
		}
	}
}

func (p *ProgressBar) drawFinal() {
	if !p.enableCR {
		return
	}

	if p.firstRender {
		return
	}

	if p.total <= 0 {
		elapsed := time.Since(p.started)
		line := fmt.Sprintf("%s: done (%s, %d items)",
			p.desc, formatDuration(elapsed), p.current)
		fmt.Fprintf(p.out, "\r\x1b[K%s\n", line)
		return
	}

	bar := strings.Repeat("█", p.width)
	elapsed := time.Since(p.started)
	line := fmt.Sprintf("%s [%s] 100%% (%d/%d) in %s",
		p.desc, bar, p.current, p.total, formatDuration(elapsed))
	fmt.Fprintf(p.out, "\r\x1b[K%s\n", line)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

type ProgressTracker struct {
	mu      sync.Mutex
	bars    map[string]*ProgressBar
	ordered []string
}

func NewProgressTracker() *ProgressTracker {
	return &ProgressTracker{
		bars: make(map[string]*ProgressBar),
	}
}

func (t *ProgressTracker) AddBar(name string, total int64, desc string) *ProgressBar {
	t.mu.Lock()
	defer t.mu.Unlock()

	if bar, exists := t.bars[name]; exists {
		return bar
	}

	bar := NewProgressBar(total, desc)
	t.bars[name] = bar
	t.ordered = append(t.ordered, name)
	return bar
}

func (t *ProgressTracker) AddSpinner(name string, desc string) *ProgressBar {
	t.mu.Lock()
	defer t.mu.Unlock()

	if bar, exists := t.bars[name]; exists {
		return bar
	}

	bar := NewSpinner(desc)
	t.bars[name] = bar
	t.ordered = append(t.ordered, name)
	return bar
}

func (t *ProgressTracker) Get(name string) *ProgressBar {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bars[name]
}

func (t *ProgressTracker) Finish(name string) {
	t.mu.Lock()
	bar, exists := t.bars[name]
	t.mu.Unlock()

	if exists {
		bar.Finish()
	}
}

func (t *ProgressTracker) FinishAll() {
	t.mu.Lock()
	bars := make([]*ProgressBar, 0, len(t.bars))
	for _, name := range t.ordered {
		if bar, exists := t.bars[name]; exists {
			bars = append(bars, bar)
		}
	}
	t.mu.Unlock()

	for _, bar := range bars {
		bar.Finish()
	}
}

type MultiProgress struct {
	mu      sync.Mutex
	tracker *ProgressTracker
	out     io.Writer
	enabled bool
}

func NewMultiProgress() *MultiProgress {
	return &MultiProgress{
		tracker: NewProgressTracker(),
		out:     os.Stderr,
		enabled: isTerminal(os.Stderr),
	}
}

func (m *MultiProgress) AddBar(name string, total int64, desc string) *ProgressBar {
	bar := m.tracker.AddBar(name, total, desc)
	if !m.enabled {
		bar.SetStyle(StyleQuiet)
	}
	return bar
}

func (m *MultiProgress) AddSpinner(name string, desc string) *ProgressBar {
	bar := m.tracker.AddSpinner(name, desc)
	if !m.enabled {
		bar.SetStyle(StyleQuiet)
	}
	return bar
}

func (m *MultiProgress) Finish(name string) {
	m.tracker.Finish(name)
}

func (m *MultiProgress) FinishAll() {
	m.tracker.FinishAll()
}
