//go:build collector_proc

package logcollector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	apiv1 "github.com/chins-xing/asscor/api/v1"
	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/logger"
)

type procClient struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	nextID int
}

func startProcClient(path string) (*procClient, error) {
	cmd := exec.Command(path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &procClient{cmd: cmd, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 1<<20)}, nil
}

func (c *procClient) call(method string, params any, out any, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd == nil {
		return fmt.Errorf("logcollector child not running")
	}
	c.nextID++
	id := c.nextID
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	line, err := json.Marshal(rpcRequest{ID: id, Method: method, Params: raw})
	if err != nil {
		return err
	}
	if _, err := c.stdin.Write(append(line, '\n')); err != nil {
		c.killLocked()
		return fmt.Errorf("write child: %w", err)
	}
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b, err := c.stdout.ReadBytes('\n')
		ch <- result{b, err}
	}()
	var got result
	select {
	case got = <-ch:
	case <-time.After(timeout):
		c.killLocked()
		return fmt.Errorf("logcollector child timeout on %s", method)
	}
	if got.err != nil {
		c.killLocked()
		return fmt.Errorf("read child: %w", got.err)
	}
	var resp rpcResponse
	if err := json.Unmarshal(got.b, &resp); err != nil {
		return fmt.Errorf("decode child response: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("child: %s", resp.Error)
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("decode child result: %w", err)
		}
	}
	return nil
}

func (c *procClient) killLocked() {
	if c.cmd != nil {
		_ = c.cmd.Process.Kill()
		_, _ = c.cmd.Process.Wait()
		c.cmd = nil
	}
}

func (c *procClient) Close() {
	_ = c.call("shutdown", nil, nil, time.Second)
	c.mu.Lock()
	if c.cmd != nil {
		_ = c.cmd.Wait()
		c.cmd = nil
	}
	c.mu.Unlock()
}

// Proxy is the kernel-side plugin that forwards log writes to the child.
type Proxy struct {
	mu      sync.Mutex
	state   kernel.PluginState
	kc      kernel.KernelContext
	path    string
	logPath string
	client  *procClient
	lastErr error
}

func NewProxy() *Proxy { return &Proxy{state: kernel.PluginUnregistered, path: childPath()} }

func childPath() string {
	if v := os.Getenv("ASSCOR_LOGCOLLECTOR_CHILD"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "logcollector-mod")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return "logcollector-mod"
}

func (p *Proxy) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "log_collector",
		Version:     "1.3.0-proc",
		Description: "Log collector (process-isolated): kernel proxy + logcollector-mod child",
		Author:      "ASSCOR Core Team",
	}
}

func (p *Proxy) Dependencies() []kernel.PluginDependency { return nil }
func (p *Proxy) Priority() int                           { return 70 }

func (p *Proxy) Init(ctx context.Context, kc kernel.KernelContext) error {
	p.mu.Lock()
	p.kc = kc
	p.state = kernel.PluginInitialized
	p.logPath = "ASSCOR-kernel.log"
	if cfg := kc.GetConfigObj(); cfg != nil && cfg.DataDir != "" {
		p.logPath = filepath.Join(cfg.DataDir, "ASSCOR-kernel.log")
	}
	p.mu.Unlock()
	kc.Container().Bind((*kernel.LogCollectorInterface)(nil), p)
	return nil
}

func (p *Proxy) Start(ctx context.Context) error {
	p.setState(kernel.PluginStarted)
	client, err := startProcClient(p.path)
	if err != nil {
		p.setErr(err)
		logger.WithComponent("log_collector").Warn("process mode: cannot start child; append will degrade", "error", err)
		return nil
	}
	p.mu.Lock()
	path := p.logPath
	p.mu.Unlock()
	if err := client.call("configure", configureParams{Path: path}, nil, 5*time.Second); err != nil {
		client.Close()
		p.setErr(err)
		logger.WithComponent("log_collector").Warn("process mode: child configure failed; append will degrade", "error", err)
		return nil
	}
	p.mu.Lock()
	p.client = client
	p.lastErr = nil
	p.mu.Unlock()
	logger.WithComponent("log_collector").Info("log collector process started", "child", p.path, "pid", client.cmd.Process.Pid, "path", path)
	return nil
}

func (p *Proxy) getClient() *procClient {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.client
}

func (p *Proxy) Append(entry *apiv1.LogEntry) error {
	client := p.getClient()
	if client == nil {
		return fmt.Errorf("log collector child unavailable")
	}
	if err := client.call("append", appendParams{Entry: entry}, nil, 2*time.Second); err != nil {
		p.setErr(err)
		return err
	}
	p.publish(entry)
	return nil
}

func (p *Proxy) AppendBatch(entries []*apiv1.LogEntry) error {
	client := p.getClient()
	if client == nil {
		return fmt.Errorf("log collector child unavailable")
	}
	if err := client.call("append_batch", appendBatchParams{Entries: entries}, nil, 5*time.Second); err != nil {
		p.setErr(err)
		return err
	}
	for _, e := range entries {
		p.publish(e)
	}
	return nil
}

func (p *Proxy) publish(entry *apiv1.LogEntry) {
	if entry == nil || p.kc == nil || p.kc.Extensions() == nil {
		return
	}
	p.kc.Extensions().Execute(p.kc.Context(), "log.entry_received", map[string]interface{}{
		"host_id": entry.HostId, "level": entry.Level, "timestamp": entry.Timestamp,
	})
}

func (p *Proxy) LogPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logPath
}

func (p *Proxy) Stop(ctx context.Context) error {
	p.setState(kernel.PluginStopping)
	p.mu.Lock()
	client := p.client
	p.client = nil
	p.mu.Unlock()
	if client != nil {
		client.Close()
	}
	p.setState(kernel.PluginStopped)
	return nil
}

func (p *Proxy) State() kernel.PluginState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (p *Proxy) HealthCheck(ctx context.Context) error {
	client := p.getClient()
	if client == nil {
		return fmt.Errorf("log collector child not running")
	}
	if err := client.call("ping", nil, nil, 2*time.Second); err != nil {
		return fmt.Errorf("log collector child unhealthy: %w", err)
	}
	return nil
}

func (p *Proxy) setState(s kernel.PluginState) {
	p.mu.Lock()
	p.state = s
	p.mu.Unlock()
}

func (p *Proxy) setErr(err error) {
	p.mu.Lock()
	p.lastErr = err
	p.mu.Unlock()
}
