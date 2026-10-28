package federation

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

	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/logger"
)

// procClient 是内核侧到联邦子进程的 JSON-Lines RPC 客户端。
// 串行化请求（子进程是单线程循环），带超时与故障清理。
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
		return fmt.Errorf("federation child not running")
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
	req := rpcRequest{ID: id, Method: method, Params: raw}
	line, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := c.stdin.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write child: %w", err)
	}
	type readResult struct {
		b   []byte
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		b, err := c.stdout.ReadBytes('\n')
		ch <- readResult{b, err}
	}()
	var got readResult
	select {
	case got = <-ch:
	case <-time.After(timeout):
		c.killLocked()
		return fmt.Errorf("federation child timeout on %s", method)
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

// Close 发送 shutdown 并回收子进程。
func (c *procClient) Close() {
	_ = c.call(methodShutdown, nil, nil, time.Second)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != nil {
		_ = c.cmd.Wait()
		c.cmd = nil
	}
}

// Proxy 是进程隔离模式的 kernel.Plugin：内核只启动/喂数据/查询子进程，
// 联邦的 master/node 逻辑与全部 HTTP 处理都在子进程里。
type Proxy struct {
	mu      sync.Mutex
	state   kernel.PluginState
	kc      kernel.KernelContext
	cfg     Config
	cfgErr  error
	cfgObj  interface{}
	client  *procClient
	path    string
	started time.Time
	lastErr error
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewProxy 构建进程隔离代理（进程模式由 -tags federation_proc 选择）。
func NewProxy() *Proxy {
	p := &Proxy{state: kernel.PluginUnregistered, cfg: Defaults(), path: childPath()}
	setCurrentAPI(p)
	return p
}

func childPath() string {
	if v := os.Getenv("ASSCOR_FEDERATION_CHILD"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "federation-mod")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return "federation-mod"
}

func (p *Proxy) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "federation",
		Version:     PluginVersion,
		Description: "T4 federation extension (process-isolated): kernel proxy + out-of-process master/node",
		Author:      "ASSCOR Core Team",
	}
}

func (p *Proxy) Dependencies() []kernel.PluginDependency {
	return []kernel.PluginDependency{{Name: "assessor"}}
}

func (p *Proxy) Priority() int { return 95 }

func (p *Proxy) Init(ctx context.Context, kc kernel.KernelContext) error {
	p.mu.Lock()
	p.kc = kc
	p.state = kernel.PluginInitialized
	p.mu.Unlock()

	var cfgObj interface{}
	if kc != nil {
		if c := kc.GetConfigObj(); c != nil {
			cfgObj = unwrapConfig(c)
		}
	}
	cfg, err := ParseConfig(configGetter(cfgObj))
	p.mu.Lock()
	p.cfgObj = cfgObj
	p.cfg = cfg
	p.cfgErr = err
	if err != nil {
		p.cfg.Role = RoleOff
	}
	p.mu.Unlock()
	if err != nil {
		logger.WithComponent("federation").Warn("process mode: bad [federation] config, staying off", "error", err)
	}
	return nil
}

func (p *Proxy) Start(ctx context.Context) error {
	p.mu.Lock()
	cfg := p.cfg
	p.mu.Unlock()
	if cfg.Role == RoleOff {
		p.setState(kernel.PluginStarted)
		return nil
	}
	client, err := startProcClient(p.path)
	if err != nil {
		p.setErr(err)
		logger.WithComponent("federation").Warn("process mode: failed to start child", "path", p.path, "error", err)
		p.setState(kernel.PluginStarted)
		return nil
	}
	configure := ConfigureParams{
		Role:              string(cfg.Role),
		NodeID:            cfg.NodeID,
		MasterURL:         cfg.MasterURL,
		ListenAddr:        cfg.ListenAddr,
		Token:             cfg.Token,
		ReportIntervalSec: cfg.ReportIntervalSec(),
	}
	if err := client.call(methodConfigure, configure, nil, 5*time.Second); err != nil {
		logger.WithComponent("federation").Warn("process mode: configure failed", "error", err)
		client.Close()
		p.setErr(err)
		p.setState(kernel.PluginStarted)
		return nil
	}

	p.mu.Lock()
	p.client = client
	p.started = time.Now()
	p.stopCh = make(chan struct{})
	p.state = kernel.PluginStarted
	p.mu.Unlock()

	p.wg.Add(1)
	go p.pushLoop(cfg)
	logger.WithComponent("federation").Info("federation process started", "child", p.path, "role", cfg.Role, "pid", client.cmd.Process.Pid)
	return nil
}

// pushLoop 周期把内核快照推给子进程（进程隔离下这是唯一的数据入口）。
func (p *Proxy) pushLoop(cfg Config) {
	defer p.wg.Done()
	interval := cfg.ReportInterval
	if interval <= 0 {
		interval = time.Duration(DefaultReportIntervalSec) * time.Second
	}
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	p.pushSnapshot()
	for {
		select {
		case <-p.stopCh:
			return
		case <-t.C:
			p.pushSnapshot()
		}
	}
}

func (p *Proxy) pushSnapshot() {
	p.mu.Lock()
	client := p.client
	kc := p.kc
	cfg := p.cfg
	p.mu.Unlock()
	if client == nil {
		return
	}
	report := BuildNodeReport(kc, cfg)
	hosts, policies, known := localFactsFromTopology()
	params := SnapshotParams{
		Report:       report,
		Hosts:        hosts,
		Policies:     policies,
		PolicyKnown:  known,
		CapturedUnix: time.Now().Unix(),
	}
	if err := client.call(methodSnapshot, params, nil, 5*time.Second); err != nil {
		p.setErr(err)
		logger.WithComponent("federation").Warn("process mode: snapshot push failed", "error", err)
	}
}

func (p *Proxy) Stop(ctx context.Context) error {
	p.setState(kernel.PluginStopping)
	p.mu.Lock()
	ch := p.stopCh
	client := p.client
	p.client = nil
	p.mu.Unlock()
	if ch != nil {
		close(ch)
	}
	p.wg.Wait()
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
	p.mu.Lock()
	client := p.client
	err := p.lastErr
	role := p.cfg.Role
	p.mu.Unlock()
	if role == RoleOff {
		return nil
	}
	if client == nil {
		if err != nil {
			return fmt.Errorf("federation child unavailable: %w", err)
		}
		return fmt.Errorf("federation child not running")
	}
	if err := client.call(methodPing, nil, nil, 2*time.Second); err != nil {
		return fmt.Errorf("federation child unhealthy: %w", err)
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

func (p *Proxy) FederationRole() Role {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.Role
}

func (p *Proxy) FederationStatus() Status {
	p.mu.Lock()
	client := p.client
	cfg := p.cfg
	cfgErr := p.cfgErr
	started := p.started
	lastErr := p.lastErr
	p.mu.Unlock()
	if cfgErr != nil {
		cfg.Role = RoleOff
	}
	st := Status{
		Role:              cfg.Role,
		NodeID:            cfg.NodeID,
		MasterURL:         cfg.MasterURL,
		ReportIntervalSec: cfg.ReportIntervalSec(),
		ConfigError:       errString(cfgErr),
		Running:           client != nil,
	}
	if !started.IsZero() {
		t := started
		st.StartedAt = &t
	}
	if cfg.Role == RoleMaster {
		st.ListenAddr = cfg.ListenAddr
	}
	if client == nil {
		_ = lastErr
		return st
	}
	var child Status
	if err := client.call(methodStatus, nil, &child, 3*time.Second); err != nil {
		st.ConfigError = err.Error()
		return st
	}
	return child
}

func (p *Proxy) MergedCheck(src, dst string) (any, error) {
	p.mu.Lock()
	client := p.client
	p.mu.Unlock()
	if client == nil {
		return nil, fmt.Errorf("federation 子进程未运行")
	}
	var res MergedCheck
	if err := client.call(methodCheck, CheckParams{Src: src, Dst: dst}, &res, 5*time.Second); err != nil {
		return nil, err
	}
	return &res, nil
}

func (p *Proxy) ExportMerged() (any, error) {
	p.mu.Lock()
	client := p.client
	p.mu.Unlock()
	if client == nil {
		return nil, fmt.Errorf("federation 子进程未运行")
	}
	var exp TopologyExport
	if err := client.call(methodExport, nil, &exp, 5*time.Second); err != nil {
		return nil, err
	}
	return exp, nil
}

func (p *Proxy) ReportNow(ctx context.Context) error {
	p.mu.Lock()
	client := p.client
	p.mu.Unlock()
	if client == nil {
		return fmt.Errorf("federation 子进程未运行")
	}
	p.pushSnapshot()
	return client.call(methodReportNow, nil, nil, 5*time.Second)
}
