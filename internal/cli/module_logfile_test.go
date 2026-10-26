package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsInteractiveTerminalRejectsNonTTY 钉住事故的根因：
// systemd/journald/管道/普通文件都不是终端，CLI **不得**把日志重定向走 ——
// 否则管理员在单元配置的日志路径里看不到运行期日志（2026-10-26 真实发生）。
func TestIsInteractiveTerminalRejectsNonTTY(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if isInteractiveTerminal(r) {
		t.Error("管道被误判为终端")
	}

	f, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer f.Close()
	if isInteractiveTerminal(f) {
		t.Error("普通文件被误判为终端")
	}

	if isInteractiveTerminal(nil) {
		t.Error("nil 被误判为终端")
	}

	if p, ok := cliLogFile(r); ok || p != "" {
		t.Errorf("非终端时不应重定向日志，got (%q, %v)", p, ok)
	}
}

// TestCLILogPathIsAbsolute 钉住"相对路径"缺陷：无论环境变量给的是相对还是绝对，
// 最终路径都必须是绝对的（否则日志位置会随进程 cwd 漂移）。
func TestCLILogPathIsAbsolute(t *testing.T) {
	t.Setenv("ASSCOR_LOG_FILE", "relative-cli.log")
	defer os.Unsetenv("ASSCOR_LOG_FILE")
	p := cliLogPath()
	if !filepath.IsAbs(p) {
		t.Fatalf("日志路径不是绝对路径: %q", p)
	}
	if !strings.HasSuffix(p, "relative-cli.log") {
		t.Errorf("文件名未保留: %q", p)
	}
}

func TestCLILogPathHonorsLogDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSCOR_LOG_FILE", "")
	t.Setenv("ASSCOR_LOG_DIR", dir)
	defer func() {
		os.Unsetenv("ASSCOR_LOG_FILE")
		os.Unsetenv("ASSCOR_LOG_DIR")
	}()

	p := cliLogPath()
	if filepath.Dir(p) != dir {
		t.Errorf("日志目录未按 ASSCOR_LOG_DIR: got %q want dir %q", p, dir)
	}
	if filepath.Base(p) != "ASSCOR-kernel.log" {
		t.Errorf("日志文件名异常: %q", filepath.Base(p))
	}
}
