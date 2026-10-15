//go:build expr && engine && checks

// 本文件是 Task 13 的用例：`-target` 的第四种**基质前缀** —— `qemu:<vmid|名字>`
// （dl360gen9 上的 **QEMU/KVM 虚拟机**，方向② 的生产基质）。
//
// ⚠️ **文件名刻意不带 `_vm` / `_<GOOS>` / `_<GOARCH>` 尾巴**：Go 把 `foo_linux.go`、
// `foo_amd64.go`、`foo_arm_test.go` 这类后缀当**隐式构建约束**，一个名字起错的测试文件
// 会在别的平台上被**静默忽略**（本仓踩过：`policy_arm_test.go` 整个文件在 amd64 上从没跑过）。
// 故这里叫 `node_target_qemu_test.go`。
//
// 判据分四层，与 `node_target_pve_test.go` **逐条对应**（那一轮定下的形态照搬，不另立一套）：
//
//  1. **`qemu:<vmid>` 真的走 `scp` + `ssh`**：四条命令的形状
//     （`scp <连接参数> -O <本地> <主机>:<路径>`、`ssh <连接参数> -- <主机> chmod 0755 <路径>`、
//     `ssh <连接参数> -- <主机> sudo -n env <ENV>=<nonce> <二进制> -emit-checks`、
//     `ssh <连接参数> -- <主机> sudo -n rm -f <路径>`）逐项正确；
//  2. **四种基质互不顶替**：跑 `qemu:` 时 docker / lxc / pct **一次都不能被调用**，反之亦然；
//  3. **nonce 绝不进参数位**（本项目最硬的一条）：客人侧二进制的 argv 必须**恰好是
//     `[-emit-checks]`**，nonce 只出现在 `env` 的位置参数那一格；
//  4. **取数必须是 root 等价**（Task 16）：客人侧那条命令必须以 `sudo -n` 起头 ——
//     `pct exec` 天生 root，而 VM 基质登录的是 `asc`，实测同一份二进制在同一台 VM 上
//     会因取数用户不同而让 **10/80** 条检查翻转（含决定基线活跃集 `B` 的 `OT-005`/`KS-012`）；
//  5. **SSH 目标只从具名环境变量来**：取值、默认值、"私钥路径不存在 ⇒ 响亮失败"、
//     以及"任何别的环境变量都不得把 `-o` 注入 argv"这条守卫。
//
// **为什么这里另写一个夹具（而不是复用 `writeCLIShim`）**：判据分两半，两半各有各的手段 ——
//
//  1. **"到底起了哪个 CLI、起了几次"**：用下面的 `writeCLICallShim`（只记调用、不记参数）。
//     它证明的是"这条路真的走到了 scp/ssh 上"，也是"四种基质互不顶替"的观测手段。
//  2. **"argv 逐格长什么样"**：直接在 `qemuSSHArgs` / `qemuSCPArgs` 上断言（那两个函数返回
//     `[]string`，与平台无关）。
//
// **为什么 argv 不走夹具**（本机实测，值得记一笔）：Windows 的 `cmd.exe` 在把参数交给
// `.bat` 之前就把 `=` 当成**分隔符**，于是 `BatchMode=yes` 到 `.bat` 里已经变成两格
// （`for %%a in (%*)` 与 `%~1` + `shift` 两种写法**都是**如此 —— 实测日志
// `ARG[-o] / ARG[BatchMode] / ARG[yes]`）。也就是说 `.bat` 夹具**无法**无损承载
// `KEY=VALUE` 这种 argv，而 `EDGESCEN_NODE_NONCE=<nonce>` 恰恰就是那种形状 ——
// 硬用它做断言，得到的是一条**假绿**（"nonce 不在参数位"可能只是因为被切成了两格）。
// POSIX 侧（dl360gen9 / CI）没有这个问题，而"哪一侧跑"不该改变判据的强度，
// 故断言统一放在与平台无关的那一层。
//
// （注：条目式注释刻意**不写成 gofmt 认得的列表**（`// · …` 会被 go1.26 的 gofmt 重排）——
// 与本包其它文件同一约定。）
package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ============================================================================
// 调用夹具：只记"哪个 CLI 被起了几次"（argv 断言在构造函数那一层做）
// ============================================================================

// writeCLICallShim 放一个假 CLI：被调用时把**一次调用**追加进日志（每行一次）。
//
// 日志里写的是 `$*` / `%*`（人读的形态），**不做** argv 断言 —— 见上面那段说明。
func writeCLICallShim(t *testing.T, cli, stdout string, exitCode int, stderrText string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, cli+".done")

	posix := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + quote(log) + " 2>/dev/null\n"
	if stdout != "" {
		posix += "printf '%s\\n' " + quote(stdout) + "\n"
	}
	if exitCode != 0 {
		posix += "printf '%s\\n' " + quote(stderrText) + " 1>&2\nexit " + strconv.Itoa(exitCode) + "\n"
	} else {
		posix += "exit 0\n"
	}
	if err := os.WriteFile(filepath.Join(dir, cli), []byte(posix), 0o755); err != nil {
		t.Fatalf("写假 %s: %v", cli, err)
	}

	bat := "@echo off\r\n" +
		"echo %*>> \"" + log + "\"\r\n"
	if stdout != "" {
		bat += "echo " + stdout + "\r\n"
	}
	if exitCode != 0 {
		bat += "echo " + stderrText + " 1>&2\r\nexit /b " + strconv.Itoa(exitCode) + "\r\n"
	} else {
		bat += "exit /b 0\r\n"
	}
	if err := os.WriteFile(filepath.Join(dir, cli+".bat"), []byte(bat), 0o755); err != nil {
		t.Fatalf("写假 %s.bat: %v", cli, err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// readCLICallLog 读回夹具记录的调用行（每行一次调用，用于**计数**与粗形状断言）。
func readCLICallLog(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读假 CLI 的调用日志 %s: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// writeSSHShim / writeSCPShim 是 qemu 基质的两把夹具（同时是"四种基质不能互相顶替"的
// 观测手段：被测代码走哪一条，哪一个假 CLI 的日志才会出现）。
func writeSSHShim(t *testing.T, stdout string, exitCode int, stderrText string) string {
	t.Helper()
	return writeCLICallShim(t, substrateBinSSH, stdout, exitCode, stderrText)
}

func writeSCPShim(t *testing.T, exitCode int, stderrText string) string {
	t.Helper()
	return writeCLICallShim(t, substrateBinSCP, "", exitCode, stderrText)
}

// ============================================================================
// 环境变量夹具
// ============================================================================

// qemuTestEnv 把 qemu 基质的四个环境变量钉成用例取值，并返回一颗**真的存在**的临时私钥文件路径。
//
// 为什么私钥要真的存在：实现里对 `EDGEEXP_VM_SSH_KEY` 做 `os.Stat`（路径不可读即响亮失败），
// 而那条判据本身也单独有用例（`TestQEMUKeyPathMustExist`）。成功路径要用一个真文件，
// 否则每条成功用例都会撞在"私钥不可读"上而变成假红。
func qemuTestEnv(t *testing.T, host, keyPath, user, port string) {
	t.Helper()
	t.Setenv(qemuSSHHostEnv, host)
	t.Setenv(qemuSSHKeyEnv, keyPath)
	t.Setenv(qemuSSHUserEnv, user)
	t.Setenv(qemuSSHPortEnv, port)
}

// qemuTestKey 造一个可读的临时文件当私钥（内容无关紧要：ssh 是假的）。
func qemuTestKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(p, []byte("not-a-real-key\n"), 0o600); err != nil {
		t.Fatalf("写临时私钥文件: %v", err)
	}
	return p
}

// sshConnPrefix 是"连接参数"那一段的期望前缀（四种最小充分项，顺序固定）。
//
// 断言写成"整段逐格相等"而不是"包含这几项"：连接参数一旦被追加/改序，包含式断言照样绿，
// 而 ssh 的行为可能已经变了（例如 `-o` 被顶到 `--` 之后 ⇒ 那一格变成**远程命令**）。
//
// ⚠️ 用户那一格是 `-o User=<用户>` 而**不是** `-l <用户>`（Task 15 真机实测改）：
// 这一段是 `ssh` 与 `scp` **共用**的，而 `scp -l <值>` 是**带宽上限**（要数字）⇒
// `scp … -l asc …` 会直接报 `usage: scp [-346ABCOpqRrsTv] …`，qemu 基质因此**从来没有**
// 跑通过端到端。这个用例正是那条不变量的守卫：把 `-l` 改回来必须让它红。
func sshConnPrefix(user string) []string {
	return []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		"-o", "User=" + user,
	}
}

// ============================================================================
// 语法解析：qemu 的写法 + 报错
// ============================================================================

// TestParseNodeTargetQEMUSyntax：`qemu:<vmid|名字>` 的合法写法与三种报错形态。
func TestParseNodeTargetQEMUSyntax(t *testing.T) {
	cases := []struct {
		raw   string
		want  nodeTarget
		why   string
		bad   bool
		inErr string
	}{
		{raw: "qemu:910", want: nodeTarget{substrateQEMU, "910"},
			why: "qemu 前缀 + vmid（Task 13 的生产基质，VMID 从 910 起、避开 CT 904）"},
		{raw: "qemu:asc-vm910", want: nodeTarget{substrateQEMU, "asc-vm910"},
			why: "qemu **也收名字**（与 pve 刻意不同）：vm 的标识同时存在于 qm list 的 VMID 列与 Name 列"},
		{raw: "qemu: 910", want: nodeTarget{substrateQEMU, "910"},
			why: "前缀后的空白同样被吃掉"},
		{raw: "  qemu:910  ", want: nodeTarget{substrateQEMU, "910"},
			why: "两侧空白被吃掉"},
		{raw: "qemu:", bad: true, inErr: "缺少 vmid 或名字",
			why: "前缀给了标识为空 ⇒ 报错（不得回落本机，也不得回落 docker）"},
		{raw: "qemu:   ", bad: true, inErr: "缺少 vmid 或名字", why: "同上（全是空白）"},
		{raw: "qemuu:910", bad: true, inErr: "未知",
			why: "像基质前缀却不在白名单 ⇒ 专门诊断（不是让它变成一次 No such container）"},
		{raw: "QEMU:910", bad: true, inErr: "未知",
			why: "前缀大小写敏感：`QEMU` 不在白名单 ⇒ 报错而不是猜"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := parseNodeTarget(tc.raw)
			if tc.bad {
				if err == nil {
					t.Fatalf("必须报错（%s），实际得到 %+v", tc.why, got)
				}
				if !strings.Contains(err.Error(), tc.inErr) {
					t.Errorf("错误信息必须指向真正的原因（期望含 %q）: %v", tc.inErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("应当解析成功（%s）: %v", tc.why, err)
			}
			if got != tc.want {
				t.Errorf("解析 = %+v, want %+v（%s）", got, tc.want, tc.why)
			}
		})
	}
}

// TestQEMUErrorNamesTheEnvVars：`qemu:` 缺标识时的错误必须把**两个环境变量名**写出来。
//
// 为什么单列一条：VM 基质的节点标识与"连哪台机器"是**两件事**（前者写在 `-target` 里，
// 后者只从环境变量来）。错误串里不提环境变量名时，操作者最可能的动作是去猜一个主机名写法
// （例如 `qemu:192.168.1.5`），而那条路径会以"ssh 连不上"收场 ——
// 错误指向网络，真正的原因是少了一个环境变量。
func TestQEMUErrorNamesTheEnvVars(t *testing.T) {
	_, err := parseNodeTarget("qemu:")
	if err == nil {
		t.Fatal("`qemu:` 必须报错")
	}
	for _, want := range []string{qemuSSHHostEnv, qemuSSHKeyEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误串里必须写明环境变量 %s（否则操作者会去猜主机名写法）；实际：%v", want, err)
		}
	}
}

// TestTargetFlagHelpNamesAllFiveForms：`-h` 文案必须写明**五种**写法（四种前缀 + 裸名字/本机）。
func TestTargetFlagHelpNamesAllFiveForms(t *testing.T) {
	usage := nodeTargetFlagHelpText(t)
	for _, want := range []string{"docker:", "lxd:", "pve:", "qemu:", "本机"} {
		if !strings.Contains(usage, want) {
			t.Errorf("-%s 的文案里必须写明 %q；实际：%s", nodeTargetFlag, want, usage)
		}
	}
}

// ============================================================================
// qemu 路径：命令形状、观测主体、不顶替
// ============================================================================

// TestQEMUNodeTargetUsesSSHAndSCPAndRecordsSubstrate：`qemu:<vmid>` 必须**真的**用 scp + ssh 取数。
//
// 逐条判据：
//  1. 只起三个子进程（`scp` + `ssh chmod` + `ssh env … -emit-checks`），argv 逐格正确；
//  2. **docker / lxc / pct 三个假 CLI 一次都不能被调用**；
//  3. 观测主体把基质写进记录（`substrate=qemu`）—— CT 与 VM 的数据**禁止混算**，
//     而"这条记录采自哪种基质"就是那条纪律的机器可读凭据。
func TestQEMUNodeTargetUsesSSHAndSCPAndRecordsSubstrate(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	key := qemuTestKey(t)
	qemuTestEnv(t, "asc-vm910", key, "asc", "22")

	nodeChecks := hostChecksWithFailures("RS-006")
	sshLog := writeSSHShim(t, mustEnvelope(t, "asc-vm910", nodeChecks), 0, "")
	scpLog := writeSCPShim(t, 0, "")
	dockerLog := writeDockerShim(t, fakeDocker{stdout: "docker-shim-must-not-be-used"})
	lxcLog := writeLXCShim(t, fakeDocker{stdout: "lxc-shim-must-not-be-used"})
	pctLog := writePCTShim(t, fakeDocker{stdout: "pct-shim-must-not-be-used"})

	host, observationTarget, err := collectChecksForTarget("qemu:910")
	if err != nil {
		t.Fatalf("qemu 基质取数: %v", err)
	}
	for name, log := range map[string]string{
		"docker": dockerLog, "lxc": lxcLog, "pct": pctLog,
	} {
		if !shimLogAbsent(t, log) {
			t.Errorf("qemu 基质**不得**起任何 %s 子进程（基质选错的形态），实际留下了调用日志 %s", name, log)
		}
	}

	// 第一条：`scp <连接参数> -O <本地> asc-vm910:/tmp/asscor-edgescen`
	scpCalls := readCLICallLog(t, scpLog)
	if len(scpCalls) != 1 {
		t.Fatalf("qemu 取数应当只起一个 scp 子进程（送二进制），实际 %d 条: %v", len(scpCalls), scpCalls)
	}
	if !strings.Contains(scpCalls[0], "-O") {
		t.Errorf("scp 必须带 `-O`（强制 legacy SCP 协议，免得依赖客人侧的 sftp-server 子系统），实际 %q", scpCalls[0])
	}
	if !strings.Contains(scpCalls[0], qemuGuestBinaryPath) {
		t.Errorf("scp 的目标路径必须是**固定**的 %q（Task 16：带 pid 的路径会让每次采集在客人 /tmp "+
			"里留下一个 8.5 MB 的孤儿），实际 %q", qemuGuestBinaryPath, scpCalls[0])
	}

	// 第二、三、四条：三条 ssh（chmod + emit-checks + 清理）
	sshCalls := readCLICallLog(t, sshLog)
	if len(sshCalls) != 3 {
		t.Fatalf("qemu 取数应当起三个 ssh 子进程（chmod + emit-checks + 清理客人侧二进制），实际 %d 条: %v",
			len(sshCalls), sshCalls)
	}
	// 清理那一条必须真的删**那个**路径（Task 16 / concern 7：25 场景 ≈ 210 MB 常驻客人 /tmp）。
	if !strings.Contains(sshCalls[len(sshCalls)-1], "rm -f "+qemuGuestBinaryPath) {
		t.Errorf("最后一条 ssh 必须是 `rm -f %s`（取完就回收，不让客人 /tmp 累积），实际 %q",
			qemuGuestBinaryPath, sshCalls[len(sshCalls)-1])
	}

	// argv 的**逐格**判据打在构造函数上（见文件头"为什么 argv 不走夹具"）：
	// 夹具只回答"起了哪个 CLI、几次"，这里回答"那几条命令长什么样"。
	wantConn := append(sshConnPrefix("asc"), "-p", "22", "-o", "IdentitiesOnly=yes", "-i", key)

	scpArgs, err := qemuSCPArgs("910", "/local/edgescen", "/tmp/edgescen-4242")
	if err != nil {
		t.Fatalf("构造 scp argv: %v", err)
	}
	if got := strings.Join(scpArgs[:len(wantConn)], "\x00"); got != strings.Join(wantConn, "\x00") {
		t.Errorf("scp 的连接参数必须与 ssh **逐格相同**\n got %q\nwant %q", scpArgs, wantConn)
	}
	if rest := scpArgs[len(wantConn):]; len(rest) != 3 || rest[0] != "-O" {
		t.Fatalf("scp 的尾部必须是 `-O <本地> <主机>:<路径>`，实际 %q", rest)
	} else if rest[2] != "asc-vm910:/tmp/edgescen-4242" {
		t.Errorf("scp 的目标必须是 `<SSH 主机>:<目标路径>`（主机与路径拼在**同一格**），实际 %q", rest[2])
	}

	chmodArgs, err := qemuSSHArgs("910", "chmod", "0755", "/tmp/edgescen-4242")
	if err != nil {
		t.Fatalf("构造 chmod argv: %v", err)
	}
	wantExec := append(append([]string{}, "sudo", "-n"), "env", nodeNonceEnv+"="+fixtureNonce,
		qemuGuestBinaryPath, emitChecksFlag)
	execArgs, err := qemuSSHArgs("910", wantExec...)
	if err != nil {
		t.Fatalf("构造 emit-checks argv: %v", err)
	}
	for i, call := range [][]string{chmodArgs, execArgs} {
		if got := strings.Join(call[:len(wantConn)], "\x00"); got != strings.Join(wantConn, "\x00") {
			t.Errorf("第 %d 条 ssh 的连接参数不对\n got %q\nwant %q", i+1, call, wantConn)
		}
		if call[len(wantConn)] != "--" || call[len(wantConn)+1] != "asc-vm910" {
			t.Errorf("第 %d 条 ssh 必须是 `… -- <主机> <远程命令…>`（`--` 必须在主机名之前："+
				"`ssh <主机> -emit-checks` 会把那格当成 ssh 自己的选项），实际 %q", i+1, call)
		}
	}
	// 第二条：远程命令 = `chmod 0755 <路径>`
	if chmodCmd := chmodArgs[len(wantConn)+2:]; len(chmodCmd) != 3 || chmodCmd[0] != "chmod" || chmodCmd[1] != "0755" {
		t.Errorf("第一次 ssh 必须显式 `chmod 0755 <路径>`（scp 只保留权限位、**不**保证可执行），实际 %q", chmodCmd)
	}
	// 第三条：远程命令 = `sudo -n env <ENV>=<nonce> <二进制> -emit-checks`
	execCmd := execArgs[len(wantConn)+2:]
	if len(execCmd) != 6 {
		t.Fatalf("客人侧的远程命令必须**恰好六格**（sudo -n env K=V <二进制> -emit-checks），实际 %d 格: %q",
			len(execCmd), execCmd)
	}
	// 第 0~1 格：**root 等价**（Task 16 的测量语义对齐；少了它 B 与 −30 都会被权限带偏）。
	if execCmd[0] != "sudo" || execCmd[1] != "-n" {
		t.Errorf("客人侧的命令必须以 `sudo -n` 起头（与 CT 基质的 `pct exec` 天生 root 等价）；"+
			"非 root 取数会让 6 条检查被跳过却**算通过**、4 条**假失败**，实际前两格是 %q",
			execCmd[:2])
	}
	if execCmd[2] != "env" {
		t.Errorf("客人侧 nonce 那一格必须由 `env` 承载（ssh 没有 `-e`，nonce 只能靠它下发），实际 %q", execCmd[2])
	}
	if execCmd[3] != nodeNonceEnv+"="+fixtureNonce {
		t.Errorf("第 4 格必须是 `%s=%s`（nonce 经**环境变量**下发），实际 %q",
			nodeNonceEnv, fixtureNonce, execCmd[3])
	}
	if execCmd[4] != qemuGuestBinaryPath {
		t.Errorf("第 5 格必须是客人侧二进制的**固定路径** %q，实际 %q", qemuGuestBinaryPath, execCmd[4])
	}
	if execCmd[5] != emitChecksFlag {
		t.Errorf("客人侧二进制的 argv 必须**恰好是** [%s]，实际 %q", emitChecksFlag, execCmd[5])
	}

	if len(host) != len(nodeChecks) {
		t.Fatalf("取回的检查集长度 = %d, want %d", len(host), len(nodeChecks))
	}
	for i := range nodeChecks {
		if host[i] != nodeChecks[i] {
			t.Fatalf("取回的检查集与节点载荷不同（第 %d 项）：\n got %+v\nwant %+v", i, host[i], nodeChecks[i])
		}
	}
	wantTarget := "node:910 (substrate=qemu, hostname=asc-vm910)"
	if observationTarget != wantTarget {
		t.Errorf("观测主体 = %q, want %q（节点标识 + 基质 + 客人内进程自报的 hostname）", observationTarget, wantTarget)
	}
}

// TestQEMUNonceNeverEntersNodeArgv 是"nonce 绑定不得削弱"在 qemu 侧的**那把尺子**。
//
// 为什么单列一条：`ssh` 没有 `docker exec -e` 那种"只改环境"的写法，它把整串当远程命令
// 交给客人侧的 shell。这条路有三种写法，只有第一种是对的：
//
//	对： `ssh <选项> -- <主机> env K=V <二进制> -emit-checks`  ⇒ 客人侧二进制 argv 恰好 [-emit-checks]
//	错： `ssh <选项> -- <主机> <二进制> -emit-checks <nonce>`  ⇒ nonce 进了**参数位**
//	错： `ssh <选项> -- <主机> K=V <二进制> -emit-checks`      ⇒ 少一层 `env`，K=V 被当成命令名
//
// 判据打在**客人侧那一侧**：把 `-- <主机>` 之后的 argv 逐格拆开，断言
// `[env, K=V, <二进制>, -emit-checks]` 恰好四格、且**二进制自己那一格之后只有 `-emit-checks`**。
// 若将来有人图省事改成第二种，这条用例立刻红。
func TestQEMUNonceNeverEntersNodeArgv(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	key := qemuTestKey(t)
	qemuTestEnv(t, "asc-vm910", key, "asc", "22")

	sshLog := writeSSHShim(t, mustEnvelope(t, "asc-vm910", hostChecksWithFailures("RS-006")), 0, "")
	writeSCPShim(t, 0, "")

	if _, _, err := collectChecksForTarget("qemu:910"); err != nil {
		t.Fatalf("qemu 基质取数: %v", err)
	}
	// 先证明"真的起了三条 ssh"（夹具那一层），再把 argv 逐格拆开（构造函数那一层）。
	if calls := readCLICallLog(t, sshLog); len(calls) != 3 {
		t.Fatalf("应当有三条 ssh 调用（chmod + emit-checks + 清理），实际 %d 条: %v", len(calls), calls)
	}
	wantConn := append(sshConnPrefix("asc"), "-p", "22", "-o", "IdentitiesOnly=yes", "-i", key)

	execArgs, err := qemuSSHArgs("910", append(append([]string{}, "sudo", "-n"), "env",
		nodeNonceEnv+"="+fixtureNonce, qemuGuestBinaryPath, emitChecksFlag)...)
	if err != nil {
		t.Fatalf("构造 emit-checks argv: %v", err)
	}
	remote := execArgs[len(wantConn)+2:] // 去掉连接参数与 `-- <主机>`
	if len(remote) != 6 {
		t.Fatalf("客人侧的远程命令必须**恰好六格**，实际 %d 格: %q", len(remote), remote)
	}
	if remote[3] != nodeNonceEnv+"="+fixtureNonce {
		t.Errorf("nonce 必须落在 `env` 的位置参数那一格（%s=%s），实际 %q",
			nodeNonceEnv, fixtureNonce, remote[3])
	}
	// 客人侧二进制自己那一格之后**只有** -emit-checks：nonce 一格都不许出现。
	for _, a := range remote[5:] {
		if strings.Contains(a, fixtureNonce) {
			t.Errorf("nonce **绝不**能进客人侧二进制的参数位，实际参数位有 %q（整条 %q）", a, remote)
		}
	}
	// chmod 那条**完全不含** nonce（连环境赋值那一格都没有）—— 顺带证明 nonce 不是"到处都撒"。
	chmodArgs, err := qemuSSHArgs("910", "chmod", "0755", "/tmp/edgescen-4242")
	if err != nil {
		t.Fatalf("构造 chmod argv: %v", err)
	}
	for _, a := range chmodArgs {
		if strings.Contains(a, fixtureNonce) {
			t.Errorf("chmod 那条 ssh 里不该出现 nonce，实际 %q", chmodArgs)
		}
	}
	// 反向：确认 `-emit-checks` 那条守卫**没有**被开出一个"合法参数"。
	if code := runCLI([]string{"-" + emitChecksFlag, fixtureNonce}, &strings.Builder{}, &strings.Builder{}); code != exitUsage {
		t.Errorf("`-%s <值>` 必须仍然被拒（exit %d），实际 rc=%d —— "+
			"nonce 只能经环境变量下发", emitChecksFlag, exitUsage, code)
	}
}

// ============================================================================
// SSH 目标解析：环境变量、默认值、响亮失败
// ============================================================================

// TestQEMUSSHHostResolution：`EDGEEXP_VM_SSH_HOST` 的四种取值语义。
//
// 四条判据（每一条都对应一种"连到别的机器上、而记录照常"的形态）：
//  1. 没给 ⇒ 默认 `asc-vm<vmid>`（与 provisioning 写进宿主 `/etc/hosts` 的主机名一致，
//     故**不需要 DNS** —— 管理 VLAN 30 上没有 DNS，实测 CT 内 DNS FAIL）；
//  2. 给了含 `%s` 的模板 ⇒ `%s` 换成节点标识（**多机就是靠这条**：`--count N` 起 N 台，
//     每台的取数地址可被逐台指定）；
//  3. 给了不含 `%s` 的常量 ⇒ 所有节点都指向那一台（单机场景；**不做**任何"自动加后缀"的猜测）；
//  4. 非数字标识（`qemu:asc-vm910`）不走默认规则，**原样**当主机名 —— 它本身就是一个主机名。
func TestQEMUSSHHostResolution(t *testing.T) {
	key := qemuTestKey(t)
	cases := []struct {
		name     string
		node     string
		hostEnv  string
		wantHost string
		why      string
	}{
		{name: "默认规则", node: "910", hostEnv: "", wantHost: "asc-vm910",
			why: "没给环境变量时 vmid → asc-vm<vmid>（与 /etc/hosts 那一行同源，不需要 DNS）"},
		{name: "默认规则-另一个-vmid", node: "911", hostEnv: "", wantHost: "asc-vm911",
			why: "多机时每台的默认主机名各不同"},
		{name: "模板含占位符", node: "911", hostEnv: "asc-vm%s.lab", wantHost: "asc-vm911.lab",
			why: "`%s` 被换成节点标识"},
		{name: "常量", node: "910", hostEnv: "192.0.2.7", wantHost: "192.0.2.7",
			why: "不含 `%s` ⇒ 所有节点都指这一台（单机场景）"},
		{name: "非数字标识原样用", node: "asc-vm910", hostEnv: "", wantHost: "asc-vm910",
			why: "`qemu:asc-vm910` 的标识本身就是一个主机名（不猜它对应哪个 vmid）"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qemuTestEnv(t, tc.hostEnv, key, "asc", "22")
			args, err := qemuSSHArgs(tc.node, emitChecksFlag)
			if err != nil {
				t.Fatalf("解析 SSH 目标（%s）: %v", tc.why, err)
			}
			if args[len(args)-2] != tc.wantHost {
				t.Errorf("SSH 目标 = %q, want %q（%s）；整条 %v",
					args[len(args)-2], tc.wantHost, tc.why, args)
			}
			if args[len(args)-1] != emitChecksFlag {
				t.Errorf("远程命令必须在主机名之后，实际 %v", args)
			}
		})
	}
}

// TestQEMUKeyPathMustExist：私钥路径不可读 ⇒ **响亮失败**，不许悄悄退回 ssh 自己的默认钥匙。
//
// 为什么这条比看起来重要：`EDGEEXP_VM_SSH_KEY` 指向一个不存在的路径时，若实现选择
// "不传 `-i`"，ssh 会去试 agent 与 `~/.ssh/id_*` —— **大概率也能连上**（同一个操作者的
// 同一把钥匙），于是整条链路看起来完全正常；而"这条记录是哪把钥匙进去采的"就没人知道了。
// 判据是**失败**，不是"能连上"。
func TestQEMUKeyPathMustExist(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-there")
	qemuTestEnv(t, "asc-vm910", missing, "asc", "22")
	_, err := qemuSSHArgs("910", emitChecksFlag)
	if err == nil {
		t.Fatal("私钥路径不可读时**必须**报错（不许退回 ssh 自己的默认钥匙）")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("错误串里必须写出那个不可读的路径，实际：%v", err)
	}
}

// TestQEMUPortMustBeNumeric：端口不是合法数字 ⇒ 响亮失败并说明取值范围。
func TestQEMUPortMustBeNumeric(t *testing.T) {
	key := qemuTestKey(t)
	for _, bad := range []string{"abc", "0", "65536", "-1", "22x"} {
		t.Run(bad, func(t *testing.T) {
			qemuTestEnv(t, "asc-vm910", key, "asc", bad)
			if _, err := qemuSSHArgs("910", emitChecksFlag); err == nil {
				t.Fatalf("端口 %q 必须报错（`ssh -p abc` 自己那条错误看起来像『端口不对』，"+
					"而真正的原因是环境变量写错）", bad)
			}
		})
	}
}

// TestQEMUUserMustNotContainWhitespace：登录用户含空白 ⇒ 响亮失败（不许拼出一个"另一个账号"）。
func TestQEMUUserMustNotContainWhitespace(t *testing.T) {
	key := qemuTestKey(t)
	qemuTestEnv(t, "asc-vm910", key, "asc root", "22")
	if _, err := qemuSSHArgs("910", emitChecksFlag); err == nil {
		t.Fatal("含空白的登录用户必须报错：拼进 `-l` 之后连的是**另一个账号**，而记录看不出来")
	}
}

// TestQEMUNoEnvironmentVariableCanInjectSSHOptions：**不接受**从环境变量来的 SSH 选项串。
//
// 这条守卫针对的形态：若实现支持 `EDGEEXP_VM_SSH_OPTS="-o ProxyCommand=…"` 这类变量，
// 那么取数目标就能在操作者看不见的地方被改到别处（记录里的 `observation_target` 照常印着
// 节点名）。故判据是"无论环境里出现什么怪东西，ssh 的 argv 形状只由那四个**具名**变量决定"。
func TestQEMUNoEnvironmentVariableCanInjectSSHOptions(t *testing.T) {
	key := qemuTestKey(t)
	qemuTestEnv(t, "asc-vm910", key, "asc", "22")
	// 这类变量**不存在于实现的白名单**里，设了也不该有任何效果。
	t.Setenv("EDGEEXP_VM_SSH_OPTS", "-o ProxyCommand=/bin/false")
	t.Setenv("EDGEEXP_VM_SSH_ARGS", "-o ProxyCommand=/bin/false")
	t.Setenv("EDGEEXP_QEMU_SSH_OPTS", "-o ProxyCommand=/bin/false")

	args, err := qemuSSHArgs("910", emitChecksFlag)
	if err != nil {
		t.Fatalf("解析 SSH 目标: %v", err)
	}
	for _, a := range args {
		if strings.Contains(a, "ProxyCommand") {
			t.Errorf("任何环境变量都**不得**能把 SSH 选项注入 argv（实际出现 %q，整条 %v）", a, args)
		}
	}
	if got := args[len(args)-2]; got != "asc-vm910" {
		t.Errorf("目标仍须由 %s 与默认规则决定，实际 %q", qemuSSHHostEnv, got)
	}
}

// TestQEMUDefaultsAreAppliedWhenEnvIsEmpty：四个变量都空 ⇒ 默认值全部生效。
//
// 两条"**不得**出现"的判据与两条"必须出现"的同样重要：
//
//	· 端口没给 ⇒ **不得**出现 `-p`（ssh 自己的默认值就是 22，显式写一遍只多一个漂移点）；
//	· 私钥没给 ⇒ **不得**出现 `-i`（此时由操作者的 ssh 配置决定，而不是由本工具猜一个路径）。
func TestQEMUDefaultsAreAppliedWhenEnvIsEmpty(t *testing.T) {
	qemuTestEnv(t, "", "", "", "")
	args, err := qemuSSHArgs("910", emitChecksFlag)
	if err != nil {
		t.Fatalf("全空环境变量下必须能解析（默认值生效）: %v", err)
	}
	joined := strings.Join(args, " ")
	// 用户那一格是 `-o User=<用户>`（Task 15 起；见 sshConnPrefix 的说明 —— `-l <用户>`
	// 在 scp 上是带宽上限，是 qemu 基质端到端此前跑不通的直接原因）。
	if !strings.Contains(joined, " -o User="+qemuSSHUserDefault+" ") {
		t.Errorf("用户默认值必须是 %q（以 `-o User=` 下发），实际 %v", qemuSSHUserDefault, args)
	}
	// 反向判据：连接参数里**不得**再出现 `-l`（它只对 ssh 有效、对 scp 是另一种含义）。
	if strings.Contains(joined, " -l ") {
		t.Errorf("连接参数里**不得**出现 `-l`（scp 会把它当带宽上限并直接报 usage），实际 %v", args)
	}
	if strings.Contains(joined, " -p ") {
		t.Errorf("端口没给时**不得**出现 `-p`，实际 %v", args)
	}
	if strings.Contains(joined, " -i ") {
		t.Errorf("私钥没给时**不得**出现 `-i`，实际 %v", args)
	}
	if got := args[len(args)-2]; got != "asc-vm910" {
		t.Errorf("默认主机名规则必须生效，实际 %q", got)
	}
}

// ============================================================================
// 失败形态：与 pve 侧逐条对应
// ============================================================================

// TestQEMUNodeCollectionFailuresAreLoud 是 `TestPVENodeCollectionFailuresAreLoud` 的 qemu 版本。
//
// 两条失败形态都必须**响亮报错**且**不得回落**到别的基质：
//
//	· scp 失败（客人不可达 / 私钥不对 / DNS 解析不到）；
//	· ssh chmod 失败（连接被拒 / 认证失败）。
func TestQEMUNodeCollectionFailuresAreLoud(t *testing.T) {
	cases := []struct {
		name  string
		scp   int
		ssh   int
		sshEr string
		inErr string
	}{
		{name: "scp失败", scp: 255, ssh: 0,
			inErr: "scp"},
		{name: "chmod失败", scp: 0, ssh: 255, sshEr: "ssh: connect to host asc-vm910 port 22: Connection refused",
			inErr: "ssh 失败"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registerFixtureChecks()
			useFixtureNonce(t)
			key := qemuTestKey(t)
			qemuTestEnv(t, "asc-vm910", key, "asc", "22")
			writeSCPShim(t, tc.scp, "ssh: Could not resolve hostname asc-vm910: Name or service not known")
			writeSSHShim(t, "", tc.ssh, tc.sshEr)
			dockerLog := writeDockerShim(t, fakeDocker{stdout: "docker-shim-must-not-be-used"})

			if _, _, err := collectChecksForTarget("qemu:910"); err == nil {
				t.Fatal("必须报错")
			} else if !strings.Contains(err.Error(), tc.inErr) {
				t.Errorf("错误串必须指向真正的原因（期望含 %q）: %v", tc.inErr, err)
			}
			if !shimLogAbsent(t, dockerLog) {
				t.Errorf("qemu 路径失败时也不得回落到 docker 基质，实际留下了 docker 调用日志 %s", dockerLog)
			}
		})
	}
}

// TestQEMUErrorTextNamesHostAndRemoteCommand：ssh 失败的错误串必须报出**主机**与**远程命令**。
//
// 为什么单列一条：ssh 的失败原因几乎都在 stderr（`Could not resolve hostname` /
// `Permission denied (publickey)` / `Connection refused`），而"连的是哪台机器、跑的是哪条
// 远程命令"决定了下一步该查什么。只把 stderr 带出来是不够的。
func TestQEMUErrorTextNamesHostAndRemoteCommand(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	key := qemuTestKey(t)
	qemuTestEnv(t, "asc-vm910", key, "asc", "22")
	writeSCPShim(t, 0, "")
	// 两条 ssh 都失败：chmod 那条先失败。
	writeSSHShim(t, "", 255, "Permission denied (publickey).")

	_, _, err := collectChecksForTarget("qemu:910")
	if err == nil {
		t.Fatal("必须报错")
	}
	for _, want := range []string{"asc-vm910", "chmod", "Permission denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误串里必须有 %q，实际：%v", want, err)
		}
	}
}

// ============================================================================
// Task 16：取数权限对齐（root 等价）—— 拿不到就**响亮失败**，绝不降级
// ============================================================================

// TestQEMUSudoArgsDefaultAndOverride：root 等价那一格的默认值与覆盖语义。
//
// 判据三条：
//
//  1. 不给环境变量 ⇒ **恰好** `[sudo, -n]`（`-n` 是关键：它让"拿不到权限"当场失败，
//     而不是挂在口令提示上被 ssh 的 BatchMode 变成一句语焉不详的 rc=1）；
//  2. 给了合法取值 ⇒ 逐格用它（例如客人里装的是 `doas`）；
//  3. 给了含危险字符的取值 ⇒ **响亮失败**（那一格会被拼进客人侧的 shell 命令行，
//     "清洗后继续"会拼出一条操作者没写过的命令）。
func TestQEMUSudoArgsDefaultAndOverride(t *testing.T) {
	t.Run("默认", func(t *testing.T) {
		t.Setenv(qemuSSHSudoEnv, "")
		got, err := qemuSSHSudoArgs()
		if err != nil {
			t.Fatalf("默认取值不该报错: %v", err)
		}
		if strings.Join(got, " ") != "sudo -n" {
			t.Errorf("默认必须是 `sudo -n`（拿不到 root 等价就当场失败），实际 %q", got)
		}
	})
	t.Run("覆盖", func(t *testing.T) {
		t.Setenv(qemuSSHSudoEnv, "doas")
		got, err := qemuSSHSudoArgs()
		if err != nil {
			t.Fatalf("合法覆盖不该报错: %v", err)
		}
		if strings.Join(got, " ") != "doas" {
			t.Errorf("覆盖取值应当逐格生效，实际 %q", got)
		}
	})
	for _, bad := range []string{"sudo; rm -rf /", "sudo`id`", "sudo $HOME"} {
		t.Run("拒绝:"+bad, func(t *testing.T) {
			t.Setenv(qemuSSHSudoEnv, bad)
			if _, err := qemuSSHSudoArgs(); err == nil {
				t.Fatalf("取值 %q 必须报错 —— 它会被拼进客人侧的 shell 命令行"+
					"（含空白/分号/反引号/`$` 的一律不许），而『清洗后继续』会拼出一条"+
					"操作者没写过的命令", bad)
			} else if !strings.Contains(err.Error(), qemuSSHSudoEnv) {
				t.Errorf("错误串里必须点名 %s，实际：%v", qemuSSHSudoEnv, err)
			}
		})
	}
	t.Run("空值回默认", func(t *testing.T) {
		// 空串（含只写空白）等同于"没给"——与其它几格同一条口径（不猜：给了空串就等于没给）。
		t.Setenv(qemuSSHSudoEnv, "   ")
		got, err := qemuSSHSudoArgs()
		if err != nil {
			t.Fatalf("空白取值应当按【没给】处理: %v", err)
		}
		if strings.Join(got, " ") != "sudo -n" {
			t.Errorf("空白取值应当回落到默认 `sudo -n`，实际 %q", got)
		}
	})
}

// TestQEMUSudoDeniedIsLoudAndSaysDoNotDowngrade：客人侧拿不到 root 等价 ⇒ 错误串必须
// **点明"不许降级"**并给出修法。
//
// 为什么这条比看起来重要：`sudo: a password is required` 的原文只说明"这条命令失败了"，
// 而真正的后果是**测量语义已经变了** —— 非 root 取数下 6 条检查被跳过却**算通过**、
// 4 条**假失败**，记录里的 detail 还会写成「SELinux和AppArmor均未检测到」
// （**看起来像机器真的没装**）。操作者最自然的动作会是"那就用 asc 跑吧"，而那正是要堵的路。
func TestQEMUSudoDeniedIsLoudAndSaysDoNotDowngrade(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	key := qemuTestKey(t)
	qemuTestEnv(t, "asc-vm910", key, "asc", "22")

	writeSCPShim(t, 0, "")
	// 三条 ssh 全部返回同一句 sudo 报错（chmod 那条与 emit-checks 那条都会撞上）。
	writeSSHShim(t, "", 1, "sudo: a password is required")

	_, _, err := collectChecksForTarget("qemu:910")
	if err == nil {
		t.Fatal("拿不到 root 等价权限时**必须**报错（绝不降级成 asc 去取数）")
	}
	for _, want := range []string{"a password is required", "绝不降级", qemuSSHSudoEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误串里必须有 %q —— 否则下一位执行者最自然的动作是『那就用 asc 跑吧』。"+
				"实际：%v", want, err)
		}
	}
}

// TestQEMUSudoMissingIsLoud：客人里没有 sudo ⇒ 同样响亮失败并点名修法。
func TestQEMUSudoMissingIsLoud(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	key := qemuTestKey(t)
	qemuTestEnv(t, "asc-vm910", key, "asc", "22")
	writeSCPShim(t, 0, "")
	writeSSHShim(t, "", 127, "bash: line 1: sudo: command not found")

	_, _, err := collectChecksForTarget("qemu:910")
	if err == nil {
		t.Fatal("客人里没有 sudo 时**必须**报错")
	}
	for _, want := range []string{"command not found", qemuSSHSudoEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误串里必须有 %q，实际：%v", want, err)
		}
	}
}

// TestQEMUHostKeyChangedIsSelfExplaining：**同名重建**导致的 host key 变更必须被解释清楚。
//
// 为什么单列一条：`REMOTE HOST IDENTIFICATION HAS CHANGED!` 与
// 「私钥不对 / 机器不可达」在操作者眼里**同形**，而「建机 → 清机 → 用同一个 vmid/名字重建」
// 恰恰是这台基质的**正常循环**（重建后 host key 必然变）。错误串不说清，下一步就是去查错的东西。
func TestQEMUHostKeyChangedIsSelfExplaining(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	key := qemuTestKey(t)
	qemuTestEnv(t, "asc-vm910", key, "asc", "22")
	writeSCPShim(t, 0, "")
	// ⚠️ stderr 只用**单行**且不含 `%`：夹具的 `.bat` 分支（Windows）是 `echo` 逐行写的，
	// 多行/百分号会被 cmd.exe 自己解释掉，于是"错误串里必须有 X"会在 Windows 上**假红**
	// （与判据无关的平台差异 —— 本文件的其它失败用例都走同一个约定）。
	writeSSHShim(t, "", 255, "Host key verification failed.")

	_, _, err := collectChecksForTarget("qemu:910")
	if err == nil {
		t.Fatal("host key 变更时必须报错（不许静默接受新键）")
	}
	for _, want := range []string{"host key 变了", "重建", "ssh-keygen -R", qemuSSHKnownHostsEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误串里必须有 %q（否则这条错误与『私钥不对』同形），实际：%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "StrictHostKeyChecking=no") &&
		!strings.Contains(err.Error(), "不要") {
		t.Errorf("错误串若提到 StrictHostKeyChecking=no，必须同时说明**不要**那么做，"+
			"实际：%v", err)
	}
}

// TestQEMUKnownHostsOptionIsHonoured：给了 known_hosts 路径 ⇒ ssh/scp 都显式用它
// （建机侧删旧键、取数侧读同一份 ⇒ 同名重建不再炸）；没给 ⇒ 一个字节都不加。
func TestQEMUKnownHostsOptionIsHonoured(t *testing.T) {
	key := qemuTestKey(t)

	t.Run("给了就用同一个文件", func(t *testing.T) {
		kh := filepath.Join(t.TempDir(), "asscor-edge-vm_known_hosts")
		if err := os.WriteFile(kh, nil, 0o600); err != nil {
			t.Fatalf("写临时 known_hosts: %v", err)
		}
		qemuTestEnv(t, "asc-vm910", key, "asc", "22")
		t.Setenv(qemuSSHKnownHostsEnv, kh)
		args, err := qemuSSHArgs("910", emitChecksFlag)
		if err != nil {
			t.Fatalf("解析 SSH 目标: %v", err)
		}
		if !containsOption(args, "UserKnownHostsFile="+kh) {
			t.Errorf("ssh 必须显式用 %s 指定的那一份 known_hosts（`UserKnownHostsFile=`），实际 %q",
				qemuSSHKnownHostsEnv, args)
		}
	})
	t.Run("没给就不加", func(t *testing.T) {
		qemuTestEnv(t, "asc-vm910", key, "asc", "22")
		t.Setenv(qemuSSHKnownHostsEnv, "")
		args, err := qemuSSHArgs("910", emitChecksFlag)
		if err != nil {
			t.Fatalf("解析 SSH 目标: %v", err)
		}
		for _, a := range args {
			if strings.Contains(a, "UserKnownHostsFile") {
				t.Errorf("没给 %s 时**不得**加这一格（用 ssh 自己的 ~/.ssh/known_hosts，"+
					"与既有行为逐字相同），实际 %q", qemuSSHKnownHostsEnv, args)
			}
		}
	})
	t.Run("目录不可用就响亮失败", func(t *testing.T) {
		qemuTestEnv(t, "asc-vm910", key, "asc", "22")
		t.Setenv(qemuSSHKnownHostsEnv, filepath.Join(t.TempDir(), "no-such-dir", "known_hosts"))
		if _, err := qemuSSHArgs("910", emitChecksFlag); err == nil {
			t.Fatal("known_hosts 的目录不存在时必须报错（不许退回 ssh 自己的文件：" +
				"那会让建机侧删的键与取数侧读的键**不是同一份**，同名重建照样炸）")
		}
	})
}

// containsOption 判断 argv 里有没有那一格（`-o` 的取值是一整格）。
func containsOption(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// ============================================================================
// 变异：把 qemu 的 ssh 换成 docker ⇒ 用例**必须**红
// ============================================================================
// TestQEMUMutationToDockerMustTurnTheCasesRed 是"qemu 路径必须**真的**用 ssh"这条判据的变异证明。
//
// 变异手法与 Task 6 的 pve 版本相同：把 `runSSH` 指到 `runDocker`，也就是那个最像的错法
// （`qemu:` 前缀认了、但二进制还是 docker）。此时假 docker 的调用日志**必须**出现 ——
// 于是 `TestQEMUNodeTargetUsesSSHAndSCPAndRecordsSubstrate` 里那条
// "不得起 docker 子进程"会红。本用例只断言"变异确实被观测到"，即在证明那把尺子**有牙**
// （否则"没有 docker 调用"可能只是因为实现根本没跑）。
//
// 恢复必须做（`t.Cleanup`）：`runSSH` 是**包级变量**，泄漏到别的用例会污染它们。
func TestQEMUMutationToDockerMustTurnTheCasesRed(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	key := qemuTestKey(t)
	qemuTestEnv(t, "asc-vm910", key, "asc", "22")

	original := runSSH
	t.Cleanup(func() { runSSH = original })
	runSSH = func(args ...string) ([]byte, error) {
		return runDocker(args...)
	}

	dockerLog := writeDockerShim(t, fakeDocker{stdout: "docker-shim-must-not-be-used"})
	writeSCPShim(t, 0, "")
	writeSSHShim(t, mustEnvelope(t, "asc-vm910", hostChecksWithFailures("RS-006")), 0, "")

	// 变异之后取数会失败（docker 不认识 ssh 的参数形状）—— 这不重要；重要的是
	// 假 docker **真的被调用过**，否则"不得起 docker 子进程"那条断言就是空洞的。
	_, _, _ = collectChecksForTarget("qemu:910")
	if shimLogAbsent(t, dockerLog) {
		t.Fatal("变异之后假 docker **必须**被调用过 —— 否则说明这条路径根本没跑，" +
			"『不得起 docker 子进程』那条断言是空洞的")
	}
}
