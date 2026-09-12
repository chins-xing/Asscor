//go:build expr && engine && checks

// 本文件是 Task 4C 的用例：**观测主体**（评估发生在哪台机器）。
//
// 三组钉子：
//  1. **默认路径逐位不变**：不传 `-target` 时取数路径就是 `runHostChecks()` 本身
//     （逐要素比较 + "一个 docker 子进程都没起"）。
//  2. **节点内路径真的取回节点数据**，并把运行位置写进记录（`meta.observation_target`）。
//  3. **失败一律响亮**：目标缺失 / docker 不可用 / 取回的检查集为空 —— 绝不静默回落到本机
//     （那正是今天这个缺陷最危险的形态：记录看起来是节点数据、实际是宿主数据）。
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/edgeexp"
	"github.com/chins-xing/asscor/internal/model"
)

// ============================================================================
// 假 docker：把"节点内采集"的外部依赖变成可观测的
// ============================================================================

// fakeDocker 描述一个假 docker 的行为。
//
// 它替代真实的 docker CLI（只用得上两个子命令：`cp` 与 `exec`），故"节点内取数"这条路径可以
// 在**没有容器**的机器上被完整测到 —— 包括它必须失败的那几种形态。真实 lab 上的验证是另一次
// 单独的实验（Task 4C Step 4 的一次 `docker cp` + 一次 `docker exec`），不是这些用例的替代品。
type fakeDocker struct {
	// stdout 是假 docker 每次调用都会打印的那一行（cp 的返回被忽略，exec 的返回被解析，
	// 故两个分支共用同一份设置即可）。
	stdout string
	// exitCode 非零时，假 docker 以该码失败并把 stderr 写成 dockerErr（真实 docker 的诊断
	// 就在 stderr，`runDocker` 会把它原样带进错误）。
	exitCode  int
	dockerErr string
}

// writeDockerShim 在临时目录里放一个假 docker，并把它前置到 PATH，返回它的调用日志路径。
//
// 为什么用 **PATH 前置**而不是给被测代码留一个注入点：`runDocker` 走的就是
// `exec.Command("docker", …)`，把假 CLI 放到 PATH 最前面即可。测试因此不依赖"实现里有没有
// 一个只在测试里有人用的接缝"（那种接缝会让生产路径与测试路径悄悄分叉）。
func writeDockerShim(t *testing.T, d fakeDocker) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "docker.done")

	// POSIX 分支（Linux CI / WSL）：每一行参数都追加进日志，然后打印预设 stdout。
	posix := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + quote(posixLogRef(log)) + "\n" +
		"printf '%s\\n' " + quote(d.stdout) + "\n"
	if d.exitCode != 0 {
		posix += "printf '%s\\n' " + quote(d.dockerErr) + " 1>&2\nexit " + itoa(d.exitCode) + "\n"
	} else {
		posix += "exit 0\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(posix), 0o755); err != nil {
		t.Fatalf("写假 docker: %v", err)
	}

	// Windows 分支：Go 在 Windows 上按 PATHEXT 找 `docker.bat`。
	// 只用 `echo` 与重定向：信封 JSON 里不含 `<`/`>`/`|`/`&`/`%`，无需转义。
	bat := "@echo off\r\n" +
		"echo %*>> \"" + log + "\"\r\n" +
		"echo " + d.stdout + "\r\n"
	if d.exitCode != 0 {
		bat += "echo " + d.dockerErr + " 1>&2\r\nexit /b " + itoa(d.exitCode) + "\r\n"
	} else {
		bat += "exit /b 0\r\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "docker.bat"), []byte(bat), 0o755); err != nil {
		t.Fatalf("写假 docker.bat: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// posixLogRef 只为了让上面的字符串拼接读起来清楚（shell 里的路径也要引号）。
func posixLogRef(p string) string { return p }

// quote 把一段文本包成 shell 单引号字面量（内部的单引号按标准手法转义）。
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		return "-" + string(buf)
	}
	return string(buf)
}

// mustEnvelope 造一份节点内进程会输出的信封 JSON（单行）。
func mustEnvelope(t *testing.T, hostname string, checks []model.CheckResult) string {
	t.Helper()
	raw, err := json.Marshal(nodeCheckEnvelope{Marker: nodeEnvelopeMagic, Hostname: hostname, Checks: checks})
	if err != nil {
		t.Fatalf("造信封: %v", err)
	}
	return string(raw)
}

// ============================================================================
// Step 1：默认路径逐位不变
// ============================================================================

// TestCollectChecksForTargetDefaultsToLocalHostChecks 是 Task 4C 的**默认行为钉子**。
//
// 判据两条，缺一不可：
//  1. 返回值与 `runHostChecks()` **逐要素相等**（同一个形状、同一个顺序、同一个内容）；
//  2. 整个过程**一个 docker 子进程都没起**（假 docker 的调用日志必须不存在）—— 只看第 1 条
//     的话，"先起 docker 再退回本机结果"这种实现会通过，而它恰恰是最危险的形态：
//     机器上有 docker 就采节点、没有就悄悄采宿主，同一轮实验里混着两种观测主体。
func TestCollectChecksForTargetDefaultsToLocalHostChecks(t *testing.T) {
	registerFixtureChecks()
	dir := t.TempDir()
	log := filepath.Join(dir, "docker.done")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got, observationTarget, err := collectChecksForTarget("")
	if err != nil {
		t.Fatalf("默认路径（不带 target）不得报错: %v", err)
	}
	if observationTarget != "" {
		t.Errorf("默认路径的观测主体必须是空串（= 本机，字段因 omitempty 不落盘 ⇒ 与今天写出的字节一致），实际 %q", observationTarget)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Errorf("默认路径**不得**启动任何 docker 子进程，实际留下了调用日志 %s", log)
	}

	want := runHostChecks()
	if len(got) != len(want) {
		t.Fatalf("默认路径的检查集长度 = %d, want %d（必须与 runHostChecks 逐要素一致）", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("默认路径的第 %d 个检查结果与 runHostChecks 不同：\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

// TestDefaultPathRecordHasNoObservationTarget：默认路径写出的记录**不含** `meta.observation_target`
// （既不写空串、也不写本机标识）——"本机"这个事实由字段缺席表达，记录字节因此与今天一致。
func TestDefaultPathRecordHasNoObservationTarget(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	rec, err := buildRecord(context.Background(), "S0-baseline", cfg, newGroundTruth(false, 0, 0, 0, true), 1, "")
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	if rec.Meta.ObservationTarget != "" {
		t.Errorf("默认路径的记录不得带 observation_target，实际 %q", rec.Meta.ObservationTarget)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "observation_target") {
		t.Errorf("默认路径的 JSON 里不得出现 observation_target 键（omitempty）:\n%s", raw)
	}
}

// ============================================================================
// Step 2：节点内取数 + 观测主体可判定
// ============================================================================

// TestTargetPathUsesNodeChecksAndRecordsObservationTarget：`-target` 路径必须**真的**用节点内
// 取回的检查集（而不是再跑一遍本机登记表），并把运行位置写进记录。
//
// 夹具刻意让节点的检查集与本机**不同**（节点上 RS-006 真实失败）：若实现偷偷回落本机结果，
// 记录的 checks[] 里就不会有 RS-006，这条用例立刻红。
func TestTargetPathUsesNodeChecksAndRecordsObservationTarget(t *testing.T) {
	registerFixtureChecks()
	nodeChecks := hostChecksWithFailures("RS-006")
	writeDockerShim(t, fakeDocker{stdout: mustEnvelope(t, "host1", nodeChecks)})

	host, observationTarget, err := collectChecksForTarget("asc-asscor-host1")
	if err != nil {
		t.Fatalf("节点内取数: %v", err)
	}
	if len(host) != len(nodeChecks) {
		t.Fatalf("取回的检查集长度 = %d, want %d", len(host), len(nodeChecks))
	}
	for i := range nodeChecks {
		if host[i] != nodeChecks[i] {
			t.Fatalf("取回的检查集与节点载荷不同（第 %d 项）：\n got %+v\nwant %+v", i, host[i], nodeChecks[i])
		}
	}
	wantTarget := "node:asc-asscor-host1 (hostname=host1)"
	if observationTarget != wantTarget {
		t.Errorf("观测主体 = %q, want %q（容器名 + 节点内进程自证的 hostname）", observationTarget, wantTarget)
	}

	// 记录层面：装配出来的记录必须带着它，且用节点数据评出来的失败检查里能看到 RS-006。
	cfg := fixtureConfig(t)
	rec, err := assembleRecord(context.Background(), cfg, "R-no-ids", newGroundTruth(true, 100, 2, 1, false), 1, host, observationTarget)
	if err != nil {
		t.Fatalf("assembleRecord: %v", err)
	}
	if rec.Meta.ObservationTarget != wantTarget {
		t.Errorf("记录 meta.observation_target = %q, want %q", rec.Meta.ObservationTarget, wantTarget)
	}
	failed := map[string]bool{}
	for _, ck := range rec.Observed.Checks {
		failed[ck.ID] = true
	}
	if !failed["RS-006"] {
		t.Errorf("R 组的自然失败必须来自**节点**的检查集，实际失败检查: %v", failed)
	}
}

// TestCLIInNodeRunWritesNodeObservationTarget：CLI 端到端 —— `--target` 出的那条记录必须能被
// 消费者读回，且 `meta.observation_target` 说明它出自节点；摘要里要有一行观测主体。
func TestCLIInNodeRunWritesNodeObservationTarget(t *testing.T) {
	registerFixtureChecks()
	dir := t.TempDir()
	writeDockerShim(t, fakeDocker{stdout: mustEnvelope(t, "host1", hostChecksWithFailures("RS-006"))})

	cfgPath := filepath.Join(dir, "m0.ini")
	if err := os.WriteFile(cfgPath, []byte(fixtureConfigINI), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	attackPath := filepath.Join(dir, "attack-R.json")
	if err := os.WriteFile(attackPath, []byte(`{"scenario":"R-no-ids","compromised":true,
	  "time_to_compromise_s":100,"ttps_achieved":2,"nodes_affected":1,"block_effective":false}`), 0o600); err != nil {
		t.Fatalf("写 harness 产物: %v", err)
	}
	outPath := filepath.Join(dir, "records.jsonl")

	var stdout, stderr strings.Builder
	code := runCLI([]string{
		"--scenario", "R-no-ids", "--config", cfgPath, "--attack-out", attackPath,
		"--out", outPath, "--run", "1", "--env", "clab-host1", "--target", "asc-asscor-host1",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("退出码 = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	recs, err := edgeexp.LoadFileAs("test", outPath)
	if err != nil {
		t.Fatalf("读回: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("写出行数 = %d, want 1", len(recs))
	}
	want := "node:asc-asscor-host1 (hostname=host1)"
	if recs[0].Meta.ObservationTarget != want {
		t.Errorf("meta.observation_target = %q, want %q", recs[0].Meta.ObservationTarget, want)
	}
	if !strings.Contains(stdout.String(), "观测主体：") {
		t.Errorf("节点内评估的日志必须打印观测主体那一行（否则日志与宿主评估同形）:\n%s", stdout.String())
	}
}

// TestDefaultPathCLIStillPrintsNoObservationTargetLine：默认路径的摘要**不得**多出观测主体行 ——
// 既有脚本与日志按行消费它，多一行就是行为变化。
func TestDefaultPathCLIStillPrintsNoObservationTargetLine(t *testing.T) {
	registerFixtureChecks()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "m0.ini")
	if err := os.WriteFile(cfgPath, []byte(fixtureConfigINI), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	attackPath := filepath.Join(dir, "attack-S0.json")
	if err := os.WriteFile(attackPath, []byte(`{"scenario":"S0-baseline","compromised":false,
	  "time_to_compromise_s":0,"ttps_achieved":0,"nodes_affected":0,"block_effective":true}`), 0o600); err != nil {
		t.Fatalf("写 harness 产物: %v", err)
	}
	outPath := filepath.Join(dir, "records.jsonl")

	var stdout, stderr strings.Builder
	code := runCLI([]string{
		"--scenario", "S0-baseline", "--config", cfgPath, "--attack-out", attackPath, "--out", outPath,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("退出码 = %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "观测主体") {
		t.Errorf("默认路径（不带 -target）的摘要不得出现观测主体行:\n%s", stdout.String())
	}
}

// ============================================================================
// Step 2 的另一半：失败必须响亮（绝不静默回落到本机）
// ============================================================================

// TestNodeCollectionFailuresAreLoud 是把"看起来是节点数据、实际是宿主数据"这条静默路径堵死的
// 一组用例。每个分支都断言：**报错**、**不返回任何检查集**、错误里出现能指向真正原因的线索。
//
// 为什么"取回的检查集为空"也算失败：空集的记录长成"这台机器什么检查都没失败"的样子，
// 而它最可能的成因是二进制被截断 / 平台闸门不匹配 —— 不是"节点很干净"。
func TestNodeCollectionFailuresAreLoud(t *testing.T) {
	registerFixtureChecks()
	cases := []struct {
		name      string
		docker    fakeDocker
		wantInErr string
	}{
		{
			name: "目标容器不存在",
			docker: fakeDocker{exitCode: 1,
				dockerErr: "Error response from daemon: No such container: asc-nope"},
			wantInErr: "No such container",
		},
		{
			name:      "docker 不可用",
			docker:    fakeDocker{exitCode: 127, dockerErr: "docker: command not found"},
			wantInErr: "command not found",
		},
		{
			name:      "stdout 里没有信封",
			docker:    fakeDocker{stdout: "not json at all"},
			wantInErr: "信封",
		},
		{
			name:      "信封标记不匹配",
			docker:    fakeDocker{stdout: `{"marker":"other","hostname":"h","checks":[{"check_id":"X"}]}`},
			wantInErr: "标记",
		},
		{
			name:      "检查集为空",
			docker:    fakeDocker{stdout: mustEnvelope(t, "host1", nil)},
			wantInErr: "为空",
		},
		{
			name:      "信封没有 hostname",
			docker:    fakeDocker{stdout: mustEnvelope(t, "", hostChecksWithFailures("RS-006"))},
			wantInErr: "hostname",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeDockerShim(t, tc.docker)
			host, observationTarget, err := collectChecksForTarget("asc-asscor-host1")
			if err == nil {
				t.Fatal("必须**响亮失败**，绝不能静默回落到本机检查集（那样记录看起来是节点数据、实际是宿主数据）")
			}
			if host != nil {
				t.Errorf("失败时不得返回任何检查集（回落到本机正是这个缺陷的形态），实际 %d 条", len(host))
			}
			if observationTarget != "" {
				t.Errorf("失败时不得给出观测主体 %q", observationTarget)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("错误信息必须指向真正的原因（期望含 %q）: %v", tc.wantInErr, err)
			}
		})
	}
}

// TestTargetPathNeverFallsBackWhenDockerMissing：PATH 上**没有** docker 时同样必须报错。
//
// 这条单独列出来：它是最容易写成"起不了 docker 就用本机结果"的那个分支（"反正数据都有"），
// 而它产出的记录与节点内采集**在字段上完全无法区分**（只有 env 那个手填标签能看出区别）。
func TestTargetPathNeverFallsBackWhenDockerMissing(t *testing.T) {
	registerFixtureChecks()
	t.Setenv("PATH", t.TempDir())
	host, _, err := collectChecksForTarget("asc-asscor-host1")
	if err == nil {
		t.Fatal("docker 不可用时必须报错，不得回落到本机评估")
	}
	if host != nil {
		t.Fatalf("必须返回 nil 检查集，实际 %d 条", len(host))
	}
}

// TestEmitChecksModeIsNodeOnlyEntry：`-emit-checks` 是节点内进程的入口，只接受空参数集。
//
// 为什么要拒绝而不是忽略其它开关：忽略会让"父进程以为配置被读过了"静默成立，而节点内进程
// 其实什么都没读 —— 两边的数据看起来完全一样。
func TestEmitChecksModeIsNodeOnlyEntry(t *testing.T) {
	// 合法用法：只给 -emit-checks（父进程就是这么把节点内进程调起来的）。
	var stdout, stderr strings.Builder
	code := runCLI([]string{"-" + emitChecksFlag}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("-emit-checks 退出码 = %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	env, err := parseNodeEnvelope([]byte(stdout.String()))
	if err != nil {
		t.Fatalf("节点内输出必须能被父进程解析: %v\nstdout:\n%s", err, stdout.String())
	}
	if env.Hostname == "" {
		t.Error("信封必须带节点内进程自己报的 hostname（记录靠它说明观测出自哪台机器）")
	}
	if len(env.Checks) == 0 {
		t.Error("信封必须带检查集（空集会让父进程把这条路径判失败）")
	}

	// 非法用法：混进任何别的开关都必须被拒（退出码 2）。
	for _, args := range [][]string{
		{"-" + emitChecksFlag, "--scenario", "S0-baseline"},
		{"-" + emitChecksFlag, "--config", "x.ini"},
		{"-" + emitChecksFlag, "-" + nodeTargetFlag, "asc-asscor-host1"},
	} {
		var out, errOut strings.Builder
		if code := runCLI(args, &out, &errOut); code != exitUsage {
			t.Errorf("args=%v 退出码 = %d, want %d（用法错误）", args, code, exitUsage)
		}
	}
}

// TestParseNodeEnvelopePicksItsLine：信封必须能从**混着杂散输出**的 stdout 里被挑出来。
//
// 为什么较真：节点里跑的是同一份二进制，将来任何一行日志（运行时诊断、检查项自己打的字）
// 都会进入同一个 stdout。把整个 stdout 赌成"就是那份 JSON"会让这类输出变成一次采集失败，
// 或者更糟 —— 让父进程解析到别的东西。
func TestParseNodeEnvelopePicksItsLine(t *testing.T) {
	env := mustEnvelope(t, "host1", hostChecksWithFailures("RS-006"))
	mixed := "some warning line\nanother line\n" + env + "\ntrailing noise\n"
	got, err := parseNodeEnvelope([]byte(mixed))
	if err != nil {
		t.Fatalf("必须能从杂散输出里挑出信封: %v", err)
	}
	if got.Hostname != "host1" || len(got.Checks) == 0 {
		t.Fatalf("解析结果不对: %+v", got)
	}
	if _, err := parseNodeEnvelope([]byte("nothing here\n")); err == nil {
		t.Fatal("没有信封时必须报错（绝不能当成空检查集）")
	}
}
