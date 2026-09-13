//go:build expr && engine && checks

// 本文件是 Task 4D Step 2 的用例：`-target` 的**基质前缀**（`docker:<容器>` / `lxd:<实例>`）。
//
// 判据分三层，缺一不可：
//
//  1. **`docker:<容器>` 与裸名字逐位等价**：两条路径发出的 docker 命令**逐条相同**、
//     记录里的 `meta.observation_target` 也**逐字相同**（Task 4C 已经落盘的数据与断言不能动）。
//  2. **`lxd:<实例>` 真的走 lxc**：两条命令的形状（`lxc file push <本地> <实例><目标>`、
//     `lxc exec --env K=V <实例> -- <二进制> -emit-checks`）与 docker 侧**逐项对应**，
//     而 nonce 绑定、信封解析（取最后一行）、失败一律响亮这些性质与 docker 侧**共用同一份
//     实现** —— 不是另写一套判据。
//  3. **两条路径不互相顶替**：跑 `lxd:` 时 docker 假 CLI 一次都不能被调用，反之亦然。
//     这条是"绝不静默回落"在基质维度的形态：`lxd:probe-ot005` 若被当成 docker 容器名，
//     docker 会以 `No such container: lxd:probe-ot005` 失败 —— 错误指向一个不存在的容器，
//     而真正的原因（基质选错）完全看不出来。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/edgeexp"
)

// ============================================================================
// 语法解析：三种写法 + 报错的两种形态
// ============================================================================

// TestParseNodeTargetSyntax：`-target` 的三种合法写法与"看着像基质前缀却不在白名单"的诊断。
//
// 为什么把解析单独钉住：语法是**跨工具接口**（Go 侧与 `lunwen/clab-lab/scripts/*.sh` 都要用
// 同一个拼写）。它写错时不会报错 —— 只会让某一侧以为自己在采另一种基质的数据。
func TestParseNodeTargetSyntax(t *testing.T) {
	cases := []struct {
		raw   string
		want  nodeTarget
		why   string
		bad   bool
		inErr string
	}{
		{raw: "asc-asscor-host1", want: nodeTarget{substrateDocker, "asc-asscor-host1"},
			why: "裸名字 = docker（Task 4C 以来的语义，向后兼容）"},
		{raw: "  asc-asscor-host1  ", want: nodeTarget{substrateDocker, "asc-asscor-host1"},
			why: "两侧空白必须被吃掉（脚本传值时的引号/空格不该变成容器名的一部分）"},
		{raw: "docker:asc-asscor-host1", want: nodeTarget{substrateDocker, "asc-asscor-host1"},
			why: "显式 docker 前缀 = 与裸名字同一件事"},
		{raw: "lxd:probe-ot005", want: nodeTarget{substrateLXD, "probe-ot005"},
			why: "lxd 前缀是新基质（A-1）"},
		{raw: "lxd: probe-ot005", want: nodeTarget{substrateLXD, "probe-ot005"},
			why: "前缀后的空白同样被吃掉"},
		{raw: "foo:bar", bad: true, inErr: "未知",
			why: "`foo` 是标识符形状的前缀 ⇒ 按『未知基质』报错，而不是让它变成一次不存在的容器名"},
		{raw: "docker:", bad: true, inErr: "缺少节点名", why: "前缀给了名字为空 ⇒ 报错，不得回落本机"},
		{raw: "lxd:", bad: true, inErr: "缺少实例名", why: "同上"},
		{raw: "unknown:host1", bad: true, inErr: "未知", why: "像基质前缀却不在白名单 ⇒ 专门诊断（不是让它变成一次 No such container）"},
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
	// 空串是**调用方**处理的默认路径（= 本机），解析层不得悄悄把它当成某个节点。
	if _, err := parseNodeTarget("   "); err == nil {
		t.Error("空 target 必须由解析层报错：空串的语义是『本机』，由 collectChecksForTarget 处理")
	}
}

// nodeTargetFlagHelpText 取 `edgescen -h` 的文案（Go 的 flag 包把它写到 fs 的输出流 = stderr）。
//
// 直接问 CLI 而不是把期望文案抄一份到测试里：抄一份的写法会把"帮助里到底写了什么"与
// "测试里写了什么"变成两份真源 —— 而这条判据要证明的恰恰是**操作者能看到三种写法**。
func nodeTargetFlagHelpText(t *testing.T) string {
	t.Helper()
	var stdout, stderr strings.Builder
	runCLI([]string{"-h"}, &stdout, &stderr) // -h 的退出码是 0（flag.ErrHelp），这里不关心
	return stderr.String()
}

// TestTargetFlagHelpNamesAllThreeForms：`-h` 文案必须把三种写法都写出来。
//
// 为什么单列一条：语法只在一处实现，而 `-h` 是操作者看到的唯一说明 —— 少写一种，操作者就会
// 去猜第三种（`lxd:…` 猜不出来时最可能的动作是把手打的实例名交给 docker）。
func TestTargetFlagHelpNamesAllThreeForms(t *testing.T) {
	usage := nodeTargetFlagHelpText(t)
	for _, want := range []string{"docker:", "lxd:", "本机"} {
		if !strings.Contains(usage, want) {
			t.Errorf("-%s 的文案里必须写明 %q；实际：%s", nodeTargetFlag, want, usage)
		}
	}
}

// ============================================================================
// lxd 路径：命令形状、nonce 绑定、观测主体、不顶替
// ============================================================================

// TestLXDNodeTargetUsesLXCAndRecordsSubstrate：`lxd:<实例>` 必须**真的**用 lxc 取数。
//
// 三条判据：
//
// 只起两个 lxc 子进程（`file push` + `exec`），形状逐项正确（`--` 分隔符、`--env` nonce）；
// **一个 docker 子进程都没有**（基质选错的形态在这里变红）；
// 观测主体把基质写进记录（`substrate=lxd`）：否则 `docker exec host1` 与
// `lxc exec host1 --` 两种观测在数据上完全同形。
//
// （注：这四行刻意**不写成 gofmt 认得的列表**（`// · …` 会被 go1.26 的 gofmt 重排成
// `//\n//\t· …`）—— 本文件里所有条目式注释都按同一约定写，保持本仓既有的注释风格。）
func TestLXDNodeTargetUsesLXCAndRecordsSubstrate(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	nodeChecks := hostChecksWithFailures("RS-006")
	lxcLog := writeLXCShim(t, fakeDocker{stdout: mustEnvelope(t, "probe-ot005", nodeChecks)})
	dockerLog := writeDockerShim(t, fakeDocker{stdout: "docker-shim-must-not-be-used"})

	host, observationTarget, err := collectChecksForTarget("lxd:probe-ot005")
	if err != nil {
		t.Fatalf("lxd 基质取数: %v", err)
	}
	if !shimLogAbsent(t, dockerLog) {
		t.Errorf("lxd 基质**不得**起任何 docker 子进程（基质选错的形态），实际留下了调用日志 %s", dockerLog)
	}

	invocations := readShimLog(t, lxcLog)
	if len(invocations) != 2 {
		t.Fatalf("lxd 取数应当只起两个 lxc 子进程（file push + exec），实际 %d 条: %v", len(invocations), invocations)
	}
	if !strings.HasPrefix(invocations[0], "file push ") {
		t.Errorf("第一次调用必须是 `lxc file push <本进程二进制> <实例><目标路径>`，实际 %q", invocations[0])
	}
	// 判据是"**目标**参数不带 docker cp 的冒号分隔符"（`<实例>:<路径>`），而不是"整条命令里没有
	// 冒号"：本地路径在 Windows 上是 `C:\…`，那个冒号与分隔符无关。
	args0 := strings.Fields(invocations[0])
	if n := len(args0); n == 0 || !strings.HasPrefix(args0[n-1], "probe-ot005/tmp/edgescen-") {
		t.Errorf("lxc file push 的目标必须是 `<实例><路径>`（**不得**用 docker cp 的 `<实例>:<路径>`），实际 %q", invocations[0])
	}
	if !strings.HasPrefix(invocations[1], "exec --env "+nodeNonceEnv+"=") {
		t.Errorf("第二次调用必须是 `lxc exec --env %s=<nonce> …`（nonce 经环境变量下发，不进参数位），实际 %q",
			nodeNonceEnv, invocations[1])
	}
	if !strings.Contains(invocations[1], "probe-ot005 -- /tmp/edgescen-") {
		t.Errorf("`lxc exec` 必须用 `--` 把命令与 lxc 自己的开关分开（`-emit-checks` 以 `-` 开头），实际 %q", invocations[1])
	}
	if !strings.HasSuffix(invocations[1], " "+emitChecksFlag) {
		t.Errorf("节点内进程的入口开关必须原样带上前导 `-`（%q），实际调用 %q", emitChecksFlag, invocations[1])
	}
	if !strings.Contains(invocations[1], nodeNonceEnv+"="+fixtureNonce) {
		t.Errorf("下发的 nonce 必须是用例固定下来的 %q，实际调用 %q", fixtureNonce, invocations[1])
	}

	if len(host) != len(nodeChecks) {
		t.Fatalf("取回的检查集长度 = %d, want %d", len(host), len(nodeChecks))
	}
	for i := range nodeChecks {
		if host[i] != nodeChecks[i] {
			t.Fatalf("取回的检查集与节点载荷不同（第 %d 项）：\n got %+v\nwant %+v", i, host[i], nodeChecks[i])
		}
	}
	wantTarget := "node:probe-ot005 (substrate=lxd, hostname=probe-ot005)"
	if observationTarget != wantTarget {
		t.Errorf("观测主体 = %q, want %q（实例名 + 基质 + 节点内进程自报的 hostname）", observationTarget, wantTarget)
	}
}

// TestDockerPrefixedTargetIsByteIdenticalToBareName 是 Step 2 的**逐位不变**钉子：
// `-target docker:<容器>` 与 `-target <容器>` 必须发出**逐条相同**的 docker 命令，并产出
// **逐字相同**的观测主体。
//
// 为什么用"两条路径互相比较"而不是写死一份期望：写死的期望只能证明"今天是这样"，而这条判据要
// 证明的是"新前缀没有改变旧路径"。两条路径同时跑、逐条比较，任何"给 docker: 加一层处理"的
// 实现都会立刻红。
func TestDockerPrefixedTargetIsByteIdenticalToBareName(t *testing.T) {
	registerFixtureChecks()
	nodeChecks := hostChecksWithFailures("RS-006")

	// 裸名字路径
	useFixtureNonce(t)
	bareLog := writeDockerShim(t, fakeDocker{stdout: mustEnvelope(t, "host1", nodeChecks)})
	bareChecks, bareTarget, err := collectChecksForTarget("asc-asscor-host1")
	if err != nil {
		t.Fatalf("裸名字路径: %v", err)
	}
	// 显式 docker: 前缀路径（同一个假 CLI 目录被第二次 writeDockerShim 覆盖 —— 故分两次读日志）
	bareInvocations := readShimLog(t, bareLog)

	useFixtureNonce(t)
	prefixedLog := writeDockerShim(t, fakeDocker{stdout: mustEnvelope(t, "host1", nodeChecks)})
	prefixedChecks, prefixedTarget, err := collectChecksForTarget("docker:asc-asscor-host1")
	if err != nil {
		t.Fatalf("docker: 前缀路径: %v", err)
	}
	prefixedInvocations := readShimLog(t, prefixedLog)

	if len(bareInvocations) != len(prefixedInvocations) {
		t.Fatalf("两条路径的 docker 调用条数不同：裸 %d 条 %v｜前缀 %d 条 %v",
			len(bareInvocations), bareInvocations, len(prefixedInvocations), prefixedInvocations)
	}
	for i := range bareInvocations {
		if bareInvocations[i] != prefixedInvocations[i] {
			t.Errorf("第 %d 条 docker 调用不同：\n 裸名字:   %q\n docker:: %q", i, bareInvocations[i], prefixedInvocations[i])
		}
	}
	if bareTarget != prefixedTarget {
		t.Errorf("观测主体不同：裸名字 %q｜docker: %q（`docker:` 只是把基质显式写出来，不是新取值）",
			bareTarget, prefixedTarget)
	}
	// Task 4C 留下的**逐字**期望：docker 侧不得出现 substrate= 字样（那会改掉已落盘记录的形状）。
	want := "node:asc-asscor-host1 (hostname=host1)"
	if prefixedTarget != want {
		t.Errorf("docker 侧的观测主体 = %q, want %q（Task 4C 的形状必须逐字保持）", prefixedTarget, want)
	}
	if len(bareChecks) != len(prefixedChecks) {
		t.Errorf("两条路径的检查集长度不同：%d vs %d", len(bareChecks), len(prefixedChecks))
	}
	if strings.Contains(prefixedTarget, "substrate=") {
		t.Errorf("docker 基质的观测主体**不得**带 substrate=：默认基质要逐字保持 Task 4C 的形状，实际 %q", prefixedTarget)
	}
}

// TestNodeTargetUnknownPrefixIsLoudAndNeverTouchesEitherCLI：基质前缀写错时必须**在起子进程之前**
// 报错，且**两条 CLI 都不许被碰到**。
//
// 这条堵的是"猜一个基质继续跑"：把 `lxd:probe-ot005` 的拼写写成 `lxd.;probe-ot005` 之类的形态
// 若被当成裸名字，docker 会以一个不存在的容器名失败 —— 错误信息指向容器，而原因是基质拼错。
func TestNodeTargetUnknownPrefixIsLoudAndNeverTouchesEitherCLI(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	dockerLog := writeDockerShim(t, fakeDocker{stdout: mustEnvelope(t, "probe-ot005", hostChecksWithFailures("RS-006"))})
	lxcLog := writeLXCShim(t, fakeDocker{stdout: mustEnvelope(t, "probe-ot005", hostChecksWithFailures("RS-006"))})

	// `unknown:` 会被解析层直接拒掉（见 TestParseNodeTargetSyntax），这里从**取数入口**再钉一次
	// "拒掉之后什么都没发生"。
	host, target, err := collectChecksForTarget("unknown:probe-ot005")
	if err == nil {
		t.Fatal("未知基质前缀必须**响亮失败**，不得猜一个基质继续跑")
	}
	if host != nil || target != "" {
		t.Errorf("失败时不得返回任何检查集/观测主体（回落到某个基质正是危险形态）：host=%d target=%q",
			len(host), target)
	}
	if !strings.Contains(err.Error(), "未知") {
		t.Errorf("错误信息必须指出是基质前缀的问题: %v", err)
	}
	if !shimLogAbsent(t, dockerLog) {
		t.Errorf("解析失败时**不得**起 docker 子进程，实际留下了调用日志 %s", dockerLog)
	}
	if !shimLogAbsent(t, lxcLog) {
		t.Errorf("解析失败时**不得**起 lxc 子进程，实际留下了调用日志 %s", lxcLog)
	}
}

// ============================================================================
// 失败形态：把 Task 4C 的 docker 侧 8 种形态**逐条映射**到 lxd 侧
// ============================================================================

// TestLXDNodeCollectionFailuresAreLoud 是 `TestNodeCollectionFailuresAreLoud` 的 lxd 版本：
// 同一批失败形态、同一条处置（报错 + 不返回检查集 + 错误指向真正原因）。
//
// 为什么必须逐条映射而不是只测成功路径：这 8 条里有 4 条是"信封层"的（缺信封 / 标记不符 / 空集 /
// 缺 hostname / nonce 不匹配 / 没有 nonce），它们走的是**与基质无关**的那段实现 —— 映射过来
// 顺带证明了两侧共用同一份解析（若将来有人给 lxd 另写一套解析，这几条会以不同的错误串变红）。
func TestLXDNodeCollectionFailuresAreLoud(t *testing.T) {
	registerFixtureChecks()
	cases := []struct {
		name     string
		lxc      fakeDocker
		wantInEr string
	}{
		{
			name:     "实例不存在",
			lxc:      fakeDocker{exitCode: 1, dockerErr: "Error: Instance not found"},
			wantInEr: "Instance not found",
		},
		{
			name:     "lxc 不可用",
			lxc:      fakeDocker{exitCode: 127, dockerErr: "lxc: command not found"},
			wantInEr: "command not found",
		},
		{
			name:     "stdout 里没有信封",
			lxc:      fakeDocker{stdout: "not json at all"},
			wantInEr: "信封",
		},
		{
			name:     "信封标记不匹配",
			lxc:      fakeDocker{stdout: `{"marker":"other","hostname":"h","checks":[{"check_id":"X"}]}`},
			wantInEr: "标记",
		},
		{
			name:     "检查集为空",
			lxc:      fakeDocker{stdout: mustEnvelope(t, "probe-ot005", nil)},
			wantInEr: "为空",
		},
		{
			name:     "信封没有 hostname",
			lxc:      fakeDocker{stdout: mustEnvelope(t, "", hostChecksWithFailures("RS-006"))},
			wantInEr: "hostname",
		},
		{
			name:     "信封的 nonce 不匹配",
			lxc:      fakeDocker{stdout: mustEnvelopeWithNonce(t, "probe-ot005", "another-runs-nonce", hostChecksWithFailures("RS-006"))},
			wantInEr: "nonce",
		},
		{
			name:     "信封没有 nonce",
			lxc:      fakeDocker{stdout: mustEnvelopeWithNonce(t, "probe-ot005", "", hostChecksWithFailures("RS-006"))},
			wantInEr: "没有 nonce",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useFixtureNonce(t)
			writeLXCShim(t, tc.lxc)
			dockerLog := writeDockerShim(t, fakeDocker{stdout: "docker-shim-must-not-be-used"})
			host, observationTarget, err := collectChecksForTarget("lxd:probe-ot005")
			if err == nil {
				t.Fatal("必须**响亮失败**，绝不能静默回落（既不能回落到本机，也不能回落到 docker 基质）")
			}
			if host != nil {
				t.Errorf("失败时不得返回任何检查集，实际 %d 条", len(host))
			}
			if observationTarget != "" {
				t.Errorf("失败时不得给出观测主体 %q", observationTarget)
			}
			if !strings.Contains(err.Error(), tc.wantInEr) {
				t.Errorf("错误信息必须指向真正的原因（期望含 %q）: %v", tc.wantInEr, err)
			}
			if !shimLogAbsent(t, dockerLog) {
				t.Errorf("lxd 路径失败时也不得回落到 docker 基质，实际留下了 docker 调用日志 %s", dockerLog)
			}
		})
	}
}

// TestLXDTargetNeverFallsBackWhenLXCMissing：PATH 上**没有** lxc 时同样必须报错。
//
// 单独列出的理由与 docker 侧相同：这是最容易写成"起不了 lxc 就换一种基质/本机"的那个分支，
// 而它产出的记录与真正的 lxd 采集**在字段上无法区分**（只有 env 那个手填标签能看出区别）。
func TestLXDTargetNeverFallsBackWhenLXCMissing(t *testing.T) {
	registerFixtureChecks()
	t.Setenv("PATH", t.TempDir())
	host, target, err := collectChecksForTarget("lxd:probe-ot005")
	if err == nil {
		t.Fatal("lxc 不可用时必须报错，不得回落到 docker 或本机")
	}
	if host != nil || target != "" {
		t.Fatalf("必须返回空结果，实际 host=%d target=%q", len(host), target)
	}
}

// ============================================================================
// 端到端：CLI 走 lxd 写出的记录
// ============================================================================

// TestCLILXDTargetWritesRecordWithSubstrate：CLI 端到端 —— `--target lxd:<实例>` 写出的记录必须
// 能被消费者读回，`meta.observation_target` 说明它出自哪个实例**以及哪种基质**。
func TestCLILXDTargetWritesRecordWithSubstrate(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	dir := t.TempDir()
	writeLXCShim(t, fakeDocker{stdout: mustEnvelope(t, "probe-ot005", hostChecksWithFailures("RS-006"))})
	dockerLog := writeDockerShim(t, fakeDocker{stdout: "docker-shim-must-not-be-used"})

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
		"--out", outPath, "--run", "1", "--env", "a1-ubuntu", "--target", "lxd:probe-ot005",
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
	want := "node:probe-ot005 (substrate=lxd, hostname=probe-ot005)"
	if recs[0].Meta.ObservationTarget != want {
		t.Errorf("meta.observation_target = %q, want %q", recs[0].Meta.ObservationTarget, want)
	}
	if !strings.Contains(stdout.String(), "观测主体：") {
		t.Errorf("节点内评估的日志必须打印观测主体那一行:\n%s", stdout.String())
	}
	// 记录里的 checks[] 必须来自 lxd 侧取回的检查集（RS-006 在节点夹具里真实失败）。
	failed := map[string]bool{}
	for _, ck := range recs[0].Observed.Checks {
		failed[ck.ID] = true
	}
	if !failed["RS-006"] {
		t.Errorf("R 组的自然失败必须来自**节点**的检查集，实际失败检查: %v", failed)
	}
	if !shimLogAbsent(t, dockerLog) {
		t.Errorf("lxd 端到端路径不得起 docker 子进程，实际留下了调用日志 %s", dockerLog)
	}
}

// TestLXDTargetRefusesToWriteWhenEnvelopeIsForged：矩阵级把"nonce 绑定的两个方向"钉在 lxd 侧。
//
// 这一条是**真的走了一遍子进程**的（环境变量 → 信封 → 父进程校验）：下发 nonce ⇒ 信封回显它；
// 换成一个不是本次运行的 nonce ⇒ 父进程拒绝且**不写记录**。docker 侧的同一判据在
// `TestEmitChecksModeIsNodeOnlyEntry` 里（两侧共用同一份 `-emit-checks` 实现）。
func TestLXDTargetRefusesToWriteWhenEnvelopeIsForged(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	dir := t.TempDir()
	writeLXCShim(t, fakeDocker{
		stdout: mustEnvelopeWithNonce(t, "probe-ot005", "stale-run-nonce", hostChecksWithFailures("RS-006")),
	})
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
		"--out", outPath, "--target", "lxd:probe-ot005",
	}, &stdout, &stderr)
	if code == exitOK {
		t.Fatalf("nonce 不匹配的信封必须让整轮失败，实际退出码 0\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "nonce") {
		t.Errorf("失败原因必须指向 nonce: %s", stderr.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Errorf("失败时**不得**写出任何记录（不写半条记录是既有纪律），实际 %s 存在", outPath)
	}
}

// ============================================================================
// M-1：docker 路径的错误串必须与 Task 4C（97581d8）**逐字相同**
// ============================================================================

// TestDockerErrorStringsMatchTask4CBytes 把"抽象前那几条错误串"钉成字面量。
//
// 为什么必须有这一条（Fix round 1 / M-1）：写"逐位不变"的钉子如果只比较**两条新路径**
// （`docker:x` vs 裸名字），它抓不到"两条路径一起变了"的情形 —— 而 Step 2 泛化 `runDocker`
// 时恰好就是这样：错误串被统一成 `docker exec 失败（<整条 argv>）`，与 97581d8 的
// `docker exec %s %s 失败` **不同**。评审用一条 overlay 检查读出了这个差异。
//
// 这里的期望值**逐字抄自 97581d8 的 `runDocker`**（不是从当前实现反推的）：
//
//	"节点内采集：docker cp %s 失败: %s"        （args[2] = 本地文件）
//	"节点内采集：docker exec %s %s 失败: %s"   （args[1] = "-e"、args[2] = "EDGESCEN_NODE_NONCE=<nonce>"）
//	"节点内采集：docker %s 失败: %s"           （兜底，整条 argv）
//	"docker 内采集：取本进程可执行文件路径失败: %w"
//
// 顺带证明 lxd 侧**不受**这条约束（它没有"不许变"的历史包袱，说得更准才有用）：同一个假 CLI
// 以 lxc 形态失败时，错误串按 `lxc file push <本地> → <实例><目标>` 报。
func TestDockerErrorStringsMatchTask4CBytes(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)

	t.Run("docker cp 失败（97581d8 的字面量）", func(t *testing.T) {
		writeDockerShim(t, fakeDocker{exitCode: 1, dockerErr: "Error response from daemon: No such container: nope"})
		_, _, err := collectChecksForTarget("docker:nope")
		if err == nil {
			t.Fatal("必须报错")
		}
		if !strings.Contains(err.Error(), "节点内采集：docker cp ") ||
			!strings.Contains(err.Error(), " 失败: Error response from daemon: No such container: nope") {
			t.Errorf("docker cp 的错误串必须与 Task 4C 逐字同形（`节点内采集：docker cp <本地> 失败: <stderr>`）；实际: %v", err)
		}
	})

	t.Run("docker exec 失败（97581d8 的字面量：args[1] 与 args[2] 两个占位）", func(t *testing.T) {
		dir := t.TempDir()
		// cp 必须成功、exec 必须失败：用一个按子命令分派的假 docker。
		script := "#!/bin/sh\n" +
			"if [ \"$1\" = \"cp\" ]; then exit 0; fi\n" +
			"echo 'Error response from daemon: No such container: nope' 1>&2\nexit 1\n"
		if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
			t.Fatalf("写假 docker: %v", err)
		}
		bat := "@echo off\r\nif \"%1\"==\"cp\" exit /b 0\r\n" +
			"echo Error response from daemon: No such container: nope 1>&2\r\nexit /b 1\r\n"
		if err := os.WriteFile(filepath.Join(dir, "docker.bat"), []byte(bat), 0o755); err != nil {
			t.Fatalf("写假 docker.bat: %v", err)
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

		_, _, err := collectChecksForTarget("nope")
		if err == nil {
			t.Fatal("必须报错")
		}
		// 97581d8 的形状：`docker exec <args[1]> <args[2]> 失败`，即 `-e` 与 `NONCE=…` 各占一格。
		wantPrefix := "节点内采集：docker exec -e " + nodeNonceEnv + "=" + fixtureNonce + " 失败: "
		if !strings.HasPrefix(err.Error(), wantPrefix) {
			t.Errorf("docker exec 的错误串必须与 Task 4C 逐字同形（`%s…`）；实际: %v", wantPrefix, err)
		}
	})

	t.Run("lxd 侧不受 docker 字面量约束（按 file push 的形状报）", func(t *testing.T) {
		writeLXCShim(t, fakeDocker{exitCode: 1, dockerErr: "Error: Instance not found"})
		_, _, err := collectChecksForTarget("lxd:nope")
		if err == nil {
			t.Fatal("必须报错")
		}
		if !strings.Contains(err.Error(), "lxc file push ") || !strings.Contains(err.Error(), " → ") {
			t.Errorf("lxd 的错误串应报出 `file push <本地> → <实例><目标>`；实际: %v", err)
		}
	})
}

// ============================================================================
// 变异：把 lxd 侧的 lxc 换成 docker ⇒ 用例**必须**红
// ============================================================================

// TestLXDMutationToDockerMustTurnTheCasesRed 是 Step 2 判据里那句"把假 lxc 换成假 docker 的
// 等价变异必须让用例红/绿按预期"的实现。
//
// 为什么必须在**同一份源码**上证明这一点（而不是靠通读）：lxd 路径的用例若只用假 lxc 夹具驱动，
// 那么"实现其实调的是 docker、而假 lxc 恰好也打印了同样的信封"这种错法不会被发现 —— 判据关心
// 的正是"**命令发给了谁**"。
//
// 做法：`runLXC` 是包级变量（同 `newNodeNonce` 的接缝手法），把它指到 `runDocker`，也就是那个
// 最像的错法（基质前缀认了、但二进制还是 docker）。此时：
//
// 假 lxc 的调用日志**必然不存在**（用例内部的两条断言因此变红）；
// 传给 docker 的参数里带 lxc 的 `exec --env … --` 形状，也不等于 docker 的形状。
//
// 这里把那两条断言的**判据**复算一遍，并断言它们确实不成立 —— 若将来有人把源码改回"基质前缀
// 只改标签、命令照旧给 docker"，这条用例会红。
func TestLXDMutationToDockerMustTurnTheCasesRed(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	nodeChecks := hostChecksWithFailures("RS-006")
	lxcLog := writeLXCShim(t, fakeDocker{stdout: mustEnvelope(t, "probe-ot005", nodeChecks)})
	dockerLog := writeDockerShim(t, fakeDocker{stdout: mustEnvelope(t, "probe-ot005", nodeChecks)})

	// —— 变异：lxd 路径的 lxc 换成 docker ——
	prev := runLXC
	runLXC = runDocker
	t.Cleanup(func() { runLXC = prev })

	if _, _, err := collectChecksForTarget("lxd:probe-ot005"); err != nil {
		t.Fatalf("变异之后取数仍应『成功』（它确实取到了检查集）—— 这正是危险之处：数据看起来正常: %v", err)
	}
	// 判据 1（`TestLXDNodeTargetUsesLXCAndRecordsSubstrate` 的第一条断言）：假 lxc 必须被调用过。
	if shimLogAbsent(t, lxcLog) {
		t.Log("变异已生效：假 lxc 一次都没被调用 ⇒ 那条断言会红（这正是我们想看到的）")
	} else {
		t.Fatalf("变异没有生效（假 lxc 仍被调用）⇒ 这条用例本身失效，必须修夹具而不是放行")
	}
	// 判据 2：docker 假 CLI 必须**没有**被调用 —— 变异之后它被调用了。
	if shimLogAbsent(t, dockerLog) {
		t.Fatal("变异之后 docker 仍未被调用 ⇒ 这条用例没有观测到变异")
	}
	// 判据 3：这条路发出去的 CLI **就是 docker**（这正是判据 1/2 要抓的东西）。
	//
	// 注意参数形状：变异之后 docker 收到的仍然是 `exec --env … --`（那是 `runNodeProcess` 里
	// **按基质分派**的 args，不是按二进制名生成的）—— 也就是说，单看参数形状**看不出**基质选错，
	// 只有"哪一个 CLI 被真的调用了"能看出。这句话本身就是这条用例存在的理由。
	dockerInvocations := readShimLog(t, dockerLog)
	if len(dockerInvocations) < 2 {
		t.Fatalf("变异之后应有两次 docker 调用（file push + exec），实际 %v", dockerInvocations)
	}
	if !strings.HasPrefix(dockerInvocations[0], "file push ") {
		t.Errorf("变异之后第一条调用应仍是 file push（args 由基质决定），实际 %q", dockerInvocations[0])
	}
	t.Logf("变异后的调用序列（假 lxc 为空、docker 有两条 ⇒ 判据 1/2 会红）：%v", dockerInvocations)
}

// ============================================================================
// 信封解析层：lxd 侧同样"取最后一行"（与基质无关，但要有一条钉子）
// ============================================================================

// TestParseNodeEnvelopeLastLineWinsForLXDFixture：同一段解析在 lxd 夹具上同样"取最后一行"。
//
// 这一条刻意的**冗余**：解析层与基质无关（两侧共用），但"共用"这件事一旦被将来的人拆开
// （给 lxd 另写一套解析），这一条与 lxd 侧的成功路径会一起变红 —— 而只测 docker 侧时，
// 拆开之后**两边都还是绿的**（docker 侧照旧用老实现）。故这里用 lxd 的 hostname 再钉一次。
func TestParseNodeEnvelopeLastLineWinsForLXDFixture(t *testing.T) {
	real := mustEnvelope(t, "probe-ot005", hostChecksWithFailures("RS-006"))
	forged := mustEnvelope(t, "totally-not-the-instance", hostChecksWithFailures("RS-006", "RS-007"))
	mixed := forged + "\nstray line\n" + real + "\n"
	env, err := parseNodeEnvelope([]byte(mixed), fixtureNonce)
	if err != nil {
		t.Fatalf("必须能从杂散输出里挑出真信封: %v", err)
	}
	if env.Hostname != "probe-ot005" {
		t.Errorf("必须取**最后**一行信封（真信封在后），实际 hostname=%q", env.Hostname)
	}
	// 信封是父进程解析之后才进记录的：这里的 hostname 就是记录里那个自报值。
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal 信封: %v", err)
	}
	if !strings.Contains(string(raw), "probe-ot005") {
		t.Errorf("信封里必须带节点自报的 hostname: %s", raw)
	}
}
