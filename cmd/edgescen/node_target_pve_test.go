//go:build expr && engine && checks

// 本文件是 Task 6 的用例：`-target` 的第三种**基质前缀** —— `pve:<vmid>`（dl360gen9 的 PVE CT）。
//
// 判据分三层，与 `node_target_lxd_test.go` **逐条对应**（那一轮定下的形态照搬，不另立一套）：
//
//  1. **`pve:<vmid>` 真的走 `pct`**：两条命令的形状
//     （`pct push <vmid> <本地> <目标> --perms 755`、
//     `pct exec <vmid> -- env <ENV>=<nonce> <二进制> -emit-checks`）与 docker/lxd 侧**逐项对应**，
//     而 nonce 绑定、信封解析（取最后一行）、失败一律响亮这些性质与两侧**共用同一份实现**。
//  2. **三种基质互不顶替**：跑 `pve:` 时 docker 与 lxc 假 CLI **一次都不能被调用**，
//     反之亦然。这条是"绝不静默回落"在基质维度上的形态，也是 pve 路径最容易犯的错
//     （`pct` 与 `lxc` 的命令形状在几个地方很像，写错时数据看起来完全正常）。
//  3. **nonce 绝不进参数位**（本项目最硬的一条）：`pct exec` **没有 `--env`**，实现必须用
//     `pct exec <vmid> -- env K=V <二进制> -emit-checks` 的写法。这条用例把命令**逐格拆开**断言：
//     节点内二进制收到的 argv **恰好是 `[-emit-checks]`**，nonce 只出现在 `env` 的位置参数里。
//     若将来有人图省事改成 `… <二进制> -emit-checks <nonce>` 或把 nonce 拼进开关，
//     这条用例立刻红（下面 `TestPVENonceNeverEntersNodeArgv` 就是那把尺子）。
//
// （注：条目式注释刻意**不写成 gofmt 认得的列表**（`// · …` 会被 go1.26 的 gofmt 重排）——
// 与本包其它文件同一约定。）
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/edgeexp"
)

// writePCTShim 与 writeDockerShim / writeLXCShim 同款，但放的是假 **pct**（Task 6 的 pve 基质）。
//
// 它同时是"三种基质**不能互相顶替**"这条判据的观测手段：被测代码走哪一条，
// 哪一个假 CLI 的调用日志才会出现（`pct` 与 `lxc`/`docker` 的日志是三份独立的文件）。
func writePCTShim(t *testing.T, d fakeDocker) string {
	t.Helper()
	return writeCLIShim(t, "pct", d)
}

// ============================================================================
// 语法解析：pve 的三种写法 + 报错
// ============================================================================

// TestParseNodeTargetPVESyntax：`pve:<vmid>` 的合法写法与两种报错形态。
func TestParseNodeTargetPVESyntax(t *testing.T) {
	cases := []struct {
		raw   string
		want  nodeTarget
		why   string
		bad   bool
		inErr string
	}{
		{raw: "pve:904", want: nodeTarget{substratePVE, "904"},
			why: "pve 前缀（dl360gen9 的 CT，vmid 由基质层 lab_target_spec 解析）"},
		{raw: "pve: 904", want: nodeTarget{substratePVE, "904"},
			why: "前缀后的空白同样被吃掉"},
		{raw: "  pve:904  ", want: nodeTarget{substratePVE, "904"},
			why: "两侧空白被吃掉"},
		{raw: "pve:", bad: true, inErr: "缺少 vmid",
			why: "前缀给了 vmid 为空 ⇒ 报错（不得回落本机，也不得回落 docker）"},
		{raw: "pve:   ", bad: true, inErr: "缺少 vmid", why: "同上（全是空白）"},
		{raw: "pve2:904", bad: true, inErr: "未知",
			why: "像基质前缀却不在白名单 ⇒ 专门诊断（不是让它变成一次 No such container）"},
		{raw: "PVE:904", bad: true, inErr: "未知",
			why: "前缀大小写敏感：`PVE` 不在白名单 ⇒ 报错而不是猜"},
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

// TestTargetFlagHelpNamesAllFourForms：`-h` 文案必须写明**四种**写法（三种前缀 + 裸名字/本机）。
//
// 为什么单列一条：语法只在一处实现，而 `-h` 是操作者看到的唯一说明 —— 少写一种，
// 操作者就会去猜第三种（`pve:…` 猜不出来时最可能的动作是把 CT 名字直接交给 pct，
// 而 pct 只认数字 vmid，那条错误会指向"CT 不存在"而不是"少了一层解析"）。
func TestTargetFlagHelpNamesAllFourForms(t *testing.T) {
	usage := nodeTargetFlagHelpText(t)
	for _, want := range []string{"docker:", "lxd:", "pve:", "本机"} {
		if !strings.Contains(usage, want) {
			t.Errorf("-%s 的文案里必须写明 %q；实际：%s", nodeTargetFlag, want, usage)
		}
	}
}

// ============================================================================
// pve 路径：命令形状、nonce 绑定、观测主体、不顶替
// ============================================================================

// TestPVENodeTargetUsesPCTAndRecordsSubstrate：`pve:<vmid>` 必须**真的**用 pct 取数。
//
// 逐条判据：
//  1. 只起两个 pct 子进程（`push` + `exec`），形状逐项正确；
//  2. **docker 与 lxc 两个假 CLI 一次都不能被调用**（基质选错的形态在这里变红）；
//  3. 观测主体把基质写进记录（`substrate=pve`）：否则 `lxc exec` / `pct exec` / `docker exec`
//     三种观测在数据上完全同形。
func TestPVENodeTargetUsesPCTAndRecordsSubstrate(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	nodeChecks := hostChecksWithFailures("RS-006")
	pctLog := writePCTShim(t, fakeDocker{stdout: mustEnvelope(t, "asc-tgt-c2", nodeChecks)})
	dockerLog := writeDockerShim(t, fakeDocker{stdout: "docker-shim-must-not-be-used"})
	lxcLog := writeLXCShim(t, fakeDocker{stdout: "lxc-shim-must-not-be-used"})

	host, observationTarget, err := collectChecksForTarget("pve:904")
	if err != nil {
		t.Fatalf("pve 基质取数: %v", err)
	}
	if !shimLogAbsent(t, dockerLog) {
		t.Errorf("pve 基质**不得**起任何 docker 子进程（基质选错的形态），实际留下了调用日志 %s", dockerLog)
	}
	if !shimLogAbsent(t, lxcLog) {
		t.Errorf("pve 基质**不得**起任何 lxc 子进程（lxd 与 pve 不得互相顶替），实际留下了调用日志 %s", lxcLog)
	}

	invocations := readShimLog(t, pctLog)
	if len(invocations) != 2 {
		t.Fatalf("pve 取数应当只起两个 pct 子进程（push + exec），实际 %d 条: %v", len(invocations), invocations)
	}
	// 第一条：`pct push <vmid> <本地> <目标> --perms 755`
	// （与 `lxc file push <本地> <实例><目标>` **参数顺序相反**，且目标路径独立成参。）
	pushArgs := strings.Fields(invocations[0])
	if len(pushArgs) < 5 || pushArgs[0] != "push" || pushArgs[1] != "904" {
		t.Errorf("第一次调用必须是 `pct push 904 <本地> <目标> --perms 755`，实际 %q", invocations[0])
	} else {
		if !strings.HasPrefix(pushArgs[3], "/tmp/edgescen-") {
			t.Errorf("pct push 的目标必须是 CT 内的 /tmp/edgescen-<pid>，实际 %q", pushArgs[3])
		}
		if pushArgs[len(pushArgs)-2] != "--perms" || pushArgs[len(pushArgs)-1] != "755" {
			t.Errorf("pct push 必须带 `--perms 755`（送进去就能执行），实际 %q", invocations[0])
		}
		// lxd 的 `<实例><目标>` 拼接形态**不得**出现在 pve 侧（那是把两种基质混起来的写法）。
		if strings.HasPrefix(pushArgs[3], "904") {
			t.Errorf("pct push 的目标**不得**是 lxc 的 `<实例><路径>` 拼接形态，实际 %q", pushArgs[3])
		}
	}
	// 第二条：`pct exec <vmid> -- env <ENV>=<nonce> <二进制> -emit-checks`
	execArgs := strings.Fields(invocations[1])
	if len(execArgs) != 7 {
		t.Fatalf("`pct exec` 的调用必须是**恰好七格**（exec <vmid> -- env K=V <二进制> -emit-checks），"+
			"实际 %d 格: %q", len(execArgs), invocations[1])
	}
	if execArgs[0] != "exec" || execArgs[1] != "904" || execArgs[2] != "--" {
		t.Errorf("必须是 `pct exec <vmid> --`（`--` 让 pct 把后面整串原样交给容器），实际 %q", invocations[1])
	}
	if execArgs[3] != "env" {
		t.Errorf("`pct exec` 没有 `--env`，nonce 必须经节点内的 `env` 下发，实际第 4 格是 %q（整条 %q）",
			execArgs[3], invocations[1])
	}
	if execArgs[4] != nodeNonceEnv+"="+fixtureNonce {
		t.Errorf("第 5 格必须是 `%s=%s`（nonce 经**环境变量**下发），实际 %q",
			nodeNonceEnv, fixtureNonce, execArgs[4])
	}
	if !strings.HasPrefix(execArgs[5], "/tmp/edgescen-") {
		t.Errorf("第 6 格必须是刚推进去的二进制路径，实际 %q", execArgs[5])
	}
	if execArgs[6] != emitChecksFlag {
		t.Errorf("节点内进程的入口开关必须是 %q（**前导 `-`**），实际 %q", emitChecksFlag, execArgs[6])
	}

	if len(host) != len(nodeChecks) {
		t.Fatalf("取回的检查集长度 = %d, want %d", len(host), len(nodeChecks))
	}
	for i := range nodeChecks {
		if host[i] != nodeChecks[i] {
			t.Fatalf("取回的检查集与节点载荷不同（第 %d 项）：\n got %+v\nwant %+v", i, host[i], nodeChecks[i])
		}
	}
	wantTarget := "node:904 (substrate=pve, hostname=asc-tgt-c2)"
	if observationTarget != wantTarget {
		t.Errorf("观测主体 = %q, want %q（vmid + 基质 + 节点内进程自报的 hostname）", observationTarget, wantTarget)
	}
}

// TestPVENonceNeverEntersNodeArgv 是"nonce 绑定不得削弱"在 pve 侧的**那把尺子**。
//
// 为什么单列一条（简报 §2 把这条点成"关键差异"）：`lxc exec` 有 `--env`，**`pct exec` 没有**，
// 于是 pve 侧的 nonce 只能靠节点内的 `env` 下发。这条路有两种写法看起来都对：
//
//	对： `pct exec <vmid> -- env K=V <二进制> -emit-checks`   ⇒ 节点内二进制的 argv 恰好是 [-emit-checks]
//	错： `pct exec <vmid> -- <二进制> -emit-checks <nonce>`   ⇒ nonce 进了**参数位**
//
// 第二种会让"`-emit-checks` 只接受空参数集"这道守卫退化成"有一个例外"（见 main.go 的
// rejectEmitChecksArgs），而且**行为看起来完全正常**（信封照样回来、nonce 照样对上）。
// 判据只能是"逐格拆开看 argv"：
//  1. 节点内二进制路径**后面只有一格**，且那一格就是 `-emit-checks`；
//  2. nonce **只**出现在 `env` 的位置参数里（`ENV=值` 这一格），不出现在别处。
func TestPVENonceNeverEntersNodeArgv(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	pctLog := writePCTShim(t, fakeDocker{stdout: mustEnvelope(t, "asc-tgt-c2", hostChecksWithFailures("RS-006"))})

	if _, _, err := collectChecksForTarget("pve:904"); err != nil {
		t.Fatalf("pve 基质取数: %v", err)
	}
	invocations := readShimLog(t, pctLog)
	if len(invocations) != 2 {
		t.Fatalf("应当只起两个 pct 子进程，实际 %v", invocations)
	}
	args := strings.Fields(invocations[1])
	// 二进制路径的位置：`exec <vmid> -- env K=V <二进制> -emit-checks` ⇒ 下标 5。
	const binIndex = 5
	if len(args) != binIndex+2 {
		t.Fatalf("节点内二进制之后必须**恰好**还有一格（就是入口开关），实际整条 %q", invocations[1])
	}
	if args[binIndex+1] != emitChecksFlag {
		t.Errorf("节点内二进制之后那一格必须是 %q，实际 %q", emitChecksFlag, args[binIndex+1])
	}
	// nonce 只能出现在 env 的位置参数那一格上；把它从整条命令里抹掉之后，剩下的参数里不得再出现它。
	envCell := args[binIndex-1]
	if envCell != nodeNonceEnv+"="+fixtureNonce {
		t.Fatalf("nonce 应当落在 `env` 的位置参数那一格（%s=%s），实际 %q", nodeNonceEnv, fixtureNonce, envCell)
	}
	rest := append(append([]string{}, args[:binIndex-1]...), args[binIndex:]...)
	for _, a := range rest {
		if strings.Contains(a, fixtureNonce) {
			t.Errorf("nonce 出现在参数位 %q —— nonce **绝不进参数位**（`-emit-checks` 只接受空参数集"+
				"这条性质必须保住；整条 %q）", a, invocations[1])
		}
	}

	// 反证：**真的**把 nonce 放进参数位时，节点内那道守卫必须拒绝（这是"为什么不能那样写"的
	// 正面证据，而不是一句声明）。`-emit-checks` 只接受空参数集，任何位置参数都是用法错误。
	var out, errOut strings.Builder
	if code := runCLI([]string{"-" + emitChecksFlag, fixtureNonce}, &out, &errOut); code != exitUsage {
		t.Errorf("把 nonce 放进参数位时 `-emit-checks` 退出码 = %d, want %d（拒绝），stderr:\n%s",
			code, exitUsage, errOut.String())
	}
	if !strings.Contains(errOut.String(), "只接受空参数集") {
		t.Errorf("拒绝理由必须说明这道守卫的口径（只接受空参数集）:\n%s", errOut.String())
	}
}

// ============================================================================
// 失败形态：把 docker 侧 8 种形态**逐条映射**到 pve 侧
// ============================================================================

// TestPVENodeCollectionFailuresAreLoud 是 `TestNodeCollectionFailuresAreLoud` 的 pve 版本。
//
// 8 条里有 4 条是"信封层"的（缺信封 / 标记不符 / 空集 / 缺 hostname / nonce 不匹配 / 没有 nonce），
// 它们走的是**与基质无关**的那段实现 —— 映射过来顺带证明了三侧共用同一份解析
// （若将来有人给 pve 另写一套解析，这几条会以不同的错误串变红）。
func TestPVENodeCollectionFailuresAreLoud(t *testing.T) {
	registerFixtureChecks()
	cases := []struct {
		name     string
		pct      fakeDocker
		wantInEr string
	}{
		{
			name:     "vmid 不存在",
			pct:      fakeDocker{exitCode: 2, dockerErr: "Configuration file 'nodes/pve/lxc/904.conf' does not exist"},
			wantInEr: "does not exist",
		},
		{
			name:     "pct 不可用",
			pct:      fakeDocker{exitCode: 127, dockerErr: "pct: command not found"},
			wantInEr: "command not found",
		},
		{
			name:     "stdout 里没有信封",
			pct:      fakeDocker{stdout: "not json at all"},
			wantInEr: "信封",
		},
		{
			name:     "信封标记不匹配",
			pct:      fakeDocker{stdout: `{"marker":"other","hostname":"h","checks":[{"check_id":"X"}]}`},
			wantInEr: "标记",
		},
		{
			name:     "检查集为空",
			pct:      fakeDocker{stdout: mustEnvelope(t, "asc-tgt-c2", nil)},
			wantInEr: "为空",
		},
		{
			name:     "信封没有 hostname",
			pct:      fakeDocker{stdout: mustEnvelope(t, "", hostChecksWithFailures("RS-006"))},
			wantInEr: "hostname",
		},
		{
			name:     "信封的 nonce 不匹配",
			pct:      fakeDocker{stdout: mustEnvelopeWithNonce(t, "asc-tgt-c2", "another-runs-nonce", hostChecksWithFailures("RS-006"))},
			wantInEr: "nonce",
		},
		{
			name:     "信封没有 nonce",
			pct:      fakeDocker{stdout: mustEnvelopeWithNonce(t, "asc-tgt-c2", "", hostChecksWithFailures("RS-006"))},
			wantInEr: "没有 nonce",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useFixtureNonce(t)
			writePCTShim(t, tc.pct)
			dockerLog := writeDockerShim(t, fakeDocker{stdout: "docker-shim-must-not-be-used"})
			lxcLog := writeLXCShim(t, fakeDocker{stdout: "lxc-shim-must-not-be-used"})
			host, observationTarget, err := collectChecksForTarget("pve:904")
			if err == nil {
				t.Fatal("必须**响亮失败**，绝不能静默回落（既不能回落到本机，也不能回落到 docker/lxd 基质）")
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
				t.Errorf("pve 路径失败时也不得回落到 docker 基质，实际留下了 docker 调用日志 %s", dockerLog)
			}
			if !shimLogAbsent(t, lxcLog) {
				t.Errorf("pve 路径失败时也不得回落到 lxd 基质，实际留下了 lxc 调用日志 %s", lxcLog)
			}
		})
	}
}

// TestPVETargetNeverFallsBackWhenPCTMissing：PATH 上**没有** pct 时同样必须报错。
//
// 单独列出的理由与 docker/lxd 侧相同：这是最容易写成"起不了 pct 就换一种基质/本机"的那个分支，
// 而它产出的记录与真正的 pve 采集**在字段上无法区分**（只有 env 那个手填标签能看出区别）。
func TestPVETargetNeverFallsBackWhenPCTMissing(t *testing.T) {
	registerFixtureChecks()
	t.Setenv("PATH", t.TempDir())
	host, target, err := collectChecksForTarget("pve:904")
	if err == nil {
		t.Fatal("pct 不可用时必须报错，不得回落到 docker/lxd 或本机")
	}
	if host != nil || target != "" {
		t.Fatalf("必须返回空结果，实际 host=%d target=%q", len(host), target)
	}
}

// ============================================================================
// 端到端：CLI 走 pve 写出的记录
// ============================================================================

// TestCLIPVETargetWritesRecordWithSubstrate：CLI 端到端 —— `--target pve:<vmid>` 写出的记录必须
// 能被消费者读回，`meta.observation_target` 说明它出自哪个 vmid**以及哪种基质**。
func TestCLIPVETargetWritesRecordWithSubstrate(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	dir := t.TempDir()
	writePCTShim(t, fakeDocker{stdout: mustEnvelope(t, "asc-tgt-c2", hostChecksWithFailures("RS-006"))})
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
		"--out", outPath, "--run", "1", "--env", "pve-dl360", "--target", "pve:904",
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
	want := "node:904 (substrate=pve, hostname=asc-tgt-c2)"
	if recs[0].Meta.ObservationTarget != want {
		t.Errorf("meta.observation_target = %q, want %q", recs[0].Meta.ObservationTarget, want)
	}
	if !strings.Contains(stdout.String(), "观测主体：") {
		t.Errorf("节点内评估的日志必须打印观测主体那一行:\n%s", stdout.String())
	}
	failed := map[string]bool{}
	for _, ck := range recs[0].Observed.Checks {
		failed[ck.ID] = true
	}
	if !failed["RS-006"] {
		t.Errorf("R 组的自然失败必须来自**节点**的检查集，实际失败检查: %v", failed)
	}
	if !shimLogAbsent(t, dockerLog) {
		t.Errorf("pve 端到端路径不得起 docker 子进程，实际留下了调用日志 %s", dockerLog)
	}
}

// TestPVETargetRefusesToWriteWhenEnvelopeIsForged：把"nonce 绑定的两个方向"钉在 pve 侧。
//
// 两个方向**必须分开报**（诊断不同、处置也不同）：nonce **不匹配**（另一次运行/另一个进程）
// 与**没有 nonce**（残留的旧二进制）。两种伪造信封都必须让整轮失败且**不写任何记录**。
func TestPVETargetRefusesToWriteWhenEnvelopeIsForged(t *testing.T) {
	cases := []struct {
		name     string
		forge    func(t *testing.T) string
		wantInEr string
	}{
		{
			name: "nonce 不匹配（另一次运行）",
			forge: func(t *testing.T) string {
				return mustEnvelopeWithNonce(t, "asc-tgt-c2", "stale-run-nonce", hostChecksWithFailures("RS-006"))
			},
			wantInEr: "nonce",
		},
		{
			name: "没有 nonce（旧二进制/别人的输出）",
			forge: func(t *testing.T) string {
				return mustEnvelopeWithNonce(t, "asc-tgt-c2", "", hostChecksWithFailures("RS-006"))
			},
			wantInEr: "没有 nonce",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registerFixtureChecks()
			useFixtureNonce(t)
			dir := t.TempDir()
			writePCTShim(t, fakeDocker{stdout: tc.forge(t)})
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
				"--out", outPath, "--target", "pve:904",
			}, &stdout, &stderr)
			if code == exitOK {
				t.Fatalf("伪造的信封必须让整轮失败，实际退出码 0\nstdout:\n%s", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantInEr) {
				t.Errorf("失败原因必须含 %q: %s", tc.wantInEr, stderr.String())
			}
			if _, err := os.Stat(outPath); !os.IsNotExist(err) {
				t.Errorf("失败时**不得**写出任何记录（不写半条记录是既有纪律），实际 %s 存在", outPath)
			}
		})
	}
}

// ============================================================================
// 错误串：pct 侧按自己的形状报（不受 docker 字面量约束）
// ============================================================================

// TestPCTErrorStringsPointAtTheRealCause：pct 的失败要报出**排障要看的那两个东西**。
//
// 与 docker 侧不同，pct 侧是**新**基质，没有"不许变"的历史包袱 —— 说得更准才有用：
//  1. `pct push <vmid> <本地> <目标>` 失败 ⇒ 报出**本地文件 → 目标**；
//  2. `pct exec` 失败 ⇒ 报出完整的 exec 命令。
//
// 为什么值得单列：`pct push` 的目标路径与 `lxc file push` 的拼接形态不同，
// 而"推进去失败"最常见的两个原因（本地文件不可读 / 目标目录不存在）只能靠这两个值区分；
// 只报一句"pct 失败"会让操作者去查 vmid，而 vmid 根本没错。
func TestPCTErrorStringsPointAtTheRealCause(t *testing.T) {
	t.Run("pct push 失败 ⇒ 报出 本地 → 目标", func(t *testing.T) {
		useFixtureNonce(t)
		writePCTShim(t, fakeDocker{exitCode: 2, dockerErr: "ERROR: no such container"})
		_, _, err := collectChecksForTarget("pve:904")
		if err == nil {
			t.Fatal("必须报错")
		}
		if !strings.Contains(err.Error(), "pct push ") || !strings.Contains(err.Error(), " → ") {
			t.Errorf("pct 的错误串应报出 `push <本地> → <目标>`；实际: %v", err)
		}
		if !strings.Contains(err.Error(), "no such container") {
			t.Errorf("pct 自己的 stderr 必须原样带进错误；实际: %v", err)
		}
	})

	t.Run("pct exec 失败 ⇒ 报出完整的 exec 命令", func(t *testing.T) {
		useFixtureNonce(t)
		dir := t.TempDir()
		// push 必须成功、exec 必须失败。
		script := "#!/bin/sh\n" +
			"if [ \"$1\" = \"push\" ]; then exit 0; fi\n" +
			"echo 'ERROR: CT is not running' 1>&2\nexit 2\n"
		if err := os.WriteFile(filepath.Join(dir, "pct"), []byte(script), 0o755); err != nil {
			t.Fatalf("写假 pct: %v", err)
		}
		bat := "@echo off\r\nif \"%1\"==\"push\" exit /b 0\r\n" +
			"echo ERROR: CT is not running 1>&2\r\nexit /b 2\r\n"
		if err := os.WriteFile(filepath.Join(dir, "pct.bat"), []byte(bat), 0o755); err != nil {
			t.Fatalf("写假 pct.bat: %v", err)
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

		_, _, err := collectChecksForTarget("pve:904")
		if err == nil {
			t.Fatal("必须报错")
		}
		if !strings.Contains(err.Error(), "pct exec 失败（exec 904 -- env "+nodeNonceEnv+"=") {
			t.Errorf("pct exec 的错误串应报出完整的 exec 命令；实际: %v", err)
		}
		if !strings.Contains(err.Error(), "CT is not running") {
			t.Errorf("pct 自己的 stderr 必须原样带进错误；实际: %v", err)
		}
	})
}

// ============================================================================
// 变异：把 pve 侧的 pct 换成 docker ⇒ 用例**必须**红
// ============================================================================

// TestPVEMutationToDockerMustTurnTheCasesRed 是"pve 路径必须**真的**用 pct"这条判据的变异证明。
//
// 做法与 lxd 侧同款：`runPCT` 是包级变量（与 `newNodeNonce`/`runLXC` 同一个接缝手法），把它指到
// `runDocker`，也就是那个最像的错法（`pve:` 前缀认了、但二进制还是 docker）。此时：
//
//	· 假 pct 的调用日志**必然不存在**（`TestPVENodeTargetUsesPCTAndRecordsSubstrate` 会红）；
//	· 假 docker 被调用了（那条"不得起任何 docker 子进程"的断言会红）；
//	· 数据本身**完全正常**（信封照旧取回来）—— 这正是危险之处，也是这条用例存在的理由。
func TestPVEMutationToDockerMustTurnTheCasesRed(t *testing.T) {
	registerFixtureChecks()
	useFixtureNonce(t)
	nodeChecks := hostChecksWithFailures("RS-006")
	pctLog := writePCTShim(t, fakeDocker{stdout: mustEnvelope(t, "asc-tgt-c2", nodeChecks)})
	dockerLog := writeDockerShim(t, fakeDocker{stdout: mustEnvelope(t, "asc-tgt-c2", nodeChecks)})

	prev := runPCT
	runPCT = runDocker
	t.Cleanup(func() { runPCT = prev })

	if _, _, err := collectChecksForTarget("pve:904"); err != nil {
		t.Fatalf("变异之后取数仍应『成功』（它确实取到了检查集）—— 这正是危险之处：数据看起来正常: %v", err)
	}
	if shimLogAbsent(t, pctLog) {
		t.Log("变异已生效：假 pct 一次都没被调用 ⇒ 那条断言会红（这正是我们想看到的）")
	} else {
		t.Fatalf("变异没有生效（假 pct 仍被调用）⇒ 这条用例本身失效，必须修夹具而不是放行")
	}
	if shimLogAbsent(t, dockerLog) {
		t.Fatal("变异之后 docker 仍未被调用 ⇒ 这条用例没有观测到变异")
	}
	// 判据 3：变异后发出去的形状**就是 pve 的形状**（args 由 runNodeProcess 按基质分派，
	// 不是按二进制名生成的）—— 也就是说，单看参数形状**看不出**基质选错，
	// 只有"哪一个 CLI 被真的调用了"能看出。这句话本身就是这条用例存在的理由。
	dockerInvocations := readShimLog(t, dockerLog)
	if len(dockerInvocations) < 2 {
		t.Fatalf("变异之后应有两次 docker 调用（push + exec），实际 %v", dockerInvocations)
	}
	if !strings.HasPrefix(dockerInvocations[0], "push 904 ") {
		t.Errorf("变异之后第一条调用应仍是 pct 的 push 形状（args 由基质决定），实际 %q", dockerInvocations[0])
	}
	if !strings.Contains(dockerInvocations[1], "-- env "+nodeNonceEnv+"=") {
		t.Errorf("变异之后第二条调用应仍是 `-- env K=V …` 形状，实际 %q", dockerInvocations[1])
	}
	t.Logf("变异后的调用序列（假 pct 为空、docker 有两条 ⇒ 判据会红）：%v", dockerInvocations)
}

// ============================================================================
// 信封解析层：pve 侧同样"取最后一行"（与基质无关，但要有一条钉子）
// ============================================================================

// TestParseNodeEnvelopeLastLineWinsForPVEFixture：同一段解析在 pve 夹具上同样"取最后一行"。
//
// 这一条刻意的**冗余**：解析层与基质无关（三侧共用），但"共用"这件事一旦被将来的人拆开
// （给 pve 另写一套解析），这一条会与 pve 侧的成功路径一起变红 —— 而只测 docker 侧时，
// 拆开之后**两边都还是绿的**。故这里用 pve 夹具的 hostname 再钉一次。
func TestParseNodeEnvelopeLastLineWinsForPVEFixture(t *testing.T) {
	real := mustEnvelope(t, "asc-tgt-c2", hostChecksWithFailures("RS-006"))
	forged := mustEnvelope(t, "totally-not-the-ct", hostChecksWithFailures("RS-006", "RS-007"))
	mixed := forged + "\nstray line\n" + real + "\n"
	env, err := parseNodeEnvelope([]byte(mixed), fixtureNonce)
	if err != nil {
		t.Fatalf("必须能从杂散输出里挑出真信封: %v", err)
	}
	if env.Hostname != "asc-tgt-c2" {
		t.Errorf("必须取**最后**一行信封（真信封在后），实际 hostname=%q", env.Hostname)
	}
}
