//go:build expr && engine && checks

// 本文件实现"观测主体在节点内"这条**可选**路径（Task 4C Step 1/2）。
//
// 为什么需要它（C1 只读勘测的实测结论）：本工具此前**没有**任何 target/host 参数，
// `runHostChecks()` 跑的是"跑 edgescen 的这台机器"的检查登记表 —— 冒烟记录因此描述的是
// **WSL 开发机**（输出路径 `/mnt/f/...` 是铁证），而被攻击的节点是 host1 容器、
// ground truth（`compromised`）来自 host1 上的 Caldera agent。观测主体错位会让
// "记录描述这次部署"这个前提不成立，而记录本身看起来完全正常。
//
// 三条纪律：
//
//  1. **additive**：不传 `-target` 时取数路径与今天**逐位一致**（同一个 `runHostChecks()`、
//     同一个切片原样交给装配层），且这条有显式用例钉住（main_test.go 的
//     `TestCollectChecksForTargetDefaultsToLocalHostChecks`）。
//  2. **绝不静默回落到本机**：目标缺失、docker 不可用、节点内进程失败、取回的检查集为空
//     —— 一律报错退出，绝不"改用本机结果继续跑"。那正是今天这个缺陷最危险的形态：
//     记录看起来是节点数据，实际是宿主数据。
//  3. **同一份二进制**：节点里跑的就是本进程自己（`os.Executable()`），不是另一个工具 ——
//     "节点内评估"与"宿主评估"因此只差**运行位置**这一个变量，检查登记表、引擎版本、
//     注入逻辑完全相同。`-emit-checks` 是那个二进制在节点内的入口（只读、只输出检查结果）。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/chins-xing/asscor/internal/checks"
	"github.com/chins-xing/asscor/internal/model"
)

// nodeEnvelopeMagic 是节点内进程输出的信封标记（`-emit-checks`）。
//
// 为什么要有显式标记而不是"stdout 就是一个数组"：将来任何一行杂散输出（Go 运行时的
// 日志、检查项自己打的字）都会让父进程解析失败或解析到错的东西。带标记的信封让父进程
// 能**挑出**自己那一行，而不是把整个 stdout 赌成一份 JSON。
const nodeEnvelopeMagic = "edgescen.node-checks.v1"

// nodeCheckEnvelope 是节点内进程交给父进程的载荷：**运行位置的自证**（hostname 来自节点内
// 进程自己的 `os.Hostname()`）+ 该节点上登记表的全部检查结果。
//
// hostname 不是"顺手带的诊断信息"：它是父进程唯一能找到的、关于"数据出自哪台机器"的
// 机器可读证据（见 record.go 里 `Meta.ObservationTarget` 的说明）。
type nodeCheckEnvelope struct {
	Marker   string              `json:"marker"`
	Hostname string              `json:"hostname"`
	Checks   []model.CheckResult `json:"checks"`
}

// parseNodeEnvelope 从节点内进程的 stdout 里取出信封。
//
// 解析失败必须**报错**：把"没解析出检查集"当成空集会让装配层拿到一个空检查集，
// 而空检查集的记录看起来像"这台机器什么检查都没失败"—— 那是本条路径最坏的静默形态。
func parseNodeEnvelope(stdout []byte) (nodeCheckEnvelope, error) {
	line := findEnvelopeLine(stdout)
	if line == nil {
		return nodeCheckEnvelope{}, fmt.Errorf("节点内进程的 stdout 里没有 `%s` 信封（前 400 字节: %s）",
			nodeEnvelopeMagic, truncate(string(stdout), 400))
	}
	var env nodeCheckEnvelope
	if err := json.Unmarshal(line, &env); err != nil {
		return nodeCheckEnvelope{}, fmt.Errorf("节点内进程的信封不是合法 JSON: %w", err)
	}
	if env.Marker != nodeEnvelopeMagic {
		return nodeCheckEnvelope{}, fmt.Errorf("节点内进程的信封标记是 %q，want %q —— 不是本工具的输出（版本不匹配？）",
			env.Marker, nodeEnvelopeMagic)
	}
	if strings.TrimSpace(env.Hostname) == "" {
		return nodeCheckEnvelope{}, fmt.Errorf("节点内进程没有报出自己的 hostname —— 记录将无法说明观测出自哪台机器")
	}
	if len(env.Checks) == 0 {
		return nodeCheckEnvelope{}, fmt.Errorf("节点内取回的检查集为空 —— 该节点上没有注册任何检查（平台闸门不匹配 / 二进制被截断）；" +
			"空集会让记录看起来像『这台机器什么检查都没失败』")
	}
	return env, nil
}

// findEnvelopeLine 逐行找出信封（每行尝试一次解析），跳过所有杂散输出。
//
// 判据刻意**不是**"这一行含 magic 字符串"：那样一来"标记不匹配"（例如节点里残留的是另一个
// 版本的信封）会退化成"根本没有信封"，而这两种情况的处置完全不同（前者要换二进制，后者要查
// 节点内进程为什么什么都没输出）。这里改为认"带 marker 字段的 JSON 行"，标记本身由
// parseNodeEnvelope 核对。
func findEnvelopeLine(stdout []byte) []byte {
	for _, raw := range bytes.Split(stdout, []byte("\n")) {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 || line[0] != '{' || !json.Valid(line) {
			continue
		}
		var probe struct {
			Marker string `json:"marker"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			continue
		}
		if probe.Marker != "" {
			return line
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// collectChecksForTarget 是本工具的**唯一取数分派点**。
//
// target 为空 ⇒ 与今天逐位一致：`runHostChecks()` 的结果原样返回（同一个切片、同一个顺序）。
// target 非空 ⇒ 在目标节点内跑同一份二进制取回检查集；任何一种失败都返回错误，
// **绝不**退回本机结果。
func collectChecksForTarget(target string) ([]model.CheckResult, string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return runHostChecks(), "", nil
	}
	env, err := fetchNodeChecks(target)
	if err != nil {
		return nil, "", err
	}
	return env.Checks, observationTargetNode(target, env.Hostname), nil
}

// observationTargetNode 是记录里"这次评估发生在哪台机器"的取值（进 `meta.observation_target`）。
//
// 同时带上容器名与容器内 hostname：前者是操作者用来复现的那把钥匙（`docker exec <name>`），
// 后者是**节点内进程自己报的**、不依赖操作者那个标签写对 —— 两者都在，读者不必相信任何一个。
func observationTargetNode(target, hostname string) string {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "node:" + target
	}
	return fmt.Sprintf("node:%s (hostname=%s)", target, hostname)
}

// fetchNodeChecks 把**本进程自己的可执行文件**送进目标节点执行，取回该节点的检查结果。
//
// 为什么送二进制而不是"在节点里另装一个工具"：同一份二进制 ⇒ 会话里的评分链、检查登记表、
// 甚至检查实现都与宿主路径是同一份代码，唯一变量是**运行位置**。任何"节点里跑另一个版本"
// 的形态都会让两份数据不可比，而差异看起来只是"节点更严格"。
func fetchNodeChecks(target string) (nodeCheckEnvelope, error) {
	bin, err := os.Executable()
	if err != nil {
		return nodeCheckEnvelope{}, fmt.Errorf("节点内采集：取本进程可执行文件路径失败: %w", err)
	}
	containerPath, err := copyBinaryIntoNode(target, bin)
	if err != nil {
		return nodeCheckEnvelope{}, err
	}
	stdout, err := runDockerExec(target, containerPath, emitChecksFlag)
	if err != nil {
		return nodeCheckEnvelope{}, err
	}
	return parseNodeEnvelope(stdout)
}

// copyBinaryIntoNode 把二进制 `docker cp` 进节点并返回容器内路径。
//
// 覆盖容器的 `/tmp/edgescen-<pid>`：**每次采集都重新送**，绝不复用节点里可能残留的旧二进制
// —— 旧二进制会让"同一份二进制"这条前提静默失效（节点里跑的是上一次修复前的版本，
// 而数据看起来只是一点点不同）。
func copyBinaryIntoNode(target, localPath string) (string, error) {
	dest := fmt.Sprintf("/tmp/edgescen-%d", os.Getpid())
	if _, err := runDocker("cp", localPath, target+":"+dest); err != nil {
		return "", err
	}
	return dest, nil
}

// runDockerExec 在目标节点内执行刚送进去的二进制，返回它的 stdout。
//
// 只传 `-emit-checks`：节点内进程不装载配置、不读 harness 产物、不评分，只把**登记表的
// 原始检查结果**交出来（评分与装配仍由父进程做 —— 那是本工具的全部契约与自检所在，
// 不能在节点里重跑第二遍）。因此也就不需要把配置/harness 产物也送进容器。
func runDockerExec(target, containerPath, emitFlag string) ([]byte, error) {
	return runDocker("exec", target, containerPath, emitFlag)
}

// runDocker 执行一次 docker 子命令（stdout/stderr 分开收集）。
//
// 失败时把 docker 的 stderr **原样带进错误**：目标不存在、容器没在跑、docker 不在 PATH
// —— 这三种情况的处置完全不同，笼统地说"节点采集失败"会让操作者去查错的东西。
func runDocker(args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		switch args[0] {
		case "cp":
			return nil, fmt.Errorf("节点内采集：docker cp %s 失败: %s", args[2], detail)
		case "exec":
			return nil, fmt.Errorf("节点内采集：docker exec %s %s 失败: %s", args[1], args[2], detail)
		}
		return nil, fmt.Errorf("节点内采集：docker %s 失败: %s", strings.Join(args, " "), detail)
	}
	return stdout.Bytes(), nil
}

// emitChecksPayload 是 `-emit-checks` 模式产出的信封（节点内进程调用）。
//
// 检查集取自**节点自己的**登记表（`checks.GetAll()`：平台闸门按 `runtime.GOOS` 过滤，
// 容器是 Linux ⇒ 75 条全部注册），逐条执行一次。
func emitChecksPayload() ([]byte, error) {
	items := checks.GetAll()
	out := make([]model.CheckResult, 0, len(items))
	for _, item := range items {
		out = append(out, item.Run())
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	return json.Marshal(nodeCheckEnvelope{Marker: nodeEnvelopeMagic, Hostname: hostname, Checks: out})
}
