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
//  2. **绝不静默回落到本机**：目标缺失、基质 CLI 不可用、节点内进程失败、取回的检查集为空
//     —— 一律报错退出，绝不"改用本机结果继续跑"。那正是今天这个缺陷最危险的形态：
//     记录看起来是节点数据，实际是宿主数据。
//  3. **同一份二进制**：节点里跑的就是本进程自己（`os.Executable()`），不是另一个工具 ——
//     "节点内评估"与"宿主评估"因此只差**运行位置**这一个变量，检查登记表、引擎版本、
//     注入逻辑完全相同。`-emit-checks` 是那个二进制在节点内的入口（只读、只输出检查结果）。
//
// Task 4D Step 2 起，本文件同时是**两种基质**的取数实现（`-target docker:<容器>` / `lxd:<实例>`）：
// 上面三条纪律在两种基质上逐条成立。基质只决定两件事 —— 怎么把文件送进去（`docker cp` vs
// `lxc file push`）、怎么让它执行（`docker exec -e` vs `lxc exec --env … --`）；**nonce 绑定、
// 信封解析（取最后一行）、失败一律响亮**这些性质全部共用同一份实现，不存在"lxd 侧另有一套
// 判据"（那种分叉迟早会让其中一边退化，而从数据上看不出来）。
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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

// nodeNonceEnv 是下发一次性 nonce 的**环境变量名**（不是命令行参数）。
//
// 为什么用环境变量而不是 `-emit-checks <nonce>`：`-emit-checks` 只接受空参数集这条性质
// 本身是一道守卫（见 main.go 的 rejectEmitChecksArgs），把 nonce 塞进参数位就等于给它开了
// 一个"合法参数"，那道守卫立刻退化成"有一个例外"。`docker exec -e`（lxd 侧是
// `lxc exec --env`）不改 argv，两件事互不干扰。
const nodeNonceEnv = "EDGESCEN_NODE_NONCE"

// nodeSubstrate 是节点采集的**基质**（Task 4D Step 2）：同一份二进制在这两种基质上都能跑，
// 区别只有"怎么把文件送进去、怎么让它执行"。
type nodeSubstrate string

const (
	// substrateDocker = 今天的基质（Docker/ContainerLab 容器）—— `docker cp` + `docker exec -e`。
	// 裸节点名（不带前缀）也走这条，保持向后兼容。
	substrateDocker nodeSubstrate = "docker"
	// substrateLXD = A-1 上的 LXD 实例 —— `lxc file push` + `lxc exec --env … --`。
	// 用户 2026-09-12 裁定实验基质搬到 A-1（LXD，环境真实），这是那条路径的入口。
	substrateLXD nodeSubstrate = "lxd"
)

// targetPrefixDocker / targetPrefixLXD 是 `-target` 的**基质前缀**（`docker:<名>` / `lxd:<名>`）。
//
// 为什么要有前缀（而不是一个 `-substrate` 开关）：观测主体是**每一条记录**的属性，而不是
// 整个进程的属性 —— 一个进程内混采两种基质时，开关式的写法会让"这条记录采自哪里"取决于
// 调用顺序。前缀把它绑在目标本身（`-target lxd:probe-ot005`），跨工具也就一个拼写。
const (
	targetPrefixDocker = string(substrateDocker) + ":"
	targetPrefixLXD    = string(substrateLXD) + ":"
)

// nodeTarget 是解析后的 `-target`：**基质 + 节点名**。
type nodeTarget struct {
	Substrate nodeSubstrate
	Node      string
}

// parseNodeTarget 解析 `-target`，语法三种（`-h` 文案与错误串里必须写明同一套）：
//
//	""                 ⇒ 由调用方处理（collectChecksForTarget 的默认路径 = 本机）
//	<裸名字>            ⇒ docker（**向后兼容**：Task 4C 以来的语义，逐位不变）
//	docker:<容器>       ⇒ docker（与裸名字等价，只是把基质显式写出来）
//	lxd:<实例>          ⇒ lxd（新）
//
// 为什么"未知前缀"必须报错而不是当成裸名字：`lxd:probe-ot005` 里的名字若被当成
// **docker 容器名**，docker 会以 `No such container: lxd:probe-ot005` 失败 —— 那条错误指向
// 一个不存在的容器，而真正的原因是基质名拼错。判据是"冒号**前面**那一段是否像一个基质名"
// （`[A-Za-z0-9_-]+`）且冒号后面还有名字：**看着像基质前缀却不在白名单**一律报错
// （`foo:bar` 里的 `foo` 完全可能是个拼错的基质名，报出来比让它变成一次"容器不存在"有用得多）。
// 只有"冒号前面不像标识符"（例如路径或 IPv6 里的冒号）才继续按今天的裸名字语义走 docker。
func parseNodeTarget(target string) (nodeTarget, error) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return nodeTarget{}, fmt.Errorf("节点内采集：target 为空（空串的语义是『本机』，由调用方处理）")
	}
	switch {
	case strings.HasPrefix(raw, targetPrefixDocker):
		node := strings.TrimSpace(strings.TrimPrefix(raw, targetPrefixDocker))
		if node == "" {
			return nodeTarget{}, fmt.Errorf("节点内采集：target %q 缺少节点名（用法：%s<容器名>）", raw, targetPrefixDocker)
		}
		return nodeTarget{Substrate: substrateDocker, Node: node}, nil
	case strings.HasPrefix(raw, targetPrefixLXD):
		node := strings.TrimSpace(strings.TrimPrefix(raw, targetPrefixLXD))
		if node == "" {
			return nodeTarget{}, fmt.Errorf("节点内采集：target %q 缺少实例名（用法：%s<实例名>）", raw, targetPrefixLXD)
		}
		return nodeTarget{Substrate: substrateLXD, Node: node}, nil
	}
	if i := strings.Index(raw, ":"); i >= 0 {
		prefix := raw[:i]
		// 只有"像一个基质前缀"时才报错：前缀是纯字母/数字/下划线/连字符（即一个标识符）而后面
		// 还有名字。`foo:bar` 因此仍然按今天的裸名字走 docker，不会因本次改动改变语义。
		if isIdentifier(prefix) && strings.TrimSpace(raw[i+1:]) != "" {
			return nodeTarget{}, fmt.Errorf("节点内采集：target %q 的基质前缀 %q 未知（只认 %q 与 %q；"+
				"不带前缀的裸名字按 %s 处理）", raw, prefix, strings.TrimPrefix(targetPrefixDocker, ":"),
				strings.TrimPrefix(targetPrefixLXD, ":"), substrateDocker)
		}
	}
	return nodeTarget{Substrate: substrateDocker, Node: raw}, nil
}

// isIdentifier 判断一段文本是否"像一个基质名"（`[A-Za-z0-9_-]+`）。
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// nodeCheckEnvelope 是节点内进程交给父进程的载荷：**节点内进程自报的运行位置**
// （hostname 来自节点内进程自己的 `os.Hostname()`）+ 该节点上登记表的全部检查结果。
//
// hostname 不是"顺手带的诊断信息"：它是父进程唯一能找到的、关于"数据出自哪台机器"的
// 机器可读证据（见 record.go 里 `Meta.ObservationTarget` 的说明）。
//
// **它同时不是防伪凭据**（Fix round 1 / I-2）：hostname 与 nonce 都是节点内进程自己写出来的，
// 而本任务的前提恰恰是"要评估的那台机器可能已被攻陷"——被控节点上的进程**本来就能撒谎**
// （换掉二进制、包装一层 shell、直接伪造整个信封）。这里防的是**事故性顶替**：
// 容器里残留的另一个版本二进制、某个检查/包装脚本多打的一行 JSON 日志、多版本并存时的
// 乱序输出 —— nonce 是本次运行生成、只经环境变量交给本次 `docker exec` 的，
// 那些来源拿不到它，于是它们的信封会被拒绝而不是被当成真信封。
type nodeCheckEnvelope struct {
	Marker   string              `json:"marker"`
	Nonce    string              `json:"nonce"`
	Hostname string              `json:"hostname"`
	Checks   []model.CheckResult `json:"checks"`
}

// parseNodeEnvelope 从节点内进程的 stdout 里取出信封并校验它属于**本次运行**。
//
// 解析失败必须**报错**：把"没解析出检查集"当成空集会让装配层拿到一个空检查集，
// 而空检查集的记录看起来像"这台机器什么检查都没失败"—— 那是本条路径最坏的静默形态。
//
// 四条校验逐条都有独立的诊断（Fix round 1 / I-2 把第 2 条补上）：
//  1. marker 必须是本工具的标记；
//  2. **nonce 必须非空且等于本次运行下发的那个** —— "没有 nonce"（旧二进制 / 别人的输出）
//     与"nonce 不匹配"（另一个进程 / 另一次运行）分开报，因为处置不同；
//  3. hostname 非空；
//  4. 检查集非空。
func parseNodeEnvelope(stdout []byte, wantNonce string) (nodeCheckEnvelope, error) {
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
	if strings.TrimSpace(env.Nonce) == "" {
		return nodeCheckEnvelope{}, fmt.Errorf("节点内进程的信封没有 nonce —— 它不是本次运行调起来的那个进程"+
			"（残留的旧二进制 / 别人的输出；本次下发的 nonce 经环境变量 %s 传递）", nodeNonceEnv)
	}
	if env.Nonce != wantNonce {
		return nodeCheckEnvelope{}, fmt.Errorf("节点内进程回显的 nonce 与本次运行下发的不同（本次请求 %d 字节）—— "+
			"这份信封来自另一次运行/另一个进程，不能当作本次观测", len(wantNonce))
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

// findEnvelopeLine 逐行找出信封（每行尝试一次解析），跳过所有杂散输出，**取最后一行**。
//
// 判据刻意**不是**"这一行含 magic 字符串"：那样一来"标记不匹配"（例如节点里残留的是另一个
// 版本的信封）会退化成"根本没有信封"，而这两种情况的处置完全不同（前者要换二进制，后者要查
// 节点内进程为什么什么都没输出）。这里改为认"带 marker 字段的 JSON 行"，标记本身由
// parseNodeEnvelope 核对。
//
// **为什么是最后一行**（Fix round 1 / I-2）：本工具的信封必然是 stdout 上最后一段输出
// （节点内进程跑完登记表才写它，之后立即退出）；而"取第一个"会让**任何**先于它出现的一行
// 带 marker 的 JSON（残留进程的输出、某个检查多打的一行 JSON 日志）**顶替**真信封 ——
// 实测过的最坏形态是：真信封是空集（本该判失败），前面一行伪造信封带着 8 条检查，
// 整轮被悄悄救成"一切正常"。取最后一行把"顶替"压成"被顶替也无害"（最后一行的候选者
// 只有本进程自己的输出），nonce 再叠一层"属于本次运行"的绑定。
func findEnvelopeLine(stdout []byte) []byte {
	var last []byte
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
			last = line
		}
	}
	return last
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// collectChecksForTarget 是本工具的**唯一取数分派点**（Task 4D Step 2 起 target 带基质前缀）。
//
// target 为空 ⇒ 与今天逐位一致：`runHostChecks()` 的结果原样返回（同一个切片、同一个顺序）。
// target 非空 ⇒ 解析出**基质**（docker|lxd）与节点名，在目标节点内跑同一份二进制取回检查集；
// 任何一种失败都返回错误，**绝不**退回本机结果。
func collectChecksForTarget(target string) ([]model.CheckResult, string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return runHostChecks(), "", nil
	}
	nt, err := parseNodeTarget(target)
	if err != nil {
		return nil, "", err
	}
	env, err := fetchNodeChecks(nt)
	if err != nil {
		return nil, "", err
	}
	return env.Checks, observationTargetNode(nt, env.Hostname), nil
}

// observationTargetNode 是记录里"这次评估发生在哪台机器"的取值（进 `meta.observation_target`）。
//
// 同时带上**节点名**与节点内 hostname：前者是操作者用来复现的那把钥匙
// （`docker exec <容器>`），后者是**节点内进程自己报的** —— 它是"节点侧自报"而不是"自证"
// （I-2）：被控节点上的进程本来就能报出任何 hostname。它的价值在于**事故性**区分
// （本机路径 vs 节点路径、哪个节点被真的 exec 过），不构成密码学证据。
//
// **docker 的取值逐字不变**（Task 4D Step 2 钉住）：裸名字与 `docker:<容器>` 都产出
// `node:<容器> (hostname=…)` —— 上一个任务已经落盘的记录、以及所有既有断言都按这个形状写。
// 只有 lxd 基质额外印出 `substrate=lxd`：非默认基质必须能从记录里看出来，否则
// `docker exec host1` 与 `lxc exec host1 --` 两种观测在数据上完全同形。
//
// hostname 为空的情形已经在 `parseNodeEnvelope` 被拒（那里有独立诊断），故这里不再有
// "回退成 node:<target>" 的分支 —— 那种回退一旦可达就会产出一条**更弱**的取值
// （丢掉节点自报的 hostname），恰是本函数最该避免的"看起来正常但没有机器证据"的形态。
func observationTargetNode(nt nodeTarget, hostname string) string {
	host := strings.TrimSpace(hostname)
	if nt.Substrate == substrateDocker {
		return fmt.Sprintf("node:%s (hostname=%s)", nt.Node, host)
	}
	return fmt.Sprintf("node:%s (substrate=%s, hostname=%s)", nt.Node, nt.Substrate, host)
}

// fetchNodeChecks 把**本进程自己的可执行文件**送进目标节点执行，取回该节点的检查结果。
//
// 为什么送二进制而不是"在节点里另装一个工具"：同一份二进制 ⇒ 会话里的评分链、检查登记表、
// 甚至检查实现都与宿主路径是同一份代码，唯一变量是**运行位置**。任何"节点里跑另一个版本"
// 的形态都会让两份数据不可比，而差异看起来只是"节点更严格"。
func fetchNodeChecks(nt nodeTarget) (nodeCheckEnvelope, error) {
	bin, err := os.Executable()
	if err != nil {
		return nodeCheckEnvelope{}, fmt.Errorf("%s 内采集：取本进程可执行文件路径失败: %w", nt.Substrate, err)
	}
	// 一次性 nonce（Fix round 1 / I-2）：本次运行生成、只经环境变量交给**本次**节点执行命令，
	// 故它同时把"不是本次运行的信封"排除掉（残留二进制、另一次运行、别人打的 JSON 行）。
	nonce, err := newNodeNonce()
	if err != nil {
		return nodeCheckEnvelope{}, err
	}
	containerPath, err := copyBinaryIntoNode(nt, bin)
	if err != nil {
		return nodeCheckEnvelope{}, err
	}
	stdout, err := runNodeProcess(nt, containerPath, emitChecksFlag, nonce)
	if err != nil {
		return nodeCheckEnvelope{}, err
	}
	return parseNodeEnvelope(stdout, nonce)
}

// newNodeNonce 生成一次性 nonce（16 字节随机、hex 编码）。
//
// 它是**包级变量**而不是直接调用 `rand.Read`，唯一目的是给用例一个接缝：真实 nonce 每次运行
// 都不同，静态夹具（假 CLI 的固定 stdout）无法预先知道它。用该接缝，用例就能造出"nonce
// 匹配"的信封（正常路径），并另行构造"错值/空值"两种信封来证明这条绑定有牙。
// 生产代码从不改写它。
var newNodeNonce = func() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("节点内采集：生成一次性 nonce 失败: %w（不降级为固定值：那会让信封失去"+
			"『属于本次运行』这条绑定，而行为看起来完全正常）", err)
	}
	return hex.EncodeToString(buf), nil
}

// copyBinaryIntoNode 把二进制送进节点并返回节点内路径。
//
// 覆盖容器的 `/tmp/edgescen-<pid>`：**每次采集都重新送**，绝不复用节点里可能残留的旧二进制
// —— 旧二进制会让"同一份二进制"这条前提静默失效（节点里跑的是上一次修复前的版本，
// 而数据看起来只是一点点不同）。
func copyBinaryIntoNode(nt nodeTarget, localPath string) (string, error) {
	dest := fmt.Sprintf("/tmp/edgescen-%d", os.Getpid())
	switch nt.Substrate {
	case substrateDocker:
		if _, err := runDocker("cp", localPath, nt.Node+":"+dest); err != nil {
			return "", err
		}
	case substrateLXD:
		// `lxc file push <本地> <实例><目标路径>`（**没有** `docker cp` 的冒号分隔符）。
		if _, err := runLXC("file", "push", localPath, nt.Node+dest); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("节点内采集：未知基质 %q", nt.Substrate)
	}
	return dest, nil
}

// runNodeProcess 在目标节点内执行刚送进去的二进制，返回它的 stdout。
//
// 只传 `-emit-checks`：节点内进程不装载配置、不读 harness 产物、不评分，只把**登记表的
// 原始检查结果**交出来（评分与装配仍由父进程做 —— 那是本工具的全部契约与自检所在，
// 不能在节点里重跑第二遍）。因此也就不需要把配置/harness 产物也送进容器。
//
// nonce 经**环境变量**下发（docker: `-e <ENV>=<nonce>`；lxd: `--env <ENV>=<nonce>`）而不是
// 参数位：`-emit-checks` 只接受空参数集这条性质要保住（见 nodeNonceEnv 的说明）。两种基质的
// 开关拼写不同（`-e` vs `--env`），但**语义同一件事**：给节点内进程设一个只属于本次运行的值。
func runNodeProcess(nt nodeTarget, containerPath, emitFlag, nonce string) ([]byte, error) {
	switch nt.Substrate {
	case substrateDocker:
		return runDocker("exec", "-e", nodeNonceEnv+"="+nonce, nt.Node, containerPath, emitFlag)
	case substrateLXD:
		// `--` 把命令与 lxc 自己的开关分开：`lxc exec <实例> -- <cmd…>`。少了它，以 `-` 开头的
		// 命令串（这里就是 `-emit-checks`）会被 lxc 当成自己的参数而报错（实测 rc=1）。
		return runLXC("exec", "--env", nodeNonceEnv+"="+nonce, nt.Node, "--", containerPath, emitFlag)
	default:
		return nil, fmt.Errorf("节点内采集：未知基质 %q", nt.Substrate)
	}
}

// runDocker 执行一次 docker 子命令（stdout/stderr 分开收集）。
func runDocker(args ...string) ([]byte, error) {
	return runNodeCLI("docker", args...)
}

// runLXC 执行一次 lxc 子命令（stdout/stderr 分开收集）。
//
// 它是**包级变量**而不是普通函数，唯一的目的是给用例一个接缝（与 `newNodeNonce` 同一个手法）：
// 判据要求"把假 lxc 换成假 docker 的等价变异必须让用例红" —— 有接缝时这条可以在**同一份源码**
// 上被证明（用例把 `runLXC` 指到 `runDocker`，也就是"基质前缀认了、但二进制还是 docker"这个
// 最像的错法），而不必依赖 `go test -overlay` 之类的源码改写。生产代码从不改写它。
var runLXC = func(args ...string) ([]byte, error) {
	return runNodeCLI("lxc", args...)
}

// runNodeCLI 是节点侧 CLI 的**唯一**执行点（Task 4D Step 2 把 docker 专用实现泛化到这里）。
//
// 失败时把子进程的 stderr **原样带进错误**：目标不存在、容器没在跑、CLI 不在 PATH
// —— 这三种情况的处置完全不同，笼统地说"节点采集失败"会让操作者去查错的东西。
// 诊断串里带上**是哪一种基质**（`docker` / `lxc`）：同一个 `No such container` 在两种基质上
// 的排障动作不同，而错误信息是同一条（那正是最容易被读成"环境问题"的形态）。
func runNodeCLI(bin string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		if len(args) == 0 {
			return nil, fmt.Errorf("节点内采集：%s 失败（无参数）: %s", bin, detail)
		}
		switch args[0] {
		case "cp":
			if len(args) >= 3 {
				return nil, fmt.Errorf("节点内采集：%s cp %s 失败: %s", bin, args[2], detail)
			}
		case "file":
			// `lxc file push <本地> <实例><目标>`：报出**本地文件**与**目标**，两者都是排障要的信息。
			if len(args) >= 4 {
				return nil, fmt.Errorf("节点内采集：%s file push %s → %s 失败: %s", bin, args[2], args[3], detail)
			}
		case "exec":
			// docker: `exec <容器> <二进制> …`；lxc: `exec [--env K=V] <实例> -- <二进制> …`。
			// 这里刻意**不猜**参数位（两种基质的形状不同），统一报完整命令 —— 逐位对齐的猜测
			// 一旦猜错，错误信息会指向错的那个参数，比不猜更坏。
			return nil, fmt.Errorf("节点内采集：%s exec 失败（%s）: %s", bin, strings.Join(args, " "), detail)
		}
		return nil, fmt.Errorf("节点内采集：%s %s 失败: %s", bin, strings.Join(args, " "), detail)
	}
	return stdout.Bytes(), nil
}

// emitChecksPayload 是 `-emit-checks` 模式产出的信封（节点内进程调用）。
//
// 检查集取自**节点自己的**登记表（`checks.GetAll()`：平台闸门按 `runtime.GOOS` 过滤，
// 容器是 Linux ⇒ 注册表里的全部检查都注册，实测 **80 条** —— 勘测里写的 75 是旧数字，
// 注册表在 `internal/checks/linux/checks.go` 的 `All()` 68 项 + `kernel_security.go`
// 的 `ksAll()` 12 项），逐条执行一次。
//
// nonce 从环境变量读（父进程经 `docker exec -e` 下发）：读不到就写空串，父进程会以
// "没有 nonce"明确拒绝 —— 不能在这里静默补一个值（那样等于没有绑定）。
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
	return json.Marshal(nodeCheckEnvelope{
		Marker:   nodeEnvelopeMagic,
		Nonce:    strings.TrimSpace(os.Getenv(nodeNonceEnv)),
		Hostname: hostname,
		Checks:   out,
	})
}
