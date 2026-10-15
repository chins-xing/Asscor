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
	"strconv"
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
	// substratePVE = dl360gen9 上的 **PVE CT** —— `pct push` + `pct exec <vmid> -- env … `。
	// 用户 2026-09-12 的裁定把方向② 的实验基质交给真实环境，dl360gen9 上是 PVE（没有 LXD、
	// 也没有给节点用的 Docker），节点是 CT（`pct`），这是那条路径的入口（Task 6）。
	//
	// ⚠️ **`pct exec` 没有 `--env`**（实测 `pct help exec` 只有 `--keep-env`）—— 这是与
	// docker/lxd 唯一的**结构性**差别，nonce 因此只能经节点内的 `env` 下发；三侧的信封校验
	// 仍然共用同一份实现（见 runNodeProcess 与 parseNodeEnvelope）。
	substratePVE nodeSubstrate = "pve"
	// substrateQEMU = dl360gen9 上的 **QEMU/KVM 虚拟机** —— `scp` + `ssh`（Task 13）。
	//
	// 为什么 VM 是**另一种基质**而不是"pve 的一个变体"（用户 2026-10-15 两条裁定）：
	// ① CT（LXC）是**快速验证 / 轻量模拟 / 临时**的基质，VM 是**长线 + 中重型拓扑 + 重要任务**
	// 的基质 —— 两者的**定位**不同，不是同一件事的两种实现；
	// ② 在 CT 里 `OT-005`/`KS-012` 是**结构性不可观测**的（LXC 的 apparmor 命名空间不向容器
	// 暴露 profile，`aa-status` 报 `Failed to get profiles: 2`），于是基线活跃集被迫声明成
	// `{EF-SELINUX, EF-APPARMOR}`、每条链上挂着一个常量 **−30** 惩罚；VM 里 LSM 真的能
	// enforcing ⇒ **基线活跃集随基质变**。两套基质的数据**禁止混算/互相解释**。
	// 把 VM 塞进 `pve:` 前缀就等于让"这条记录采自哪种基质"在数据上消失 —— 而那正是
	// 后面所有结论的前提。
	//
	// ⚠️ **取数手段与前三者都不同（这是唯一一个"不经节点侧 CLI"的基质）**：VM 里没有
	// `docker`/`lxc`/`pct` 这类宿主侧的 CLI，而"在客人里 exec 一条本地命令"本来就不是 VM 的
	// 语义（`qm` 的客人侧执行要 `qemu-guest-agent`，实测宿主上**没装**它，见 Task 13 报告）。
	// ⇒ 走**通用的** `scp`（送文件）与 `ssh`（执行），两者都不新增运行期二进制依赖之外的
	// 东西（openssh-client 是宿主既有）。nonce 依旧**只经环境变量**下发（`ssh <host>
	// env EDGESCEN_NODE_NONCE=<nonce> <二进制> -emit-checks`），**绝不进 argv** ——
	// 这条硬不变量在 docker/lxd/pve 三侧逐条成立，VM 侧不破例（见 TestQEMUNonceNeverEntersNodeArgv）。
	substrateQEMU nodeSubstrate = "qemu"
)

// targetPrefixDocker / targetPrefixLXD / targetPrefixPVE / targetPrefixQEMU 是 `-target` 的
// **基质前缀**（`docker:<名>` / `lxd:<名>` / `pve:<vmid>` / `qemu:<vmid|名字>`）。
//
// 为什么要有前缀（而不是一个 `-substrate` 开关）：观测主体是**每一条记录**的属性，而不是
// 整个进程的属性 —— 一个进程内混采两种基质时，开关式的写法会让"这条记录采自哪里"取决于
// 调用顺序。前缀把它绑在目标本身（`-target lxd:probe-ot005`），跨工具也就一个拼写。
const (
	targetPrefixDocker = string(substrateDocker) + ":"
	targetPrefixLXD    = string(substrateLXD) + ":"
	targetPrefixPVE    = string(substratePVE) + ":"
	targetPrefixQEMU   = string(substrateQEMU) + ":"
)

// nodeTarget 是解析后的 `-target`：**基质 + 节点名**。
type nodeTarget struct {
	Substrate nodeSubstrate
	Node      string
}

// binary 是这条目标路径**实际执行**的节点侧 CLI（仅用于诊断串：同一个 `No such container`
// 在两种基质上的排障动作不同，而"到底是哪个 CLI 说的"必须能从报错里读出来）。
func (nt nodeTarget) binary() string {
	switch nt.Substrate {
	case substrateLXD:
		return "lxc"
	case substratePVE:
		return "pct"
	case substrateQEMU:
		return "ssh"
	default:
		return "docker"
	}
}

// parseNodeTarget 解析 `-target`，语法五种（`-h` 文案与错误串里必须写明同一套）：
//
//	""                 ⇒ 由调用方处理（collectChecksForTarget 的默认路径 = 本机）
//	<裸名字>            ⇒ docker（**向后兼容**：Task 4C 以来的语义，逐位不变）
//	docker:<容器>       ⇒ docker（与裸名字等价，只是把基质显式写出来）
//	lxd:<实例>          ⇒ lxd（A-1 的 LXD）
//	pve:<vmid>          ⇒ pve（dl360gen9 的 PVE CT；这里是 **VMID**，由 `lab_target_spec` 解析后给出）
//	qemu:<vmid|名字>    ⇒ qemu（dl360gen9 的 **QEMU/KVM VM**；Task 13。这里**既收 vmid 也收名字**，
//	                     与 pve **刻意不同**：pve 的节点标识由 `pct list` 唯一决定（只能是 vmid），
//	                     而 VM 的标识同时出现在 `qm list` 的 VMID 列与 Name 列 —— 两种写法都指向
//	                     同一个对象，收窄反而会让 `qemu:asc-vm910` 这种**正确**写法变成错误）
//
// 为什么"未知前缀"必须报错而不是当成裸名字：`lxd:probe-ot005` 里的名字若被当成
// **docker 容器名**，docker 会以 `No such container: lxd:probe-ot005` 失败 —— 那条错误指向
// 一个不存在的容器，而真正的原因是基质名拼错。判据是"冒号**前面**那一段是否像一个基质名"
// （`[A-Za-z0-9_-]+`）且冒号后面还有名字：**看着像基质前缀却不在白名单**一律报错
// （`foo:bar` 里的 `foo` 完全可能是个拼错的基质名，报出来比让它变成一次"容器不存在"有用得多）。
// 只有"冒号前面不像标识符"（例如路径或 IPv6 里的冒号）才继续按今天的裸名字语义走 docker。
//
// pve 这一格**刻意不做"必须是纯数字"的额外校验**：解析层在三种基质上做的是同一件事
// （把基质前缀摘掉、留下节点标识），把 pct 的"vmid 必须是数字"这条**基质内部规则**搬到这里，
// 会让三层解析各有一套关于节点标识的语法。名字→vmid 的解析**只有一处**，在基质层
// （`edge_lab.sh` 的 `lab_node_vmid`）；给一个非数字的标识时 `pct` 自己会失败（实测 rc≠0），
// 那条失败照样响亮、照样不写任何记录。
//
// qemu 这一格同款：这里**不**去校验节点标识"是不是 vmid 也不是名字"—— 解析层做的是
// "摘前缀、留标识"，`ssh` 解析不到那个主机名时自己会响亮失败（`Could not resolve hostname`），
// 而"名字→SSH 主机"的解析只有一处（基质层 `edge_lab.sh` 的 `lab_node_ssh_host`）。
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
	case strings.HasPrefix(raw, targetPrefixPVE):
		node := strings.TrimSpace(strings.TrimPrefix(raw, targetPrefixPVE))
		if node == "" {
			return nodeTarget{}, fmt.Errorf("节点内采集：target %q 缺少 vmid（用法：%s<vmid>；"+
				"vmid 由基质层 `lab_target_spec` 从 CT 名字解析出来）", raw, targetPrefixPVE)
		}
		return nodeTarget{Substrate: substratePVE, Node: node}, nil
	case strings.HasPrefix(raw, targetPrefixQEMU):
		node := strings.TrimSpace(strings.TrimPrefix(raw, targetPrefixQEMU))
		if node == "" {
			return nodeTarget{}, fmt.Errorf("节点内采集：target %q 缺少 vmid 或名字（用法：%s<vmid|名字>；"+
				"SSH 主机与私钥走环境变量 %s / %s，**不进 argv、不进仓库**）",
				raw, targetPrefixQEMU, qemuSSHHostEnv, qemuSSHKeyEnv)
		}
		return nodeTarget{Substrate: substrateQEMU, Node: node}, nil
	}
	if i := strings.Index(raw, ":"); i >= 0 {
		prefix := raw[:i]
		// 只有"像一个基质前缀"时才报错：前缀是纯字母/数字/下划线/连字符（即一个标识符）而后面
		// 还有名字。`foo:bar` 因此仍然按今天的裸名字走 docker，不会因本次改动改变语义。
		if isIdentifier(prefix) && strings.TrimSpace(raw[i+1:]) != "" {
			return nodeTarget{}, fmt.Errorf("节点内采集：target %q 的基质前缀 %q 未知（只认 %q、%q、%q 与 %q；"+
				"不带前缀的裸名字按 %s 处理）", raw, prefix, strings.TrimPrefix(targetPrefixDocker, ":"),
				strings.TrimPrefix(targetPrefixLXD, ":"), strings.TrimPrefix(targetPrefixPVE, ":"),
				strings.TrimPrefix(targetPrefixQEMU, ":"), substrateDocker)
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
// pve（Task 6）与 qemu（Task 13）按同一形状印出 `substrate=pve` / `substrate=qemu` ——
// 这一格对 VM 基质**比其它任何一条都关键**：CT 与 VM 是两种**不同定位**的基质
// （CT = 快速验证/轻量/临时；VM = 长线/中重型/重要任务），且**基线活跃集随基质变**，
// 拿一份看不出基质的记录去比较两套数据，会把"基质差异"读成"因子效果"。
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

// osExecutable 是本进程可执行文件路径的来源。
//
// 它是**包级变量**（同 `newNodeNonce` 的接缝手法）：`os.Executable()` 失败在实际运行里几乎不可达，
// 而"取不到路径时那句话必须与 Task 4C 逐字同形"这条判据只能靠注入被真正执行到 ——
// 上一轮那条期望值就是因为**没有断言**才允许了"抄错方向"（复审 Minor-新-1）。生产代码从不改写它。
var osExecutable = os.Executable

// fetchNodeChecks 把**本进程自己的可执行文件**送进目标节点执行，取回该节点的检查结果。
//
// 为什么送二进制而不是"在节点里另装一个工具"：同一份二进制 ⇒ 会话里的评分链、检查登记表、
// 甚至检查实现都与宿主路径是同一份代码，唯一变量是**运行位置**。任何"节点里跑另一个版本"
// 的形态都会让两份数据不可比，而差异看起来只是"节点更严格"。
func fetchNodeChecks(nt nodeTarget) (nodeCheckEnvelope, error) {
	bin, err := osExecutable()
	if err != nil {
		// **逐字恢复 97581d8 的字面量**（复审 Minor-新-1）：上一轮我按基质分派成了
		// `%s 内采集：…`（⇒ 实际产出 `docker 内采集：…`），而 Task 4C 的原文是 `节点内采集：…`
		// —— 那条"唯一没恢复的错误串"当时还被注释与文档声称"已逐字恢复"（声称比事实更强的典型）。
		// 现在回到原文：`os.Executable()` 失败与基质**种类**无关（取不到的是父进程自己的可执行文件
		// 路径），故两种基质下这句话本来就该是同一句。断言见
		// `TestDockerErrorStringsMatchTask4CBytes/取本进程可执行文件路径失败`。
		return nodeCheckEnvelope{}, fmt.Errorf("节点内采集：取本进程可执行文件路径失败: %w", err)
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
	case substratePVE:
		// `pct push <vmid> <本地> <目标路径> --perms 755` —— 与 lxd 那行**逐项对应**，
		// 但参数顺序**相反**（vmid 在前、目标路径是独立的一个参数，没有 lxc 那种
		// `<实例><路径>` 拼接）。`--perms 755` 让"送进去就能执行"在**送进去的那一刻**成立，
		// 与 docker 侧 `docker cp` 之后依赖镜像里的权限不同（docker 侧的历史行为不动）。
		if _, err := runPCT("push", nt.Node, localPath, dest, "--perms", "755"); err != nil {
			return "", err
		}
	case substrateQEMU:
		// `scp -O <本地> <ssh 目标>:<目标路径>`（Task 13）——**VM 侧唯一能用的送文件手段**：
		// 客人里没有 `docker`/`lxc`/`pct` 这类宿主侧 CLI，而"在客人里 exec 一条本地命令"
		// 本来就不是 VM 的语义（`qm` 的客人侧执行要 guest agent，宿主实测**没装**）。
		//
		// `-O`（强制走 legacy SCP 协议）**不是可选的**：OpenSSH 9.0+ 默认用 SFTP 子系统，
		// 而 cloud image 里 `sftp-server` 与 `/usr/lib/openssh/sftp-server` 的位置随发行版变、
		// 缺了就报 `subsystem request failed` —— 那条错误指向"子系统没配"，与真正的原因
		// （本机 scp 版本 vs 客人 sshd 的默认）差得很远。`-O` 把这条依赖整个去掉。
		//
		// 送进去之后**必须显式 `chmod 0755`**：`scp` 保留源文件的权限位而**不**保证可执行
		// —— 而"送进去但不可执行"的失败形态是客人侧的 `Permission denied`（看起来像
		// "这个用户权限不足"，与"忘了 chmod"完全不像）。pve 侧靠 `pct push --perms 755`
		// 一次到位，VM 侧靠这一条显式的 `ssh chmod`。
		//
		// 两条命令**都用 `qemuSSHArgs` 造的完整 argv**（连接参数逐格相同）—— 只传主机名
		// 会让这次 ssh 用到操作者的 `~/.ssh/config` 与默认钥匙（`-l`/`-i`/`-p` 全丢），
		// 于是"scp 送进去的那台"与"chmod 改的那台"可能**不是同一台**，而两边都成功。
		scpArgs, err := qemuSCPArgs(nt.Node, localPath, dest)
		if err != nil {
			return "", err
		}
		if _, err := runSCP(scpArgs...); err != nil {
			return "", err
		}
		chmodArgs, err := qemuSSHArgs(nt.Node, "chmod", "0755", dest)
		if err != nil {
			return "", err
		}
		if _, err := runSSH(chmodArgs...); err != nil {
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
// nonce 经**环境变量**下发（docker: `-e <ENV>=<nonce>`；lxd: `--env <ENV>=<nonce>`；
// pve: `-- env <ENV>=<nonce> …`）而不是参数位：`-emit-checks` 只接受空参数集这条性质要保住
// （见 nodeNonceEnv 的说明）。三种基质的开关拼写不同，但**语义同一件事**：给节点内进程设一个
// 只属于本次运行的值。
func runNodeProcess(nt nodeTarget, containerPath, emitFlag, nonce string) ([]byte, error) {
	switch nt.Substrate {
	case substrateDocker:
		return runDocker("exec", "-e", nodeNonceEnv+"="+nonce, nt.Node, containerPath, emitFlag)
	case substrateLXD:
		// `--` 把命令与 lxc 自己的开关分开：`lxc exec <实例> -- <cmd…>`。少了它，以 `-` 开头的
		// 命令串（这里就是 `-emit-checks`）会被 lxc 当成自己的参数而报错（实测 rc=1）。
		return runLXC("exec", "--env", nodeNonceEnv+"="+nonce, nt.Node, "--", containerPath, emitFlag)
	case substratePVE:
		// **`pct exec` 没有 `--env`**（实测 `pct help exec` 只有 `--keep-env`），故 nonce 只能
		// 靠节点内的 `env` 下发。这条形状把下面三条性质一条不落地保住：
		//   · nonce **不在** `-emit-checks` 那一侧的参数里 —— 节点内进程收到的 argv 仍然
		//     **恰好是 `[-emit-checks]`**（`env K=V <bin> -emit-checks` 里 `K=V` 是 `env` 自己的
		//     位置参数，进程的 argv[0] 之后只有那个开关）。"`-emit-checks` 只接受空参数集"
		//     这条守卫因此没有被开出一个"合法参数"，nonce 没有进参数位；
		//   · `--` 把命令与 `pct` 自己的开关分开（**实测必需**：`pct exec` 把 `--` 之后的整串
		//     当 `<extra-args>` 原样交给容器，`-emit-checks` 不会被 pct 的选项解析器吃掉）；
		//   · 信封校验（标记 / nonce 非空且等于本次下发 / hostname / 非空检查集 / 取最后一行）
		//     走的仍是 `parseNodeEnvelope`，**与 docker/lxd 共用同一份实现**。
		return runPCT("exec", nt.Node, "--", "env", nodeNonceEnv+"="+nonce, containerPath, emitFlag)
	case substrateQEMU:
		// `ssh <选项> -- <主机> env <ENV>=<nonce> <二进制> -emit-checks`（Task 13）。
		// 这条形状与 pve 侧**逐项对应**，只有"谁来把命令交给客人"不同（`ssh` 而不是 `pct`），
		// 于是下面三条性质一条不落地保住：
		//   · nonce **不在** `-emit-checks` 那一侧的参数里 —— 客人侧二进制的 argv 仍然
		//     **恰好是 `[-emit-checks]`**（`env K=V <bin> -emit-checks` 里 `K=V` 是 `env` 自己的
		//     位置参数）。"`-emit-checks` 只接受空参数集"那条守卫因此没有被开出一个
		//     "合法参数"，nonce 没有进参数位；
		//   · `--` 把命令与 ssh 自己的开关分开（**实测必需**：`ssh <host> -emit-checks` 会把
		//     以 `-` 开头的那一格当作 ssh 的选项；`--` 之后的一格才是"远程命令"）。
		//     **注意 `--` 必须在主机名之前**：ssh 的 `[user@]hostname` 位置参数之后的东西
		//     本来就是"远程命令"，而 `--` 放在前面同时管住了"主机名以 `-` 开头"这种形态；
		//   · 信封校验（标记 / nonce 非空且等于本次下发 / hostname / 非空检查集 / 取最后一行）
		//     走的仍是 `parseNodeEnvelope`，**与其它三种基质共用同一份实现**。
		//
		// `env` 是客人侧的 `/usr/bin/env`（cloud image 必有），不需要客人里装任何本项目的东西。
		args, err := qemuSSHArgs(nt.Node, "env", nodeNonceEnv+"="+nonce, containerPath, emitFlag)
		if err != nil {
			return nil, err
		}
		return runSSH(args...)
	default:
		return nil, fmt.Errorf("节点内采集：未知基质 %q", nt.Substrate)
	}
}

// runDocker 执行一次 docker 子命令（stdout/stderr 分开收集）。
//
// **错误串与 Task 4C（提交 97581d8）逐字相同** —— 见 runNodeCLI 的说明：那是本工具唯一
// 面向 docker 的取数入口，操作者日志与既有断言都按它的字面量写。
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

// runPCT 执行一次 pct 子命令（stdout/stderr 分开收集）—— 与 `runLXC` 同一个手法。
//
// 它同样是**包级变量**（Task 6）：判据要求"把假 pct 换成假 docker 的等价变异必须让用例红"，
// 有接缝时这条可以在**同一份源码**上被证明（用例把 `runPCT` 指到 `runDocker`，
// 也就是"`pve:` 前缀认了、但二进制还是 docker"这个最像的错法）。生产代码从不改写它。
var runPCT = func(args ...string) ([]byte, error) {
	return runNodeCLI("pct", args...)
}

// ---------------------------------------------------------------------------
// qemu 基质（Task 13）：SSH/SCP 取数
// ---------------------------------------------------------------------------
//
// 前三套基质（docker/lxd/pve）都是"宿主上有一个 CLI，它替我们在客人里执行"。
// **VM 上没有这样一个 CLI** —— 客人里跑的是真的虚拟硬件 + 真的 systemd，宿主侧只有
// QEMU 进程；`qm` 里唯一能"进客人执行"的入口是 `qm guest exec`，而它要
// `qemu-guest-agent`（实测宿主上**没有** `/usr/share/pve-qemu-guest-agent`）。
// ⇒ VM 侧的取数走**通用**手段：`scp` 送文件、`ssh` 执行。
//
// 三条纪律（都在下面有对应的用例）：
//
//  1. **SSH 目标与私钥一律走环境变量**，两者**都不进 argv、不进记录、不进仓库**。
//     `EDGEEXP_VM_SSH_KEY` 指向的是**私钥文件路径**（不是密钥内容）；
//     口令/私钥内容本身不许出现在任何一处。
//  2. **默认连接参数是硬编码的常量**（BatchMode / accept-new / ConnectTimeout / IdentitiesOnly），
//     **不接受**从环境变量来的"SSH 选项串" —— 那种变量会被当成 `-o` 的值，于是
//     `-o ProxyCommand=…` 这类取值能在操作者看不见的地方把**取数目标**改到别处
//     （记录里的 `observation_target` 照常印着节点名）。要换目标就换 `EDGEEXP_VM_SSH_HOST`。
//  3. **nonce 只经环境变量下发**（`ssh <选项> -- <主机> env K=V <二进制> -emit-checks`）——
//     与 pve 侧同一条硬不变量：客人侧二进制的 argv **恰好是 `[-emit-checks]`**。
const (
	// qemuSSHHostEnv 是 SSH 目标主机（值里出现的 `%s` 会被替换成节点标识；
	// 不含 `%s` 则所有节点都指向同一台，供单机场景使用）。默认：`asc-vm<vmid>`
	// —— 与 provisioning 脚本写进宿主 `/etc/hosts` 的客户机主机名一致
	// （cloud-init 把 hostname 设成 `asc-vm<vmid>`），故**不需要 DNS**：
	// 管理 VLAN 30 上没有 DNS（实测 CT 内 DNS FAIL），而 `/etc/hosts` 是宿主本地的。
	qemuSSHHostEnv = "EDGEEXP_VM_SSH_HOST"
	// qemuSSHKeyEnv 是 SSH **私钥文件路径**（`IdentityFile`）。默认：不传 `-i`
	// （由操作者的 ssh 配置决定）——provisioning 脚本会把生成的私钥路径写进未跟踪的本地
	// env 文件，**从不**写进仓库。
	qemuSSHKeyEnv = "EDGEEXP_VM_SSH_KEY"
	// qemuSSHUserEnv 是 SSH 登录用户（cloud-init 里建的那个）。默认 `asc`。
	qemuSSHUserEnv = "EDGEEXP_VM_SSH_USER"
	// qemuSSHPortEnv 是 SSH 端口。默认 `22`。端口是**数字**语义，故这里单独校验。
	qemuSSHPortEnv = "EDGEEXP_VM_SSH_PORT"
	// qemuSSHUserDefault 是登录用户的默认值。
	qemuSSHUserDefault = "asc"
	// substrateBinSSH / substrateBinSCP 是 qemu 基质实际起的两个**宿主侧**二进制名。
	// 它们是 `runNodeCLI` 错误分派与诊断串的键（"到底是哪个 CLI 说的"必须能从报错里读出来）。
	substrateBinSSH = "ssh"
	substrateBinSCP = "scp"
	// newNodeHostnamePattern 是"没给 EDGEEXP_VM_SSH_HOST 时，vmid → SSH 主机名"的**唯一**规则
	// （`%d` 是数字 vmid）。它必须与 provisioning 脚本写进 `/etc/hosts` 的那一行一致 ——
	// 两处一旦分叉，症状是"SSH 解析不到主机名"，而真正的原因是两台机器对同一个 vmid
	// 起了不同的名字。非数字节点标识（`qemu:asc-vm910` 这种写法）不走这条规则，
	// 而是原样当作主机名（它**就是**一个主机名）。
	newNodeHostnamePattern = "asc-vm%d"
)

// qemuSSHHost 解析"这次连哪台客人"（**唯一**的节点标识 → SSH 主机的解析点）。
//
// 参数从**环境变量**实时取（`os.Getenv` 而不是包级变量）：这两个值属于**运行环境**，
// 每一条记录都可能连不同的机器，把它们缓存在包级变量里会让"改了环境变量但仍旧连旧机器"
// 这种形态成为可能（症状是采到了**另一台**机器的数据，而记录里的节点名照常）。
func qemuSSHHost(node string) (string, error) {
	host := strings.TrimSpace(os.Getenv(qemuSSHHostEnv))
	if host != "" {
		// 显式给了模板：`%s` 被替换成节点标识，没给 `%s` 就所有节点都用这一台。
		host = strings.ReplaceAll(host, "%s", node)
	} else if vmid, ok := vmidFromNode(node); ok {
		host = fmt.Sprintf(newNodeHostnamePattern, vmid)
	} else {
		// 非数字标识（`qemu:asc-vm910`）**原样**当主机名 —— 它本身就是一个主机名，
		// 这里不去猜它对应哪个 vmid（猜错就是采到另一台机器的数据，而看起来完全正常）。
		host = node
	}
	if host == "" {
		return "", fmt.Errorf("节点内采集：qemu 基质的 SSH 主机解析为空（节点 %q；%s 与默认规则都没给出取值）",
			node, qemuSSHHostEnv)
	}
	return host, nil
}

// qemuSSHConnArgs 是 ssh 与 scp **共用**的那几格连接参数（硬编码、不做配置面）。
func qemuSSHConnArgs() ([]string, error) {
	args := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"}

	// 登录用户：空 ⇒ 默认（**不猜**：给了空串就等于没给）。
	user := strings.TrimSpace(os.Getenv(qemuSSHUserEnv))
	if user == "" {
		user = qemuSSHUserDefault
	}
	if strings.ContainsAny(user, " \t\n") {
		return nil, fmt.Errorf("节点内采集：%s 不能含空白（收到 %q）—— "+
			"它会被拼进 `user@host`，含空白时拼出来的目标与操作者写的**不是一个**", qemuSSHUserEnv, user)
	}
	args = append(args, "-l", user)

	// 端口：**数字**语义，非数字一律响亮失败（`ssh -p abc` 自己会报，但那条错误看起来像
	// "端口不对"，而真正的原因是环境变量写错）。
	if raw := strings.TrimSpace(os.Getenv(qemuSSHPortEnv)); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("节点内采集：%s=%q 不是合法端口（1..65535）", qemuSSHPortEnv, raw)
		}
		args = append(args, "-p", raw)
	}

	// 私钥：**路径**。`IdentitiesOnly=yes` 让这次连接**只用**这一把钥匙 —— 没有它，
	// ssh 还会去试 agent 与 `~/.ssh/id_*` 里的其它钥匙，于是"连上了"这件事可能靠的是
	// 操作者没想到的那把钥匙（换人做实验时行为就变了，而两次的实验记录看不出差别）。
	if keyPath := strings.TrimSpace(os.Getenv(qemuSSHKeyEnv)); keyPath != "" {
		if _, err := os.Stat(keyPath); err != nil {
			return nil, fmt.Errorf("节点内采集：%s=%s 不可读: %w —— "+
				"私钥路径由环境变量给出（**从不**写进仓库）；provisioning 脚本 "+
				"`lunwen/clab-lab/scripts/edge_vm_provision.sh` 在没有这把钥匙时会自己生成一把",
				qemuSSHKeyEnv, keyPath, err)
		}
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", keyPath)
	}
	return args, nil
}

// qemuSSHArgs = 连接参数 + `-- <主机> <远程命令…>`。
//
// `--` **必须在主机名之前**：`ssh <主机> -emit-checks` 会把以 `-` 开头的那一格当作 ssh 自己的
// 选项（实测形态：`ssh: unknown option -- e`），而 `--` 之后的第一格才是主机名。
func qemuSSHArgs(node string, cmd ...string) ([]string, error) {
	args, err := qemuSSHConnArgs()
	if err != nil {
		return nil, err
	}
	host, err := qemuSSHHost(node)
	if err != nil {
		return nil, err
	}
	return append(append(args, "--", host), cmd...), nil
}

// qemuSCPArgs = 连接参数 + `-O <本地> <主机>:<目标>`。
//
// `-O`（强制走 legacy SCP 协议）**不是可选的**：OpenSSH 9.0+ 默认用 SFTP 子系统，
// 而 cloud image 里 `sftp-server` 的位置随发行版变、缺了就报 `subsystem request failed`
// —— 那条错误指向"子系统没配"，与真正的原因（本机 scp 版本 vs 客人 sshd 的默认）差得很远。
// `-O` 把这条依赖整个去掉。
//
// scp **没有** `--` 那种分隔：主机与路径拼在**同一格**（`<主机>:<路径>`）。
func qemuSCPArgs(node, localPath, remotePath string) ([]string, error) {
	args, err := qemuSSHConnArgs()
	if err != nil {
		return nil, err
	}
	host, err := qemuSSHHost(node)
	if err != nil {
		return nil, err
	}
	return append(args, "-O", localPath, host+":"+remotePath), nil
}

// vmidFromNode 判断节点标识是不是一个**纯数字 vmid**，是则给出数值。
func vmidFromNode(node string) (int, bool) {
	n, err := strconv.Atoi(node)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// runSSH 执行一次 ssh 子命令（`runLXC`/`runPCT` 同一个手法：包级变量 = 用例接缝，
// 让"把 qemu 的 ssh 换成 docker 的等价变异必须让用例红"能在**同一份源码**上被证明）。
// 生产代码从不改写它。
var runSSH = func(args ...string) ([]byte, error) {
	return runNodeCLI(substrateBinSSH, args...)
}

// runSCP 执行一次 scp 子命令（同上）。
var runSCP = func(args ...string) ([]byte, error) {
	return runNodeCLI(substrateBinSCP, args...)
}

// indexOf 是 `[]string` 上的 `strings.Index`（Go 标准库没有这一条，而错误分派里要用它
// 把 ssh 的"连接参数"与"远程命令"分开）。
func indexOf(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

// runNodeCLI 是节点侧 CLI 的执行点（Task 4D Step 2 把 docker 专用实现泛化到这里）。
//
// 失败时把子进程的 stderr **原样带进错误**：目标不存在、容器没在跑、CLI 不在 PATH
// —— 这三种情况的处置完全不同，笼统地说"节点采集失败"会让操作者去查错的东西。
//
// **错误串按基质分派，且 docker 那几条逐字保持 Task 4C 的取值**（Fix round 1 / M-1）：
// 泛化时曾统一成 `%s exec 失败（整条 argv）`，于是 `docker:` 路径的错误信息与抽象前**不同**了
// —— 而 brief 与报告写的是"`docker:` 路径不得改变任何字节"。评审用一条 overlay 检查把它读出来：
// ```
// 97581d8: 节点内采集：docker exec %s %s 失败: %s   （args[1]="-e"、args[2]="EDGESCEN_NODE_NONCE=<nonce>"）
// 泛化后 : 节点内采集：docker exec 失败（exec -e EDGESCEN_NODE_NONCE=<nonce> <容器> <二进制> -emit-checks）: …
// ```
// 现在三条路径各有自己的措辞：docker 保留字面量（**含那个把 `-e` / `NONCE=…` 当参数打印的形状**，
// 它是既有日志的形态，不是本次引入的），lxc 与 pct 用按实例/vmid 与目标路径报错的说法
// （`file push <本地> → <实例><目标>` / `push <本地> → <目标>`，以及完整的 `exec` 命令）——
// 后两者是**新**基质，没有"不许变"的历史包袱，说得更准才有用。
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
		if bin == "lxc" {
			switch args[0] {
			case "file":
				// `lxc file push <本地> <实例><目标>`：报出**本地文件**与**目标**，两者都是排障要的信息。
				if len(args) >= 4 {
					return nil, fmt.Errorf("节点内采集：lxc file push %s → %s 失败: %s", args[2], args[3], detail)
				}
			case "exec":
				return nil, fmt.Errorf("节点内采集：lxc exec 失败（%s）: %s", strings.Join(args, " "), detail)
			}
			return nil, fmt.Errorf("节点内采集：lxc %s 失败: %s", strings.Join(args, " "), detail)
		}
		if bin == "pct" {
			switch args[0] {
			case "push":
				// `pct push <vmid> <本地> <目标> [--perms …]`：报出**本地文件**与**目标**。
				if len(args) >= 4 {
					return nil, fmt.Errorf("节点内采集：pct push %s → %s 失败: %s", args[2], args[3], detail)
				}
			case "exec":
				return nil, fmt.Errorf("节点内采集：pct exec 失败（%s）: %s", strings.Join(args, " "), detail)
			}
			return nil, fmt.Errorf("节点内采集：pct %s 失败: %s", strings.Join(args, " "), detail)
		}
		if bin == substrateBinSSH {
			// `ssh <选项…> -- <主机> <远程命令…>`：报出**主机**与**远程命令**，而**不**打印整条
			// argv 的原样长串（那段里没有口令，但把连接参数逐格打出来对排障没有增益，
			// 而"哪台机器、哪条远程命令"才是要看的）。主机名与远程命令都从 `--` 之后取。
			//
			// ⚠️ 这里**不得**改成人读的更详细形态时带上 `nodeNonceEnv` 的值：nonce 是
			// 一次性绑定，进日志就等于把它写进了一个长期留存的文本里（本函数只拼 argv，
			// 而 nonce 在 argv 里是**环境赋值**那一格 —— 故这里只报主机与那条远程命令的
			// 前几格，见下面 join 的范围）。
			if i := indexOf(args, "--"); i >= 0 && len(args) > i+1 {
				host := args[i+1]
				remote := args[i+2:]
				if len(remote) > 2 {
					remote = append(append([]string{}, remote[:2]...), "…")
				}
				return nil, fmt.Errorf("节点内采集：ssh 失败（主机 %s；远程命令 %s）: %s",
					host, strings.Join(remote, " "), detail)
			}
			return nil, fmt.Errorf("节点内采集：ssh 失败: %s", detail)
		}
		if bin == substrateBinSCP {
			// `scp -O <本地> <主机>:<目标>`（Task 13）：报出**本地文件**与**目标**，
			// 与 `pct push` 那一格同款（同一个失败在两种基质上的排障动作一样）。
			if len(args) >= 3 {
				return nil, fmt.Errorf("节点内采集：scp %s → %s 失败: %s", args[1], args[2], detail)
			}
			return nil, fmt.Errorf("节点内采集：scp 失败（%s）: %s", strings.Join(args, " "), detail)
		}
		switch args[0] {
		case "cp":
			if len(args) >= 3 {
				return nil, fmt.Errorf("节点内采集：docker cp %s 失败: %s", args[2], detail)
			}
		case "exec":
			if len(args) >= 3 {
				return nil, fmt.Errorf("节点内采集：docker exec %s %s 失败: %s", args[1], args[2], detail)
			}
		}
		return nil, fmt.Errorf("节点内采集：docker %s 失败: %s", strings.Join(args, " "), detail)
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
