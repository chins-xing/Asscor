#!/bin/bash
# ============================================================================
# edge_lab.sh —— 实验**基质**抽象（被 edge_*.sh 共同 source 的函数库）
# ============================================================================
#
# 这不是可执行脚本，而是被 `edge_reset.sh` / `edge_attack.sh` / `edge_collect.sh` /
# `edge_matrix.sh` / `edge_probe.sh` **共用**的基质层。source 进来即用（`set -euo pipefail`
# 由调用方负责；本文件只定义函数与变量）。
#
# 为什么要有这一层（Task 4D Step 1）：2026-09-12 用户裁定实验基质搬到 **A-1 远程服务器（LXD，
# 环境真实）**，WSL2 Containerlab 退为开发与离线。矩阵脚本此前把 `clab` / `docker` 的命令**写
# 死在调用点**（建/毁拓扑、在目标内执行、把文件送进目标、取目标信息四处），换基质等于重写四个
# 脚本 —— 而"重写"正是把门禁与注入逻辑一起改坏的最短路径。
#
# 接口（**单一来源**：所有基质相关命令只能从这里出去，调用点不得再出现 `clab`/`docker`/`lxc`
# 命令字面 —— 需要新增一条基质命令时改本文件，不要在调用点写）：
#
#   lab_substrate                当前基质名（clab|lxd，只读）
#   lab_topology                 拓扑文件路径（clab 用；lxd 下是"占位"，不参与命令）
#   lab_topology_bin             拓扑级 CLI（clab: `clab`；lxd: `lxc`）
#   lab_target_bin               目标级 CLI（clab: `docker`；lxd: `lxc`）
#   lab_require_bins             前置检查：当前基质需要的 CLI 都在 PATH 上吗（缺则返回非零）
#   lab_up                       建拓扑（clab: deploy）
#   lab_down                     毁拓扑（clab: destroy --cleanup）
#   lab_target_exec <node> <cmd…>   在目标内执行命令（stdout/stderr 原样透传）
#   lab_target_exec_detached <node> <cmd…>  在目标内起一个不随连接结束而退出的进程
#   lab_push <local> <node> <dest>  把文件送进目标
#   lab_node_ip <node> <iface>      取目标某接口的 CIDR（无则空、返回非零）
#   lab_node_running <node>         实例在跑吗（true/false；不存在则非零）
#   lab_inspect <node>              取目标的基质视图（存在性/状态的权威判据）
#   lab_list                        列出目标（每行一个名字）
#   lab_node_counts                 回显 "total up down"（失败回显 "-1 -1 -1"）
#   lab_target_spec <node>          节点名 → `edgescen -target` 的语法（clab 裸名 / lxd:<实例>）
#
# 覆盖开关（**与抽象前逐条对应**，别把它们合并成一个）：
#   EDGEEXP_SUBSTRATE          clab（默认）| lxd
#   EDGEEXP_TOPOLOGY           拓扑文件路径
#   EDGEEXP_LAB_TOPOLOGY_BIN   拓扑级 CLI 的可执行文件（离线夹具用）
#   EDGEEXP_LAB_TARGET_BIN     目标级 CLI 的可执行文件（离线夹具用；clab 下默认 = DOCKER_BIN）
#   EDGEEXP_DOCKER_BIN         **抽象前就有的**接缝：目标级的 `docker`（`edge_probe.sh` 用它）
#   EDGEEXP_LXC_BIN            lxd 基质的 `lxc`
#
# **clab 分支逐位等价**是最硬的门禁：函数体里每一条命令、参数顺序、重定向目标、日志文件名都
# 与抽象**之前**的调用点逐字相同（日志仍叫 `/tmp/edgeexp-clab-*.log` —— 名字里的 clab 只是历史
# 留痕，改名会让既有排障手册与错误串对不上；两份日志都是"最近一次调用的原文"）。这条有离线
# 复现夹具钉住（`build/lab-diff.sh`：从 `git archive <base>` 取**真基线**跑同一批假 CLI 做差分），
# 不是靠通读保证的。
#
# 基质选择的失败处置：`EDGEEXP_SUBSTRATE` 只认 `clab`（默认）与 `lxd`，别的值**在 source 时就
# 响亮失败** —— 一个拼错的基质名如果被当成默认值静默降级，整轮矩阵会在 WSL 的 clab 上跑，
# 而记录里的 `env` 标签看起来仍然正常。**没有 `set -e` 的调用方也会被中止**（见下方实现）。
#
# lxd 分支的边界（**必须显式**，不能默默什么都不做）：
#   · `lab_up` / `lab_down` **不支持**：LXD 侧的"环境"是 A-1 上既有的实例集合（控制侧已裁定
#     `probe-ot005` 等实例不得被删改），没有"建/毁拓扑"这个动作。两者一律**响亮失败**并说明
#     原因，绝不静默返回 0 —— 一次"复位成功"但环境其实没被动过的假象，比一次失败危险得多。
#   · `lab_node_counts` 对 lxd 回显 `-1 -1 -1`（"Node status cannot be determined"）。
#     `-1` 的既有语义在 `edge_reset.sh` 里是"查不出来 ≠ 已清空"，调用方据此失败；这与
#     `clab inspect` 自己失败时的取值一致。
#   · `lab_target_exec` / `lab_push` / `lab_node_ip` / `lab_inspect` / `lab_list` 支持：
#     它们只要求"实例存在"，正是 LXD 上取数与探针路径需要的四件事。
#   · 本文件的 lxd 分支只**访问既有实例**：不 launch、不 delete、不 stop、不 restart，
#     也不改任何实例的配置。
# ============================================================================

# lab_substrate —— 当前基质（变量名带 lab_ 前缀：避免与调用方自己的 SUBSTRATE/SUBSTRATE_*
# 撞名，同 edge_probe.sh 的 probe_target/probe_docker_bin 约定）。
lab_substrate="${EDGEEXP_SUBSTRATE:-clab}"
case "$lab_substrate" in
  clab|lxd) : ;;
  *)
    echo "edge_lab: EDGEEXP_SUBSTRATE 只认 clab（默认）与 lxd，收到 '$lab_substrate' ——" >&2
    echo "  基质名拼错时静默退回默认值会让整轮矩阵在另一种基质上跑（记录里的 env 标签照常），" >&2
    echo "  故这里直接失败。用法：EDGEEXP_SUBSTRATE=clab|lxd。" >&2
    # 三种加载方式都要**中止调用方**（Fix round 1 / M-4）：
    #   · 被 source + 调用方有 `set -e` ⇒ `return 2` 就能带走调用方；
    #   · 被 source + 调用方**没有** `set -e` ⇒ `return` 只返回这一层，调用方会**继续跑**，
    #     于是整轮矩阵在默认基质（clab）上跑起来，而记录里的 env 标签照常 —— 这正是本守卫
    #     要堵的东西。故这里**主动结束调用方的 shell**（`kill -TERM $$`）。
    #     非交互式 shell 才 kill：交互式会话语境下把操作者的 shell 打死是过度惩罚，
    #     那时 `return 2` + 上面三行 stderr 已经足够（人看得见）。
    #   · 被 `bash edge_lab.sh` 直接执行 ⇒ `return` 会报错，故退回 `exit 2`。
    # 判据是 shell 的既有约定：source 进来的脚本 `$0` 仍是**调用方**的名字。
    if [ "${BASH_SOURCE[0]}" != "$0" ]; then
      case $- in *i*) return 2 ;; esac
      kill -TERM $$
      return 2
    fi
    exit 2 ;;
esac

# ---------------------------------------------------------------------------
# 两条 CLI：**拓扑级**与**目标级**（Fix round 1 / I-1 + M-3）
# ---------------------------------------------------------------------------
# 抽象前每个路径上的覆盖效力必须**逐条保留**，这条纪律决定了下面的结构：
#
#   · 拓扑级（`lab_up` / `lab_down` / `lab_node_counts`）在 clab 下跑的是 `clab`；
#   · 目标级（`lab_target_exec(_detached)` / `lab_push` / `lab_node_ip` / `lab_node_running`
#     / `lab_inspect` / `lab_list`）在 clab 下跑的是 **`docker`**、在 lxd 下是 `lxc`。
#
# 抽象前这两类**没有任何共用开关**：`clab` 那几条命令写死 `clab`，容器级命令写死 `docker`
# （`edge_probe.sh` 另有一个 `EDGEEXP_DOCKER_BIN` 专门覆盖**容器级**的 `docker`）。
# 修复前的实现把两者塞进同一个 `lab_bin`，于是 `edge_probe.sh` 把 `EDGEEXP_LAB_BIN=docker`
# 钉进来之后：容器级命令**完全看不到**这个覆盖（clab 分支写死 `docker`），而拓扑级命令
# **反而被它带偏**（去调 `docker inspect -t <拓扑>`）—— 一个变量同时造成"覆盖失效"与"错 CLI"，
# 这就是评审 I-1/M-3 的根因。现在两个名字各管一层，互不影响。
lab_topology_bin="${EDGEEXP_LAB_TOPOLOGY_BIN:-}"
if [ -z "$lab_topology_bin" ]; then
  case "$lab_substrate" in
    clab) lab_topology_bin="clab" ;;
    lxd)  lab_topology_bin="${EDGEEXP_LXC_BIN:-lxc}" ;;
  esac
fi

# 目标级 CLI 在 clab 下就是 `docker` —— **保留抽象前的覆盖开关 `EDGEEXP_DOCKER_BIN`**
# （它是 `edge_probe.sh` 的既有接缝，也是"用两个可分辨的假 docker 证明覆盖有牙"那条判据的入口）。
# lxd 下是 `lxc`（`EDGEEXP_LXC_BIN` 可覆盖，供离线夹具用）。
lab_docker_bin="${EDGEEXP_DOCKER_BIN:-docker}"
lab_target_bin="${EDGEEXP_LAB_TARGET_BIN:-}"
if [ -z "$lab_target_bin" ]; then
  case "$lab_substrate" in
    clab) lab_target_bin="$lab_docker_bin" ;;
    lxd)  lab_target_bin="${EDGEEXP_LXC_BIN:-lxc}" ;;
  esac
fi

# lab_require_bins —— 前置检查（**单一来源**：调用脚本不再自己写一份命令清单）。
#
# 抽象前 `edge_reset.sh` 里那句 `for bin in clab docker curl python3 sha256sum` 就是一份
# 硬编码清单；搬进本层之后，清单按基质派生，调用脚本里不再出现基质命令字面（Fix round 1 / M-2）。
# 缺命令即返回 1 并说明缺的是哪一个 —— 调用方自己决定退出码（脚本侧一律 `exit 1`）。
lab_require_bins() {
  local bins=() bin
  case "$lab_substrate" in
    clab) bins=("$lab_topology_bin" "$lab_target_bin") ;;
    lxd)  bins=("$lab_topology_bin") ;;
  esac
  for bin in "${bins[@]}"; do
    command -v "$bin" >/dev/null 2>&1 || {
      echo "edge_lab: 缺少必需命令 $bin（基质 $lab_substrate）—— 先装好基质 CLI 再跑。" >&2
      return 1
    }
  done
  return 0
}

# lab_lab_dir / lab_topology —— lab 目录与拓扑文件。
#
# 路径的解析基准是本文件自己的位置（`edge_lab.sh` 与四个调用脚本同在 scripts/ 下），
# 因此调用方不必先把 `LAB_DIR` 算好再 source 本文件 —— source 顺序不再影响取到的是哪个路径。
lab_lab_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lab_topology="${EDGEEXP_TOPOLOGY:-$lab_lab_dir/asscor.clab.yml}"

# lab_inspect_log —— clab `inspect` 的 stderr 落点。**与抽象前的 `edge_reset.sh` 逐字相同**：
# `edge_reset.sh` 的 I9 分支与多句错误串都直接引用这个路径。
#
# `lab_tmp` 是本层临时文件的目录（默认 `/tmp`，抽象前写的就是这个值）。它**必须**可覆盖：
# 离线复现夹具要用自己的目录跑同一条命令（本机 /tmp 里躺着历史上 root 写下的同名文件，
# 夹具会以一个与"命令序列变了"完全无关的 Permission denied 变红 —— 那正是假证据的形态）。
lab_tmp="${EDGEEXP_LAB_TMP:-/tmp}"
lab_inspect_json="$lab_tmp/edgeexp-clab-inspect.json"
lab_inspect_log="$lab_tmp/edgeexp-clab-inspect.log"

# lab_target_spec <node> —— 把基质层的节点名翻成 **`edgescen -target` 的语法**
# （`docker:<容器>` / `lxd:<实例>`；见 cmd/edgescen 的 `parseNodeTarget`）。
#
# 为什么必须有一个**单一来源**做这件事（而不是在采集脚本里手工拼前缀）：记录里的
# `meta.observation_target` 来自 `edgescen` 那侧的解析结果，而 `edge_collect.sh` 的观测主体
# 断言拿 `EDGEEXP_TARGET` 去比对它 —— 两处对"这个节点叫什么"的口径一旦分叉，
# 断言就会以"记录声称观测主体是 X，而本轮声明的节点是 Y"的名义把每条记录都判死，
# 而真正的原因只是少了一个前缀。**clab 基质保持裸名字**：`docker exec <容器名>` 是既有语义，
# 也是抽象前的字节（题面要求 `docker:` 前缀下逐位不变）。
lab_target_spec() {
  local node="$1"
  case "$lab_substrate" in
    clab) printf '%s\n' "$node" ;;
    lxd)  printf 'lxd:%s\n' "$node" ;;
  esac
}

# lab_node_counts —— 节点计数（回显 "total up down"），**clab 分支与抽象前的 `clab_node_counts`
# 逐字等价**（同一份 python 解析、同一个 `--format json`、同一个 stderr 落点）。
#
# 为什么解析仍然留在基质层：`clab inspect --format json` 是拓扑自己的视图，它的形状
# （`{<lab 名>: [节点…]}` / 0.78 实测）是基质知识；换基质时"节点数"本来就要求另一套说法。
#
# **inspect 本身失败时回显 `-1 -1 -1`**（而不是 0 0 0）：0 节点的含义是"拓扑已清空"，那是一条
# 会被"destroy 之后断言拓扑为空"采信的结论 —— inspect 挂了却报 0 会让那条断言**空洞地通过**
# （Fix round 2 的 I9 项）。等待循环只看 total > 0，-1 会被当作"还没就绪"继续等。
lab_node_counts() {
  case "$lab_substrate" in
  clab)
    "$lab_topology_bin" inspect -t "$lab_topology" --format json > "$lab_inspect_json" 2>>"$lab_inspect_log"
    local rc=$?
    python3 - "$rc" "$lab_inspect_json" <<'PY'
import json, sys
rc = int(sys.argv[1])
if rc != 0:
    print(-1, -1, -1); raise SystemExit
try:
    data = json.load(open(sys.argv[2]))
except Exception:
    print(-1, -1, -1); raise SystemExit
# clab 的 --format json 是 {<lab 名>: [节点…]}（0.78 实测）；同时兼容 {containers:[…]} 形态
nodes = []
if isinstance(data, dict):
    if isinstance(data.get('containers'), list):
        nodes = data['containers']
    else:
        for value in data.values():
            if isinstance(value, list):
                nodes.extend(value)
elif isinstance(data, list):
    nodes = data
up = sum(1 for c in nodes if (c.get('state') or '').lower() in ('running', 'up'))
print(len(nodes), up, len(nodes) - up)
PY
    ;;
  lxd)
    # LXD 侧没有"拓扑"这个对象，节点数不是能从这个基质问出来的东西。回显 -1（"查不出来"）
    # 并**响亮说明** —— 调用方把它读成"环境不可用"而失败，正是这里想要的处置。
    echo "edge_lab: lab_node_counts 对 lxd 不适用（LXD 上没有拓扑对象；节点集合由实例列表定义）——" >&2
    echo "  返回 -1 -1 -1（=『查不出来』，不是『0 个节点』），调用方不得据此断言环境已清空。" >&2
    printf '%s\n' "-1 -1 -1"
    ;;
  esac
}

# lab_up —— 建拓扑（clab: `deploy`；幂等性由 clab 自己负责）。
#
# 关键路径：**不做任何容错**（`edge_reset.sh` 的既有契约：deploy 失败即整轮失败）。
# 不用 `--reconfigure`：后者不重建 veth，上一场景的接口状态会带进下一场景（Task 3 之前实测过）。
lab_up() {
  case "$lab_substrate" in
  clab)
    "$lab_topology_bin" deploy -t "$lab_topology"
    ;;
  lxd)
    echo "edge_lab: lab_up 对 lxd 不适用 —— A-1 上的实验环境是【既有实例集合】（控制侧裁定" >&2
    echo "  probe-ot005 等实例不得被删改），LXD 侧没有『建拓扑』这个动作，本层不会 launch 任何实例。" >&2
    echo "  这不是可以放过的不一致：静默返回 0 会让一次『复位成功』的假象进入记录。" >&2
    return 2 ;;
  esac
}

# lab_down —— 毁拓扑（clab: `destroy --cleanup`）。
#
# 与抽象前一致：这里的失败**由调用方容忍**（没部署过时 destroy 本来就会报错），
# 故本函数不自己判断、不打印、不吞错 —— 退出码原样交给调用方（它要据此走 I9 的补断言）。
lab_down() {
  case "$lab_substrate" in
  clab)
    "$lab_topology_bin" destroy -t "$lab_topology" --cleanup
    ;;
  lxd)
    echo "edge_lab: lab_down 对 lxd 不适用 —— 本层**永不**删除 A-1 上的实例（probe-ot005 等是" >&2
    echo "  控制侧的对照容器）。需要清理实例时由操作者显式手工执行，不在实验脚本的路径上。" >&2
    return 2 ;;
  esac
}

# lab_target_exec <node> <cmd…> —— 在目标内部执行命令（stdout/stderr 原样透传给调用方）。
#
# 两条等价性纪律（clab 分支）：
#   · 参数**逐条**透传（`"$@"`）：调用方写的是 `lab_target_exec "$NODE" bash -c "…"`，
#     而不是把一整串命令交给某个 shell 再分词 —— 后者会让含空格/引号的判据体被拆开。
#   · 不自己重定向 stdout/stderr：抽象前的调用点各自决定 `2>/dev/null` 或 `>/dev/null 2>&1`
#     （有的故意要看错误），本层一律不做决定。
lab_target_exec() {
  local node="$1"; shift
  case "$lab_substrate" in
  clab)
    # 用 `$lab_target_bin`（clab 下默认 `docker`，`EDGEEXP_DOCKER_BIN` 可覆盖），
    # **不是**写死的 `docker` —— 写死会让抽象前那个覆盖开关在容器级路径上失效（I-1）。
    "$lab_target_bin" exec "$node" "$@"
    ;;
  lxd)
    # `--` 把命令与 lxc 自己的开关分开：`lxc exec <实例> -- <cmd…>`。少了它，
    # 一条以 `-` 开头的命令串会被 lxc 当成自己的参数（实测 rc=1）。
    "$lab_target_bin" exec "$node" -- "$@"
    ;;
  esac
}

# lab_push <local> <node> <dest> —— 把文件送进目标（dest 是**目标内**绝对路径）。
#
# 两种基质的语法不同（clab: `docker cp <local> <node>:<dest>`；lxd: `lxc file push <local> <node><dest>`）
# —— 这正是本层存在的理由：调用方只说"把这个文件放到那个位置的节点里"。
lab_push() {
  local local_path="$1" node="$2" dest="$3"
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" cp "$local_path" "$node:$dest"
    ;;
  lxd)
    "$lab_target_bin" file push "$local_path" "$node$dest"
    ;;
  esac
}

# lab_target_exec_detached <node> <cmd…> —— 在目标内起一个**不随本次连接结束而退出**的进程
# （调用方立即返回，不等它跑完）。
#
# 为什么不能复用 `lab_target_exec`：两种基质的"脱离"机制不同，而错的机制会**静默**失效——
# 进程被 SIGHUP 带走后，调用方只看到"agent 一直没回连"，那与"agent 起不来"同形。
#
#   · clab（`docker exec -d`）：docker 在容器内起进程后立即返回，stdin 为 /dev/null，
#     不随客户端断开而终止 —— 与抽象前的调用点逐字等价。
#   · lxd（`lxc exec` 没有 -d）：走**shell 的脱离惯用法**。实测过
#     `lxc exec <实例> -- nohup bash -c 'sleep 5; …' &`（**必须**加 nohup 与重定向：
#     只写 `&` 的话命令的 stdio 还挂在掉线即断的 exec 通道上，客户端一断进程就被带走）。
#
# **argv 必须逐条保真**（Fix round 1 / I-2）：修复前这里把 `"$@"` 压成 `"$*"` 再拼成
# `nohup sh -c '<整串>'`，于是同一个调用点（`lab_target_exec_detached <node> bash -c "…"`）
# 在两种基质下**语义不同** —— lxd 侧节点内拿到的是"`bash -c` + 若干分离参数"，
# `bash -c` 只取第一个参数当脚本、其余变成 `$0/$1…`，命令串本身被丢掉；而调用点**返回 0**，
# 兜底只剩 180 s 的 agent 回连超时。评审用假 CLI 直接复现（sandcat 收到空 argv）。
# 现在与 clab 同语义：把调用方给的 **argv** 原样转交节点内的 `sh -c`（`"$@"` 放在
# `sh -c` 的脚本位置之后，于是 `sh` 的 `$@` 就是这些 argv；`_` 占位 `$0`）。
#
# **返回码语义（Fix round 1 / M-6，逐条写明）**：两种基质返回的都是"**交付这条启动请求**的结果"，
# 不是"被启动的进程后来怎么样了"：
#   · clab：`docker exec -d` 的退出码（docker CLI 自己起不来/容器不在 ⇒ 非零；它把请求交给
#     daemon 之后立刻返回 0，**之后**进程崩掉与这个 rc 无关）；
#   · lxd：`lxc exec …` 的退出码（实例不存在/连不上 ⇒ 非零；节点内那段 `nohup … &` 把命令挂进
#     后台后立即返回 0，**它自己**是否成功不由这个 rc 表达）。
#   ⇒ 两侧**都**不能用 rc 判断"agent 有没有起来"。既有兜底（`edge_reset.sh` 的 `AGENT_WAIT_S`）
#   就是为这件事存在的，本轮**没有**给它加第二套判据 —— 加"启动后立刻查一次"会把两件事混成一个
#   结论（实例活着 ≠ 命令跑成功），而要真正区分它得让节点内进程把结果写回来，那是 Step 3/4 的事
#   （真机上验证"会话断开后进程仍在跑"也必须在那时候做）。
lab_target_exec_detached() {
  local node="$1"; shift
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" exec -d "$node" "$@"
    ;;
  lxd)
    "$lab_target_bin" exec "$node" -- sh -c 'nohup "$@" >/dev/null 2>&1 </dev/null &' _ "$@"
    ;;
  esac
}

# lab_node_ip <node> <iface> —— 取目标某接口的 IPv4 CIDR（例如 `10.217.208.42/24`）。
#
# 无地址/接口不存在 ⇒ 打印空行并返回非零（调用方据此走"探测候选为空"的既有分支）；
# clab 分支的命令、重定向与抽象前的 `docker exec "$NODE" ip -4 -o addr show eth0 2>/dev/null` 逐字相同。
lab_node_ip() {
  local node="$1" iface="$2"
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" exec "$node" ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4; exit}'
    ;;
  lxd)
    "$lab_target_bin" exec "$node" -- ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4; exit}'
    ;;
  esac
}

# lab_node_running <node> —— 实例在跑吗：打印 `true`/`false`，**实例不存在则非零退出**。
#
# 两种基质的取值手段不同、形状也不同（clab: `docker inspect -f {{.State.Running}}`；
# lxd: `lxc info` 的 `Status:` 行），这正是本层要收口的东西：调用方（探针）只问"能不能在里面执行"，
# 不该知道 `true` 是从哪来的。**判据必须把"不存在"与"在跑/没跑"分开**：
# 假 docker 夹具（`build/test-edge-probe.sh`）注入的假可执行文件正是按 `inspect -f` 应答的，
# 故 clab 分支的命令形状与抽象前逐字相同。
lab_node_running() {
  local node="$1"
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" inspect -f '{{.State.Running}}' "$node"
    ;;
  lxd)
    local out status
    out="$("$lab_target_bin" info "$node" 2>/dev/null)" || return 1
    status="$(printf '%s\n' "$out" | awk -F': *' '$1 ~ /^ *Status$/ {print tolower($2); exit}')"
    [ -n "$status" ] || return 1
    case "$status" in
      running) printf 'true\n' ;;
      *)       printf 'false\n' ;;
    esac
    ;;
  esac
}

# lab_inspect <node> —— 目标的基质视图（存在性/运行状态的**权威**判据），打印 JSON。
#
# 调用方只用它的退出码回答"这个节点存在吗"（clab 是 `docker inspect`、lxd 是 `lxc info`）；
# 打印出来的 JSON 留在日志里供排障。抽象前该处是 `docker inspect "$NODE" >/dev/null 2>&1`，
# 本函数把输出**收下**再交给调用方重定向 —— 退出码语义不变。
lab_inspect() {
  local node="$1"
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" inspect "$node"
    ;;
  lxd)
    "$lab_target_bin" info "$node"
    ;;
  esac
}

# lab_list —— 列出目标（每行一个名字，**含非 running 的**：调用方自己判断状态）。
#
# clab 的 `docker ps -a` 是"这台机器上所有容器"，不是"本拓扑的节点"；拓扑视图请用
# `lab_node_counts`（它才是 `clab inspect` 的拓扑视图）。这里刻意给出两种基质的"实例名字面"，
# 供干跑与排障使用。
lab_list() {
  case "$lab_substrate" in
  clab)
    "$lab_target_bin" ps -a --format '{{.Names}}'
    ;;
  lxd)
    "$lab_target_bin" list --format csv -c n
    ;;
  esac
}
