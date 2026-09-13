#!/bin/bash
# shellcheck disable=SC2154
#
# ↑ 文件级豁免 SC2154（"引用了但没赋值"）：`lab_*` 由 `. edge_lab.sh` 在 source 时赋值，
#   而 shellcheck 不跨文件跟踪变量。代价：本文件里拼错的 `$lab_xxx` 也不会被报出来
#   （ShellCheck 0.9 不支持按名字限定豁免）—— 基质的离线用例负责兜住这件事。
# ============================================================================
# edge_probe.sh —— **节点内**真实条件探针（Task 4C Step 3）
# ============================================================================
#
# 用法（被 edge_attack.sh source；也可手工 source 来单独验证探针）：
#   . scripts/edge_probe.sh <容器名>       # 必须在**顶层** source 并传参（见下方"命名与调用约定"）
#   probe_host_ready                       # 容器存在且 docker 可用，否则**响亮失败**
#   probe_host                              # 节点内进程自报的 hostname（失败 ⇒ 非零）
#   probe_condition_holds EF-NO-IDS         # 0 = 缺失；1 = 在位；2 = 探针没跑成
#
# 为什么必须搬进节点：此前 `condition_holds()` 用的是**跑脚本的这台机器**的
# `cat /proc/sys/...`、`ps -eo comm`、`getenforce` —— 而脚本在 WSL 上跑、被攻节点是
# host1 容器。于是 R 组"我们真的把 IDS 去掉了"这句话探的是另一台机器。
#
# 本脚本的判据逐条对齐 `internal/checks/linux` 的同名检查（OT-005 / RS-005 / RS-006 /
# RS-007 / EF-001 / EF-002）—— 记录构造要求是"checks[] 是引擎真实失败的检查"，
# 所以"条件是否成立"必须用**引擎的判据**来问，不是另立一套。
# **因子 → 触发检查**的映射不在本文件里重抄：它来自配置的 `trigger.<ID>`
# （`configs/edgeexp/m0-baseline.ini` 的 `[edge_factors.model]` 段，与
# `config.ResolveEdgeFactorTriggerMap` 同源），由 `edge_attack.sh` 解析后经 `probe_entry`
# 写进 `condition_probes[].check` —— 故那个字段可能与下面的 case 标签不同（例如
# `EF-3FA` → `EF-002`），改动配置时必须同步本文件的 case。
#
# 三类退出码（调用方必须区分前两个）：
#   0 = 该防护在这台节点上**确实缺失**（条件成立）
#   1 = 条件不成立（防护在位）
#   2 = 探针**没跑成**（docker 不可用 / 容器不在跑 / 节点里没有 bash / **判据没有跑到底**）
#       —— 这不是"条件不成立"，把它当成 1 会让"探针没执行"静默变成一条有效的否定证据。
#
# 命名与调用约定（Fix round 1 / M-11）：本文件在**顶层**定义 `probe_target` 与
# `probe_docker_bin` 两个全局变量，并读取**调用方的 `$1`/`$EDGEEXP_TARGET`**。因此：
#   · 必须在**顶层** source（在函数里 source 会静默绑定到那个函数的位置参数）；
#   · 若调用方已在自己的命名空间里用了同名的变量，请改名后再 source（这两个名字属于本文件的契约）。
# ============================================================================

# probe_target 是探针要进去的容器名（由调用方给出；空 = 未声明，任何探针都直接失败）。
probe_target="${1:-${EDGEEXP_TARGET:-}}"

# probe_docker_bin 允许覆盖 docker 可执行文件（测试用；默认 PATH 上的 docker）。
#
# 它同时是**基质层**的 CLI：下面把它钉进 `EDGEEXP_LAB_BIN` 再 source `edge_lab.sh`，
# 于是"假 docker"这类既有夹具仍然只需替换一个可执行文件，不必知道基质层存在（Task 4D Step 1）。
probe_docker_bin="${EDGEEXP_DOCKER_BIN:-docker}"

# --- 基质层（Task 4D Step 1）----------------------------------------------------
# 本脚本是**节点内**执行最多的那一处（探针的每次判定都在目标内跑），故它必须与
# edge_reset/attack/collect 走同一个基质调用点：`docker exec`/`docker cp` 曾在这里各写死一处，
# 换基质（A-1/LXD）时"探针还在 WSL 的 docker 上跑"而记录看起来完全正常 —— 那是最危险的形态。
#
# 覆盖规则：`EDGEEXP_LAB_BIN` 取 `probe_docker_bin`（默认 docker），`EDGEEXP_SUBSTRATE` 取
# 调用方给的值（默认 clab ⇒ 与抽象前逐字等价：同一条 `docker exec` / `docker cp`）。
export EDGEEXP_LAB_BIN="$probe_docker_bin"
# shellcheck source=scripts/edge_lab.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/edge_lab.sh"

# probe_root 是判据体的**根路径**（默认 `/`，节点内就是它自己的根）。
#
# 为什么留这个参数（Fix round 1 / I-4）：`EF-002` 的三类计数判据需要**离线夹具**才能证明
# 它和引擎一致（"只有 1 类 PAM 模块 ⇒ 引擎判失败"，这需要造一棵假 /etc/pam.d）。
# 有了它，夹具能在临时目录里跑同一份判据体，不必碰 lab。
# **生产用法永远是默认的 `/`**；把它设成别的值只允许出现在测试里。
probe_root="${EDGEEXP_PROBE_ROOT:-/}"

# probe_sentinel 是"判据跑到底了"的哨兵行。
#
# 为什么必须有哨兵（Fix round 1 / I-5）：判据的结论是**退出码**，而节点里的登录 shell
# （旧实现用的 `bash -ls`）会先跑 `/etc/profile`、`~/.bash_profile|.bash_login|.profile`，
# 退出时还会跑 `~/.bash_logout` —— 任何一个 `exit` 都能**顶替**判据的退出码（评审实测：
# profile 里一句 `exit 0` 就把"判据其实没跑"读成"防护缺失"）。现在节点内进程改用
# **非登录** shell（`bash -s`）并在判据体末尾无条件打一行哨兵，父进程**必须**看到它才接受
# 0/1；看不到（stdin 丢了 / 只读到一半 / 判据被提前终结）一律返回 2。
probe_sentinel="__edge_probe_ran__"

# probe_tmp_prefix 是"判据体临时文件"的容器内前缀（父进程落本地文件 → docker cp → 执行 → 删）。
# 用固定前缀 + PID：同一台机器上并发跑两轮探针时不会互相覆盖。
probe_tmp_prefix="/tmp/edge_probe"

# probe_host 返回节点内进程**自报**的 hostname（写进 condition_probes，让"探针在哪台机器上
# 跑的"这句话本身可核对）。它是自报、不是密码学自证（被控节点上的进程能报任何值）。
# 失败时**非零退出**：调用方据此判定"探针没跑成"。
probe_host() {
  local out rc
  out="$(lab_target_exec "$probe_target" hostname 2>/dev/null)" && rc=0 || rc=$?
  [ "$rc" -eq 0 ] || return 2
  printf '%s\n' "$(printf '%s' "$out" | tr -d '[:space:]')"
}

# probe_host_ready 在**任何**探针之前调用：docker 不可用 / 容器不存在或不在跑 ⇒ 响亮失败。
#
# 为什么不能省：探针没跑成与"条件不成立"在退出码上必须分开（见文件头），而"容器根本没起"
# 是这两种情况里最难在数据上看出来的 —— 记录里只会少几条 condition_probes。
#
# 说明：这里用**基质视图**判"在不在跑"，用 `lab_target_exec` 判"能不能在里面执行"
# （一个停掉的实例其视图仍然存在，而 exec 会失败）—— 两条都要过。
probe_host_ready() {
  if [ -z "$probe_target" ]; then
    echo "edge_probe: 没有声明目标节点 —— R 组的真实缺失探针必须**在节点上**执行" >&2
    echo "  请给出容器名（. edge_probe.sh <容器名> 或 EDGEEXP_TARGET=<容器名>）。" >&2
    echo "  不得退回本机探针：那正是『探的是跑脚本的这台机器』这个缺陷的形态。" >&2
    return 2
  fi
  command -v "$lab_bin" >/dev/null 2>&1 || {
    echo "edge_probe: 找不到基质命令 $lab_bin（基质 $lab_substrate）—— 无法在节点 $probe_target 内执行探针" >&2
    echo "  探针没跑成不等于条件成立；整轮失败，不得退回本机探针。" >&2
    return 2
  }
  local running
  running="$(lab_node_running "$probe_target" 2>/dev/null)" || {
    echo "edge_probe: 目标节点 $probe_target 不存在（基质 $lab_substrate 的 inspect 失败）—— 探针无从执行" >&2
    return 2
  }
  [ "$running" = "true" ] || {
    echo "edge_probe: 目标节点 $probe_target 不在运行（State.Running=$running）—— 探针无从执行" >&2
    return 2
  }
  return 0
}

# _probe_script 是**在节点里执行**的那段判据（与 factor 一一对应）。
#
# 协议（Fix round 1 / I-5 定稿）：判据体**只报结论文字**（`DEFENSE_PRESENT|ABSENT`）并把结论
# 写在**退出码之外**；"判据跑到底了"由**哨兵行**回答，而哨兵用 `trap … EXIT` 打 —— 见 preamble。
# 这样节点里任何 `exit`（包括判据体自己的提前退出）都**顶替不了**它，退出码也不再承担语义。
#
# 判据文字的两种取值（其余一律视为"没跑成"=2）：
#   DEFENSE_PRESENT = 该防护在位（引擎的对应检查会**通过**）
#   DEFENSE_ABSENT  = 该防护缺失（引擎的对应检查会**失败**）
_probe_script() {
  local factor="$1"
  local body
  case "$factor" in
    EF-SELINUX|EF-APPARMOR)
      # OT-005（checks.go 的 ot005）：**先跑 getenforce**，只有它执行失败才回退 aa-status；
      # 执行成功时仅当 trim 后 == Enforcing 才算在位。
      # Fix round 1 / M-6：旧探针在"getenforce 能跑但输出非 Enforcing"时**仍会回退** aa-status，
      # 而引擎不会 —— 那条路径上探针可以说"在位"而引擎判失败。现在同构：getenforce 能跑就不再回退。
      #
      # `aa-status` 那条同理要用绝对路径：引擎在容器里跑的是 `common.RunCmd`（按 PATH 查找），
      # 而判据体是喂给 `bash -s` 的**字符串**、不走 PATH 缓存，故显式写绝对路径最贴近它。
      body='
if command -v getenforce >/dev/null 2>&1; then
  if [ "$(getenforce 2>/dev/null | tr -d "[:space:]")" = "Enforcing" ]; then echo DEFENSE_PRESENT; else echo DEFENSE_ABSENT; fi
  exit 0
fi
for p in /usr/sbin/aa-status /sbin/aa-status /usr/bin/aa-status; do
  if [ -x "$PROBE_ROOT$p" ] && [ "$("$PROBE_ROOT$p" 2>/dev/null | grep -c "profiles are loaded")" -gt 0 ]; then echo DEFENSE_PRESENT; exit 0; fi
done
echo DEFENSE_ABSENT' ;;
    EF-SYNCOOKIE)
      # RS-005：只读 $PROBE_ROOT/proc/sys/net/ipv4/tcp_syncookies，要求值恰为 1；读失败算缺失。
      body='
if [ "$(cat "$PROBE_ROOT/proc/sys/net/ipv4/tcp_syncookies" 2>/dev/null | tr -d "[:space:]")" = "1" ]; then
  echo DEFENSE_PRESENT
else
  echo DEFENSE_ABSENT
fi' ;;
    EF-NO-IDS)
      # RS-006：先逐个 systemctl is-active（11 个工具），**全部落空**才扫 ps 的进程名（9 个）。
      body='
present=0
for tool in wazuh-agent ossec-hids ossec-agent aide tripwire samhain rkhunter suricata snort snort3 zeek; do
  if command -v systemctl >/dev/null 2>&1 && [ "$(systemctl is-active "$tool" 2>/dev/null || true)" = "active" ]; then present=1; fi
done
if [ "$present" -eq 0 ] && command -v ps >/dev/null 2>&1; then
  while read -r comm; do
    case "$comm" in
      suricata|snort|snort3|zeek|wazuh-agent|ossec-agent|aide|tripwire|samhain) present=1 ;;
    esac
  done < <(ps -eo comm --no-headers 2>/dev/null || true)
fi
if [ "$present" -eq 1 ]; then echo DEFENSE_PRESENT; else echo DEFENSE_ABSENT; fi' ;;
    EF-NO-SIEM)
      # RS-007：三份告警配置文件之一存在且（小写后）含 email/alert/notification。
      #
      # 逐文件用 `grep -c` 而不是 `grep -q`：`-q` 命中即退出会让上游吃到 SIGPIPE
      # （实测：判据体的 stdout 被杀 ⇒ 哨兵没打出来 ⇒ 整轮被判"没跑到底"）。
      body='
present=0
for cfg in /var/ossec/etc/ossec.conf /etc/wazuh-agent/ossec.conf /etc/aide/aide.conf; do
  if [ -r "$PROBE_ROOT$cfg" ] && [ "$(grep -ciE "email|alert|notification" "$PROBE_ROOT$cfg")" -gt 0 ]; then present=1; fi
done
if [ "$present" -eq 1 ]; then echo DEFENSE_PRESENT; else echo DEFENSE_ABSENT; fi' ;;
    EF-002FA)
      # EF-001（checks.go 的 ef001）：三份 PAM 文件任一含 5 个子串之一 ⇒ 通过（在位）。
      #
      # 注意这条**故意**与 EF-002 不同：EF-001 是"出现任一第二因素模块即通过"，
      # 而 EF-3FA 对应的 EF-002 要求三类齐备（见下一个分支）。
      body='
present=0
for pam in /etc/pam.d/sshd /etc/pam.d/common-auth /etc/pam.d/system-auth; do
  if [ -r "$PROBE_ROOT$pam" ] && [ "$(grep -cE "pam_google_authenticator|pam_oath|pam_duo|pam_u2f|pam_pkcs11" "$PROBE_ROOT$pam")" -gt 0 ]; then present=1; fi
done
if [ "$present" -eq 1 ]; then echo DEFENSE_PRESENT; else echo DEFENSE_ABSENT; fi' ;;
    EF-3FA)
      # EF-002（`checks.go` 的 `ef002`）—— **按文件累加**，`factorCount >= 3` 才通过：
      #   对三个 PAM 文件各走一遍，每类在该文件里至多 +1（同类命中多个子串不重复计分）：
      #   ① pam_google_authenticator | pam_oath   ② pam_u2f | pam_pkcs11
      #   ③ pam_fprintd | pam_biometric
      #   文件读不到（不存在/不可读）⇒ `continue`（+0），与引擎的 `os.ReadFile` 失败分支一致。
      #
      # Fix round 1 / I-4：旧探针在这里复用 EF-001 的判据（"出现任一 2FA 子串即在位"），
      # 完全没有第三类 —— 一台只装了 `pam_u2f` 的节点上引擎判**失败**、探针却报"在位"。
      #
      # 计数口径改成与引擎**同构的按文件累加**（Fix round 2 残余 I-4）：
      # 此前的"三类**并集**"（同一类跨两个文件只算一类）会造出**单向保守的假缺失** ——
      # `pam_google_authenticator` 同时在 `/etc/pam.d/sshd` 与 `/etc/pam.d/common-auth`（同类 ①
      # 命中两个文件）再叠一类 ② ⇒ 引擎 `factorCount = 3` **通过**，而并集只看到 2 类 ⇒ 探针报
      # "缺失"，`S5-cascade-3fa` 的节点侧证据与 `checks[]` 又一次**反向**。
      # 现在两侧同构 ⇒ 同一份 PAM 布局必然得到**同一个结论**（不再有"更严/更宽"的方向差）。
      #
      # 逐子串用 `grep -c` 而不是 `grep -q`：`-q` 命中即退出会让上游命令吃到 SIGPIPE
      # （实测：文件写入端被杀 ⇒ 哨兵没打出来 ⇒ 整轮被判"没跑到底"）。
      body='
factor_count=0
for pam in /etc/pam.d/sshd /etc/pam.d/common-auth /etc/pam.d/system-auth; do
  [ -r "$PROBE_ROOT$pam" ] || continue
  [ "$(grep -cE "pam_google_authenticator|pam_oath" "$PROBE_ROOT$pam")" -gt 0 ] && factor_count=$((factor_count + 1))
  [ "$(grep -cE "pam_u2f|pam_pkcs11" "$PROBE_ROOT$pam")" -gt 0 ] && factor_count=$((factor_count + 1))
  [ "$(grep -cE "pam_fprintd|pam_biometric" "$PROBE_ROOT$pam")" -gt 0 ] && factor_count=$((factor_count + 1))
done
if [ "$factor_count" -ge 3 ]; then echo DEFENSE_PRESENT; else echo DEFENSE_ABSENT; fi' ;;
    *)
      echo "edge_probe: 因子 $factor 没有条件探针（新增因子时必须补一条，否则真实缺失对照会静默失效）" >&2
      return 2 ;;
  esac
  # 哨兵在**判据体之外**统一追加，且用 `trap … EXIT` 打：这样"判据到底跑没跑完"与判据体
  # 自己有没有中途 `exit` 无关（实测踩到过：EF-SELINUX 的 `if … then … exit 0; fi` 分支一进，
  # 末尾那句 `echo 哨兵` 就永远不会执行，整轮被误判成"没跑到底"）。
  # 退出码不再承担语义 ⇒ 判据体的 `exit` 可以是任意值。
  #
  # preamble 做三件事：
  #   · 给夹具一条**明确的失败路径**：`EDGEEXP_PROBE_ROOT` 指向的树必须长得像一个根
  #     （至少有 `/proc`），否则直接报 PROBE_FIXTURE_ROOT（父进程读成"没给出结论"=2）。
  #     这堵住的是"夹具配错 ⇒ 判据在残缺的 PATH/根上乱跑 ⇒ 给出一个看似有效的结论"。
  #   · 把判据体依赖的**两个根**设好（`PROBE_ROOT` 与 `PATH`）：`PATH` 用
  #     `$PROBE_ROOT/usr/sbin:sbin:usr/bin:bin:/usr/sbin:/sbin:/usr/bin:/bin` —— 前四段让夹具能
  #     **遮蔽**工具（放一个空的同名可执行文件即可让 `command -v` 命中、而它什么都不输出），
  #     后两段保证 `grep`/`tr`/`cat` 这类**判据自己要用的**基础工具仍然可用。
  #     生产上 `PROBE_ROOT=/`，于是路径退化成 `/usr/sbin:/sbin:/usr/bin:/bin`（Docker 容器的
  #     默认 PATH 子集；判据体用的都是绝对路径或这几个目录里的命令）。
  #   · 清掉节点侧可能存在的 `CDPATH`（它会污染 `cd` 的输出；本判据体不用 `cd`，防将来）。
  preamble='export PROBE_ROOT='"$probe_root"'
trap "echo '"$probe_sentinel"'" EXIT
if [ ! -d "$PROBE_ROOT/proc" ]; then echo PROBE_FIXTURE_ROOT; exit 0; fi
PATH="$PROBE_ROOT/usr/sbin:$PROBE_ROOT/sbin:$PROBE_ROOT/usr/bin:$PROBE_ROOT/bin:/usr/sbin:/sbin:/usr/bin:/bin"
export PATH
unset CDPATH'
  printf '#!/bin/bash\n%s\n%s\nexit 0\n' "$preamble" "$body"
}

# probe_condition_holds 是唯一的对外探针入口。
#
# 它把判据送进节点执行，并按**哨兵 + 结论文字**映射成三类结论：
#   0 ⇒ 条件成立（防护确实不在）   1 ⇒ 条件不成立   2 ⇒ 探针没跑成（docker/容器/bash 的问题）
#
# 三条实现要点（每一条都对应一次实测事故）：
#   · `probe_host_ready` 必须先过：**不同的 docker 失败会给出不同的退出码**（容器不存在是 1、
#     daemon 不可达是 125），而 1 在旧协议里恰好是"条件不成立" ⇒ 会把"容器根本不在"读成一条
#     有效的否定证据。
#   · `_probe_script` 对"没有探针的因子"返回非零，而它出现在**普通赋值**里 ⇒ 在 `set -e` 的
#     调用方会直接把整个脚本带走（实测：探针循环静默停在那一行）。故自己接住退出码再分类。
#   · 节点内用**非登录** `bash -s`（不是 `bash -ls`）：登录 shell 的 profile/logout 能顶替退出码
#     并重写 PATH（评审实测）。同时 `-i` 必须保留：丢了 stdin 会让 bash 以 0 退出。
probe_condition_holds() {
  # `out`/`probe_err` 显式初始化：`set -u` 下"没有赋值就被读"会直接终止脚本，而
  # "探针没跑成"这条路径**本来**就不给 `out` 赋值（判据体没生成 ⇒ 不进 docker exec 分支）。
  local factor="$1" body="" dc=0 out="" probe_err="" verdict="" script_in_container=""
  probe_host_ready || return 2

  # M-10：保存调用方的 `-e` / `pipefail` 状态，函数返回前**原样还原** —— 无条件 `set -e`
  # 会把一个交互式调用方的 shell 永久打开 `-e`（且原本开着的 `pipefail` 也不该被本函数关掉）。
  #
  # 那两条判定用的 `printf … | grep` 的退出码本来就被 `if` / 命令替换接住，故在 `set +e` 下跑
  # 不影响结论；真正的"探针跑成没有"只由 `docker exec` 的退出码与哨兵回答。
  local had_e=0 had_pipefail=0
  case $- in *e*) had_e=1 ;; esac
  case "$(set -o | awk '$1=="pipefail"{print $2}')" in on) had_pipefail=1 ;; esac
  set +e
  set +o pipefail
  body="$(_probe_script "$factor")"
  dc=$?
  script_in_container=""
  if [ "$dc" -eq 0 ] && [ -n "$body" ]; then
    # **判据体走文件、不走 stdin**（Fix round 1 实测的坑）：`… | docker exec -i <node> bash -s`
    # 会在节点里丢掉脚本的**末尾几行**（实测：结论行打出来了、紧跟其后的哨兵行没有 ⇒ 整轮被
    # 判"没跑到底"）。改用"父进程落一个临时文件 → docker cp 进节点 → `bash <路径>`"：
    # 脚本来自文件 ⇒ bash 不从 stdin 边读边执行 ⇒ 末尾必然执行；顺带也不再依赖 `-i`。
    #
    # 文件名用 `$$`（**父进程** PID，整棵调用树里稳定）而不是 `$BASHPID`：后者在每个
    # 命令替换里都不同，会让 cp 与 exec 指向两个文件名（调试时实测踩到过）。
    local instance="$$"
    local body_file="$probe_tmp_prefix.$factor.$instance.sh"
    local container_file="$probe_tmp_prefix.$instance.sh"
    if printf '%s\n' "$body" > "$body_file" &&
      lab_push "$body_file" "$probe_target" "$container_file" >/dev/null 2>&1; then
      script_in_container="$container_file"
      out="$(lab_target_exec "$probe_target" bash "$script_in_container" 2>&1)"
      dc=$?
      probe_err="$out"
      lab_target_exec "$probe_target" rm -f "$script_in_container" >/dev/null 2>&1
    else
      dc=2
      probe_err="判据体没能送进节点（写 $body_file 或基质 lab_push 失败）"
    fi
    rm -f "$body_file"
  else
    dc=2
  fi
  set +e
  [ "$had_pipefail" -eq 1 ] && set -o pipefail
  [ "$had_e" -eq 1 ] && set -e

  # 哨兵：看不到就一律 2（判据被提前终结 / 只读到一半 / 判据体没送进去）。
  #
  # 输出收集方式：把判据的 **stdout+stderr 一起**收进变量（stderr 也要 —— 判据体的报错在那里，
  # 且 `grep -qx` 不会被它误命中）。用 `$(…)` 而不是临时文件，于是本函数**不在调用方命名空间
  # 留下任何变量**（旧的 `PROBE_LAST_OUTPUT` 全局已删除）。
  if ! printf '%s\n' "$out" | grep -qx "$probe_sentinel"; then
    if [ "$dc" -ne 0 ]; then
      echo "edge_probe: 探针 $factor 在节点 $probe_target 内没有跑成（docker exec 退出码 $dc）——" >&2
      printf '%s\n' "$probe_err" | tail -n 3 | sed 's/^/  │ /' >&2
    else
      echo "edge_probe: 探针 $factor 在节点 $probe_target 内没有跑到底（没看到哨兵 $probe_sentinel）——" >&2
      echo "  判据被提前终结 / 只读到一半 / 判据体没送进去都会长这样；整轮失败，不得据此写任何结论。" >&2
    fi
    return 2
  fi

  verdict="$(printf '%s\n' "$out" | grep -xE 'DEFENSE_(PRESENT|ABSENT)' | tail -n 1)"
  case "$verdict" in
    DEFENSE_PRESENT) return 1 ;;
    DEFENSE_ABSENT) return 0 ;;
    *)
      echo "edge_probe: 探针 $factor 在节点 $probe_target 内跑到底了，但没给出结论（哨兵在、DEFENSE_* 不在）——" >&2
      echo "  最常见的原因是夹具根配错（preamble 会报 PROBE_FIXTURE_ROOT）或判据体写错；" >&2
      echo "  整轮失败，不得据此写任何结论。" >&2
      return 2 ;;
  esac
}
