#!/usr/bin/env bash
# ============================================================================
# federation-verify.sh —— T4 联邦实验验收（在 PVE 宿主 dl360gen9 上运行）
#
# 检查项（对应 docs/2-experiments/T4_FEDERATION_ENV_2026-10-28.md §8）：
#   1 33 台 CT（930-932 节点 kernel + 940-969 agent）全部 running
#   2 3 个节点 kernel 已部署本仓库的差异配置（role/node_id/master_url/prism 参数）
#   3 30 个 agent.ini 全部指向**所属节点 kernel**（940-949→nk1、950-959→nk2、960-969→nk3）
#   4 每个节点 kernel 的 :50051 上都有 10 条 agent 会话（ss -tn）
#   5 每个节点 kernel 日志里有 10 个 agent 的心跳 + 评估结果
#   6 主 kernel（VM 910）的 :50051 上**没有**这 30 个 agent 的会话（ss + 日志双重检查）
#   7 主 kernel 能列出 3 个节点（federation status / curl 收集端点）
#   8 三个节点日志里的 "prism effective config" 参数互不相同且与模板一致
#   （信息检查）3 个节点 kernel 的 CA 指纹互不相同
#
# 用法：
#   bash scripts/federation-verify.sh              # 全部检查
#   bash scripts/federation-verify.sh -h           # 帮助
#
# 环境变量覆盖（默认值即 2026-10-28 规划值）：
#   NODE_IPS="192.168.30.71 192.168.30.72 192.168.30.73"
#   MASTER_HOST=192.168.30.50  MASTER_SSH_KEY=/root/.ssh/asc_kernel
#   AGENT_INI=/etc/asscor/agent.ini   CERT_DIR=/etc/asscor/certs
#
# 退出码：0 = 全部 PASS（WARN/INFO 不影响）；1 = 有 FAIL（含环境不满足）。
#
# 约定：本脚本只读（pct exec 只跑 ss/cat/grep/systemctl is-active/hostname，
#       ssh 到 910 只跑 ss/grep/curl/kernel --cli），不做任何创建/修改。
#       rc 判定一律用 `cmd; rc=$?` 形式，不依赖管道退出码。
# ============================================================================
set -u

# ---- 规划参数（与 docs 一致；可被环境变量覆盖） -----------------------------
NODE_CT_IDS_STR="${NODE_CT_IDS:-930 931 932}"
NODE_IPS_STR="${NODE_IPS:-192.168.30.71 192.168.30.72 192.168.30.73}"
NODE_NAMES_STR="${NODE_NAMES:-asc-nk1 asc-nk2 asc-nk3}"
NODE_IDS_STR="${NODE_IDS:-nk1 nk2 nk3}"
AGENT_GROUPS_STR="${AGENT_GROUPS:-940:949 950:959 960:969}"

AGENT_INI="${AGENT_INI:-/etc/asscor/agent.ini}"
CERT_DIR="${CERT_DIR:-/etc/asscor/certs}"
NODE_CONF_CANDIDATES="${NODE_CONF_CANDIDATES:-/etc/asscor/kernel.ini /opt/asscor/etc/kernel.ini /home/asc/asscor/etc/kernel.ini}"
NODE_LOG_CANDIDATES="${NODE_LOG_CANDIDATES:-/var/log/asscor-kernel.log /var/log/asscor/kernel.log}"
NODE_UNIT="${NODE_UNIT:-asscor-kernel}"

MASTER_HOST="${MASTER_HOST:-192.168.30.50}"
MASTER_USER="${MASTER_USER:-asc}"
MASTER_SSH_KEY="${MASTER_SSH_KEY:-/root/.ssh/asc_kernel}"
MASTER_KERNEL_BIN="${MASTER_KERNEL_BIN:-/home/asc/asscor/bin/kernel}"
MASTER_CLI_SOCK="${MASTER_CLI_SOCK:-/opt/asscor/asscor-cli.sock}"
MASTER_LOG="${MASTER_LOG:-/var/log/asscor-kernel.log}"
MASTER_FED_URL="${MASTER_FED_URL:-http://127.0.0.1:5099/federation/nodes}"
# 端点已由 internal/federation 实现（master.go）：
#   POST /federation/report —— 节点上报（带 X-Federation-Token）
#   GET  /federation/nodes  —— 收集结果（带 X-Federation-Token；token 为空才免头）
FED_TOKEN_HEADER="${FED_TOKEN_HEADER:-X-Federation-Token}"
FED_MASTER_URL="${FED_MASTER_URL:-http://192.168.30.50:5099}"
FED_TOKEN="${FED_TOKEN:-asscor-t4-demo}"

read -r -a NODE_CT_IDS <<< "$NODE_CT_IDS_STR"
read -r -a NODE_IPS <<< "$NODE_IPS_STR"
read -r -a NODE_NAMES <<< "$NODE_NAMES_STR"
read -r -a NODE_IDS <<< "$NODE_IDS_STR"
read -r -a AGENT_GROUPS <<< "$AGENT_GROUPS_STR"
NODE_COUNT="${#NODE_CT_IDS[@]}"

# 每个节点的期望 prism 参数（与 configs/federation/nk{1,2,3}.ini 对齐）
EXPECT_PRISM_SIG_nk1="debt_alpha=1.2 path_decay=0.80 max_path_depth=5 aggregation=rss"
EXPECT_PRISM_SIG_nk2="debt_alpha=1.5 path_decay=0.65 max_path_depth=7 aggregation=max"
EXPECT_PRISM_SIG_nk3="debt_alpha=1.8 path_decay=0.50 max_path_depth=9 aggregation=linear"

PASS=0
FAIL=0
WARN=0
INFO=0
FAILED_ITEMS=""

mark_pass() { PASS=$((PASS + 1)); printf '[PASS] %s\n' "$*"; }
mark_fail() { FAIL=$((FAIL + 1)); FAILED_ITEMS="$FAILED_ITEMS
  - $*"; printf '[FAIL] %s\n' "$*"; }
mark_warn() { WARN=$((WARN + 1)); printf '[WARN] %s\n' "$*"; }
mark_info() { INFO=$((INFO + 1)); printf '[INFO] %s\n' "$*"; }

usage() {
  sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}
[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

# ---- 通用小工具 ------------------------------------------------------------
trim() { printf '%s' "${1:-}" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

# 在 CT 内执行命令（read-only），输出到 stdout
ct_exec() {
  local vmid="$1"; shift
  pct exec "$vmid" -- "$@" 2>/dev/null
}

# 一次性抓取 pct list（避免 34 次 pct status；容器状态是后续所有检查的前置条件）
PCT_LIST=""
pct_list_refresh() {
  PCT_LIST="$(pct list 2>/dev/null)"
  [ -n "$PCT_LIST" ] || return 1
  return 0
}
status_of_vmid() {
  printf '%s\n' "$PCT_LIST" | awk -v id="$1" '$1==id {print $2; exit}'
}

ct_alive() {
  local st
  st="$(status_of_vmid "$1")"
  [ "$st" = "running" ] || return 1
  return 0
}

# INI 读取：从 stdin 的内容里取 [section] key 的值
ini_get() {
  local section="$1" key="$2"
  awk -v s="$section" -v k="$key" '
    /^[[:space:]]*\[/ {
      line=$0
      gsub(/^[[:space:]]*\[/, "", line); gsub(/\][[:space:]]*$/, "", line)
      cur=line; next
    }
    cur==s {
      eq=index($0, "=")
      if (eq > 0) {
        kk=substr($0, 1, eq-1); vv=substr($0, eq+1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", kk)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", vv)
        if (kk==k) { print vv; exit }
      }
    }
  '
}

# 读节点 kernel 配置：1 次 pct exec 返回 "PATH=<path>" + 文件内容
node_conf_dump() {
  local vmid="$1"
  pct exec "$vmid" -- sh -c '
    for f in /etc/asscor/kernel.ini /opt/asscor/etc/kernel.ini /home/asc/asscor/etc/kernel.ini; do
      if [ -f "$f" ]; then
        echo "PATH=$f"
        cat "$f"
        exit 0
      fi
    done
    exit 1
  ' 2>/dev/null
}

# 一次 pct exec 取 agent CT 的 hostname + IPv4 + agent.ini 内容 + agent 进程 cmdline
ct_agent_bundle() {
  local vmid="$1"
  pct exec "$vmid" -- sh -c '
    echo "HOST=$(hostname)"
    echo "IPS=$(hostname -I 2>/dev/null)"
    echo "@@@INI@@@"
    if [ -f /etc/asscor/agent.ini ]; then
      cat /etc/asscor/agent.ini
    else
      echo "@@@NOINI@@@"
    fi
    echo "@@@CMD@@@"
    CMD=""
    FALLBACK=""
    for p in /proc/[0-9]*; do
      [ -r "$p/comm" ] || continue
      exe=$(cat "$p/comm" 2>/dev/null)
      case "$exe" in
        *agent*)
          c=$(cat "$p/cmdline" 2>/dev/null)
          case "$c" in
            *kernel*) CMD="$c"; break ;;
          esac
          [ -z "$FALLBACK" ] && FALLBACK="$c"
          ;;
      esac
    done
    printf "%s\n" "${CMD:-$FALLBACK}"
  ' 2>/dev/null
}

# 一次 pct exec 抓节点 kernel 日志的关键信息（文件或 journald 自动选择）：
#   SRC=<path|journal>
#   HB=<heartbeat received 条数>
#   EVAL=<assessment result 条数>
#   @@@IDS@@@ 之后：去重后的 host_id 列表
#   @@@PRISM@@@ 之后：第一条 "prism effective config" 行
node_log_scan() {
  local vmid="$1"
  pct exec "$vmid" -- sh -c '
    SRC=""
    for c in $1; do
      if [ -f "$c" ]; then SRC="$c"; break; fi
    done
    if [ -n "$SRC" ]; then
      HB=$(grep -c "heartbeat received" "$SRC" 2>/dev/null)
      EVAL=$(grep -c "assessment result" "$SRC" 2>/dev/null)
      IDS=$(grep -oE "host_id\"?[:=]\"?[A-Za-z0-9._-]+" "$SRC" 2>/dev/null | sed -E "s/^host_id\"?[:=]\"?//" | sort -u)
      PRISM=$(grep -m1 "prism effective config" "$SRC" 2>/dev/null)
    else
      SRC=journal
      DATA=$(journalctl -u asscor-kernel --no-pager -n 4000 2>/dev/null)
      HB=$(printf "%s\n" "$DATA" | grep -c "heartbeat received")
      EVAL=$(printf "%s\n" "$DATA" | grep -c "assessment result")
      IDS=$(printf "%s\n" "$DATA" | grep -oE "host_id\"?[:=]\"?[A-Za-z0-9._-]+" | sed -E "s/^host_id\"?[:=]\"?//" | sort -u)
      PRISM=$(printf "%s\n" "$DATA" | grep -m1 "prism effective config")
    fi
    echo "SRC=$SRC"
    echo "HB=${HB:-0}"
    echo "EVAL=${EVAL:-0}"
    echo "@@@IDS@@@"
    printf "%s\n" "$IDS"
    echo "@@@PRISM@@@"
    printf "%s\n" "$PRISM"
  ' _ "$NODE_LOG_CANDIDATES" 2>/dev/null
}

# 从 prism 日志行提取 4 个关键参数的指纹（兼容 text/json：去引号、把 : 归一为 =）
prism_sig_from_line() {
  local line="$1" norm s k v
  norm="$(printf '%s' "$line" | tr -d '"' | tr ':' '=')"
  s=""
  for k in debt_alpha path_decay max_path_depth aggregation; do
    v="$(printf '%s\n' "$norm" | grep -o -- "${k}=[^ ,}]*" | head -n1 | cut -d= -f2)"
    if [ -z "$v" ]; then
      return 1
    fi
    s="$s ${k}=${v}"
  done
  printf '%s' "$s" | sed 's/^ //'
  return 0
}

# 规范化参数指纹：数值统一成 %g（日志里 0.8 与配置里 0.80 视为相同）
canon_sig() {
  local sig="$1" out k v
  out=""
  for k in debt_alpha path_decay max_path_depth aggregation; do
    v="$(printf '%s' "$sig" | grep -o -- "${k}=[^ ]*" | head -n1 | cut -d= -f2)"
    [ -n "$v" ] || return 1
    case "$k" in
      aggregation) : ;;
      *) v="$(awk -v x="$v" 'BEGIN{printf "%g", x+0}')" ;;
    esac
    out="$out ${k}=${v}"
  done
  printf '%s' "${out# }"
  return 0
}

# 从日志抓 host_id（兼容 text 的 host_id=x 与 json 的 "host_id":"x"）

ssh_master() {
  ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 \
    -i "$MASTER_SSH_KEY" "$MASTER_USER@$MASTER_HOST" "$@"
}

group_agent_ids() {
  # $1 = 节点序号 0..2；输出该组的 vmid 列表
  local i="$1" range start end
  range="${AGENT_GROUPS[$i]}"
  start="${range%%:*}"; end="${range##*:}"
  seq "$start" "$end"
}

# ---- 0) 环境预检 -----------------------------------------------------------
echo "============================================================"
echo " T4 联邦验收 $(date '+%F %T %Z')"
echo " 节点: ${NODE_CT_IDS[*]} / agent 组: ${AGENT_GROUPS[*]}"
echo "============================================================"

if ! command -v pct >/dev/null 2>&1; then
  echo "FATAL: 找不到 pct —— 本脚本必须在 PVE 宿主（dl360gen9）上以 root 运行" >&2
  exit 1
fi
if ! pct_list_refresh; then
  echo "FATAL: pct list 失败（当前用户不是 root 或 PVE 工具异常）" >&2
  exit 1
fi
[ -r "$MASTER_SSH_KEY" ] || mark_warn "主 kernel ssh 私钥不可读: $MASTER_SSH_KEY（检查 6/7 会失败）"

# ---- 1) 33 台 CT running ---------------------------------------------------
bad=0
for vmid in "${NODE_CT_IDS[@]}"; do
  ct_alive "$vmid" || { echo "  - CT $vmid 非 running"; bad=$((bad + 1)); }
done
for i in $(seq 0 $((NODE_COUNT - 1))); do
  for vmid in $(group_agent_ids "$i"); do
    ct_alive "$vmid" || { echo "  - CT $vmid 非 running"; bad=$((bad + 1)); }
  done
done
total_ct=$((NODE_COUNT + 30))
if [ "$bad" -eq 0 ]; then
  mark_pass "1) $total_ct 台 CT 全部 running（${NODE_CT_IDS[*]} + 940-969）"
else
  mark_fail "1) $bad/$total_ct 台 CT 不是 running（见上一行列表；用 pct list 复核）"
fi

# ---- 2) 节点 kernel 配置已部署且正确 --------------------------------------
for i in $(seq 0 $((NODE_COUNT - 1))); do
  vmid="${NODE_CT_IDS[$i]}"
  node_id="${NODE_IDS[$i]}"
  node_name="${NODE_NAMES[$i]}"
  node_ip="${NODE_IPS[$i]}"
  conf_path=""
  conf=""
  if ct_alive "$vmid"; then
    dump="$(node_conf_dump "$vmid")"; rc=$?
    if [ "$rc" -eq 0 ] && [ -n "$dump" ]; then
      conf_path="$(printf '%s\n' "$dump" | sed -n 's/^PATH=//p' | head -n1)"
      conf="$(printf '%s\n' "$dump" | sed '1d')"
    fi
  fi
  if [ -z "$conf_path" ] || [ -z "$conf" ]; then
    mark_fail "2.$((i + 1))) CT $vmid 找不到/读不到节点 kernel 配置（候选: $NODE_CONF_CANDIDATES）；请把 configs/federation/$node_id.ini 部署到 /etc/asscor/kernel.ini"
    continue
  fi
  role="$(printf '%s\n' "$conf" | ini_get federation role)"
  got_id="$(printf '%s\n' "$conf" | ini_get federation node_id)"
  master_url="$(printf '%s\n' "$conf" | ini_get federation master_url)"
  interval="$(printf '%s\n' "$conf" | ini_get federation report_interval_sec)"
  token="$(printf '%s\n' "$conf" | ini_get federation token)"
  debt_alpha="$(printf '%s\n' "$conf" | ini_get prism debt_alpha)"
  path_decay="$(printf '%s\n' "$conf" | ini_get prism path_decay)"
  depth="$(printf '%s\n' "$conf" | ini_get prism max_path_depth)"
  aggr="$(printf '%s\n' "$conf" | ini_get prism aggregation)"
  act="$(ct_exec "$vmid" systemctl is-active "$NODE_UNIT")"

  errs=""
  expect_var="EXPECT_PRISM_SIG_$node_id"
  expect="${!expect_var}"
  want_aggr="${expect##*aggregation=}"
  want_depth="$(printf '%s' "$expect" | grep -o 'max_path_depth=[^ ]*' | cut -d= -f2)"
  want_alpha="$(printf '%s' "$expect" | grep -o 'debt_alpha=[^ ]*' | cut -d= -f2)"
  want_decay="$(printf '%s' "$expect" | grep -o 'path_decay=[^ ]*' | cut -d= -f2)"
  [ "$role" = "node" ] || errs="$errs role='$role'(want node);"
  [ "$got_id" = "$node_id" ] || errs="$errs node_id='$got_id'(want $node_id);"
  [ "$master_url" = "$FED_MASTER_URL" ] || errs="$errs master_url='$master_url'(want $FED_MASTER_URL);"
  [ "$interval" = "30" ] || errs="$errs report_interval_sec='$interval'(want 30);"
  [ "$token" = "$FED_TOKEN" ] || errs="$errs token 不匹配;"
  [ "$aggr" = "$want_aggr" ] || errs="$errs aggregation='$aggr'(want $want_aggr);"
  [ "$depth" = "$want_depth" ] || errs="$errs max_path_depth='$depth'(want $want_depth);"
  [ "$debt_alpha" = "$want_alpha" ] || errs="$errs debt_alpha='$debt_alpha'(want $want_alpha);"
  [ "$path_decay" = "$want_decay" ] || errs="$errs path_decay='$path_decay'(want $want_decay);"
  [ "$(trim "$act")" = "active" ] || errs="$errs $NODE_UNIT='$act';"

  if [ -z "$errs" ]; then
    mark_pass "2.$((i + 1))) CT $vmid ($node_name/$node_id) 配置正确：role=node, debt_alpha=$debt_alpha path_decay=$path_decay depth=$depth aggregation=$aggr, kernel active"
  else
    mark_fail "2.$((i + 1))) CT $vmid ($node_name/$node_id) 配置不符合模板：$errs（文件 $conf_path）"
  fi

  # 管理网过滤（P0-2/T4 假传播防护，缺失只告警）
  excl="$(printf '%s\n' "$conf" | ini_get topology exclude_cidrs)"
  case "$excl" in
    *192.168.30.0/24*) : ;;
    *) mark_warn "CT $vmid 的 [topology] exclude_cidrs 未包含 192.168.30.0/24（管理网可能污染 SRD 拓扑）" ;;
  esac
done

# ---- 3) 30 个 agent.ini 都指向所属节点 -------------------------------------
agent_total=0
agent_bad=0
bad_reasons=""
declare -A AGENT_HOSTNAME_OF=()
declare -A AGENT_MGMT_IP_OF=()
declare -a AGENT_HOSTNAMES=()
declare -a AGENT_MGMT_IPS=()
for i in $(seq 0 $((NODE_COUNT - 1))); do
  node_id="${NODE_IDS[$i]}"
  node_ip="${NODE_IPS[$i]}"
  node_name="${NODE_NAMES[$i]}"
  for vmid in $(group_agent_ids "$i"); do
    agent_total=$((agent_total + 1))
    if ! ct_alive "$vmid"; then
      agent_bad=$((agent_bad + 1))
      bad_reasons="$bad_reasons
    CT $vmid: 容器未运行（pct start $vmid）"
      continue
    fi
    bundle="$(ct_agent_bundle "$vmid")"
    ct_hostname="$(printf '%s\n' "$bundle" | sed -n 's/^HOST=//p' | head -n1 | tr -d '\r')"
    [ -n "$ct_hostname" ] || ct_hostname="vmid-$vmid"
    mgmt_ip="$(printf '%s\n' "$bundle" | sed -n 's/^IPS=//p' | tr ' ' '\n' | grep -E '^192\.168\.30\.[0-9]+$' | head -n1)"
    ini="$(printf '%s\n' "$bundle" | sed '1,/^@@@INI@@@$/d' | sed '/^@@@CMD@@@$/,$d')"
    agent_cmd="$(printf '%s\n' "$bundle" | sed '1,/^@@@CMD@@@$/d' | tr -d '\r')"
    AGENT_HOSTNAME_OF[$vmid]="$ct_hostname"
    AGENT_MGMT_IP_OF[$vmid]="$mgmt_ip"
    AGENT_HOSTNAMES+=("$ct_hostname")
    AGENT_MGMT_IPS+=("$mgmt_ip")

    case "$ini" in
      *@@@NOINI@@@*)
        agent_bad=$((agent_bad + 1))
        bad_reasons="$bad_reasons
    CT $vmid ($ct_hostname): 缺 $AGENT_INI（用 scripts/gen-agent-configs.sh 生成后 pct push）"
        continue ;;
    esac
    if [ -z "$ini" ]; then
      agent_bad=$((agent_bad + 1))
      bad_reasons="$bad_reasons
    CT $vmid ($ct_hostname): 读不到 $AGENT_INI"
      continue
    fi
    ka="$(printf '%s\n' "$ini" | ini_get agent kernel_addr)"
    hid="$(printf '%s\n' "$ini" | ini_get agent host_id)"
    tls="$(printf '%s\n' "$ini" | ini_get agent tls_enabled)"
    cdir="$(printf '%s\n' "$ini" | ini_get agent cert_dir)"
    sname="$(printf '%s\n' "$ini" | ini_get agent tls_server_name)"
    hb="$(printf '%s\n' "$ini" | ini_get agent heartbeat_sec)"
    ci="$(printf '%s\n' "$ini" | ini_get agent check_interval_sec)"
    mr="$(printf '%s\n' "$ini" | ini_get agent max_retries)"
    rs="$(printf '%s\n' "$ini" | ini_get agent reconnect_sec)"
    want_ka="$node_ip:50051"

    errs=""
    [ "$ka" = "$want_ka" ] || errs="$errs kernel_addr='$ka'(want $want_ka);"
    [ "$hid" = "$ct_hostname" ] || errs="$errs host_id='$hid'(want $ct_hostname);"
    [ "$tls" = "true" ] || errs="$errs tls_enabled='$tls';"
    [ "$cdir" = "$CERT_DIR" ] || errs="$errs cert_dir='$cdir'(want $CERT_DIR);"
    [ "$sname" = "$node_name" ] || errs="$errs tls_server_name='$sname'(want $node_name);"
    [ "$hb" = "30" ] || errs="$errs heartbeat_sec='$hb';"
    [ "$ci" = "120" ] || errs="$errs check_interval_sec='$ci';"
    [ "$mr" = "3" ] || errs="$errs max_retries='$mr';"
    [ "$rs" = "5" ] || errs="$errs reconnect_sec='$rs';"
    # 关键：cmd/agent/main.go 里 cfg.KernelAddr 会被 --kernel 的默认值 127.0.0.1:50051
    # 无条件覆盖，cfg.CertDir 会被 --cert-dir 的默认值 "certs" 覆盖。所以"agent.ini 写对"
    # 还不够，运行参数必须显式带 --kernel <节点IP>:50051 与 --cert-dir /etc/asscor/certs。
    if [ -n "${agent_cmd:-}" ]; then
      case "$agent_cmd" in
        *"$want_ka"*) : ;;
        *) errs="$errs 运行参数缺 --kernel $want_ka（会被默认值 127.0.0.1:50051 覆盖，agent.ini 的 kernel_addr 不生效）;" ;;
      esac
      case "$agent_cmd" in
        *"$CERT_DIR"*) : ;;
        *) errs="$errs 运行参数缺 --cert-dir $CERT_DIR（会被默认值 certs 覆盖）;" ;;
      esac
    fi
    if [ -n "$errs" ]; then
      agent_bad=$((agent_bad + 1))
      bad_reasons="$bad_reasons
    CT $vmid ($ct_hostname): $errs"
    fi
  done
done
if [ "$agent_bad" -eq 0 ]; then
  mark_pass "3) $agent_total 个 agent.ini（及运行参数 --kernel/--cert-dir）均指向所属节点 kernel（940-949→nk1 .71 / 950-959→nk2 .72 / 960-969→nk3 .73），TLS/cert_dir/心跳参数正确"
else
  mark_fail "3) $agent_bad/$agent_total 个 agent.ini 不符合要求：$bad_reasons"
fi

# ---- 4) 节点 kernel :50051 的 agent 连接数 ---------------------------------
for i in $(seq 0 $((NODE_COUNT - 1))); do
  vmid="${NODE_CT_IDS[$i]}"
  node_name="${NODE_NAMES[$i]}"
  if ! ct_alive "$vmid"; then
    mark_fail "4.$((i + 1))) CT $vmid ($node_name) 未运行，无法检查 :50051 会话"
    continue
  fi
  ss_out="$(pct exec "$vmid" -- ss -tn 2>/dev/null)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    mark_fail "4.$((i + 1))) CT $vmid ($node_name) 无法执行 ss -tn（iproute2 未装或 CT 异常）"
    continue
  fi
  cnt="$(printf '%s\n' "$ss_out" | awk '$4 ~ /:50051$/ {c++} END{print c+0}')"
  if [ "$cnt" -ge 10 ]; then
    mark_pass "4.$((i + 1))) CT $vmid ($node_name) :50051 上有 $cnt 条会话（≥10）"
  else
    mark_fail "4.$((i + 1))) CT $vmid ($node_name) :50051 上只有 $cnt 条会话（期望 ≥10）；检查 agent 是否启动、证书是否由本节点 CA 签发"
  fi
done

# ---- 节点日志快照：每个节点 kernel 只做 1 次 pct exec ----------------------
NODE_LOG_SRC=()
NODE_LOG_HB=()
NODE_LOG_EVAL=()
NODE_LOG_IDS=()
NODE_LOG_PRISM=()
for i in $(seq 0 $((NODE_COUNT - 1))); do
  vmid="${NODE_CT_IDS[$i]}"
  scan=""
  if ct_alive "$vmid"; then
    scan="$(node_log_scan "$vmid")"
  fi
  if [ -n "$scan" ]; then
    NODE_LOG_SRC[$i]="$(printf '%s\n' "$scan" | sed -n 's/^SRC=//p' | head -n1)"
    NODE_LOG_HB[$i]="$(printf '%s\n' "$scan" | sed -n 's/^HB=//p' | head -n1)"
    NODE_LOG_EVAL[$i]="$(printf '%s\n' "$scan" | sed -n 's/^EVAL=//p' | head -n1)"
    NODE_LOG_IDS[$i]="$(printf '%s\n' "$scan" | sed '1,/^@@@IDS@@@$/d' | sed '/^@@@PRISM@@@$/,$d')"
    NODE_LOG_PRISM[$i]="$(printf '%s\n' "$scan" | sed '1,/^@@@PRISM@@@$/d')"
  else
    NODE_LOG_SRC[$i]=""; NODE_LOG_HB[$i]="0"; NODE_LOG_EVAL[$i]="0"
    NODE_LOG_IDS[$i]=""; NODE_LOG_PRISM[$i]=""
  fi
done

# ---- 5) 节点 kernel 日志：10 个 agent 心跳 + 评估 ---------------------------
for i in $(seq 0 $((NODE_COUNT - 1))); do
  vmid="${NODE_CT_IDS[$i]}"
  node_name="${NODE_NAMES[$i]}"
  if ! ct_alive "$vmid"; then
    mark_fail "5.$((i + 1))) CT $vmid ($node_name) 未运行，无法检查 kernel 日志"
    continue
  fi
  if [ -z "${NODE_LOG_SRC[$i]:-}" ]; then
    mark_fail "5.$((i + 1))) CT $vmid ($node_name) 读不到 kernel 日志（候选 $NODE_LOG_CANDIDATES / journalctl -u $NODE_UNIT）"
    continue
  fi
  hb_cnt="${NODE_LOG_HB[$i]:-0}"
  eval_cnt="${NODE_LOG_EVAL[$i]:-0}"
  seen_ids="${NODE_LOG_IDS[$i]:-}"
  missing=0
  missing_ids=""
  for vmid_a in $(group_agent_ids "$i"); do
    h="${AGENT_HOSTNAME_OF[$vmid_a]:-}"
    [ -n "$h" ] || h="vmid-$vmid_a"
    if ! printf '%s\n' "$seen_ids" | grep -qxF -- "$h"; then
      missing=$((missing + 1)); missing_ids="$missing_ids $h"
    fi
  done
  if [ "$missing" -eq 0 ] && [ "$eval_cnt" -ge 1 ]; then
    mark_pass "5.$((i + 1))) CT $vmid ($node_name) 日志(${NODE_LOG_SRC[$i]})：10/10 agent 心跳（heartbeat received=$hb_cnt），assessment result=$eval_cnt"
  else
    mark_fail "5.$((i + 1))) CT $vmid ($node_name) 日志不完整：缺 $missing 个 agent 心跳（$missing_ids），assessment result=$eval_cnt；心跳缺 ⇒ 看 agent 日志/证书；评估=0 ⇒ 等 check_interval_sec=120s 后的首轮，或 kernel 未用 engine tag 构建"
  fi
done

# ---- 6) 主 kernel :50051 不得有这 30 个 agent 的会话 ------------------------
master_ss="$(ssh_master sudo -n ss -tn 2>/dev/null)"; rc_ss=$?
master_log_hits=0
master_log_sample=""
if [ "$rc_ss" -ne 0 ]; then
  mark_fail "6) 无法 ssh 到主 kernel $MASTER_HOST 执行 ss -tn（检查 $MASTER_SSH_KEY / sudo -n 免密）；主 kernel 侧隔离无法验收"
else
  peer_ips="$(printf '%s\n' "$master_ss" | awk '$4 ~ /:50051$/ {split($5,a,":"); print a[1]}' | sort -u)"
  leaked=0
  leaked_list=""
  known_ips=0
  if [ -n "$peer_ips" ]; then
    for ip in "${AGENT_MGMT_IPS[@]}"; do
      [ -n "$ip" ] || continue
      known_ips=$((known_ips + 1))
      if printf '%s\n' "$peer_ips" | grep -qxF -- "$ip"; then
        leaked=$((leaked + 1)); leaked_list="$leaked_list $ip"
      fi
    done
  else
    for ip in "${AGENT_MGMT_IPS[@]}"; do [ -n "$ip" ] && known_ips=$((known_ips + 1)); done
  fi

  # 日志双保险：主 kernel 日志里不应出现任何 agent 的 host_id（兼容 text/json）
  re=""
  for h in "${AGENT_HOSTNAMES[@]}"; do
    [ -n "$h" ] || continue
    if [ -z "$re" ]; then re="$h"; else re="$re|$h"; fi
  done
  if [ -n "$re" ]; then
    master_log_sample="$(ssh_master "sudo -n grep -m 5 -E 'host_id\"?[:=]\"?($re)' $MASTER_LOG 2>/dev/null")"
    rc_gl=$?
    if [ "$rc_gl" -eq 0 ] && [ -n "$master_log_sample" ]; then
      master_log_hits="$(printf '%s\n' "$master_log_sample" | wc -l | tr -d ' ')"
    fi
  fi

  if [ "$leaked" -ne 0 ] || [ "$master_log_hits" -ne 0 ]; then
    detail=""
    [ "$leaked" -ne 0 ] && detail="$detail ss 命中 $leaked 个 agent mgmt IP:$leaked_list;"
    [ "$master_log_hits" -ne 0 ] && detail="$detail 主日志出现 agent host_id $master_log_hits 行（样例: $(printf '%s' "$master_log_sample" | head -n1)）;"
    mark_fail "6) 主 kernel 出现本不该连接的 agent 会话：$detail（强约束：agent 只允许连所属节点 kernel）"
  elif [ "$known_ips" -lt 30 ]; then
    mark_warn "6) 主 kernel :50051 未见已知 agent 会话（仅能比对 $known_ips/30 个 mgmt IP；agent CT 未全部运行，本项未完全验证）"
  else
    mark_pass "6) 主 kernel $MASTER_HOST :50051 无 30 个 agent 的会话（ss 比对 $known_ips 个 mgmt IP，日志无 host_id 命中）"
  fi
fi

# ---- 7) 主 kernel 能列出 3 个节点 ------------------------------------------
cli_out="$(ssh_master "printf 'federation status\nexit\n' | sudo -n $MASTER_KERNEL_BIN --cli $MASTER_CLI_SOCK" 2>&1)"
rc_cli=$?
curl_out="$(ssh_master "curl -fsS --max-time 3 -H '$FED_TOKEN_HEADER: $FED_TOKEN' $MASTER_FED_URL" 2>/dev/null)"
rc_curl=$?

missing_nodes=""
for nid in "${NODE_IDS[@]}"; do
  if printf '%s' "$cli_out" | grep -qF -- "$nid" && [ "$rc_cli" -eq 0 ]; then
    :
  elif printf '%s' "$curl_out" | grep -qF -- "$nid" && [ "$rc_curl" -eq 0 ]; then
    :
  else
    missing_nodes="$missing_nodes $nid"
  fi
done

if [ -z "$missing_nodes" ]; then
  if printf '%s' "$cli_out" | grep -qF -- "${NODE_IDS[0]}"; then
    mark_pass "7) 主 kernel federation status 列出 ${NODE_IDS[*]}（CLI 可用）"
  else
    mark_pass "7) 主 kernel 收集端点列出 ${NODE_IDS[*]}（curl $MASTER_FED_URL 可用；CLI 暂不可用）"
  fi
else
  hint=""
  [ "$rc_cli" -ne 0 ] && hint="$hint CLI rc=$rc_cli（federation 插件未装载：kernel 需 -tags federation 重新构建并重启；或 CLI socket 路径不对）;"
  [ "$rc_curl" -ne 0 ] && hint="$hint curl rc=$rc_curl（:5099 未监听，或 token 头 '$FED_TOKEN_HEADER' 不匹配 → 检查 master.ini 的 token 与 listen_addr）;"
  mark_fail "7) 主 kernel 没有列出节点:$missing_nodes ——$hint 端点/命令见 internal/federation/master.go（POST /federation/report、GET /federation/nodes）与 internal/cli/federation_commands.go（federation status）"
fi

# ---- 8) 三节点 prism 参数互不相同且与模板一致 -----------------------------
sig_ok=1
sigs=()
for i in $(seq 0 $((NODE_COUNT - 1))); do
  vmid="${NODE_CT_IDS[$i]}"
  node_id="${NODE_IDS[$i]}"
  line="${NODE_LOG_PRISM[$i]:-}"
  if [ -z "$line" ]; then
    mark_fail "8.$((i + 1))) CT $vmid ($node_id) 日志没有 'prism effective config'（kernel 需 -tags engine 构建；日志级别 info）"
    sig_ok=0
    continue
  fi
  sig="$(canon_sig "$(prism_sig_from_line "$line")")"
  expect_var="EXPECT_PRISM_SIG_$node_id"
  expect="$(canon_sig "${!expect_var}")"
  sigs[$i]="$sig"
  if [ "$sig" = "$expect" ]; then
    mark_pass "8.$((i + 1))) CT $vmid ($node_id) prism 生效参数 = $sig（与 nk$((i+1)).ini 一致）"
  else
    mark_fail "8.$((i + 1))) CT $vmid ($node_id) prism 生效参数 = '$sig'，期望 '$expect'（deploy 的不是本仓库的 nk$((i+1)).ini？）"
    sig_ok=0
  fi
done
if [ "$sig_ok" -eq 1 ] && [ "$NODE_COUNT" -eq 3 ]; then
  if [ "${sigs[0]}" != "${sigs[1]}" ] && [ "${sigs[1]}" != "${sigs[2]}" ] && [ "${sigs[0]}" != "${sigs[2]}" ]; then
    mark_pass "8.9) 三节点 prism 参数两两不同（nk1: ${sigs[0]} | nk2: ${sigs[1]} | nk3: ${sigs[2]}）"
  else
    mark_fail "8.9) 三节点 prism 参数存在相同项（nk1: ${sigs[0]} | nk2: ${sigs[1]} | nk3: ${sigs[2]}）"
  fi
fi

# ---- 9) 信息检查：三节点 CA 指纹互不相同 -----------------------------------
ca_fps=()
ca_missing=0
for i in $(seq 0 $((NODE_COUNT - 1))); do
  vmid="${NODE_CT_IDS[$i]}"
  fp="$(pct exec "$vmid" -- openssl x509 -in "$CERT_DIR/ca.crt" -noout -fingerprint -sha256 2>/dev/null)"
  rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$fp" ]; then
    ca_missing=$((ca_missing + 1))
    ca_fps[$i]=""
  else
    ca_fps[$i]="$(printf '%s' "$fp" | sed 's/.*=//')"
  fi
done
if [ "$ca_missing" -ne 0 ]; then
  mark_info "9) 无法读取部分节点 CA 指纹（openssl 缺失或 $CERT_DIR/ca.crt 未生成，缺 $ca_missing 个）；跳过"
elif [ "${ca_fps[0]}" != "${ca_fps[1]}" ] && [ "${ca_fps[1]}" != "${ca_fps[2]}" ] && [ "${ca_fps[0]}" != "${ca_fps[2]}" ]; then
  mark_pass "9) 三节点 kernel CA 指纹互不相同（各节点 agent 证书由各自 CA 签发 ⇒ mTLS 强制隔离）"
else
  mark_fail "9) 三节点 CA 指纹存在重复：0=${ca_fps[0]:0:16} 1=${ca_fps[1]:0:16} 2=${ca_fps[2]:0:16} —— 违反『每节点独立 CA』设计"
fi

# ---- 汇总 ------------------------------------------------------------------
echo "------------------------------------------------------------"
echo "SUMMARY: PASS=$PASS FAIL=$FAIL WARN=$WARN INFO=$INFO"
if [ "$FAIL" -ne 0 ]; then
  echo "FAILED:"
  printf '%s\n' "$FAILED_ITEMS"
  echo "------------------------------------------------------------"
  echo "RESULT: FAIL（rc=1）"
  exit 1
fi
echo "RESULT: PASS（rc=0）"
exit 0
