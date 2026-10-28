#!/usr/bin/env bash
# ============================================================================
# gen-agent-configs.sh —— T4 联邦实验：生成 30 个 agent.ini
#
# 目标布局（每个 agent 只连**所属节点 kernel**，跨节点互不连接）：
#   CT 940-949 -> nk1 (CT 930 / 192.168.30.71)  10 台
#   CT 950-959 -> nk2 (CT 931 / 192.168.30.72)  10 台
#   CT 960-969 -> nk3 (CT 932 / 192.168.30.73)  10 台
#
# 输出：<out>/<hostname>.ini + <out>/summary.tsv
#   默认 <out> = /root/t4/agent-configs （在 PVE 宿主 dl360gen9 上运行）
#
# 用法：
#   bash scripts/gen-agent-configs.sh                       # 内置清单 + 默认 IP
#   bash scripts/gen-agent-configs.sh --dry-run             # 只打印，不落盘
#   bash scripts/gen-agent-configs.sh --out /root/t4/agent-configs
#   bash scripts/gen-agent-configs.sh --kernel-ip nk1=192.168.30.71,nk2=192.168.30.72,nk3=192.168.30.73
#   bash scripts/gen-agent-configs.sh --manifest /root/t4/inventory.6col.tsv
#
# --manifest 文件格式（TAB 或空格分隔，6 列，# 开头为注释；这是本脚本的输入契约，
# 不是 /root/t4/inventory.tsv 的格式 —— 若基建清单列序不同，先用 awk 转成 6 列）：
#   vmid  hostname  node  mgmt_ip  data_ip  vnet
#   940   asc-agt-nk1-01  nk1  192.168.30.101  172.22.10.101  vnetA
#
# 配置键名依据（不是猜的）：
#   internal/agent（cmd/agent/main.go loadConfigFile）真实读取的 [agent] 键：
#     kernel_addr / host_id / hostname / version / heartbeat_sec / check_interval_sec /
#     check_timeout_sec / max_retries / reconnect_sec / tls_enabled / tls_skip_verify /
#     tls_server_name / cert_dir / hmac_key_file / log_format / log_level / log_output
#   agent 的 TLS 文件固定为 <cert_dir>/{ca.crt,agent.crt,agent.key}（internal/agent/agent.go）。
#
# 注意：tls_server_name 必须等于**所属节点 kernel 的 hostname**（asc-nk1/2/3）。
#   节点 kernel 首次启动生成的 server.crt 只含 DNS SAN：CommonName、localhost、
#   签发时本机 hostname；不含 192.168.30.7x 的 IP SAN。agent 用 IP 直连时，
#   显式 tls_server_name 才能让证书校验通过（替代 tls_skip_verify）。
#
# 依赖：bash 4+；写文件需要 root（/root/t4）。
# ============================================================================
set -u

OUT_DIR="${AGENT_CONFIGS_DIR:-/root/t4/agent-configs}"
MANIFEST="${AGENT_MANIFEST:-}"
DRY_RUN=0
EXPECTED_TOTAL=30

# 节点 kernel 的 mgmt IP（可被 --kernel-ip 覆盖；基建子代理规划值）
KERNEL_IP_nk1="192.168.30.71"
KERNEL_IP_nk2="192.168.30.72"
KERNEL_IP_nk3="192.168.30.73"

# 节点 kernel 的 hostname（= 节点 server.crt 的 DNS SAN；agent 的 tls_server_name）
SERVER_NAME_nk1="asc-nk1"
SERVER_NAME_nk2="asc-nk2"
SERVER_NAME_nk3="asc-nk3"

# 数据面：复用现有 SDN vnetA/B/C/D（轮转分配），子网见 docs/2-experiments/T4_FEDERATION_ENV_2026-10-28.md
VNET_KEYS=("vnetA" "vnetB" "vnetC" "vnetD")
declare -A VNET_PREFIX=(
  [vnetA]="172.22.10"
  [vnetB]="172.23.10"
  [vnetC]="100.64.0"
  [vnetD]="172.26.0"
)
declare -A VNET_NEXT=([vnetA]=101 [vnetB]=101 [vnetC]=101 [vnetD]=101)

CERT_DIR="/etc/asscor/certs"
HEARTBEAT_SEC=30
CHECK_INTERVAL_SEC=120
CHECK_TIMEOUT_SEC=10
MAX_RETRIES=3
RECONNECT_SEC=5

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

# ---- 参数解析 --------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --out)
      [ $# -ge 2 ] || die "--out 需要目录参数"
      OUT_DIR="$2"; shift 2 ;;
    --manifest)
      [ $# -ge 2 ] || die "--manifest 需要文件参数"
      MANIFEST="$2"; shift 2 ;;
    --kernel-ip)
      [ $# -ge 2 ] || die "--kernel-ip 需要 nk1=IP,nk2=IP,nk3=IP"
      IFS=',' read -r -a _pairs <<< "$2"
      for _pair in "${_pairs[@]}"; do
        _k="${_pair%%=*}"; _v="${_pair#*=}"
        case "$_k" in
          nk1) KERNEL_IP_nk1="$_v" ;;
          nk2) KERNEL_IP_nk2="$_v" ;;
          nk3) KERNEL_IP_nk3="$_v" ;;
          *) die "未知节点 '$_k'（只支持 nk1/nk2/nk3）" ;;
        esac
      done
      shift 2 ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    -h|--help)
      usage ;;
    *)
      die "未知参数 '$1'（用 --help 查看用法）" ;;
  esac
done

kernel_ip_for() {
  case "$1" in
    nk1) echo "$KERNEL_IP_nk1" ;;
    nk2) echo "$KERNEL_IP_nk2" ;;
    nk3) echo "$KERNEL_IP_nk3" ;;
    *) return 1 ;;
  esac
}

server_name_for() {
  case "$1" in
    nk1) echo "$SERVER_NAME_nk1" ;;
    nk2) echo "$SERVER_NAME_nk2" ;;
    nk3) echo "$SERVER_NAME_nk3" ;;
    *) return 1 ;;
  esac
}

# ---- 1) 构造清单（6 列）----------------------------------------------------
TMP_MANIFEST="$(mktemp -t t4-agent-manifest.XXXXXX)" || die "mktemp 失败"
trap 'rm -f "$TMP_MANIFEST"' EXIT INT TERM

if [ -n "$MANIFEST" ]; then
  [ -f "$MANIFEST" ] || die "manifest 不存在: $MANIFEST"
  grep -vE '^[[:space:]]*(#|$)' "$MANIFEST" > "$TMP_MANIFEST" || true
  echo "INFO: 使用外部清单 $MANIFEST（$(wc -l < "$TMP_MANIFEST") 条记录）"
else  # 内置清单：940-949/950-959/960-969 三组，vnet 按全局序号轮转
  n=0
  for gi in 0 1 2; do
    case "$gi" in
      0) node="nk1"; group_start=940 ;;
      1) node="nk2"; group_start=950 ;;
      2) node="nk3"; group_start=960 ;;
    esac
    idx=1
    vmid="$group_start"
    while [ "$vmid" -le $((group_start + 9)) ]; do
      vnet="${VNET_KEYS[$((n % 4))]}"
      data_ip="${VNET_PREFIX[$vnet]}.${VNET_NEXT[$vnet]}"
      VNET_NEXT[$vnet]=$(( VNET_NEXT[$vnet] + 1 ))
      mgmt_ip="192.168.30.$((101 + (vmid - 940)))"
      printf '%s\tasc-agt-%s-%02d\t%s\t%s\t%s\t%s\n' \
        "$vmid" "$node" "$idx" "$node" "$mgmt_ip" "$data_ip" "$vnet" \
        >> "$TMP_MANIFEST"
      vmid=$((vmid + 1))
      idx=$((idx + 1))
      n=$((n + 1))
    done
  done
fi

# 统一成 6 列 TAB 分隔（兼容空格分隔 / 多余空白 / CRLF 清单）
awk -F'[[:space:]]+' 'NF >= 6 { printf "%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $5, $6 }' \
  "$TMP_MANIFEST" > "$TMP_MANIFEST.norm" || die "规范化清单失败"
mv "$TMP_MANIFEST.norm" "$TMP_MANIFEST"

TOTAL="$(wc -l < "$TMP_MANIFEST" | tr -d ' ')"
[ "$TOTAL" -gt 0 ] || die "清单为空"
if [ -z "$MANIFEST" ] && [ "$TOTAL" -ne "$EXPECTED_TOTAL" ]; then
  die "内置清单应有 $EXPECTED_TOTAL 条，实际 $TOTAL 条（脚本 bug）"
fi
[ "$TOTAL" -eq "$EXPECTED_TOTAL" ] || echo "WARN: 清单 $TOTAL 条，预期 $EXPECTED_TOTAL 条（外部清单以实际为准）"

# ---- 2) 逐条生成 -----------------------------------------------------------
[ "$DRY_RUN" -eq 1 ] || mkdir -p "$OUT_DIR" || die "无法创建输出目录 $OUT_DIR"

SUMMARY="$OUT_DIR/summary.tsv"
[ "$DRY_RUN" -eq 1 ] || printf 'vmid\thostname\tnode\tmgmt_ip\tdata_ip\tvnet\tkernel_addr\tconfig\n' > "$SUMMARY"

ok=0
fail=0
while IFS=$'\t' read -r vmid hostname node mgmt_ip data_ip vnet _rest; do
  # 兼容空格分隔 / 多余空白 / CRLF 清单
  vmid="$(printf '%s' "$vmid" | tr -d '\r[:space:]')"
  hostname="$(printf '%s' "$hostname" | tr -d '\r[:space:]')"
  node="$(printf '%s' "$node" | tr -d '\r[:space:]')"
  mgmt_ip="$(printf '%s' "$mgmt_ip" | tr -d '\r[:space:]')"
  data_ip="$(printf '%s' "$data_ip" | tr -d '\r[:space:]')"
  vnet="$(printf '%s' "$vnet" | tr -d '\r[:space:]')"
  [ -n "$vmid" ] || continue

  kernel_ip="$(kernel_ip_for "$node" || true)"
  server_name="$(server_name_for "$node" || true)"
  if [ -z "$kernel_ip" ] || [ -z "$server_name" ]; then
    echo "FAIL: vmid=$vmid 节点 '$node' 非法（只支持 nk1/nk2/nk3）" >&2
    fail=$((fail + 1))
    continue
  fi
  if ! printf '%s' "$vmid" | grep -qE '^[0-9]+$'; then
    echo "FAIL: vmid 非数字: '$vmid'（hostname=$hostname）" >&2
    fail=$((fail + 1))
    continue
  fi
  if [ -z "$hostname" ]; then
    echo "FAIL: vmid=$vmid 缺 hostname" >&2
    fail=$((fail + 1))
    continue
  fi

  cfg_path="$OUT_DIR/$hostname.ini"
  kernel_addr="$kernel_ip:50051"

  cfg_content="$(cat <<EOF
# ============================================================================
# ASSCOR Agent 配置 —— T4 联邦实验（自动生成，请勿手改）
#   生成器   : scripts/gen-agent-configs.sh
#   vmid     : $vmid
#   node     : $node（所属节点 kernel，agent 只允许连它）
#   kernel   : $kernel_addr
#   mgmt_ip  : $mgmt_ip（CT eth1 / vmbr0 管理网，仅登记用，不写进 agent 运行通道）
#   data_ip  : $data_ip（CT eth0 / $vnet 数据面）
#   证书     : 由 $node 的独立 CA 签发，就位于 $CERT_DIR/{ca.crt,agent.crt,agent.key}
# ============================================================================

[agent]
# 内核地址：属于本 agent 的节点 kernel（不可改成主 kernel 192.168.30.50）
kernel_addr = $kernel_addr
# 主机标识 = 主机名（节点 kernel 用它做身份绑定与 [srd] roles 匹配）
host_id = $hostname
hostname = $hostname
version = v0.2.1
# 心跳 30s；完整评估 120s；连续 3 次错误后重连，重连等待 5s
heartbeat_sec = $HEARTBEAT_SEC
check_interval_sec = $CHECK_INTERVAL_SEC
check_timeout_sec = $CHECK_TIMEOUT_SEC
max_retries = $MAX_RETRIES
reconnect_sec = $RECONNECT_SEC
# mTLS：证书由所属节点 kernel 的独立 CA 签发；其它节点的 agent 证书在 TLS 握手即被拒
tls_enabled = true
tls_skip_verify = false
# 节点 kernel 的 server.crt 只有 DNS SAN（签发时的 hostname），用 IP 直连时必须显式指定
tls_server_name = $server_name
cert_dir = $CERT_DIR
log_format = text
log_level = info
log_output = stderr
EOF
)"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "----- $cfg_path -----"
    printf '%s\n' "$cfg_content"
  else
    printf '%s\n' "$cfg_content" > "$cfg_path" || { echo "FAIL: 写 $cfg_path 失败" >&2; fail=$((fail + 1)); continue; }
    chmod 644 "$cfg_path" 2>/dev/null || true
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$vmid" "$hostname" "$node" "$mgmt_ip" "$data_ip" "$vnet" "$kernel_addr" "$cfg_path" >> "$SUMMARY"
  fi
  ok=$((ok + 1))
done < "$TMP_MANIFEST"

# ---- 3) 汇总与自检 ---------------------------------------------------------
echo "------------------------------------------------------------"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "DRY-RUN: 生成 $ok 份 agent.ini（$fail 条失败），未落盘"
else
  echo "生成了 $ok 份 agent.ini -> $OUT_DIR"
  echo "清单: $SUMMARY"
  # 自检：每份配置的 kernel_addr 必须是所属节点 IP（不是主 kernel），且不得跨组
  bad=0
  addrs="$(grep -h '^kernel_addr' "$OUT_DIR"/*.ini 2>/dev/null | awk '{print $3}' | sort | uniq -c)"
  while read -r cnt addr; do
    [ -n "${addr:-}" ] || continue
    case "$addr" in
      192.168.30.71:50051|192.168.30.72:50051|192.168.30.73:50051) ;;
      *) echo "SELF-CHECK FAIL: 发现非节点 kernel 地址 $addr（$cnt 份）"; bad=1 ;;
    esac
  done <<< "$addrs"
  if grep -h '^kernel_addr' "$OUT_DIR"/*.ini 2>/dev/null | grep -q '^kernel_addr = 192.168.30.50:50051'; then
    echo "SELF-CHECK FAIL: 有 agent 被配到主 kernel 192.168.30.50:50051" >&2
    bad=1
  fi
  [ "$bad" -eq 0 ] || { echo "SELF-CHECK: 发现问题" >&2; fail=$((fail + 1)); }
fi

if [ "$fail" -ne 0 ]; then
  echo "RESULT: FAIL（$fail 条失败）" >&2
  exit 1
fi
echo "RESULT: OK（$ok 份）"
exit 0
