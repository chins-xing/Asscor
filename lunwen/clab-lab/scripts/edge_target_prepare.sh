#!/bin/bash
# shellcheck disable=SC2154  # lab_substrate/lab_target_bin 由 source edge_lab.sh 赋值（shellcheck 不跨文件跟踪变量）
# ============================================================================
# edge_target_prepare.sh —— **幂等**地准备 LXD 实验目标（Task 4D Step 4-B）
# ============================================================================
#
# 用法（在 A-1 上跑）：
#   EDGEEXP_TARGET=asc-tgt-1 \
#   EDGEEXP_POLICY_ON=1 \
#   bash scripts/edge_target_prepare.sh
#
# 它做什么（每一步都**先查后做**，重复执行不产生副作用）：
#   1. 实例不存在 ⇒ `lxc launch ubuntu:24.04 <实例>`（**不是** `images:ubuntu/24.04` —— 那个
#      别名已不再提供，实测会失败）；
#   2. 装六个控制（suricata / aide / 三个 PAM 包）并写配置（aide 告警配置、PAM 三类行）；
#   3. 设置**实验条件** `raw.apparmor`（策略在/不在，见 `EDGEEXP_POLICY_ON`）；
#      —— 变了才重启（重启会清空 `/tmp`，见第 4 步）；
#   4. 重启之后 `/tmp` 被清空，且 sandcat **不在**持久位置就会消失 ⇒ 把 payload 放到
#      `/root/sandcat` 并重新拉起；本脚本每次都确保"容器里有活着的 sandcat"。
#
# 为什么单独成一个脚本（而不是塞进 `edge_reset.sh`）：`edge_reset.sh` 在 clab 基质下是
# "建/毁拓扑 + 部 agent"，在 lxd 基质下**没有建毁动作**，只有"确保实例满足实验条件"这一件事。
# 把两套语义硬塞进同一个函数会让 clab 分支的逐位等价难以维持（Step 1 的最硬门禁）。
#
# 退出码：0 = 实例已就绪（六个控制 + 策略条件 + 活着的 agent）；非零 = 任一步失败（不降级）。
#
# 环境变量：
#   EDGEEXP_TARGET            目标实例名（必填）
#   EDGEEXP_POLICY_ON         1 = 装上 AppArmor 拒绝策略；0/空 = 卸载（实验条件）
#   EDGEEXP_POLICY_RULE       策略内容，默认 `audit deny /etc/shadow r,`
#   EDGEEXP_CALDERA_URL       Caldera API（默认 http://127.0.0.1:8888，仅在装控制时用于探活）
#   EDGEEXP_CALDERA_KEY       API key（默认 ADMIN123）
#   EDGEEXP_SANDCAT_PAYLOAD   sandcat 载荷路径（默认 /opt/caldera/plugins/sandcat/payloads/sandcat.go-linux）
#   EDGEEXP_AGENT_WAIT_S      等 agent 回连的上限（秒，默认 180）
#   EDGEEXP_APT_TIMEOUT_S     单次 apt 安装的上限（秒，默认 900）
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/edge_lab.sh
# shellcheck disable=SC2154  # lab_* 由下面那行 source 赋值
. "$SCRIPT_DIR/edge_lab.sh"

TARGET="${EDGEEXP_TARGET:-}"
POLICY_ON="${EDGEEXP_POLICY_ON:-0}"
POLICY_RULE="${EDGEEXP_POLICY_RULE:-audit deny /etc/shadow r,}"
CALDERA_URL="${EDGEEXP_CALDERA_URL:-http://127.0.0.1:8888}"
CALDERA_KEY="${EDGEEXP_CALDERA_KEY:-ADMIN123}"
PAYLOAD="${EDGEEXP_SANDCAT_PAYLOAD:-/opt/caldera/plugins/sandcat/payloads/sandcat.go-linux}"
AGENT_WAIT_S="${EDGEEXP_AGENT_WAIT_S:-180}"
APT_TIMEOUT_S="${EDGEEXP_APT_TIMEOUT_S:-900}"
PIDS_HELPER="$SCRIPT_DIR/edge_lab_pids.sh"

[ -n "$TARGET" ] || { echo "edge_target_prepare: 必须给 EDGEEXP_TARGET=<实例名>" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "edge_target_prepare: 缺少 python3" >&2; exit 2; }
[ -f "$PIDS_HELPER" ] || { echo "edge_target_prepare: 缺少 $PIDS_HELPER" >&2; exit 2; }

echo "edge_target_prepare: 目标=$TARGET 基质=$lab_substrate 策略=$([ "$POLICY_ON" = "1" ] && echo 在 || echo 不在)"

# --- 1. 实例存在？不存在就建（幂等）------------------------------------------
if lab_instance_exists "$TARGET"; then
  echo "edge_target_prepare: 实例已存在（幂等路径，不重建）"
else
  echo "edge_target_prepare: 实例不存在 ⇒ lxc launch ubuntu:24.04 $TARGET（后台 + 轮询）"
  # `ssh_exec` 约 600 s 会打断前台长命令；`lxc launch` 实测要几十秒 ⇒ 一律后台 + 轮询日志。
  nohup "$lab_target_bin" launch ubuntu:24.04 "$TARGET" > /tmp/edgeexp-lxd-launch.log 2>&1 &
  waited=0
  while :; do
    if lab_instance_exists "$TARGET"; then break; fi
    if [ "$waited" -ge "$APT_TIMEOUT_S" ]; then
      echo "edge_target_prepare: 实例在 ${APT_TIMEOUT_S}s 内没有创建出来，见 /tmp/edgeexp-lxd-launch.log 尾部：" >&2
      tail -20 /tmp/edgeexp-lxd-launch.log >&2 || true
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "edge_target_prepare: 实例已创建（等待 ${waited}s）"
fi

# 等它真的能 exec（`Status: RUNNING` 之后 exec 也可能短暂失败）
waited=0
until lab_node_running "$TARGET" >/dev/null 2>&1; do
  [ "$waited" -ge 120 ] && { echo "edge_target_prepare: 实例 $TARGET 没有回到运行态" >&2; exit 1; }
  sleep 3; waited=$((waited + 3))
done

# --- 2. 六个控制（幂等：先查后装）--------------------------------------------
MISSING="$(lab_target_exec "$TARGET" sh -c '
for p in suricata aide libpam-google-authenticator libpam-u2f libpam-fprintd; do
  dpkg-query -W -f="\${Status}" "$p" 2>/dev/null | grep -q "install ok installed" || printf "%s " "$p"
done')"
if [ -n "$MISSING" ]; then
  echo "edge_target_prepare: 缺控制包 [$MISSING] ⇒ apt-get 安装（后台 + 轮询，最长 ${APT_TIMEOUT_S}s）"
  cat > /tmp/edgeexp-harden.sh <<'HARDEN'
#!/bin/bash
set -x
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y suricata aide libpam-google-authenticator libpam-u2f libpam-fprintd
systemctl enable --now suricata
HARDEN
  lab_push /tmp/edgeexp-harden.sh "$TARGET" /root/harden.sh
  lab_target_exec "$TARGET" chmod 755 /root/harden.sh
  nohup "$lab_target_bin" exec "$TARGET" -- /root/harden.sh > /tmp/edgeexp-harden.log 2>&1 &
  waited=0
  while :; do
    if lab_target_exec "$TARGET" sh -c 'dpkg-query -W -f="${Status}" suricata 2>/dev/null | grep -q "install ok installed"' 2>/dev/null \
       && lab_target_exec "$TARGET" sh -c 'dpkg-query -W -f="${Status}" aide 2>/dev/null | grep -q "install ok installed"' 2>/dev/null \
       && lab_target_exec "$TARGET" sh -c 'dpkg-query -W -f="${Status}" libpam-u2f 2>/dev/null | grep -q "install ok installed"' 2>/dev/null; then
      break
    fi
    if [ "$waited" -ge "$APT_TIMEOUT_S" ]; then
      echo "edge_target_prepare: apt 在 ${APT_TIMEOUT_S}s 内没有装完，见 /tmp/edgeexp-harden.log 尾部：" >&2
      tail -20 /tmp/edgeexp-harden.log >&2 || true
      exit 1
    fi
    sleep 10
    waited=$((waited + 10))
  done
  echo "edge_target_prepare: 控制包安装完成（等待 ${waited}s）"
else
  echo "edge_target_prepare: 控制包已齐（幂等路径）"
fi

# 配置（幂等：用 grep 判存在，不重复追加）
lab_target_exec "$TARGET" sh -c '
set -e
# SIEM 代理判据：RS-007 要求三份配置文件之一能匹配 email|alert|notification。
# **实测坑**：只写 report_level/report_url 两行**不命中**该正则（控制侧容器里恰好有一行含
# `alert` 的注释才过）⇒ 这里写的是**真实的告警通知配置**，不是为了过门禁塞词。
if ! grep -qiE "email|alert|notification" /etc/aide/aide.conf 2>/dev/null; then
  printf "\n# 告警通知配置（RS-007 的代理判据需要一份真实的告警配置面）\nreport_level=changed\nreport_url=stdout\nmail_command=/usr/bin/mail\nreport_email=secops@example.invalid\nalert_notification=email\n" >> /etc/aide/aide.conf
fi
# 2FA/3FA：EF-001 任一子串即通过；EF-002 要求三类各≥1（按文件累加）
if ! grep -q pam_google_authenticator /etc/pam.d/sshd 2>/dev/null; then
  printf "auth required pam_google_authenticator.so\nauth required pam_u2f.so\nauth required pam_fprintd.so\n" >> /etc/pam.d/sshd
fi
systemctl enable --now suricata >/dev/null 2>&1 || true
' || { echo "edge_target_prepare: 写控制配置失败" >&2; exit 1; }

# --- 3. 实验条件：AppArmor 策略（变了才重启）---------------------------------
CUR_POLICY="$("$lab_target_bin" config get "$TARGET" raw.apparmor 2>/dev/null || true)"
WANT_POLICY=""
[ "$POLICY_ON" = "1" ] && WANT_POLICY="$POLICY_RULE"
RESTARTED=0
if [ "$(printf '%s' "$CUR_POLICY" | tr -d '[:space:]')" != "$(printf '%s' "$WANT_POLICY" | tr -d '[:space:]')" ]; then
  echo "edge_target_prepare: 设置策略 raw.apparmor='$WANT_POLICY'（原值 '$CUR_POLICY'）"
  if [ -n "$WANT_POLICY" ]; then
    "$lab_target_bin" config set "$TARGET" raw.apparmor "$WANT_POLICY" || exit 1
  else
    "$lab_target_bin" config unset "$TARGET" raw.apparmor || exit 1
  fi
  echo "edge_target_prepare: 策略变更需要重启实例（raw.apparmor 在启动时生效）"
  nohup "$lab_target_bin" restart "$TARGET" > /tmp/edgeexp-lxd-restart.log 2>&1 &
  waited=0
  until lab_node_running "$TARGET" >/dev/null 2>&1; do
    [ "$waited" -ge 120 ] && { echo "edge_target_prepare: 重启后实例没有回到运行态" >&2; exit 1; }
    sleep 3; waited=$((waited + 3))
  done
  RESTARTED=1
  echo "edge_target_prepare: 重启完成（等待 ${waited}s）"
else
  echo "edge_target_prepare: 策略已是目标状态（幂等路径，不重启）"
fi

# 策略生效的**节点内自证**（不是"我设了 config"）：读一次被拒路径，两条分支都必须可解释。
if [ "$POLICY_ON" = "1" ]; then
  lab_target_exec "$TARGET" sh -c 'head -1 /etc/shadow >/dev/null 2>&1' \
    && { echo "edge_target_prepare: 策略**没有生效**（策略在，但读 /etc/shadow 成功了）—— 拒绝目标状态不成立" >&2; exit 1; }
  echo "edge_target_prepare: 策略生效自证：节点内读 /etc/shadow 被拒（rc≠0）"
else
  lab_target_exec "$TARGET" sh -c 'head -1 /etc/shadow >/dev/null 2>&1' \
    || { echo "edge_target_prepare: 策略**没有卸载干净**（策略不在，但读 /etc/shadow 仍被拒）" >&2; exit 1; }
  echo "edge_target_prepare: 策略卸载自证：节点内读 /etc/shadow 成功（rc=0）"
fi

# --- 4. agent（重置后 /tmp 被清空 ⇒ payload 放 /root 并重新拉起）-------------
# 判据是 **`(host, 容器内活 pid)` 且心跳新鲜**（不是"Caldera 里有个 trusted 条目"）——
# Caldera 保留已死 agent 的条目，打到死 agent 上会得到 `status=-3` 而**看起来像被拦住**。
[ -f "$PAYLOAD" ] || { echo "edge_target_prepare: sandcat 载荷不存在: $PAYLOAD" >&2; exit 1; }

live_agent_paws() {
  python3 - "$CALDERA_URL" "$CALDERA_KEY" "$TARGET" "${EDGEEXP_AGENT_FRESH_S:-180}" <<'PY'
import json, sys, time, urllib.request
from datetime import datetime, timezone
api, key, host, fresh = sys.argv[1].rstrip('/'), sys.argv[2], sys.argv[3], int(sys.argv[4])
try:
    req = urllib.request.Request(api + '/api/v2/agents', headers={'KEY': key})
    agents = json.load(urllib.request.urlopen(req, timeout=15))
except Exception:
    print(''); raise SystemExit
pids = [int(x) for x in sys.stdin.read().split() if x.strip().isdigit()]
now = time.time()
for a in agents:
    if a.get('host') != host or not a.get('trusted'):
        continue
    if a.get('pid') is None or int(a['pid']) not in pids:
        continue
    try:
        seen = datetime.fromisoformat(a['last_seen'].replace('Z', '+00:00')).timestamp()
    except Exception:
        continue
    if seen >= now - fresh:
        print(a.get('paw')); raise SystemExit
print('')
PY
}

C2_URL="$(python3 - "$CALDERA_URL" <<'PY'
import sys
from urllib.parse import urlparse
u = urlparse(sys.argv[1])
host = u.hostname or '127.0.0.1'
# 节点在 lxdbr0 上，Caldera 的监听地址要取**网桥地址**（容器侧可达），不是 127.0.0.1。
print('http://%s:%s' % (host, u.port or 8888))
PY
)"

PIDS="$(bash "$PIDS_HELPER" "$TARGET" sandcat 2>/dev/null || true)"
PAW="$(printf '%s' "$PIDS" | live_agent_paws 2>/dev/null || true)"

if [ -n "$PAW" ]; then
  echo "edge_target_prepare: agent 已在跳（paw=$PAW，容器内活 pid=[$PIDS]）—— 幂等路径"
else
  echo "edge_target_prepare: 目标上没有活着的 agent（容器内 sandcat pid=[]）⇒ 送载荷并拉起"
  lab_push "$PAYLOAD" "$TARGET" /root/sandcat
  lab_target_exec "$TARGET" chmod 755 /root/sandcat
  # 用 `setsid` 起（`lxc exec` 通道一断，没有 setsid 的子进程会被带走 —— 实测过）
  lab_target_exec "$TARGET" sh -c "setsid /root/sandcat --server $C2_URL --group t4d-ttp > /tmp/sandcat.log 2>&1 < /dev/null & echo launched"
  waited=0
  while :; do
    PIDS="$(bash "$PIDS_HELPER" "$TARGET" sandcat 2>/dev/null || true)"
    PAW="$(printf '%s' "$PIDS" | live_agent_paws 2>/dev/null || true)"
    [ -n "$PAW" ] && break
    if [ "$waited" -ge "$AGENT_WAIT_S" ]; then
      echo "edge_target_prepare: agent 在 ${AGENT_WAIT_S}s 内没有回连（判据：host=$TARGET 且容器内活 pid 一致且心跳新鲜）" >&2
      lab_target_exec "$TARGET" sh -c 'tail -20 /tmp/sandcat.log' >&2 || true
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "edge_target_prepare: agent 就绪（paw=$PAW，容器内活 pid=[$PIDS]，等待 ${waited}s）"
fi

# 收尾自证：容器与 Caldera 两条证据都打出来（供运行级留痕）
echo "edge_target_prepare: 就绪 —— 实例 $TARGET 运行中，策略=$([ "$POLICY_ON" = "1" ] && echo 在 || echo 不在)，agent=$PAW，重启过=$RESTARTED"
exit 0
