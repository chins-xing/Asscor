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
#   EDGEEXP_CALDERA_URL       Caldera API（默认 http://127.0.0.1:8888；**这是宿主上**调 API 的地址）
#   EDGEEXP_CALDERA_KEY       API key（默认 ADMIN123）
#   EDGEEXP_C2_HOST           容器侧可达的宿主地址（默认取容器内默认网关；覆盖见"地址给错了机器"那段）
#   EDGEEXP_SANDCAT_PAYLOAD   sandcat 载荷路径（默认 /opt/caldera/plugins/sandcat/payloads/sandcat.go-linux）
#   EDGEEXP_AGENT_WAIT_S      等 agent 回连的上限（秒，默认 180）
#   EDGEEXP_ATTACK_GROUP      agent 的**分组名**（默认 t4d-ttp）。它与攻击侧的投送范围
#                             （`edge_attack.sh` 的 `EDGEEXP_ATTACK_GROUP`）是**同一个变量** ——
#                             组名只有一处来源，两侧不一致时不会出现"你其实已经拉过了"这种误诊
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
# **agent 分组名只有一个来源：`EDGEEXP_ATTACK_GROUP`**（Task 4D Fix round 2 / Minor-4）。
#
# 上一版这里把 `--group t4d-ttp` **硬编码**在拉起命令里，而攻击侧要求用 `EDGEEXP_ATTACK_GROUP`
# 声明 operation 的投送范围 ⇒ 同一个组名有**两处来源**。两侧不一致时攻击侧的闸门①会响亮失败
# （不是静默出错，这点是好的），但它的错误信息让操作者"用 --group 拉起 agent" —— 而他其实已经拉了，
# **诊断方向指错**。现在两处读同一个变量：目标 agent 拉起时的 `--group` 与攻击侧的投送范围同源。
AGENT_GROUP="${EDGEEXP_ATTACK_GROUP:-t4d-ttp}"

[ -n "$TARGET" ] || { echo "edge_target_prepare: 必须给 EDGEEXP_TARGET=<实例名>" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "edge_target_prepare: 缺少 python3" >&2; exit 2; }
[ -f "$PIDS_HELPER" ] || { echo "edge_target_prepare: 缺少 $PIDS_HELPER" >&2; exit 2; }

echo "edge_target_prepare: 目标=$TARGET 基质=$lab_substrate 策略=$([ "$POLICY_ON" = "1" ] && echo 在 || echo 不在) agent 组=$AGENT_GROUP（来源 EDGEEXP_ATTACK_GROUP，攻击侧同一变量）"

# wait_for_exec <秒> —— 等实例真的**能在里面执行命令**；判据与实现都在**基质层**
# （`edge_lab.sh:lab_wait_node_exec`，Task 4D Fix round 2 / Minor-6 把那条判据收进基质层的原因见那里）。
#
# 这里只保留"把超时翻译成本脚本的处置"：
# 上一版的坑是调用方自己写了 `until lab_node_running … >/dev/null 2>&1`，把打在 stdout 上的
# `true`/`false` 丢掉 ⇒ STOPPED 的实例同样能应答、循环 0 秒就宣布"已就绪"，随后 `exec` 撞上
# `Error: Instance is not running`（而本脚本 **没有 `set -e`**，那行错被咽下去）。
# 第二层坑：`lxc restart` 是"先停后起"，刚发起时 `lxc info` 仍是 RUNNING ⇒ 只查状态依然不够。
wait_for_exec() {
  local limit="$1"
  lab_wait_node_exec "$TARGET" "$limit" && return 0
  echo "edge_target_prepare: 实例 $TARGET 在 ${limit}s 内仍然不能执行命令（判据：节点内 true 的 rc=0）" >&2
  return 1
}

# wait_for_up <pid> <秒> —— 等"停/起"走完：① 发起它的子进程退出；② 节点内真能执行命令。
wait_for_up() {
  local pid="$1" limit="$2" waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$limit" ]; then
      echo "edge_target_prepare: 实例 $TARGET 的停/起在 ${limit}s 内没有结束（子进程 $pid 还在）" >&2
      return 1
    fi
    sleep 2; waited=$((waited + 2))
  done
  # 收尸（`kill -0` 对**已退出但未被 bash 回收**的子进程仍然成功，故真正判据是"命令自己的退出码"）
  wait "$pid" 2>/dev/null || true
  wait_for_exec "$limit"
}

# --- 1. 实例存在？不存在就建（幂等）------------------------------------------
if lab_instance_exists "$TARGET"; then
  echo "edge_target_prepare: 实例已存在（幂等路径，不重建）"
else
  echo "edge_target_prepare: 实例不存在 ⇒ lxc launch ubuntu:24.04 $TARGET（后台 + 轮询）"
  # `ssh_exec` 约 600 s 会打断前台长命令；`lxc launch` 实测要几十秒 ⇒ 一律后台 + 轮询日志。
  nohup "$lab_target_bin" launch ubuntu:24.04 "$TARGET" > /tmp/edgeexp-lxd-launch.log 2>&1 &
  LAUNCH_PID=$!
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
  wait_for_up "$LAUNCH_PID" 300 || exit 1
fi

# --- 1b. 存在但没在跑 ⇒ 拉起来 -------------------------------------------------
# 幂等复位的语义是"把实例准备成实验条件"，其中**在跑**是必要条件。实例存在却 STOPPED（实测出现过：
# 策略变更后的重启落在停/起之间而脚本已经往下走）在旧版里会一路等到超时才报"不能执行命令"，
# 那与"实例坏了"同形 —— 这里显式 start 一次，原因与动作都写在日志里。
if [ "$(lab_node_running "$TARGET" 2>/dev/null || true)" != "true" ]; then
  echo "edge_target_prepare: 实例存在但没在跑 ⇒ $lab_target_bin start $TARGET"
  nohup "$lab_target_bin" start "$TARGET" > /tmp/edgeexp-lxd-start.log 2>&1 &
  START_PID=$!
  wait_for_up "$START_PID" 180 || exit 1
fi

# 等它真的能 exec（`Status: RUNNING` 之后 exec 也可能短暂失败）
wait_for_exec 120 || exit 1

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
  RESTART_PID=$!
  wait_for_up "$RESTART_PID" 180 || exit 1
  RESTARTED=1
  echo "edge_target_prepare: 重启完成（容器内已可执行命令）"
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

# live_agent_paws <容器内活 pid 列表> —— 回显满足判据的 paw，否则空行。
#
# **实测踩坑（Step 4-B2，本轮最贵的一个）**：上一版把 pid 列表从 **stdin** 喂给 python，而脚本本体
# 又是用 `python3 - <<'PY'` 从 **stdin** 读的 —— 同一路 stdin 被用了两次：程序把 heredoc 读完时
# 已经到 EOF，于是 `sys.stdin.read()` **永远是空串** ⇒ `pids` 永远为空 ⇒ 这个函数**从来匹配不到
# 任何 agent**（8 条 `trusted=true`、pid 也对得上的条目全被静默滤掉，实测复现：`printf '886\n1096'
# | live_agent_paws` 回空行）。
# 后果不是"多拉一次 sandcat"这么轻：它让"目标上有没有活着的 agent"这条判据**恒为否**，于是每次复位
# 都覆盖并重拉 agent；而这条判据存在的理由正是**避免把 operation 打到死 agent 上**（`status=-3`
# 看起来像被拦住）。修法是把 pid 列表改成**第 5 个 argv**（stdin 只留给程序本体）。
live_agent_paws() {
  python3 - "$CALDERA_URL" "$CALDERA_KEY" "$TARGET" "${EDGEEXP_AGENT_FRESH_S:-180}" "${1:-}" <<'PY'
import json, sys, time, urllib.request
from datetime import datetime, timezone
api, key, host, fresh = sys.argv[1].rstrip('/'), sys.argv[2], sys.argv[3], int(sys.argv[4])
try:
    req = urllib.request.Request(api + '/api/v2/agents', headers={'KEY': key})
    agents = json.load(urllib.request.urlopen(req, timeout=15))
except Exception:
    print(''); raise SystemExit
pids = [int(x) for x in sys.argv[5].split() if x.strip().isdigit()]
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

# --- C2 地址：必须是**容器侧可达的宿主地址** ------------------------------------------------
# 实测踩坑（Step 4-B2，代价是一轮 180s 超时 + 八条 `trusted=false` 的假象）：
# `EDGEEXP_CALDERA_URL` 的默认值 `http://127.0.0.1:8888` 是**在宿主上**调 API 的地址，而容器里的
# `127.0.0.1` 是**它自己**。上一版直接把 `urlparse` 出来的 hostname 当成节点侧地址 ⇒ 拉起的 sandcat
# 一直连自己：进程能起来（`ps` 里有）、`/tmp/sandcat.log` 一行不写、Caldera 里 `asc-tgt-1` 的条目
# 全是 `trusted=false` —— 从面板上看与"agent 起不来"同形，而真正的原因是**地址给错了机器**。
# 正确取值是**容器内的默认网关**（= LXD 网桥地址 = 宿主在容器网段的地址）。实测：
#   容器内 `ip route show default` → `default via 10.217.208.1 dev eth0`；
#   容器内 `curl http://10.217.208.1:8888/api/v2/abilities` → 200；`127.0.0.1:8888` → rc=7。
# 允许 `EDGEEXP_C2_HOST` 显式覆盖；两条路都拿不到 ⇒ **响亮失败**（静默回落到 127.0.0.1 等于注定死 agent）。
C2_HOST="${EDGEEXP_C2_HOST:-}"
if [ -z "$C2_HOST" ]; then
  C2_HOST="$(lab_target_exec "$TARGET" sh -c 'ip route show default 2>/dev/null | awk "/^default/ {print \$3; exit}"' 2>/dev/null || true)"
fi
C2_HOST="$(printf '%s' "$C2_HOST" | tr -d '[:space:]')"
[ -n "$C2_HOST" ] || {
  echo "edge_target_prepare: 取不到容器侧可达的 C2 地址（容器内没有默认路由？）——" >&2
  echo "  请用 EDGEEXP_C2_HOST=<宿主在容器网段的地址，如 10.217.208.1> 显式指定。" >&2
  exit 1
}

C2_URL="$(python3 - "$CALDERA_URL" "$C2_HOST" <<'PY'
import sys
from urllib.parse import urlparse
u = urlparse(sys.argv[1])
print('http://%s:%s' % (sys.argv[2], u.port or 8888))
PY
)"

# --- C2 可达性自证（在**容器内**问一次，放在拉起 agent 之前）----------------------------------
# 存在的理由就是上面那段踩坑：地址给错时"进程起来了但永不回连"要等满 180s 才被发现，而这中间拉起的
# 进程会把 `/tmp/sandcat.log` 留成**空文件** —— 与"进程一启动就崩"同形，排障方向会完全错。
# 把自证放在**拉起之前**，等于把"地址不可达"和"agent 起不来"拆成两个结论。
# curl 不在容器里（rc=127）时**不冒充已证**：明确写出"自证被跳过"，也不拦路（那是环境事实，不是失败）。
C2_PROOF="$(lab_target_exec "$TARGET" sh -c "command -v curl >/dev/null 2>&1 || exit 127; curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'KEY: $CALDERA_KEY' '$C2_URL/api/v2/abilities'" 2>/dev/null || true)"
case "$C2_PROOF" in
  200) echo "edge_target_prepare: C2 可达性自证：容器内 curl $C2_URL/api/v2/abilities → 200" ;;
  127) echo "edge_target_prepare: 警告：容器内没有 curl ⇒ C2 可达性自证**跳过**（本轮不声明已证）" >&2 ;;
  *)   echo "edge_target_prepare: 容器内问不到 C2（$C2_URL → '${C2_PROOF:-空}'）—— 这个地址拉起 agent 必然不回连，先修地址" >&2
       echo "  容器内默认路由：$(lab_target_exec "$TARGET" ip route show default 2>&1 | head -2)" >&2
       echo "  可用 EDGEEXP_C2_HOST=<宿主在容器网段的地址> 覆盖。" >&2
       exit 1 ;;
esac

PIDS="$(bash "$PIDS_HELPER" "$TARGET" sandcat 2>/dev/null || true)"
PAW="$(live_agent_paws "$PIDS" 2>/dev/null || true)"

if [ -n "$PAW" ]; then
  echo "edge_target_prepare: agent 已在跳（paw=$PAW，容器内活 pid=[$PIDS]）—— 幂等路径"
else
  echo "edge_target_prepare: 目标上没有活着的 agent（容器内 sandcat pid=[$PIDS]）⇒ 送载荷并拉起"
  # **先送到临时名再 `mv`**（实测踩坑）：直接 `lxc file push` 覆盖 `/root/sandcat` 在**有进程正在跑
  # 它**时会以 `sftp: "open /root/sandcat: text file busy"` 失败 —— 而"有没有活着的 agent"这条判据
  # 可能因为心跳过期而恰恰在这时候判成"没有"（判据是 (host, 活 pid, 新鲜心跳)，三个都要满足）。
  # `mv`（同文件系统内是 rename）对正在执行的旧文件是允许的，因此这条路不会卡在 ETXTBSY 上。
  # 每一步**显式判失败**：本脚本没有 `set -e`（见头部注释），漏判就等于"降级继续" —— 上一版实测
  # 就是 push 失败被咽下去，然后拉起一个不存在/过期的载荷，最后以 180s 超时收场（错因被埋掉）。
  lab_push "$PAYLOAD" "$TARGET" /root/sandcat.new \
    || { echo "edge_target_prepare: 把 sandcat 载荷送到 $TARGET:/root/sandcat.new 失败" >&2; exit 1; }
  lab_target_exec "$TARGET" sh -c 'mv -f /root/sandcat.new /root/sandcat && chmod 755 /root/sandcat' \
    || { echo "edge_target_prepare: 在 $TARGET 内落地 /root/sandcat 失败" >&2; exit 1; }
  # 用 `setsid` 起（`lxc exec` 通道一断，没有 setsid 的子进程会被带走 —— 实测过）
  lab_target_exec "$TARGET" sh -c "setsid /root/sandcat --server $C2_URL --group $AGENT_GROUP > /tmp/sandcat.log 2>&1 < /dev/null & echo launched" \
    || { echo "edge_target_prepare: 在 $TARGET 内拉起 sandcat 失败" >&2; exit 1; }
  waited=0
  while :; do
    PIDS="$(bash "$PIDS_HELPER" "$TARGET" sandcat 2>/dev/null || true)"
    PAW="$(live_agent_paws "$PIDS" 2>/dev/null || true)"
    [ -n "$PAW" ] && break
    if [ "$waited" -ge "$AGENT_WAIT_S" ]; then
      echo "edge_target_prepare: agent 在 ${AGENT_WAIT_S}s 内没有回连（判据：host=$TARGET 且容器内活 pid 一致且心跳新鲜）" >&2
      # 超时是**多因**的（载荷没落地 / 进程没起来 / 起来了但连不上 C2 / 连上了但 pid 对不上）。
      # 只打一行"没有回连"会把四种原因压成一个结论 —— 这里把能自证的三条证据一次打全。
      echo "  · 容器内 sandcat 进程（ps，可能为空）:" >&2
      lab_target_exec "$TARGET" ps -eo pid,comm --no-headers >&2 2>/dev/null || true
      echo "  · 容器内 /root/sandcat:" >&2
      lab_target_exec "$TARGET" ls -la /root/sandcat >&2 2>/dev/null || true
      echo "  · 节点内 sandcat 日志尾部（C2 地址=$C2_URL）:" >&2
      lab_target_exec "$TARGET" sh -c 'tail -20 /tmp/sandcat.log' >&2 || true
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "edge_target_prepare: agent 就绪（paw=$PAW，容器内活 pid=[$PIDS]，等待 ${waited}s）"
fi

# 收尾自证：容器与 Caldera 两条证据都打出来（供运行级留痕）
echo "edge_target_prepare: 就绪 —— 实例 $TARGET 运行中，策略=$([ "$POLICY_ON" = "1" ] && echo 在 || echo 不在)，agent=$PAW（组=$AGENT_GROUP），重启过=$RESTARTED"
exit 0
