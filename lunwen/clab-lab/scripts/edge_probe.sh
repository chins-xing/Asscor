#!/bin/bash
# ============================================================================
# edge_probe.sh —— **节点内**真实条件探针（Task 4C Step 3）
# ============================================================================
#
# 用法（被 edge_attack.sh source；也可手工 source 来单独验证探针）：
#   . scripts/edge_probe.sh <容器名>
#   probe_host_ready                 # 容器存在且 docker 可用，否则**响亮失败**
#   probe_condition_holds EF-NO-IDS   # 0 = 该防护在这台**节点**上确实缺失；1 = 条件不成立；2 = 探针本身没跑成
#
# 为什么必须搬进节点：此前 `condition_holds()` 用的是**跑脚本的这台机器**的
# `cat /proc/sys/...`、`ps -eo comm`、`getenforce` —— 而脚本在 WSL 上跑、被攻节点是
# host1 容器。于是 R 组"我们真的把 IDS 去掉了"这句话探的是另一台机器。
#
# 本脚本的判据逐条对齐 `internal/checks/linux` 的同名检查（OT-005 / RS-005 / RS-006 /
# RS-007 / EF-001 / EF-002）—— 记录构造要求是"checks[] 是引擎真实失败的检查"，
# 所以"条件是否成立"必须用**引擎的判据**来问，不是另立一套。
#
# 三类退出码（调用方必须区分前两个）：
#   0 = 该防护在这台节点上**确实缺失**（条件成立）
#   1 = 条件不成立（防护在位）
#   2 = 探针**没跑成**（docker 不可用 / 容器不在跑 / 节点里没有 bash）—— 这不是"条件不成立"，
#       把它当成 1 会让"探针没执行"静默变成一条有效的否定证据。
# ============================================================================

# probe_target 是探针要进去的容器名（由调用方给出；空 = 未声明，任何探针都直接失败）。
probe_target="${1:-${EDGEEXP_TARGET:-}}"

# probe_docker_bin 允许覆盖 docker 可执行文件（测试用；默认 PATH 上的 docker）。
probe_docker_bin="${EDGEEXP_DOCKER_BIN:-docker}"

# probe_host 返回节点内进程自证的 hostname（写进 condition_probes，让"探针在哪台机器上跑的"
# 这句话本身可核对）。失败时**非零退出**：调用方据此判定"探针没跑成"。
probe_host() {
  local out rc
  out="$("$probe_docker_bin" exec "$probe_target" hostname 2>/dev/null)" && rc=0 || rc=$?
  [ "$rc" -eq 0 ] || return 2
  printf '%s\n' "$(printf '%s' "$out" | tr -d '[:space:]')"
}

# probe_host_ready 在**任何**探针之前调用：docker 不可用 / 容器不存在或不在跑 ⇒ 响亮失败。
#
# 为什么不能省：探针没跑成与"条件不成立"在退出码上必须分开（见文件头），而"容器根本没起"
# 是这两种情况里最难在数据上看出来的 —— 记录里只会少几条 condition_probes。
#
# 说明：这里用 `docker exec` 而不是 `docker inspect`：要问的是"我能不能在这个节点里执行判据"，
# 而不是"这个容器在不在"（一个 exited 的容器 inspect 照样返回，而 exec 会失败）。
probe_host_ready() {
  if [ -z "$probe_target" ]; then
    echo "edge_probe: 没有声明目标节点 —— R 组的真实缺失探针必须**在节点上**执行" >&2
    echo "  请给出容器名（. edge_probe.sh <容器名> 或 EDGEEXP_TARGET=<容器名>）。" >&2
    echo "  不得退回本机探针：那正是『探的是跑脚本的这台机器』这个缺陷的形态。" >&2
    return 2
  fi
  command -v "$probe_docker_bin" >/dev/null 2>&1 || {
    echo "edge_probe: 找不到 docker（$probe_docker_bin）—— 无法在节点 $probe_target 内执行探针" >&2
    echo "  探针没跑成不等于条件成立；整轮失败，不得退回本机探针。" >&2
    return 2
  }
  local running
  running="$("$probe_docker_bin" inspect -f '{{.State.Running}}' "$probe_target" 2>/dev/null)" || {
    echo "edge_probe: 目标节点 $probe_target 不存在（docker inspect 失败）—— 探针无从执行" >&2
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
# 它以 heredoc（单引号 ⇒ 不做任何本机展开）送进去，退出码即判据结论：
#   0 = 条件成立（防护缺失）  1 = 条件不成立（防护在位）
_probe_script() {
  local factor="$1"
  local body
  case "$factor" in
    EF-SELINUX|EF-APPARMOR)
      # OT-005：SELinux 处于 Enforcing，或 AppArmor 已加载策略 ⇒ 条件不成立
      body='
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null | tr -d "[:space:]")" = "Enforcing" ]; then exit 1; fi
if command -v aa-status >/dev/null 2>&1 && aa-status 2>/dev/null | grep -q "profiles are loaded"; then exit 1; fi
exit 0' ;;
    EF-SYNCOOKIE)
      # RS-005：只读 /proc/sys/net/ipv4/tcp_syncookies，要求值为 1
      body='
[ "$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null | tr -d "[:space:]")" = "1" ] && exit 1
exit 0' ;;
    EF-NO-IDS)
      # RS-006：任一 IDS 工具被 systemd 判 active，或其同名进程在跑
      body='
for tool in wazuh-agent ossec-hids ossec-agent aide tripwire samhain rkhunter suricata snort snort3 zeek; do
  if command -v systemctl >/dev/null 2>&1 && [ "$(systemctl is-active "$tool" 2>/dev/null || true)" = "active" ]; then exit 1; fi
done
if command -v ps >/dev/null 2>&1; then
  while read -r comm; do
    case "$comm" in
      suricata|snort|snort3|zeek|wazuh-agent|ossec-agent|aide|tripwire|samhain) exit 1 ;;
    esac
  done < <(ps -eo comm --no-headers 2>/dev/null || true)
fi
exit 0' ;;
    EF-NO-SIEM)
      # RS-007：三份告警配置文件之一存在且含 email/alert/notification
      body='
for cfg in /var/ossec/etc/ossec.conf /etc/wazuh-agent/ossec.conf /etc/aide/aide.conf; do
  if [ -r "$cfg" ] && grep -qiE "email|alert|notification" "$cfg"; then exit 1; fi
done
exit 0' ;;
    EF-002FA|EF-3FA)
      # EF-001 / EF-002：PAM 里出现第二/第三因素模块
      body='
for pam in /etc/pam.d/sshd /etc/pam.d/common-auth /etc/pam.d/system-auth; do
  if [ -r "$pam" ] && grep -qE "pam_google_authenticator|pam_oath|pam_duo|pam_u2f|pam_pkcs11" "$pam"; then exit 1; fi
done
exit 0' ;;
    *)
      echo "edge_probe: 因子 $factor 没有条件探针（新增因子时必须补一条，否则真实缺失对照会静默失效）" >&2
      return 2 ;;
  esac
  printf '%s\n' "$body"
}

# probe_condition_holds 是唯一的对外探针入口。
#
# 它把判据送进节点执行，并把节点内进程的**退出码原样**映射成结论：
#   0 ⇒ 条件成立（防护确实不在）   1 ⇒ 条件不成立   2 ⇒ 探针没跑成（docker/容器/bash 的问题）
#
# `set -e` 在 `if` 条件里是被抑制的，但这里的 docker 调用是**普通命令** ⇒ 必须用
# `|| rc=$?` 接住，否则 dc 的失败会直接终止脚本（退出码丢失，调用方只能看到一次"运行失败"）。
probe_condition_holds() {
  local factor="$1" body dc
  # 先确认"探针真的能在这个节点里跑"：**不同的 docker 失败会给出不同的退出码**
  # （容器不存在是 1、daemon 不可达是 125），而 1 恰好是本探针协议的"条件不成立"。
  # 只在 exec 之后按退出码分类，会把"容器根本不在"读成一条有效的否定证据 —— 故这里
  # 无条件先过一遍就绪检查（多一次 docker inspect，换掉一个静默误判）。
  probe_host_ready || return 2

  # `_probe_script` 对"没有探针的因子"返回非零，而它出现在**普通赋值**里 ⇒ 在 `set -e` 的
  # 调用方会直接把整个脚本带走（实测：探针循环静默停在那一行，调用方只看到一次"运行失败"
  # 而没有任何诊断）。故这里自己接住退出码再分类。
  set +e
  body="$(_probe_script "$factor")"
  dc=$?
  set -e
  [ "$dc" -eq 0 ] || return 2
  [ -n "$body" ] || return 2

  set +e
  printf '%s\n' "$body" | "$probe_docker_bin" exec -i "$probe_target" bash -ls >/dev/null 2>&1
  dc=$?
  set -e

  case "$dc" in
    0) return 0 ;;
    1) return 1 ;;
    *)
      echo "edge_probe: 探针 $factor 在节点 $probe_target 内没有跑成（docker exec 退出码 $dc）——" >&2
      echo "  这**不是**『条件不成立』：探针本身失败了。整轮失败，不得据此写任何结论。" >&2
      return 2 ;;
  esac
}
