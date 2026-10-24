#!/bin/bash
# test-edge-probe.sh —— edge_probe.sh 的**离线夹具**验证（Task 4C Fix round 1）
#
# 本机生成，不进仓库。全程只读：不碰 clab、不碰容器、不碰攻击；`docker` 是一个把 stdin 直接
# 交给**本机 bash** 的假 `docker`（判据体因此跑在临时夹具树上，`PROBE_ROOT` 指向它）。
#
# 覆盖：
#   I-4  EF-3FA 必须按 EF-002 的**三类计数**判（且与 EF-001 判据分道）
#   I-5  节点里的 profile/logout 不再能顶替结论；判据没跑到底 ⇒ 2（而不是 0/1）
#   M-6  getenforce 能跑但输出非 Enforcing 时不再回退 aa-status（与引擎 ot005 同构）
#   基础 六因子的两种取值 + 未知因子 + 未声明目标（既有行为不回归）
#   T42  root 等价：特权判据在 root / sudo 下同结论；**拿不到提权 ⇒ 2（不是 0）**；
#        privilege 留痕取 root / sudo / unprivileged；不碰无特权需求的判据（不一刀切）。
#
# 夹具纪律：每棵夹具树都必须**像一个根**（至少要有 /proc，见 edge_probe.sh 的 preamble 守卫）；
# EF-3FA 的"类"按 checks.go 的 ef002 三类**每次命中各计一次**（同一文件同时命中两类算两次）。
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$TESTS_DIR/../../.." && pwd)}"
PROBE=$REPO/lunwen/clab-lab/scripts/edge_probe.sh
D=/tmp/task4c/fix1
rm -rf "$D"; mkdir -p "$D/bin" "$D/noisybin" "$D/root/not-a-root" "$D/nodefs"

# --- 假 docker：模拟"容器文件系统"（$D/nodefs）上的 cp/exec -------------------------
# 探针的判据体现在走"**文件**进节点"（实测：用 `… | docker exec -i … bash -s` 会丢脚本末尾、
# 哨兵打不出来）。故假 docker 必须支持 cp 与"执行容器内脚本"：
#   inspect -f {{.State.Running}} <name>   ⇒ true（"容器在跑"）
#   cp <本地> <容器>:<容器内路径>            ⇒ 复制进 $D/nodefs
#   exec [-i] [-e K=V] <name> hostname      ⇒ probe-fixture（节点自报的 hostname）
#   exec <name> bash <容器内路径>            ⇒ 用本机 bash 执行 nodefs 里的那份脚本
#   exec <name> rm -f <容器内路径>           ⇒ 删掉 nodefs 里的脚本
# 判据体自己会把 PROBE_ROOT 设成夹具树，故"容器内执行"与夹具树是解耦的。
cat > "$D/bin/docker" <<SH
#!/bin/bash
NODEFS=$D/nodefs
case "\${1:-}" in
  inspect) printf 'true\n'; exit 0 ;;
  cp)
    cont="\${3#*:}"
    mkdir -p "\$NODEFS\$(dirname "\$cont")"
    cp "\$2" "\$NODEFS\$cont" || exit 1
    exit 0 ;;
  exec) ;;
  *) exit 0 ;;
esac
shift
[ "\${1:-}" = "-i" ] && shift
while [ "\${1:-}" = "-e" ]; do shift 2; done
target="\${1:-}"; shift || true
if [ "\${1:-}" = "hostname" ]; then printf 'probe-fixture\n'; exit 0; fi
if [ "\${1:-}" = "rm" ]; then rm -f "\$NODEFS/\${3:-}"; exit 0; fi
if [ "\${1:-}" = "bash" ]; then
  script="\$NODEFS\${2:-}"
  [ -f "\$script" ] || { echo "fake-docker: 容器内脚本不存在: \${2:-}" >&2; exit 127; }
  exec /bin/bash "\$script"
fi
exit 0
SH
chmod +x "$D/bin/docker"

# --- "噪声节点"：脚本进了节点但什么都不输出（模拟判据被提前终结 / 只读到一半）---------
cat > "$D/noisybin/docker" <<SH
#!/bin/bash
NODEFS=$D/nodefs
case "\${1:-}" in
  inspect) printf 'true\n'; exit 0 ;;
  cp)
    cont="\${3#*:}"
    mkdir -p "\$NODEFS\$(dirname "\$cont")"
    cp "\$2" "\$NODEFS\$cont" || exit 1
    exit 0 ;;
  exec) ;;
  *) exit 0 ;;
esac
shift
[ "\${1:-}" = "-i" ] && shift
while [ "\${1:-}" = "-e" ]; do shift 2; done
target="\${1:-}"; shift || true
if [ "\${1:-}" = "hostname" ]; then printf 'probe-fixture\n'; exit 0; fi
if [ "\${1:-}" = "rm" ]; then rm -f "\$NODEFS/\${3:-}"; exit 0; fi
exit 0
SH
chmod +x "$D/noisybin/docker"

# --- 夹具树 -------------------------------------------------------------------------
build_root() { # $1 = 根目录；$2 = pam 内容（同一个字符串写进 sshd 与 common-auth）
  # ⚠️ 注意（Fix round 2 残余 I-4）：把同一份内容写进**两个**文件会让引擎的"按文件累加"给
  # 每类各 +2（`sshd` 一次、`common-auth` 一次）—— 需要精确控制的用例请用
  # `build_root_split`（显式给每个文件的内容），别用这个辅助函数。
  build_root_split "$1" "$2" "$2"
}

build_root_split() { # $1 = 根目录；$2 = sshd 内容；$3 = common-auth 内容
  local r="$1" sshd="$2" common="$3"
  rm -rf "$r"; mkdir -p "$r/etc/pam.d" "$r/proc/sys/net/ipv4" "$r/usr/sbin" "$r/usr/bin"
  # 遮蔽 `systemctl`：夹具不是 systemd 机器（空的同名可执行文件 ⇒ command -v 命中、输出为空 ⇒
  # 判据走 ps 分支，与容器里的行为同构）。
  : > "$r/usr/sbin/systemctl"; chmod +x "$r/usr/sbin/systemctl"
  # T42：夹具默认**提供可用的提权通道**（`sudo -n` 直接执行，本机测试无法真提权）——
  # 于是"非 root 但 sudo 可用"这条路径在每个既有夹具上都成立，既有断言的期望值不变。
  # 需要"拿不到提权"的用例用 break_sudo；需要"root 身份"的用例用 fake_root_id。
  cat > "$r/usr/bin/sudo" <<'SH'
#!/bin/sh
# 夹具：模拟非 root 但 `sudo -n` 可用（判据体仍在夹具根上跑；这里不做真提权）
[ "${1:-}" = "-n" ] && shift
exec "$@"
SH
  chmod +x "$r/usr/bin/sudo"
  printf '%s\n' "$sshd" > "$r/etc/pam.d/sshd"
  printf '%s\n' "$common" > "$r/etc/pam.d/common-auth"
  printf '1\n' > "$r/proc/sys/net/ipv4/tcp_syncookies"
}

# break_sudo：把夹具里的 `sudo` 换成"存在但 `sudo -n` 不可用"（恒失败）——
# 这正是"非 root 且拿不到提权"的形态（也覆盖"sudo 存在但要密码"这一更常见的现实）。
break_sudo() { # $1 = 根目录
  printf '#!/bin/sh\nexit 1\n' > "$1/usr/bin/sudo"; chmod +x "$1/usr/bin/sudo"
}

# fake_uid：让夹具里的 `id -u` 报**指定 uid**（默认 0）。宿主本身是 root 还是普通用户都无影响
# —— 这保证 T42 的三条断言在任何宿主上都跑同样的分支（此前只造"假 root"，
# 宿主真是 root 时"非 root"用例会被宿主身份顶掉，实测在 Linux/root 上失败）。
fake_uid() { # $1 = 根目录；$2 = uid（缺省 0）
  local uid="${2:-0}"
  printf '#!/bin/sh\n[ "${1:-}" = "-u" ] && { echo %s; exit 0; }\nexec /usr/bin/id "$@"\n' "$uid" > "$1/usr/bin/id"
  chmod +x "$1/usr/bin/id"
}

# fake_root_id：让夹具里的 `id -u` 报 0 —— 模拟 CT 上 `pct exec` 的**天生 root**。
fake_root_id() { # $1 = 根目录
  fake_uid "$1" 0
}

run_probe_full() { # $1 = factor, $2 = probe_root, $3 = 备选 docker bin 目录
  # 输出 `rc|privilege`（privilege 来自 edge_probe.sh 的 probe_last_privilege，Task 42）。
  local factor="$1" root="$2" bin="${3:-}"
  # `$$` 在子 shell 里也是**父进程**的 PID，故整棵调用树里稳定；`$BASHPID` 不是（每个命令替换
  # 都是新的 BASHPID）—— 调试时踩到过一次，导致 cp 与 exec 用了两个不同的文件名。
  local instance="$$"
  (
    # 夹具树必须**同时**出现在"容器"里：判据体在容器内跑，它引用的绝对路径（/etc/pam.d、
    # /usr/sbin/getenforce…）按**容器根**解析 —— 假 docker 的容器根是 $D/nodefs，故先把夹具树
    # 铺进去；PROBE_ROOT 则指向同一棵树的宿主路径（它只影响显式拼接的 "$PROBE_ROOT$p" 与 PATH）。
    rm -rf "$D/nodefs"; mkdir -p "$D/nodefs"
    cp -a "$root/." "$D/nodefs/" 2>/dev/null || true
    PATH="${bin:+$bin:}$D/bin:$PATH"
    EDGEEXP_PROBE_ROOT="$root"
    export EDGEEXP_PROBE_ROOT PATH
    # shellcheck source=/dev/null
    . "$PROBE" probe-fixture
    if probe_condition_holds "$factor"; then rc=0; else rc=$?; fi
    printf '%s|%s\n' "$rc" "${probe_last_privilege:-}"
  )
}

run_probe() { # $1 = factor, $2 = probe_root, $3 = 备选 docker bin 目录 ⇒ 只输出 rc
  local r
  r="$(run_probe_full "$@")"
  printf '%s\n' "${r%%|*}"
}

priv_of() { # $1 = factor, $2 = probe_root ⇒ 只输出 privilege 留痕
  local r
  r="$(run_probe_full "$@")"
  printf '%s\n' "${r#*|}"
}

expect() { # $1 = 说明, $2 = got, $3 = want
  if [ "$2" = "$3" ]; then printf '  ok   %-62s rc=%s\n' "$1" "$2"
  else printf '  FAIL %-62s rc=%s want=%s\n' "$1" "$2" "$3"; fi
}

# run_probe_verbose：与 run_probe 同构，但把"探针看到的原始输出"也打出来。
# 用来定位"为什么哨兵没出现"这类问题（探针的报错只说"没跑到底"，不给原始输出）。
run_probe_verbose() {
  local factor="$1" root="$2"
  (
    rm -rf "$D/nodefs"; mkdir -p "$D/nodefs"
    cp -a "$root/." "$D/nodefs/"
    PATH="$D/bin:$PATH"
    EDGEEXP_PROBE_ROOT="$root"
    export EDGEEXP_PROBE_ROOT PATH
    # shellcheck source=/dev/null
    . "$PROBE" probe-fixture
    body="$(_probe_script "$factor")"
    printf '%s\n' "$body" > "$D/verbose-body.sh"
    echo "    [verbose] 判据体末尾: $(printf '%s\n' "$body" | tail -2 | tr '\n' '|')"
    "$D/bin/docker" cp "$D/verbose-body.sh" "probe-fixture:/tmp/edge_probe.verbose.$$.sh"
    echo "    [verbose] nodefs: $(ls "$D/nodefs/tmp/" 2>&1 | tr '\n' ' ')"
    raw="$("$D/bin/docker" exec probe-fixture bash "/tmp/edge_probe.verbose.$$.sh" 2>&1)"
    echo "    [verbose] 原始输出=[$(printf '%s' "$raw" | tr '\n' '|')]"
    echo "    [verbose] getenforce: $(ls -la "$D/nodefs/usr/sbin/getenforce" 2>&1)"
  )
}

echo "############ I-4：EF-3FA 必须与引擎 EF-002 **同构**（按文件累加、每类每文件至多 +1、≥3 在位）"
# ⚠️ 引擎是**按文件累加**：把同一份内容写进两个文件会对每类各 +2。故这里的期望值全部按
# "每类每文件至多 +1"算，需要精确控制的用例用 build_root_split（显式给每个文件的内容）。
R3="$D/root/3fa_full"        # sshd 三行三类 ⇒ 3 ⇒ EF-002 通过 ⇒ 在位 ⇒ rc=1
R2="$D/root/3fa_two_class"   # sshd 类①②（2）；common-auth 空 ⇒ 计数 2 < 3 ⇒ 缺失 ⇒ rc=0
R1="$D/root/3fa_only_dup"    # sshd 类② + common-auth 类② ⇒ 每类每文件 +1 = 2 ⇒ 缺失 ⇒ rc=0
R0="$D/root/no_pam"          # 有 /proc、没有 PAM 内容 ⇒ 计数 0 ⇒ 缺失 ⇒ rc=0
build_root "$R3" "auth required pam_u2f.so
auth required pam_google_authenticator.so
auth required pam_fprintd.so"
build_root_split "$R2" "auth required pam_google_authenticator.so
auth required pam_u2f.so" ""
build_root_split "$R1" "auth required pam_u2f.so" "auth required pam_pkcs11.so"
build_root "$R0" ""

# --- 单向保守假缺失的反例（Fix round 2 残余 I-4）--------------------------------------
# 引擎按文件累加 ⇒ 同一类跨两个文件各 +1，再叠另一类就够 3 ⇒ **判通过（在位）**。
# "三类并集"的旧实现只看到 2 类 ⇒ 判**缺失**（假缺失）—— 这两种布局就是它的反例：
RS="$D/root/3fa_same_class_two_files"  # 类① 跨 sshd(google_authenticator)+common-auth(oath) + 类②(sshd u2f) ⇒ 3 ⇒ 在位
RD="$D/root/3fa_dup_two_files"         # 类② 跨 sshd(u2f)+common-auth(pkcs11) + 类①(sshd google_authenticator) ⇒ 3 ⇒ 在位
# 反向对照：同一类跨两文件**但只有这一类** ⇒ 计数 2 ⇒ 缺失（这条证明上面的"在位"来自累加、不是恒真）
RC="$D/root/3fa_same_class_only"       # 类① 跨两文件 ⇒ 计数 2 < 3 ⇒ 缺失 ⇒ rc=0
build_root_split "$RS" "auth required pam_google_authenticator.so
auth required pam_u2f.so" "auth required pam_oath.so"
build_root_split "$RD" "auth required pam_u2f.so
auth required pam_google_authenticator.so" "auth required pam_pkcs11.so"
build_root_split "$RC" "auth required pam_google_authenticator.so" "auth required pam_oath.so"

expect "EF-3FA sshd 三类齐备（count=3）⇒ 在位（rc=1）"  "$(run_probe EF-3FA "$R3")" 1
expect "EF-3FA sshd 只有 ①②（count=2）⇒ 缺失（rc=0）"   "$(run_probe EF-3FA "$R2")" 0
expect "EF-3FA 类②跨两文件无第三类（count=2）⇒ 缺失（rc=0）" "$(run_probe EF-3FA "$R1")" 0
echo "  （I-4 的具体危害：只有 pam_u2f 时，旧探针复用 EF-001 判据会报『在位』）"
echo "  （残余 I-4 的反例：同一类跨两文件 ⇒ 引擎按文件累加判通过；并集实现会误报缺失）"
expect "EF-3FA 类①跨 sshd+common-auth + 类② ⇒ 在位（rc=1，与引擎同结论）" \
  "$(run_probe EF-3FA "$RS")" 1
expect "EF-3FA 类②跨 sshd+common-auth + 类① ⇒ 在位（rc=1，与引擎同结论）" \
  "$(run_probe EF-3FA "$RD")" 1
expect "EF-3FA 只有类①跨两文件（count=2）⇒ 缺失（rc=0，证明上面的在位来自累加）" \
  "$(run_probe EF-3FA "$RC")" 0
expect "EF-002FA 只有 ② ⇒ EF-001 判据说在位（rc=1）"      "$(run_probe EF-002FA "$R1")" 1
expect "EF-002FA 三类齐备 ⇒ 在位（rc=1）"                 "$(run_probe EF-002FA "$R3")" 1
expect "EF-002FA 无 PAM 内容 ⇒ 缺失（rc=0）"              "$(run_probe EF-002FA "$R0")" 0

echo
echo "############ 基础：其余五因子在夹具上的两种取值"
expect "EF-SYNCOOKIE=1 ⇒ 在位（rc=1）"  "$(run_probe EF-SYNCOOKIE "$R3")" 1
expect "EF-NO-IDS 无 IDS（systemctl 空输出 + 无匹配进程）⇒ 缺失（rc=0）" "$(run_probe EF-NO-IDS "$R3")" 0
expect "EF-NO-SIEM 无告警配置 ⇒ 缺失（rc=0）" "$(run_probe EF-NO-SIEM "$R3")" 0
expect "EF-SELINUX 夹具里没有 getenforce/aa-status ⇒ 缺失（rc=0）" "$(run_probe EF-SELINUX "$R0")" 0

echo
echo "############ M-6：getenforce 能跑 ⇒ 不再回退 aa-status（与引擎 ot005 同构）"
# 关键：getenforce 与 aa-status **两个都放进夹具**（宿主上有真的 /usr/sbin/aa-status，
# 不遮蔽它这条用例就测不到"回退"这件事）。
RP="$D/root/rac"
build_root "$RP" ""
printf '#!/bin/sh\necho "apparmor module is loaded."\necho "42 profiles are loaded."\n' > "$RP/usr/sbin/aa-status"
chmod +x "$RP/usr/sbin/aa-status"

printf '#!/bin/sh\necho Permissive\n' > "$RP/usr/sbin/getenforce"; chmod +x "$RP/usr/sbin/getenforce"
run_probe_verbose EF-SELINUX "$RP"
expect "getenforce=Permissive 且 aa-status 说 profiles are loaded ⇒ 仍判缺失（rc=0）" \
  "$(run_probe EF-SELINUX "$RP")" 0
printf '#!/bin/sh\necho Disabled\n' > "$RP/usr/sbin/getenforce"; chmod +x "$RP/usr/sbin/getenforce"
expect "getenforce=Disabled 且 aa-status 在位 ⇒ 仍判缺失（rc=0）" \
  "$(run_probe EF-SELINUX "$RP")" 0
printf '#!/bin/sh\necho Enforcing\n' > "$RP/usr/sbin/getenforce"; chmod +x "$RP/usr/sbin/getenforce"
expect "getenforce=Enforcing ⇒ 在位（rc=1）" "$(run_probe EF-SELINUX "$RP")" 1
rm -f "$RP/usr/sbin/getenforce"
expect "getenforce 不存在、aa-status 在位 ⇒ 回退生效（rc=1）" "$(run_probe EF-SELINUX "$RP")" 1

echo
echo "############ T42：root 等价 —— 特权判据在 root / sudo 下同结论；拿不到提权 ⇒ 2（不是 0）"
# 三份副本长**同一棵树**（getenforce=Enforcing ⇒ 在位），只差"执行身份 / 提权能力"：
#   RP42ROOT : id -u 报 0（CT 上 pct exec 的**天生 root**形态）⇒ rc=1，privilege=root
#   RP42SUDO : id -u 报 1000，夹具 sudo -n 直接执行         ⇒ rc=1（**与 root 同结论**），privilege=sudo
#   RP42NONE : id -u 报 1000，sudo 存在但恒失败（无提权通道）⇒ rc=2（**不是** 0=『防护缺失』）
# ⚠️ 三份都必须**显式指定 uid**：只造"假 root"是不够的 —— 宿主本身若是 root（Linux 上常见），
#    "非 root"两条用例会被宿主身份顶掉（实测在 Linux/root 上 3 条断言失败）。
RP42ROOT="$D/root/t42_root"; RP42SUDO="$D/root/t42_sudo"; RP42NONE="$D/root/t42_none"
for r in "$RP42ROOT" "$RP42SUDO" "$RP42NONE"; do
  build_root "$r" ""
  printf '#!/bin/sh\necho Enforcing\n' > "$r/usr/sbin/getenforce"; chmod +x "$r/usr/sbin/getenforce"
done
fake_uid "$RP42ROOT" 0
fake_uid "$RP42SUDO" 1000
fake_uid "$RP42NONE" 1000
break_sudo "$RP42NONE"

expect "root（pct exec 形态）⇒ getenforce=Enforcing 判在位（rc=1）" \
  "$(run_probe EF-SELINUX "$RP42ROOT")" 1
expect "非 root + sudo -n 可用 ⇒ 与 root **同结论**（rc=1）" \
  "$(run_probe EF-SELINUX "$RP42SUDO")" 1
expect "非 root + 无可用提权 ⇒ 特权判据 rc=2（**不是** 0=缺失）" \
  "$(run_probe EF-SELINUX "$RP42NONE")" 2
expect "非 root + 无可用提权 ⇒ 另一条特权判据 EF-NO-SIEM 也 rc=2" \
  "$(run_probe EF-NO-SIEM "$RP42NONE")" 2
expect "privilege 留痕：root|sudo|unprivileged（第三格 = 无特权需求的判据不提权）" \
  "$(priv_of EF-SELINUX "$RP42ROOT")|$(priv_of EF-SELINUX "$RP42SUDO")|$(priv_of EF-SYNCOOKIE "$RP42SUDO")" \
  "root|sudo|unprivileged"
expect "无特权需求的判据（EF-SYNCOOKIE）在没有提权通道时仍照常给结论（rc=1）" \
  "$(run_probe EF-SYNCOOKIE "$RP42NONE")" 1
echo "  （T42 修正前的危害：非 root 读不到 getenforce / AppArmor profile / 仅 root 可读的告警配置 ⇒ 命令失败被读成 0=『防护缺失』）"

echo
echo "############ I-5：判据没跑到底 ⇒ 2（不是 0、也不是 1）"
expect "节点里判据什么都没输出（哨兵也没有）⇒ rc=2" "$(run_probe EF-NO-IDS "$R3" "$D/noisybin")" 2
echo "  （旧协议下这里会因为 bash 以 0 退出而被读成 rc=0 = 『防护缺失』）"

echo
echo "############ 未知因子 / 未声明目标 ⇒ 2"
expect "未知因子 EF-NOPE ⇒ rc=2" "$(run_probe EF-NOPE "$R3")" 2
(
  PATH="$D/bin:$PATH"; export PATH
  EDGEEXP_PROBE_ROOT="$R3"; export EDGEEXP_PROBE_ROOT
  # shellcheck source=/dev/null
  . "$PROBE" ""
  if probe_condition_holds EF-NO-IDS; then rc=0; else rc=$?; fi
  printf '  %-62s rc=%s\n' "未声明目标节点 ⇒ rc=2" "$rc"
) 2>/dev/null

echo
echo "############ M-10：调用方没开 set -e 时，函数返回后也不得打开它"
(
  PATH="$D/bin:$PATH"; export PATH
  EDGEEXP_PROBE_ROOT="$R3"; export EDGEEXP_PROBE_ROOT
  # shellcheck source=/dev/null
  . "$PROBE" probe-fixture
  before="$(case $- in *e*) echo on;; *) echo off;; esac)"
  if probe_condition_holds EF-NO-IDS; then :; fi
  after="$(case $- in *e*) echo on;; *) echo off;; esac)"
  printf '  set -e before=%s after=%s （期望都是 off）\n' "$before" "$after"
)

echo
echo "############ 夹具守卫：残缺的夹具根必须变成 2（而不是一个看似有效的结论）"
expect "夹具根里没有 /proc ⇒ rc=2（PROBE_FIXTURE_ROOT）" "$(run_probe EF-NO-IDS "$D/root/not-a-root")" 2
