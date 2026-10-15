#!/bin/bash
# test-edge-lab.sh —— 基质层（edge_lab.sh）的离线用例（Fix round 1 扩写）
#
# 覆盖：
#   A) clab 分支的命令序列 == 抽象前的原始命令（逐行 diff，**零差异**）
#   B) lxd 分支在假 lxc 上真的干活；lab_up/lab_down 响亮失败；只读（无 launch/delete/stop）
#   C) 非法基质名：带/不带 `set -e` 的调用方**都必须被中止**
#   D) I-1：`EDGEEXP_DOCKER_BIN` 覆盖在 clab 的**目标级**路径上必须生效（两个可分辨的假 docker）
#   E) M-3：`EDGEEXP_DOCKER_BIN` **不得**泄漏到拓扑级命令（lab_node_counts/lab_up 仍走 clab）
#   F) I-2：`lab_target_exec_detached` 两种基质下**节点内收到的 argv 逐条相同**
#
# 全程只读：不碰 clab、不碰 LXD、不碰任何容器；假 CLI 只是记录参数/执行本机命令的回显脚本。
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$TESTS_DIR/../../.." && pwd)}"
LIB="$REPO/lunwen/clab-lab/scripts/edge_lab.sh"
D="${T4D_LAB_TEST_DIR:-${HOME:-/home/clab}}/t4d-edge-lab-test"
rm -rf "$D"; mkdir -p "$D/bin" "$D/bin-exec" "$D/work" "$D/envbin" "$D/pathbin" "$D/marker"
PASS=0; FAIL=0
ok()   { echo "  ok   $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL $*"; FAIL=$((FAIL+1)); }

# --- 假 clab / docker / lxc：只记录参数（每行一次调用）-----------------------
for cli in clab docker lxc; do
  cat > "$D/bin/$cli" <<'SH'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$REPLAY_LOG"
case "$(basename "$0")" in
  clab)
    case "$1" in inspect) printf '%s' "${REPLAY_INSPECT_JSON:-{\}}" > "$LAB_TMP/edgeexp-clab-inspect.json" ;; esac ;;
  lxc)
    case "$1" in
      info) printf 'Name: probe-ot005\nStatus: %s\n' "${REPLAY_LXC_STATUS:-RUNNING}" ;;
      exec) printf 'hostname-from-node\n' ;;
      list) printf 'probe-ot005\n' ;;
    esac ;;
  docker)
    case "$1" in inspect) printf '%s\n' '{"State":{"Running":true}}' ;; esac ;;
esac
exit "${REPLAY_EXIT:-0}"
SH
  chmod +x "$D/bin/$cli"
done

# 两个**可分辨的**假 docker（D 段用）：各自往同一份日志写不同的名字 + 记录 argv。
cat > "$D/envbin/fake-docker" <<'SH'
#!/bin/sh
printf 'ENV-OVERRIDE-DOCKER argv=%s\n' "$*" >> "$REPLAY_LOG"
printf '{\n  "State": {"Running": true}\n}\n'
exit 0
SH
cat > "$D/pathbin/docker" <<'SH'
#!/bin/sh
printf 'PATH-DOCKER argv=%s\n' "$*" >> "$REPLAY_LOG"
printf '{\n  "State": {"Running": true}\n}\n'
exit 0
SH
chmod +x "$D/envbin/fake-docker" "$D/pathbin/docker"

TOPO="$REPO/lunwen/clab-lab/asscor.clab.yml"
export REPLAY_INSPECT_JSON='{"asc-asscor":[{"name":"asc-asscor-host1","state":"running"},{"name":"asc-asscor-host2","state":"exited"}]}'
export LAB_TMP="$D/work" REPLAY_LXC_STATUS=RUNNING

# ===========================================================================
# A) clab 分支：抽象前 vs 抽象后
# ===========================================================================
cat > "$D/before.sh" <<'SH'
#!/bin/bash
set -uo pipefail
TOPOLOGY="$REPLAY_TOPO"; L="$LAB_TMP"
echo "== counts"
clab inspect -t "$TOPOLOGY" --format json > "$L/edgeexp-clab-inspect.json" 2>>"$L/edgeexp-clab-inspect.log"
python3 - "$?" "$L/edgeexp-clab-inspect.json" <<'PY'
import json, sys
rc = int(sys.argv[1])
if rc != 0:
    print(-1, -1, -1); raise SystemExit
try:
    data = json.load(open(sys.argv[2]))
except Exception:
    print(-1, -1, -1); raise SystemExit
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
echo "== up";    clab deploy -t "$TOPOLOGY" || echo "  rc=$?"
echo "== down";  clab destroy -t "$TOPOLOGY" --cleanup || echo "  rc=$?"
echo "== exec";  docker exec asc-asscor-host1 bash -c "rm -f /tmp/sandcat /tmp/sandcat.log" || echo "  rc=$?"
echo "== detach";docker exec -d asc-asscor-host1 bash -c "/tmp/sandcat --server http://10.0.0.1:8888 > /tmp/sandcat.log 2>&1" || echo "  rc=$?"
echo "== push";  docker cp /opt/payload asc-asscor-host1:/tmp/sandcat || echo "  rc=$?"
echo "== ip";    docker exec asc-asscor-host1 ip -4 -o addr show eth0 2>/dev/null | awk '{print $4; exit}' || echo "  rc=$?"
echo "== running"; docker inspect -f '{{.State.Running}}' asc-asscor-host1 || echo "  rc=$?"
echo "== inspect"; docker inspect asc-asscor-host1 >/dev/null 2>&1 || echo "  rc=$?"
echo "== list";  docker ps -a --format '{{.Names}}' || echo "  rc=$?"
SH
cat > "$D/after.sh" <<'SH'
#!/bin/bash
set -uo pipefail
. "$LIB"
lab_topology="$REPLAY_TOPO"
echo "== counts"; lab_node_counts
echo "== up";    lab_up || echo "  rc=$?"
echo "== down";  lab_down || echo "  rc=$?"
echo "== exec";  lab_target_exec asc-asscor-host1 bash -c "rm -f /tmp/sandcat /tmp/sandcat.log" || echo "  rc=$?"
echo "== detach";lab_target_exec_detached asc-asscor-host1 bash -c "/tmp/sandcat --server http://10.0.0.1:8888 > /tmp/sandcat.log 2>&1" || echo "  rc=$?"
echo "== push";  lab_push /opt/payload asc-asscor-host1 /tmp/sandcat || echo "  rc=$?"
echo "== ip";    lab_node_ip asc-asscor-host1 eth0 || echo "  rc=$?"
echo "== running"; lab_node_running asc-asscor-host1 || echo "  rc=$?"
echo "== inspect"; lab_inspect asc-asscor-host1 >/dev/null 2>&1 || echo "  rc=$?"
echo "== list";  lab_list || echo "  rc=$?"
SH

export REPLAY_TOPO="$TOPO"
PATH="$D/bin:$PATH" REPLAY_LOG="$D/before.log" EDGEEXP_LAB_TMP="$D/work" bash "$D/before.sh" > "$D/before.out" 2>&1
PATH="$D/bin:$PATH" REPLAY_LOG="$D/after.log" EDGEEXP_LAB_TMP="$D/work" EDGEEXP_SUBSTRATE=clab LIB="$LIB" bash "$D/after.sh" > "$D/after.out" 2>&1
echo "############ A) clab 分支：命令序列与输出"
if diff -q "$D/before.log" "$D/after.log" >/dev/null; then
  ok "clab 调用的**命令序列逐行相同**（$(wc -l < "$D/after.log") 条）"
else
  fail "clab 命令序列不同："; diff -u "$D/before.log" "$D/after.log" | sed 's/^/     /'
fi
if diff -q "$D/before.out" "$D/after.out" >/dev/null; then
  ok "clab 分支的 stdout/stderr 逐行相同"
else
  fail "clab 分支输出不同："; diff -u "$D/before.out" "$D/after.out" | sed 's/^/     /'
fi
if grep -q '^docker exec asc-asscor-host1 ' "$D/after.log"; then ok "clab 基质送出裸容器名"; else fail "clab 基质没有送出裸容器名"; fi

# ===========================================================================
# B) lxd 分支（假 lxc）
# ===========================================================================
: > "$D/lxd.log"
cat > "$D/lxd.sh" <<'SH'
#!/bin/bash
set -uo pipefail
. "$LIB"
echo "== exec";      lab_target_exec probe-ot005 bash -c "rm -f /tmp/x" || echo "  rc=$?"
echo "== push";      lab_push /opt/payload probe-ot005 /tmp/sandcat || echo "  rc=$?"
echo "== ip";        lab_node_ip probe-ot005 eth0 || echo "  rc=$?"
echo "== running";   lab_node_running probe-ot005 || echo "  rc=$?"
echo "== inspect";   lab_inspect probe-ot005 >/dev/null 2>&1 || echo "  rc=$?"
echo "== list";      lab_list || echo "  rc=$?"
echo "== spec";      lab_target_spec probe-ot005 || echo "  rc=$?"
echo "== require";   lab_require_bins; echo "  require-rc=$?"
echo "== up";        lab_up; echo "  rc=$?"
echo "== down";      lab_down; echo "  rc=$?"
echo "== counts";    lab_node_counts; echo "  rc=$?"
SH
PATH="$D/bin:$PATH" REPLAY_LOG="$D/lxd.log" EDGEEXP_SUBSTRATE=lxd EDGEEXP_LXC_BIN=lxc LIB="$LIB" \
  bash "$D/lxd.sh" > "$D/lxd.out" 2>&1
echo "############ B) lxd 分支（假 lxc）"
if grep -q '^lxc exec probe-ot005 -- bash -c rm -f /tmp/x' "$D/lxd.log"; then
  ok "lxd exec 带 \`--\` 分隔符且命令在实例内执行"; else fail "lxd exec 形态不对"; cat "$D/lxd.log"; fi
if grep -q '^lxc file push /opt/payload probe-ot005/tmp/sandcat' "$D/lxd.log"; then
  ok "lxd file push 语法正确（<本地> <实例><目标路径>）"; else fail "lxd file push 形态不对"; fi
if grep -q '^lxc info probe-ot005' "$D/lxd.log"; then ok "lab_node_running 用 lxc info 判状态"; else fail "lab_node_running 没走 lxc info"; fi
if grep -q '^lxc exec probe-ot005 -- ip -4 -o addr show eth0' "$D/lxd.log"; then ok "lab_node_ip 在实例内取地址"; else fail "lab_node_ip 形态不对"; fi
UP_OUT="$(sed -n '/^== up/,/^== down/p' "$D/lxd.out")"
if printf '%s' "$UP_OUT" | grep -q 'rc=2' && printf '%s' "$UP_OUT" | grep -q '不适用'; then
  ok "lab_up 在 lxd 下响亮失败（rc=2 + 说明原因）"
else fail "lab_up 在 lxd 下没有响亮失败：$UP_OUT"; fi
DOWN_OUT="$(sed -n '/^== down/,/^== counts/p' "$D/lxd.out")"
if printf '%s' "$DOWN_OUT" | grep -q 'rc=2' && printf '%s' "$DOWN_OUT" | grep -q '不适用'; then
  ok "lab_down 在 lxd 下响亮失败（rc=2 + 说明原因）"
else fail "lab_down 在 lxd 下没有响亮失败：$DOWN_OUT"; fi
if grep -q '^lxc launch\|^lxc delete\|^lxc stop' "$D/lxd.log"; then
  fail "lxd 分支发出了会改变实例状态的命令（绝不允许）"; else ok "lxd 分支只读：无 launch/delete/stop"; fi
if printf '%s' "$(sed -n '/^== spec/,/^== require/p' "$D/lxd.out")" | grep -q 'lxd:probe-ot005'; then
  ok "lab_target_spec 在 lxd 下产出 lxd:probe-ot005"; else fail "lab_target_spec 在 lxd 下不对"; fi
if sed -n '/^== require/,/^== up/p' "$D/lxd.out" | grep -q 'require-rc=0'; then
  ok "lab_require_bins 在 lxd 下检查 lxc 并放行（PATH 上有假 lxc）"; else fail "lab_require_bins 在 lxd 下不对"; fi
COUNT_OUT="$(sed -n '/^== counts/,$p' "$D/lxd.out")"
if printf '%s' "$COUNT_OUT" | grep -q -- '-1 -1 -1'; then
  ok "lab_node_counts 在 lxd 下回显 -1 -1 -1（查不出来 ≠ 0 个节点）"; else fail "lab_node_counts 在 lxd 下不对：$COUNT_OUT"; fi

# ===========================================================================
# C) 非法基质名：带/不带 set -e 的调用方都必须被中止
# ===========================================================================
echo "############ C) 非法基质名（中止调用方）"
cat > "$D/badsub-e.sh" <<SH
set -euo pipefail
. "$LIB"
echo REACHED-AFTER-SOURCE
SH
cat > "$D/badsub-noe.sh" <<SH
# **故意不写 set -e**：修复前这条会让调用方继续跑下去（M-4）
. "$LIB"
echo REACHED-AFTER-SOURCE
SH
cat > "$D/goodsub.sh" <<SH
set -euo pipefail
. "$LIB"
echo "reached-lab_substrate=\$lab_substrate"
SH
for variant in badsub-e badsub-noe; do
  rc=0
  out="$(EDGEEXP_SUBSTRATE=clabb bash "$D/$variant.sh" 2>&1)" || rc=$?
  label="有 set -e"; [ "$variant" = badsub-noe ] && label="无 set -e"
  if [ "$rc" -ne 0 ] && ! printf '%s' "$out" | grep -q 'REACHED-AFTER-SOURCE' && printf '%s' "$out" | grep -q '只认 clab'; then
    ok "$variant（$label）⇒ 调用方被中止（rc=$rc）且没有走到下一句"
  else
    fail "$variant（$label）没有被中止：rc=$rc out=$out"
  fi
done
rc=0
out="$(EDGEEXP_SUBSTRATE=lxd bash "$D/goodsub.sh" 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'reached-lab_substrate=lxd'; then
  ok "合法基质名 lxd ⇒ source 正常通过（对照组）"
else fail "合法基质名被误拦：rc=$rc out=$out"; fi

# ===========================================================================
# D) I-1：EDGEEXP_DOCKER_BIN 覆盖在 clab 的**目标级**路径上必须生效
# ===========================================================================
echo "############ D) I-1：EDGEEXP_DOCKER_BIN 覆盖（两个可分辨的假 docker）"
cat > "$D/override.sh" <<'SH'
set -euo pipefail
. "$LIB"
echo "lab_target_bin=$lab_target_bin"
lab_target_exec n1 hostname >/dev/null 2>&1 || true
lab_inspect n1 >/dev/null 2>&1 || true
SH
: > "$D/override.log"
# PATH 最前面放**另一个**假 docker（PATH-DOCKER）；覆盖值指向 envbin 里的假 docker
# （ENV-OVERRIDE-DOCKER）—— 日志里出现哪一个，就是"到底调了哪个"。
PATH="$D/pathbin:$D/bin:/usr/bin:/bin" REPLAY_LOG="$D/override.log" \
  EDGEEXP_DOCKER_BIN="$D/envbin/fake-docker" LIB="$LIB" \
  bash "$D/override.sh" > "$D/override.out" 2>&1
if grep -q '^ENV-OVERRIDE-DOCKER argv=' "$D/override.log" && ! grep -q '^PATH-DOCKER argv=' "$D/override.log"; then
  ok "目标级路径用的是 EDGEEXP_DOCKER_BIN 指定的那个二进制（抽象前的效力被保留）"
else
  fail "覆盖失效：调用日志 = $(tr '\n' ';' < "$D/override.log")"
fi

# ===========================================================================
# E) M-3：覆盖值不得泄漏到**拓扑级**命令
# ===========================================================================
echo "############ E) M-3：EDGEEXP_DOCKER_BIN 不泄漏到拓扑级命令"
: > "$D/leak.log"
cat > "$D/leak.sh" <<'SH'
set -euo pipefail
. "$LIB"
lab_node_counts >/dev/null 2>&1 || true
lab_up >/dev/null 2>&1 || true
SH
PATH="$D/pathbin:$D/bin:/usr/bin:/bin" REPLAY_LOG="$D/leak.log" \
  EDGEEXP_DOCKER_BIN="$D/envbin/fake-docker" LAB_TMP="$D/work" \
  EDGEEXP_LAB_TMP="$D/work" LIB="$LIB" \
  bash "$D/leak.sh" > "$D/leak.out" 2>&1
if grep -q '^clab inspect -t ' "$D/leak.log" && grep -q '^clab deploy -t ' "$D/leak.log" \
   && ! grep -q 'DOCKER argv=inspect -t\|DOCKER argv=deploy -t' "$D/leak.log"; then
  ok "拓扑级命令仍走 clab（覆盖值没有把它带偏成 docker inspect -t / docker deploy）"
else
  fail "拓扑级命令被带偏：调用日志 = $(tr '\n' ';' < "$D/leak.log")"
fi

# ===========================================================================
# F) I-2：detached 两种基质下**节点内收到的 argv 逐条相同**
# ===========================================================================
echo "############ F) I-2：lab_target_exec_detached 的 argv 保真"
# 假 docker/lxc 把 exec 之后的 <cmd…> **在本机原样执行**（不后台化：夹具要的是"命令有没有
# 按 argv 跑到"这个判据，后台化只会让判据变成"进程有没有被拉起来"），于是"节点内到底收到了
# 什么 argv"可以直接观测 —— 评审就是用这个手法复现 I-2 的（lxd 侧 marker 为空 / 参数丢了）。
cat > "$D/bin-exec/docker" <<'SH'
#!/bin/bash
shift 2                      # 去掉 `exec -d`：剩下的第一个参数是节点名，`$@` 是节点内的命令
shift                        # <节点名>
REPLAY_LOG="$REPLAY_LOG" "$@"
exit $?
SH
cat > "$D/bin-exec/lxc" <<'SH'
#!/bin/bash
# lxd 形状：`exec <实例> -- sh -c '<脚本>' <$0> <argv…>`；这里把那段脚本**原样执行**，
# 于是它收到的 argv 就是节点内真正收到的 argv。
shift                        # exec
shift                        # <实例>
[ "${1:-}" = "--" ] && shift
[ "${1:-}" = "sh" ] && shift
[ "${1:-}" = "-c" ] && shift
script="$1"; shift           # <脚本>
[ $# -gt 0 ] && shift        # <$0>（占位，脚本用不到）
REPLAY_LOG="$REPLAY_LOG" sh -c "$script" _ "$@"
exit $?
SH
chmod +x "$D/bin-exec"/*
# `wait_marker <路径> <期望内容>`：脱离进程是**后台**跑的，写文件要等一小会儿 —— 判据必须是
# "在合理窗口内出现"，不是"调用点刚返回就已经在"（后者会让夹具变成一次竞态：本夹具实测出现过
# 一次假红）。窗口 3 s 远大于后台 `sh` 的启动开销，也不足以掩盖"命令根本没跑"。
wait_marker() {
  local path="$1" want="$2" i=0
  while [ "$i" -lt 30 ]; do
    if [ -f "$path" ] && [ "$(cat "$path")" = "$want" ]; then return 0; fi
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}
for sub in clab lxd; do
  rm -f "$D/marker/$sub.txt"
  PATH="$D/bin-exec:/usr/bin:/bin" REPLAY_LOG="$D/detached-$sub.log" LAB_TMP="$D/work" \
    EDGEEXP_SUBSTRATE="$sub" EDGEEXP_LXC_BIN="$D/bin-exec/lxc" LIB="$LIB" \
    bash -c '. "$LIB"; lab_target_exec_detached n1 /bin/sh -c "printf RAN-'$sub' > '"$D"'/marker/'$sub'.txt"' \
    > "$D/detached-$sub.out" 2>&1
done
for sub in clab lxd; do
  if wait_marker "$D/marker/$sub.txt" "RAN-$sub"; then
    ok "detached（$sub）：节点内命令按 argv 跑起来了（marker=RAN-$sub）"
  else
    fail "detached（$sub）：节点内命令没有按 argv 跑（marker=$([ -f "$D/marker/$sub.txt" ] && cat "$D/marker/$sub.txt" || echo 不存在)｜stderr=$(tr '\n' ';' < "$D/detached-$sub.out"))"
  fi
done
# 与 edge_reset.sh:267 的真实形状（sandcat `--server http://…`）同形的那一条：
# 调用点传的是 `bash -c "<命令串含重定向>"`，节点内 `bash -c` 必须**收到那一整条命令串**。
for sub in clab lxd; do
  rm -f "$D/marker/sandcat-$sub.log"
  PATH="$D/bin-exec:/usr/bin:/bin" REPLAY_LOG="$D/detached2-$sub.log" LAB_TMP="$D/work" \
    EDGEEXP_SUBSTRATE="$sub" EDGEEXP_LXC_BIN="$D/bin-exec/lxc" LIB="$LIB" \
    bash -c '. "$LIB"; lab_target_exec_detached n1 bash -c "echo SANDCAT-STARTED argv=--server http://10.217.208.1:8888 > '"$D"'/marker/sandcat-'$sub'.log 2>&1"' \
    > "$D/detached2-$sub.out" 2>&1
done
for sub in clab lxd; do
  i=0; ready=1
  while [ "$i" -lt 30 ]; do
    if grep -q 'argv=--server http://10.217.208.1:8888' "$D/marker/sandcat-$sub.log" 2>/dev/null; then ready=0; break; fi
    sleep 0.1
    i=$((i + 1))
  done
  if [ "$ready" -eq 0 ]; then
    ok "detached（$sub）：与 edge_reset.sh 同形的调用把整条命令串送达节点内（URL 没丢）"
  else
    fail "detached（$sub）：命令串没送达（sandcat log = $([ -f "$D/marker/sandcat-$sub.log" ] && cat "$D/marker/sandcat-$sub.log" || echo 不存在)｜stderr=$(tr '\n' ';' < "$D/detached2-$sub.out"))"
  fi
done

# ===========================================================================
# G) Fix round 2 / Minor-6①：**STOPPED 的实例绝不能被读成"已就绪"**
# ===========================================================================
#
# 这条钉的是 Step 4-B2 实测到的那个缺陷（缺陷 3）：`lab_node_running` 的取值打在 **stdout**
# （`true`/`false`），rc 只表达"问得到/问不到"；调用方写成
# `until lab_node_running "$node" >/dev/null 2>&1; do …` 就把**值**丢掉了 ——
# 而 **STOPPED 的实例同样能应答**（`lxc info` 照常返回），于是循环 **0 秒就认为"已就绪"**。
# 后果：`lxc restart` 之后的第一次 `exec` 落在停/起之间（`Error: Instance is not running`），
# 而调用方没有 `set -e` ⇒ 那行错被咽下去，整轮以"agent 180s 没回连"收场。
#
# 判据三格（缺一格就证不出"旧写法坏、新写法好"）：
#   G1 假 lxc 报 STOPPED ⇒ `lab_node_running` 必须回 `false`（rc=0）；
#   G2 **旧写法**（`until … >/dev/null 2>&1`）在同一状态下 **0 轮就通过** —— 这是"旧写法的坏"的正面证据；
#   G3 **新写法**（`lab_wait_node_exec`）在同一状态下必须**判不就绪**（rc≠0），
#      而在 RUNNING + exec 可用的状态下必须判就绪。
echo "############ G) lxd 就绪判据：STOPPED 不得被读成就绪（Minor-6①）"
mkdir -p "$D/bin-stopped" "$D/bin-running"
mk_fake_lxc() { # mk_fake_lxc <目录> <状态> <节点内命令的行为>
  cat > "$1/lxc" <<SH
#!/bin/sh
case "\$1" in
  info) printf 'Name: asc-tgt-1\nStatus: $2\n' ;;
  exec) $3 ;;
esac
exit 0
SH
  chmod +x "$1/lxc"
}
mk_fake_lxc "$D/bin-stopped" STOPPED 'exit 1'          # 实例没在跑 ⇒ 节点内命令必失败
mk_fake_lxc "$D/bin-running" RUNNING 'printf "ok\n"'

cat > "$D/ready-probe.sh" <<'SH'
#!/bin/bash
# 只打印判据结果（不打印别的），供上方夹具解析。
set -uo pipefail
. "$LIB"
echo "node_running=[$(lab_node_running asc-tgt-1 2>/dev/null)]"
# 旧写法（缺陷 3 的原形）：把 stdout 丢掉 —— 循环体一次都没进就"就绪"。
loops=0
until lab_node_running asc-tgt-1 >/dev/null 2>&1; do
  loops=$((loops + 1))
  [ "$loops" -ge 5 ] && break
  sleep 0.1
done
echo "old_loop_iterations=$loops"
if lab_wait_node_exec asc-tgt-1 1; then echo "new_wait=ready"; else echo "new_wait=not-ready"; fi
SH
for st in stopped running; do
  PATH="$D/bin-$st:$PATH" EDGEEXP_SUBSTRATE=lxd EDGEEXP_LXC_BIN="$D/bin-$st/lxc" \
    EDGEEXP_LAB_WAIT_STEP=1 LIB="$LIB" bash "$D/ready-probe.sh" > "$D/ready-$st.out" 2>&1
done
STOP_OUT="$(cat "$D/ready-stopped.out")"
RUN_OUT="$(cat "$D/ready-running.out")"
if printf '%s' "$STOP_OUT" | grep -q 'node_running=\[false\]'; then
  ok "G1 STOPPED ⇒ lab_node_running 回 false（rc=0；判据在 stdout 上）"
else fail "G1 lab_node_running 对 STOPPED 的取值不对：$STOP_OUT"; fi
if printf '%s' "$STOP_OUT" | grep -q 'old_loop_iterations=0'; then
  ok "G2 **旧写法**在同一状态下 0 轮就通过（缺陷 3 的正面证据：值被 >/dev/null 丢掉）"
else fail "G2 旧写法没有复现出『0 轮通过』：$STOP_OUT"; fi
if printf '%s' "$STOP_OUT" | grep -q 'new_wait=not-ready'; then
  ok "G3 STOPPED ⇒ lab_wait_node_exec 判**不就绪**（rc≠0）"
else fail "G3 lab_wait_node_exec 把 STOPPED 判成就绪了：$STOP_OUT"; fi
if printf '%s' "$RUN_OUT" | grep -q 'new_wait=ready'; then
  ok "G3 对照组 RUNNING + exec 可用 ⇒ lab_wait_node_exec 判就绪"
else fail "G3 对照组没有判就绪：$RUN_OUT"; fi

# ===========================================================================
# H) pve 分支（Task 6）：假 pct 上的命令形状、名字→vmid、负向与不顶替
# ===========================================================================
#
# 这一段的判据与 B 段（lxd）**逐项对应**，但多了两件 pve 专属的事：
#   · 节点是**名字**（`asc-tgt-c2`）而 `pct` 要 **VMID**（`904`）⇒ 每条命令都必须是
#     `pct … 904 …`，**名字一个字节都不许进 pct 的参数位**（否则 pct 会以一个不存在的
#     vmid 失败，而错误指向"CT 不存在"，真正的原因只是少了一层解析）；
#   · **绝不猜 vmid**：名字解析不到、或解析到多个，都必须响亮失败，且**一次 pct 都没起过**。
#
# 假 pct 的 `list` 刻意给出**两种列宽**：`Lock` 为空时整行塌成三格、非空时四格 ——
# 解析若写死列号（$2/$3），塌陷的那一行会解析错（实测 `pct list` 就是这两种形态混排）。
echo "############ H) pve 分支（假 pct）"
mkdir -p "$D/bin-pve"
cat > "$D/bin-pve/pct" <<'SH'
#!/bin/sh
printf 'pct %s\n' "$*" >> "$REPLAY_LOG"
case "$1" in
  list)
    printf 'VMID       Status     Lock         Name\n'
    printf '904        running                 asc-tgt-c2\n'
    printf '905        stopped    snapshot    asc-locked\n'
    ;;
  status) printf 'status: %s\n' "${REPLAY_PCT_STATUS:-running}" ;;
  config) printf 'arch: amd64\nhostname: asc-tgt-c2\n' ;;
  exec)   printf 'hostname-from-ct\n' ;;
  push)   : ;;
esac
exit "${REPLAY_EXIT:-0}"
SH
chmod +x "$D/bin-pve/pct"

cat > "$D/pve.sh" <<'SH'
#!/bin/bash
set -uo pipefail
. "$LIB"
echo "== exec";     lab_target_exec asc-tgt-c2 bash -c "rm -f /tmp/x" || echo "  rc=$?"
echo "== push";     lab_push /opt/payload asc-tgt-c2 /tmp/sandcat || echo "  rc=$?"
echo "== ip";       lab_node_ip asc-tgt-c2 eth0 || echo "  rc=$?"
echo "== pids";     lab_node_pids asc-tgt-c2 sandcat || echo "  rc=$?"
echo "== running";  lab_node_running asc-tgt-c2 || echo "  rc=$?"
echo "== exists";   lab_instance_exists asc-tgt-c2; echo "  rc=$?"
echo "== inspect";  lab_inspect asc-tgt-c2 >/dev/null 2>&1; echo "  rc=$?"
echo "== list";     lab_list || echo "  rc=$?"
echo "== spec";     lab_target_spec asc-tgt-c2 || echo "  rc=$?"
echo "== spec-lock"; lab_target_spec asc-locked || echo "  rc=$?"
echo "== require";  lab_require_bins; echo "  require-rc=$?"
echo "== up";       lab_up; echo "  rc=$?"
echo "== down";     lab_down; echo "  rc=$?"
echo "== counts";   lab_node_counts; echo "  rc=$?"
SH
PVE_LOG="$D/pve.log"; : > "$PVE_LOG"
# PATH 上**同时**有假 docker/lxc/clab（$D/bin）与假 pct（$D/bin-pve）⇒ 日志里出现哪一种，
# 就是"命令实际发给了谁"。「绝不静默回落」在基质维度上的形态就是"只该出现 pct"。
PATH="$D/bin-pve:$D/bin:$PATH" REPLAY_LOG="$PVE_LOG" EDGEEXP_SUBSTRATE=pve EDGEEXP_PCT_BIN=pct \
  LAB_TMP="$D/work" EDGEEXP_LAB_TMP="$D/work" LIB="$LIB" \
  bash "$D/pve.sh" > "$D/pve.out" 2>&1

if grep -q '^pct exec 904 -- bash -c rm -f /tmp/x' "$PVE_LOG"; then
  ok "pve exec 带 \`--\` 分隔符、且送出去的是**解析后的 vmid**（904）"; else fail "pve exec 形态不对"; cat "$PVE_LOG"; fi
if grep -q '^pct exec 904 -- ps -eo pid,comm --no-headers' "$PVE_LOG"; then
  ok "pve lab_node_pids 在 CT 内取进程表"; else fail "pve lab_node_pids 形态不对"; fi
if grep -q '^pct exec 904 -- ip -4 -o addr show eth0' "$PVE_LOG"; then
  ok "pve lab_node_ip 在 CT 内取地址"; else fail "pve lab_node_ip 形态不对"; fi
if grep -q '^pct push 904 /opt/payload /tmp/sandcat --perms 755' "$PVE_LOG"; then
  ok "pve push 语法正确（\`pct push <vmid> <本地> <目标> --perms 755\`，注意与 lxc 的参数顺序相反）"
else fail "pve push 形态不对"; fi
if grep -q '^pct status 904' "$PVE_LOG"; then
  ok "lab_node_running 用 \`pct status <vmid>\` 判状态"; else fail "lab_node_running 没走 pct status"; fi
if grep -q '^pct config 904' "$PVE_LOG"; then
  ok "lab_inspect 用 \`pct config <vmid>\` 取基质视图"; else fail "lab_inspect 没走 pct config"; fi
# **名字绝不许进 pct 的参数位**：`pct exec asc-tgt-c2` / `pct push asc-tgt-c2` 一次都不许有。
if grep -qE '^pct (exec|push|status|config) asc-' "$PVE_LOG"; then
  fail "名字被直接交给了 pct（应当是解析后的 vmid）：$(grep -E '^pct (exec|push|status|config) asc-' "$PVE_LOG" | head -3)"
else ok "所有 pct 命令用的都是**解析后的 vmid**，名字一个字节都没进参数位"; fi
if grep -qE '^(docker|lxc|clab) ' "$PVE_LOG"; then
  fail "pve 路径起了别的基质的 CLI（基质选错/静默回落的形态）：$(grep -E '^(docker|lxc|clab) ' "$PVE_LOG" | head -3)"
else ok "pve 路径**只**起 pct：docker / lxc / clab 一次都没被调用（绝不静默回落）"; fi

PVE_OUT="$(cat "$D/pve.out")"
# `lab_target_spec` 的取值打在**它自己那一行**上（调用点在 `== spec` 与 `== spec-lock` 之间），
# 故用 sed 范围取那一段再比对 —— 直接 grep 整份输出会把别的段落的 `pve:` 也算进来。
if printf '%s' "$PVE_OUT" | sed -n '/^== spec$/,/^== spec-lock$/p' | grep -qx 'pve:904'; then
  ok "lab_target_spec 产出 pve:<vmid>（asc-tgt-c2 ⇒ pve:904）"
else fail "lab_target_spec 不对：$(printf '%s' "$PVE_OUT" | sed -n '/^== spec$/,/^== spec-lock$/p')"; fi
if printf '%s' "$PVE_OUT" | sed -n '/^== spec-lock$/,/^== require$/p' | grep -qx 'pve:905'; then
  ok "lab_target_spec 对 **Lock 非空**（四列）的那一行同样解析正确（asc-locked ⇒ pve:905）"
else fail "四列形态解析错（列位置被写死？）：$(printf '%s' "$PVE_OUT" | sed -n '/^== spec-lock$/,/^== require$/p')"; fi
if printf '%s' "$PVE_OUT" | sed -n '/^== list/,/^== spec/p' | grep -q 'asc-locked' \
   && ! printf '%s' "$PVE_OUT" | sed -n '/^== list/,/^== spec/p' | grep -qE '^(VMID|904|905)' ; then
  ok "lab_list 产出的是**名字**（每行一个，含 Lock 非空的那一行），不是 pct 的四列原表"
else fail "lab_list 契约不对（应当是每行一个名字）：$PVE_OUT"; fi
if printf '%s' "$PVE_OUT" | grep -qE '^== running$' && printf '%s' "$PVE_OUT" | sed -n '/^== running/,/^== exists/p' | grep -q 'true'; then
  ok "lab_node_running 从 \`status: running\` 取到 true"; else fail "lab_node_running 取值不对：$PVE_OUT"; fi
if printf '%s' "$PVE_OUT" | sed -n '/^== require/,/^== up/p' | grep -q 'require-rc=0'; then
  ok "lab_require_bins 在 pve 下检查 pct 并放行（PATH 上有假 pct）"; else fail "lab_require_bins 在 pve 下不对"; fi
if printf '%s' "$PVE_OUT" | sed -n '/^== up/,/^== down/p' | grep -q 'rc=2' \
   && printf '%s' "$PVE_OUT" | sed -n '/^== up/,/^== down/p' | grep -q '不适用'; then
  ok "lab_up 在 pve 下响亮失败（rc=2 + 说明原因，与 lxd 同处置）"
else fail "lab_up 在 pve 下没有响亮失败：$PVE_OUT"; fi
if printf '%s' "$PVE_OUT" | sed -n '/^== down/,/^== counts/p' | grep -q 'rc=2' \
   && printf '%s' "$PVE_OUT" | sed -n '/^== down/,/^== counts/p' | grep -q '不适用'; then
  ok "lab_down 在 pve 下响亮失败（rc=2 + 说明原因，与 lxd 同处置）"
else fail "lab_down 在 pve 下没有响亮失败：$PVE_OUT"; fi
if printf '%s' "$PVE_OUT" | sed -n '/^== counts/,$p' | grep -q -- '-1 -1 -1'; then
  ok "lab_node_counts 在 pve 下回显 -1 -1 -1（查不出来 ≠ 0 个节点）"; else fail "lab_node_counts 在 pve 下不对"; fi
# **只读**：本层永不 create/destroy/start/stop 任何 CT。
if grep -qE '^pct (create|destroy|start|stop|shutdown|reboot|del) ' "$PVE_LOG"; then
  fail "pve 分支发出了会改变 CT 状态的命令（绝不允许）：$(grep -E '^pct (create|destroy|start|stop|shutdown|reboot|del) ' "$PVE_LOG")"
else ok "pve 分支只读：无 create/destroy/start/stop/shutdown"; fi

# --- H-负向 1：名字解析不到 ⇒ 响亮失败，且**一次 pct 都没起过**（绝不猜 vmid）--------
: > "$D/pve-neg.log"
NEG_OUT="$(PATH="$D/bin-pve:$D/bin:$PATH" REPLAY_LOG="$D/pve-neg.log" EDGEEXP_SUBSTRATE=pve \
  EDGEEXP_PCT_BIN=pct LIB="$LIB" bash -c \
  '. "$LIB"; lab_target_exec no-such-node-xyz hostname; echo "rc=$?"' 2>&1)"
if printf '%s' "$NEG_OUT" | grep -q 'rc=1' && printf '%s' "$NEG_OUT" | grep -q '找不到名字为'; then
  ok "名字解析不到 ⇒ lab_target_exec 响亮失败（rc=1 + 说明原因）"
else fail "名字解析不到的处置不对：$NEG_OUT"; fi
if grep -qE '^pct (exec|push|status|config) ' "$D/pve-neg.log"; then
  fail "解析失败后**仍然**起了 pct（说明它猜了一个 vmid）：$(cat "$D/pve-neg.log")"
else ok "解析失败时**一次 pct 命令都没起**（绝不猜一个 vmid —— 猜错会作用到别人的 CT 上）"; fi
NEG_SPEC="$(PATH="$D/bin-pve:$D/bin:$PATH" REPLAY_LOG="$D/pve-neg.log" EDGEEXP_SUBSTRATE=pve \
  EDGEEXP_PCT_BIN=pct LIB="$LIB" bash -c \
  '. "$LIB"; v="$(lab_target_spec no-such-node-xyz)"; rc=$?; printf "spec=[%s]\n" "$v"; echo "rc=$rc"' 2>&1)"
if printf '%s' "$NEG_SPEC" | grep -q 'spec=\[\]' && printf '%s' "$NEG_SPEC" | grep -q '^rc=1$'; then
  ok "lab_target_spec 对解析不到的名字回**空串 + rc=1**（不产出 pve:<猜的 vmid>）"
else fail "lab_target_spec 对解析不到的名字处置不对：$NEG_SPEC"; fi

# --- H-负向 2：**重名**同样必须失败（取第一个 = 一次静默的任意选择）------------------
mkdir -p "$D/bin-dupname"
cat > "$D/bin-dupname/pct" <<'SH'
#!/bin/sh
[ "$1" = "list" ] && printf 'VMID       Status     Lock         Name\n904        running                 asc-tgt-c2\n905        running                 asc-tgt-c2\n'
exit 0
SH
chmod +x "$D/bin-dupname/pct"
DUP_OUT="$(PATH="$D/bin-dupname:$PATH" EDGEEXP_SUBSTRATE=pve EDGEEXP_PCT_BIN=pct LIB="$LIB" \
  bash -c '. "$LIB"; lab_node_vmid asc-tgt-c2; echo "rc=$?"' 2>&1)"
if printf '%s' "$DUP_OUT" | grep -q 'rc=1' && printf '%s' "$DUP_OUT" | grep -q '匹配到 2 个 VMID'; then
  ok "名字匹配到**多个** vmid ⇒ 同样响亮失败（不取第一个）"
else fail "重名的处置不对：$DUP_OUT"; fi

# --- H-负向 3：STOPPED 的 CT 必须回 false（判据打在 stdout 上）------------------------
STOPPED_OUT="$(PATH="$D/bin-pve:$D/bin:$PATH" REPLAY_LOG="$D/pve-stopped.log" REPLAY_PCT_STATUS=stopped \
  EDGEEXP_SUBSTRATE=pve EDGEEXP_PCT_BIN=pct LIB="$LIB" bash -c \
  '. "$LIB"; printf "running=[%s]\n" "$(lab_node_running asc-tgt-c2)"; echo "rc=$?"' 2>&1)"
if printf '%s' "$STOPPED_OUT" | grep -q 'running=\[false\]'; then
  ok "STOPPED 的 CT ⇒ lab_node_running 回 false（rc=0；与 lxd 侧同一条纪律）"
else fail "STOPPED 的取值不对：$STOPPED_OUT"; fi

# --- H-F) detached 的 argv 保真（与 F 段同手法，换到 pve 形状）-------------------------
mkdir -p "$D/bin-exec-pve"
cat > "$D/bin-exec-pve/pct" <<'SH'
#!/bin/bash
# pve 形状：`pct exec <vmid> -- <cmd…>`（先经过一次 `pct list` 做名字解析）。
if [ "${1:-}" = "list" ]; then
  printf 'VMID       Status     Lock         Name\n904        running                 asc-tgt-c2\n'
  exit 0
fi
shift                        # exec
shift                        # <vmid>
[ "${1:-}" = "--" ] && shift
REPLAY_LOG="$REPLAY_LOG" "$@"
exit $?
SH
chmod +x "$D/bin-exec-pve/pct"
rm -f "$D/marker/pve.txt"
PATH="$D/bin-exec-pve:/usr/bin:/bin" REPLAY_LOG="$D/detached-pve.log" EDGEEXP_SUBSTRATE=pve \
  EDGEEXP_PCT_BIN=pct LIB="$LIB" bash -c \
  '. "$LIB"; lab_target_exec_detached asc-tgt-c2 /bin/sh -c "printf RAN-pve > '"$D"'/marker/pve.txt"' \
  > "$D/detached-pve.out" 2>&1
if wait_marker "$D/marker/pve.txt" "RAN-pve"; then
  ok "detached（pve）：脱离命令按 argv 在节点内跑起来了（marker=RAN-pve）"
else
  fail "detached（pve）：命令没有按 argv 跑（marker=$([ -f "$D/marker/pve.txt" ] && cat "$D/marker/pve.txt" || echo 不存在)｜stderr=$(tr '\n' ';' < "$D/detached-pve.out"))"
fi
rm -f "$D/marker/sandcat-pve.log"
PATH="$D/bin-exec-pve:/usr/bin:/bin" REPLAY_LOG="$D/detached2-pve.log" EDGEEXP_SUBSTRATE=pve \
  EDGEEXP_PCT_BIN=pct LIB="$LIB" bash -c \
  '. "$LIB"; lab_target_exec_detached asc-tgt-c2 bash -c "echo SANDCAT-STARTED argv=--server http://192.168.30.2:8888 > '"$D"'/marker/sandcat-pve.log 2>&1"' \
  > "$D/detached2-pve.out" 2>&1
i=0; ready=1
while [ "$i" -lt 30 ]; do
  if grep -q 'argv=--server http://192.168.30.2:8888' "$D/marker/sandcat-pve.log" 2>/dev/null; then ready=0; break; fi
  sleep 0.1; i=$((i + 1))
done
if [ "$ready" -eq 0 ]; then
  ok "detached（pve）：与 edge_reset.sh 同形的调用把**整条命令串**送达节点内（URL 没丢）"
else
  fail "detached（pve）：命令串没送达（sandcat log = $([ -f "$D/marker/sandcat-pve.log" ] && cat "$D/marker/sandcat-pve.log" || echo 不存在)｜stderr=$(tr '\n' ';' < "$D/detached2-pve.out"))"
fi

# --- H) 非法基质名：pve 也必须是**白名单内**的合法值（对照组）--------------------------
cat > "$D/goodsub-pve.sh" <<SH
set -euo pipefail
. "$LIB"
echo "reached-lab_substrate=\$lab_substrate"
SH
rc=0
out="$(EDGEEXP_SUBSTRATE=pve bash "$D/goodsub-pve.sh" 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'reached-lab_substrate=pve'; then
  ok "合法基质名 pve ⇒ source 正常通过（对照组；非法值仍被 C 段钉住）"
else fail "pve 被误拦：rc=$rc out=$out"; fi

# ============================================================================
# I) qemu 分支（Task 13：QEMU/KVM VM = 方向② 的**生产**基质）
# ============================================================================
#
# 与 H) pve 段**同手法**：假 `qm` 记调用、假 `ssh`/`scp` 记账，判据全部打在"命令发给了谁、
# 发出去的 argv 长什么样"上。三条本段独有的纪律（VM 基质与 CT 基质的**结构性差别**）：
#   1. **取数走 ssh/scp**（前三套基质是 docker/lxc/pct）—— 而 qemu 的**实例视图**仍走 `qm`：
#      两级是**两个不同的二进制**，故 `lab_require_bins` 必须三项都查。
#   2. **`lab_up`/`lab_down` 照旧 rc=2**，但理由不同（不是"怕碰别人的"，而是建机/清机有
#      **单一来源** `edge_vm_provision.sh`）—— 判据是错误串里必须**点名**那个脚本。
#   3. **`lab_node_ssh_host` 是唯一的"节点标识 → SSH 主机"解析点**，默认规则 `asc-vm<vmid>`
#      必须与 provisioning 写进 `/etc/hosts` 的名字**同源**；`EDGEEXP_VM_SSH_HOST` 含 `%s`
#      时按节点标识展开（多机就靠这条）。
echo "############ I) qemu 分支（假 qm + 假 ssh/scp）"
mkdir -p "$D/bin-qemu"
cat > "$D/bin-qemu/qm" <<'SH'
#!/bin/sh
# ⚠️ 日志里带 **`[invoke] ` 前缀**（Task 16 修的一处夹具缺陷）：不加前缀时，这个日志同时装了
# "真被调用的命令"与**脚本自己 echo 出来的帮助文本** —— 而后者恰恰包含字面量
# `qm destroy --purge`（`edge_lab.sh` 的 `lab_down` 在说明"本层永不销毁 VM"时会把它写出来）。
# 于是 I 段那条"qemu 分支发出了会改变 VM 状态的命令"会把**帮助文本**当成**命令**，
# 报出一条**假红**（`FAIL … 绝不允许）：qm destroy --purge`）。而那条判据本该在
# "代码真的去 destroy 了"时才红 —— 假红与真红的区别，在这里就是"命令"与"说明"的区别。
# 加了前缀之后，所有针对本日志的判据点名的都是**真被调用过的** `qm …`。
printf '[invoke] qm %s\n' "$*" >> "$REPLAY_LOG"
case "$1" in
  list)
    printf 'VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID\n'
    printf '910  asc-vm910            running    2048               8.00 12345\n'
    printf '911  asc-vm911            stopped    2048               8.00 0\n'
    ;;
  status) printf 'status: %s\n' "${REPLAY_QM_STATUS:-running}" ;;
  config) printf 'arch: amd64\nname: asc-vm910\nmemory: 2048\nballoon: 512\nnet0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1\n' ;;
esac
exit "${REPLAY_EXIT:-0}"
SH
cat > "$D/bin-qemu/ssh" <<'SH'
#!/bin/sh
printf 'ssh %s\n' "$*" >> "$REPLAY_SSH_LOG"
printf 'hostname-from-vm\n'
SH
cat > "$D/bin-qemu/scp" <<'SH'
#!/bin/sh
printf 'scp %s\n' "$*" >> "$REPLAY_SCP_LOG"
SH
chmod +x "$D/bin-qemu/qm" "$D/bin-qemu/ssh" "$D/bin-qemu/scp"

cat > "$D/qemu.sh" <<'SH'
#!/bin/bash
set -uo pipefail
. "$LIB"
echo "== exec";     lab_target_exec 910 bash -c "rm -f /tmp/x" || echo "  rc=$?"
echo "== push";     lab_push /opt/payload 910 /tmp/sandcat || echo "  rc=$?"
echo "== ip";       lab_node_ip 910 eth0 || echo "  rc=$?"
echo "== pids";     lab_node_pids 910 sandcat || echo "  rc=$?"
echo "== running";  lab_node_running 910 || echo "  rc=$?"
echo "== exists";   lab_instance_exists 910; echo "  rc=$?"
echo "== inspect";  lab_inspect 910 >/dev/null 2>&1; echo "  rc=$?"
echo "== list";     lab_list || echo "  rc=$?"
echo "== spec";     lab_target_spec 910 || echo "  rc=$?"
echo "== specname"; lab_target_spec asc-vm911 || echo "  rc=$?"
echo "== sshhost";  lab_node_ssh_host 911 || echo "  rc=$?"
echo "== require";  lab_require_bins; echo "  require-rc=$?"
echo "== up";       lab_up; echo "  rc=$?"
echo "== down";     lab_down; echo "  rc=$?"
echo "== counts";   lab_node_counts; echo "  rc=$?"
SH
QMU_LOG="$D/qemu.log"; SSH_LOG="$D/qemu-ssh.log"; SCP_LOG="$D/qemu-scp.log"
: > "$QMU_LOG"; : > "$SSH_LOG"; : > "$SCP_LOG"
# 连接参数是**具名四个变量**决定的，故这里显式清掉可能从外层继承来的取值 ——
# 否则"没给端口时不出现 `-p`"这条判据会被外层环境静默改变（假绿/假红）。
unset EDGEEXP_VM_SSH_HOST EDGEEXP_VM_SSH_KEY EDGEEXP_VM_SSH_USER EDGEEXP_VM_SSH_PORT
# PATH 上**同时**有假 docker/lxc/clab/pct 与假 qm/ssh/scp ⇒ 日志里出现哪一种就是"实际发给了谁"。
# 「基质串味」的判据是"跑之前 / 跑之后"两份字节数比，而中间**只有**这一次 `bash "$D/qemu.sh"`。
log_bytes() { if [ -f "$1" ]; then wc -c < "$1"; else echo 0; fi; }
QI_PVE_B="$(log_bytes "$D/pve.log")"; QI_LXD_B="$(log_bytes "$D/lxd.log")"
QI_DOCKER_B="$(log_bytes "$D/docker.log")"
PATH="$D/bin-qemu:$D/bin-pve:$D/bin:$PATH" REPLAY_LOG="$QMU_LOG" \
  REPLAY_SSH_LOG="$SSH_LOG" REPLAY_SCP_LOG="$SCP_LOG" \
  EDGEEXP_SUBSTRATE=qemu EDGEEXP_QM_BIN=qm EDGEEXP_SSH_BIN=ssh EDGEEXP_SCP_BIN=scp \
  LAB_TMP="$D/work" EDGEEXP_LAB_TMP="$D/work" LIB="$LIB" \
  bash "$D/qemu.sh" > "$D/qemu.out" 2>&1
QI_PVE_A="$(log_bytes "$D/pve.log")"; QI_LXD_A="$(log_bytes "$D/lxd.log")"
QI_DOCKER_A="$(log_bytes "$D/docker.log")"

# 判据的写法：连接参数段之后必须是 `-- asc-vm910 bash -c <命令串>`。三条讲究都要留住：
#
#  1. 用 `grep -qx` 做**整行**相等（不是子串匹配）：子串匹配对"参数段里多了一格"是瞎的。
#
#  2. **不用 `-E` 的 `+`/`?` 量词**（Task 16 实测踩到的一处**夹具自身的雷**）：本机 Git Bash
#     的 grep 在 **`POSIXLY_CORRECT` 被设上时 `-E` 会退回 BRE 语义** —— 于是 `+` 与 `?`
#     变成**字面量**（实测 `grep -E 'ssh (-o [^ ]+ )+-- …'` 对完全匹配的行报 NOMATCH）。
#     ⇒ 这里不用量词，故在 BRE/ERE 两种解释下**同义**。
#
#  3. `bash -c bash -c rm -f /tmp/x` 是**正确**形态，不是双重包装的缺陷（Task 16 实测澄清）：
#     调用点写的是 `lab_target_exec 910 bash -c "rm -f /tmp/x"`（**两格**：`bash`、`-c`、
#     `rm -f /tmp/x`），而 `lab_target_exec` 的 qemu 分支把它重建成 `bash -c "$*"`
#     ⇒ 客人侧收到的命令串逐字就是 `bash -c bash -c rm -f /tmp/x`。
#     Task 16 一度按"这是多包了一层"去改（把外层 `bash -c` 去掉），**实测与理解不符、已还原**；
#     这条断言就是那次澄清的钉子（改成去掉外层的样子必须让它红）。
#
#  4. 用户那一格必须是 **`-o User=asc`** 而不是 `-l asc`（Task 16 两层对齐）：这一格是
#     `ssh` 与 `scp` **共用**的，而 `scp -l <值>` 是**带宽上限** ⇒ 原来是"bash 层用 -l、
#     Go 层用 -o User="的分歧（Go 侧 Task 15 改过、bash 侧没跟上）。断言里把这一格写死，
#     两层从此必须同源（改回 `-l` 必须让本用例红）。
if grep -qx 'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o User=asc -- asc-vm910 bash -c bash -c rm -f /tmp/x' "$SSH_LOG"; then
  ok "qemu exec 走 ssh 且目标名由 vmid 推出来（asc-vm910）"
  ok "qemu exec 的命令串与调用点写的**逐字一致**（\`bash -c\` 那两格是调用方给的，不是多包一层）"
  ok "登录用户那一格是 \`-o User=<用户>\`（**不是** \`-l\`：scp 会把 -l 当带宽上限）—— 与 Go 侧同源"
else
  fail "qemu exec 形态不对（期望整行：ssh <连接参数含 -o User=asc> -- asc-vm910 bash -c bash -c rm -f /tmp/x）"; cat "$SSH_LOG"
fi
if grep -q '^scp .* -O /opt/payload asc-vm910:/tmp/sandcat' "$SCP_LOG"; then
  ok "qemu push 走 scp（含 \`-O\` 强制 legacy SCP 协议）"
else fail "qemu push 形态不对"; cat "$SCP_LOG"; fi
if grep -qE '^ssh .*-- asc-vm910 chmod 0755 /tmp/sandcat' "$SSH_LOG"; then
  ok "qemu push 之后显式 \`chmod 0755\`（scp 不保证可执行位）"
else fail "qemu push 没有 chmod"; cat "$SSH_LOG"; fi
if grep -qE '^ssh .*-- asc-vm910 ip -4 -o addr show eth0' "$SSH_LOG"; then
  ok "qemu lab_node_ip 在客人内取地址"; else fail "qemu lab_node_ip 形态不对"; fi
if grep -qE '^ssh .*-- asc-vm910 ps -eo pid,comm --no-headers' "$SSH_LOG"; then
  ok "qemu lab_node_pids 在客人内取进程表"; else fail "qemu lab_node_pids 形态不对"; fi
if grep -q '^\[invoke\] qm status 910' "$QMU_LOG"; then
  ok "qemu lab_node_running 用 \`qm status <vmid>\` 判状态（实例视图走 qm，不走 ssh）"
else fail "qemu lab_node_running 没走 qm status"; fi
if grep -q '^\[invoke\] qm config 910' "$QMU_LOG"; then
  ok "qemu lab_inspect 用 \`qm config <vmid>\` 取基质视图"; else fail "qemu lab_inspect 没走 qm config"; fi
if printf '%s' "$(cat "$D/qemu.out")" | sed -n '/^== list/,/^== spec/p' | grep -q 'asc-vm910' \
   && ! printf '%s' "$(cat "$D/qemu.out")" | sed -n '/^== list/,/^== spec/p' | grep -qE '^(VMID|12345)'; then
  ok "qemu lab_list 取的是**名字**（\`qm list\` 的名字在第 2 格，与 pct 的最后一格相反）"
else fail "qemu lab_list 契约不对：$(sed -n '/^== list/,/^== spec/p' "$D/qemu.out")"; fi
if printf '%s' "$(cat "$D/qemu.out")" | sed -n '/^== spec$/,/^== specname/p' | grep -q 'qemu:910'; then
  ok "qemu lab_target_spec 产出 qemu:<vmid>（不在这里做名字→vmid 解析：qm 两种标识都收）"
else fail "qemu lab_target_spec 不对：$(sed -n '/^== spec/,/^== specname/p' "$D/qemu.out")"; fi
if printf '%s' "$(cat "$D/qemu.out")" | sed -n '/^== specname$/,/^== sshhost/p' | grep -q 'qemu:asc-vm911'; then
  ok "qemu lab_target_spec 对**名字**标识原样透传（qemu:asc-vm911，不猜 vmid）"
else fail "qemu lab_target_spec 对名字标识处置不对：$(sed -n '/^== specname/,/^== sshhost/p' "$D/qemu.out")"; fi
if printf '%s' "$(cat "$D/qemu.out")" | sed -n '/^== sshhost/,/^== require/p' | grep -q 'asc-vm911'; then
  ok "lab_node_ssh_host 默认规则 = asc-vm<vmid>（与 provisioning 写进 /etc/hosts 的名字同源）"
else fail "lab_node_ssh_host 默认规则不对：$(sed -n '/^== sshhost/,/^== require/p' "$D/qemu.out")"; fi
if printf '%s' "$(cat "$D/qemu.out")" | sed -n '/^== require/,/^== up/p' | grep -q 'require-rc=0'; then
  ok "lab_require_bins 在 qemu 下三项都查（qm + ssh + scp，两级是两个不同二进制）"
else fail "lab_require_bins 在 qemu 下不对：$(sed -n '/^== require/,/^== up/p' "$D/qemu.out")"; fi
if sed -n '/^== up/,/^== down/p' "$D/qemu.out" | grep -q 'rc=2' \
   && sed -n '/^== up/,/^== down/p' "$D/qemu.out" | grep -q 'edge_vm_provision.sh'; then
  ok "lab_up 在 qemu 下响亮失败并**点名**唯一来源 edge_vm_provision.sh（理由与 pve 不同）"
else fail "lab_up 在 qemu 下没有响亮失败：$(sed -n '/^== up/,/^== down/p' "$D/qemu.out")"; fi
if sed -n '/^== down/,/^== counts/p' "$D/qemu.out" | grep -q 'rc=2' \
   && sed -n '/^== down/,/^== counts/p' "$D/qemu.out" | grep -q 'edge_vm_provision.sh'; then
  ok "lab_down 在 qemu 下响亮失败并说明清机该走 \`--destroy\`"
else fail "lab_down 在 qemu 下没有响亮失败：$(sed -n '/^== down/,/^== counts/p' "$D/qemu.out")"; fi
if sed -n '/^== counts/,$p' "$D/qemu.out" | grep -q -- '-1 -1 -1'; then
  ok "lab_node_counts 在 qemu 下回显 -1 -1 -1（宿主上还有别人的 VM，不是同一个集合）"
else fail "lab_node_counts 在 qemu 下不对"; fi
# **不越界**：本层永不 create/destroy/start/stop 任何 VM；也**不得**把 pct/docker/lxc 当 qemu 用。
# ⚠️ 判据只打在**日志里带 `[invoke] qm ` 前缀**的那些行上（即**真被调用过的**命令）：
# 脚本自己 echo 的帮助文本里就有字面量 `qm destroy --purge`（`lab_down` 说明"本层永不销毁 VM"
# 时写出来的），把它当命令会让这条判据**恒红**——而它本该在"代码真去 destroy 了"时才红。
if grep -E '^\[invoke\] qm (create|destroy|start|stop|shutdown|reboot|del|importdisk|set) ' "$QMU_LOG" >/dev/null; then
  fail "qemu 分支发出了会改变 VM 状态的命令（绝不允许）：$(grep -E '^\[invoke\] qm (create|destroy|start|stop|shutdown|reboot|del|importdisk|set) ' "$QMU_LOG")"
else ok "qemu 分支只读：无 create/destroy/start/stop/importdisk/set（判据打在真被调用过的命令上）"; fi
# 「基质串味」：H 段（pve）与 B 段（lxd）的日志是**累积**的（`bash $D/pve.sh` 追加在
# `$D/pve.log` 上），故不能只看"文件非空"——那会把**上一段留下的** pct 行读成本段发的。
# 判据改成"**本段跑的那一次没有让它们增长**"（`QI_*_B` 与 `QI_*_A` 分别取自那一次
# `bash "$D/qemu.sh"` 的**紧邻前后**），既保住"绝不静默回落"这条纪律，也不再冤枉代码。
# 判据**有牙**：把 qemu 的目标级二进制换成 pct/docker 的等价变异会让右侧的字节数变大。
if [ "$QI_PVE_A" = "$QI_PVE_B" ] && [ "$QI_LXD_A" = "$QI_LXD_B" ] && [ "$QI_DOCKER_A" = "$QI_DOCKER_B" ]; then
  ok "qemu 路径**只**起 qm/ssh/scp：docker / lxc / pct 一次都没被调用（绝不静默回落）；判据是本段没让它们的日志增长（pct $QI_PVE_B→$QI_PVE_A、lxd $QI_LXD_B→$QI_LXD_A 字节）"
else
  fail "qemu 路径把命令发给了别的基质（pct/lxc/docker）—— 基质选错且不报错：pct $QI_PVE_B→$QI_PVE_A、lxd $QI_LXD_B→$QI_LXD_A、docker $QI_DOCKER_B→$QI_DOCKER_A；尾部：$(cat "$D/pve.log" "$D/lxd.log" "$D/docker.log" 2>/dev/null | tail -5)"
fi

# --- I-1) STOPPED 的 VM 必须回 false（判据打在 stdout 上，与 pve 段同款）-------------
STOPPED_Q="$(PATH="$D/bin-qemu:$PATH" REPLAY_LOG="$D/qemu-stopped.log" REPLAY_QM_STATUS=stopped \
  EDGEEXP_SUBSTRATE=qemu EDGEEXP_QM_BIN=qm LIB="$LIB" bash -c \
  '. "$LIB"; printf "running=[%s]\n" "$(lab_node_running 910)"; echo "rc=$?"' 2>&1)"
if printf '%s' "$STOPPED_Q" | grep -q 'running=\[false\]'; then
  ok "STOPPED 的 VM ⇒ lab_node_running 回 false（\`paused\` 等一律不是 true）"
else fail "STOPPED 的 VM 取值不对：$STOPPED_Q"; fi

# --- I-2) EDGEEXP_VM_SSH_HOST 的三种语义（%s 展开 / 常量 / 缺省）---------------------
HOSTENV_OUT="$(PATH="$D/bin-qemu:$PATH" EDGEEXP_SUBSTRATE=qemu LIB="$LIB" bash -c '
  . "$LIB"
  printf "tmpl=[%s]\n" "$(EDGEEXP_VM_SSH_HOST="asc-vm%s.lab" lab_node_ssh_host 911)"
  printf "const=[%s]\n" "$(EDGEEXP_VM_SSH_HOST=192.0.2.7 lab_node_ssh_host 911)"
  printf "bare=[%s]\n" "$(EDGEEXP_VM_SSH_HOST= lab_node_ssh_host asc-vm911)"
' 2>&1)"
if printf '%s' "$HOSTENV_OUT" | grep -q 'tmpl=\[asc-vm911.lab\]'; then
  ok "EDGEEXP_VM_SSH_HOST 含 \`%s\` ⇒ 按节点标识展开（**多机就靠这条**）"
else fail "EDGEEXP_VM_SSH_HOST 的 %s 展开不对：$HOSTENV_OUT"; fi
if printf '%s' "$HOSTENV_OUT" | grep -q 'const=\[192.0.2.7\]'; then
  ok "EDGEEXP_VM_SSH_HOST 不含 \`%s\` ⇒ 所有节点都指那一台（单机场景）"
else fail "EDGEEXP_VM_SSH_HOST 常量语义不对：$HOSTENV_OUT"; fi
if printf '%s' "$HOSTENV_OUT" | grep -q 'bare=\[asc-vm911\]'; then
  ok "非数字标识原样当主机名（\`qemu:asc-vm911\` 里的标识本身就是一个主机名）"
else fail "非数字标识的处置不对：$HOSTENV_OUT"; fi

# --- I-3) SSH 选项**不得**由环境变量注入（否则取数目标能被悄悄改到别处）--------------
INJ_OUT="$(PATH="$D/bin-qemu:$PATH" EDGEEXP_SUBSTRATE=qemu LIB="$LIB" \
  EDGEEXP_VM_SSH_OPTS="-o ProxyCommand=/bin/false" EDGEEXP_VM_SSH_ARGS="-o ProxyCommand=/bin/false" \
  bash -c '. "$LIB"; EDGEEXP_VM_SSH_KEY=; lab_ssh_conn_args' 2>&1)"
if printf '%s' "$INJ_OUT" | grep -q 'ProxyCommand'; then
  fail "环境变量把 SSH 选项注入进去了（取数目标可被改到别处）：$INJ_OUT"
else ok "没有任何环境变量能把 SSH 选项注入 argv（换目标只能换 EDGEEXP_VM_SSH_HOST）"; fi

# --- I-4) 私钥路径不可读 ⇒ **响亮失败**，不退回 ssh 自己的默认钥匙 ---------------------
KEYERR_OUT="$(PATH="$D/bin-qemu:$PATH" EDGEEXP_SUBSTRATE=qemu LIB="$LIB" \
  bash -c '. "$LIB"; EDGEEXP_VM_SSH_KEY=/nonexistent/id_ed25519; lab_ssh_conn_args; echo "rc=$?"' 2>&1)"
if printf '%s' "$KEYERR_OUT" | grep -q 'rc=1' && printf '%s' "$KEYERR_OUT" | grep -q '不可读'; then
  ok "私钥路径不可读 ⇒ lab_ssh_conn_args 响亮失败（不退回 ssh 的默认钥匙）"
else fail "私钥不可读的处置不对（不许悄悄换钥匙）：$KEYERR_OUT"; fi

# --- I-F) detached 的 argv 保真（与 F/H-F 段同手法，换到 qemu 形状）--------------------
mkdir -p "$D/bin-exec-qemu"
cat > "$D/bin-exec-qemu/ssh" <<'SH'
#!/bin/bash
# qemu 形状：`ssh <连接参数> -- <主机> <远程命令…>`；把 `-- <主机>` 之后的整串交给本地 sh
# （等价于远端 shell 解释那一串 —— 夹具在**本机**模拟客人）。
shift_args=(); seen=0
for a in "$@"; do
  if [ "$seen" = "1" ]; then shift_args+=("$a"); continue; fi
  if [ "$a" = "--" ]; then seen=1; fi
done
# shift_args[0] 是主机名，后面才是远程命令
unset 'shift_args[0]'
"${shift_args[@]}"
exit $?
SH
chmod +x "$D/bin-exec-qemu/ssh"
rm -f "$D/marker/qemu.txt"
PATH="$D/bin-exec-qemu:/usr/bin:/bin" EDGEEXP_SUBSTRATE=qemu EDGEEXP_SSH_BIN=ssh LIB="$LIB" \
  bash -c '. "$LIB"; lab_target_exec_detached 910 /bin/sh -c "printf RAN-qemu > '"$D"'/marker/qemu.txt"' \
  > "$D/detached-qemu.out" 2>&1
if wait_marker "$D/marker/qemu.txt" "RAN-qemu"; then
  ok "detached（qemu）：脱离命令按 argv 在客人内跑起来了（marker=RAN-qemu）"
else
  fail "detached（qemu）：命令没有按 argv 跑（marker=$([ -f "$D/marker/qemu.txt" ] && cat "$D/marker/qemu.txt" || echo 不存在)｜stderr=$(tr '\n' ';' < "$D/detached-qemu.out"))"
fi

# --- I) 非法基质名：qemu 也必须是**白名单内**的合法值（对照组）--------------------------
cat > "$D/goodsub-qemu.sh" <<SH
set -euo pipefail
. "$LIB"
echo "reached-lab_substrate=\$lab_substrate"
SH
rc=0
out="$(EDGEEXP_SUBSTRATE=qemu bash "$D/goodsub-qemu.sh" 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'reached-lab_substrate=qemu'; then
  ok "合法基质名 qemu ⇒ source 正常通过（对照组；非法值仍被 C 段钉住）"
else fail "qemu 被误拦：rc=$rc out=$out"; fi

echo "############ 汇总"
echo "  PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "residual: edge_lab 离线用例全绿"
