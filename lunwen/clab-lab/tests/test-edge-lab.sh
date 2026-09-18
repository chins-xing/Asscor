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

echo "############ 汇总"
echo "  PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "residual: edge_lab 离线用例全绿"
