#!/bin/bash
# lab-diff.sh —— Task 4D Step 1 的**真基线**差分夹具（Fix round 1：替换手抄版 lab-replay.sh）
#
# 评审指出的问题（verdict §1.1）：上一版夹具的"抽象前"是**手抄**自 edge_reset.sh 的一串命令
# （`drive-before.sh`），全程没有 git ⇒ 抄错/抄漏不会被发现，而且只覆盖 11 条命令、只跑 rc=0。
#
# 本版做法（与评审一致）：
#   1. `git archive <base>` 取**真基线**整棵树（base 默认 97581d8 = Task 4C 的最后一个提交）；
#   2. 两侧用**同一份**假 CLI（clab/docker/curl）与同一份环境，跑**真脚本** `edge_reset.sh`；
#   3. 比较"假 CLI 调用序列 / 归一化后的 stdout / 归一化后的 stderr / 退出码"；
#   4. **四个场景**：正常 / I9 拒绝（destroy 失败 + inspect 也失败）/ agent 超时 / 拓扑文件缺失。
#
# 用法：bash build/lab-diff.sh [base-commit]        （默认 97581d8）
# 全程只读：不碰 clab、不碰容器、不碰 Caldera、不写仓库（临时目录都在 mktemp -d 里）。
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$TESTS_DIR/../../.." && pwd)}"
BASE="${1:-97581d8}"
# **夹具的根不能在 /tmp 下**：下面用 `unshare -rm` 把 /tmp 换成私有的空目录（见 run_isolated），
# 那时 `/tmp/...` 里的一切都会"消失"（第一次跑就是这么拿到 rc=127 的假绿：脚本路径在私有 /tmp
# 里不存在，两侧都"失败得一模一样"）。故夹具根放到 $HOME 下。
HOST_TMP="${T4D_DIFF_ROOT:-${HOME:-/home/clab}}"
WORK="$(mktemp -d "$HOST_TMP/t4d-diff.XXXXXX")" || exit 1
BEFORE="$WORK/before"
AFTER="$WORK/after"
BIN="$WORK/bin"
mkdir -p "$BEFORE" "$AFTER" "$BIN"
PASS=0; FAIL=0
ok()  { echo "  ok   $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $*"; FAIL=$((FAIL+1)); }

echo "############ 夹具位置：$WORK（临时目录，跑完保留供复查）"
echo "############ 真基线：git archive $BASE → $BEFORE"
( cd "$REPO" && git archive "$BASE" ) | tar -x -C "$BEFORE" || { echo "git archive 失败"; exit 1; }
# 抽象后的那一侧：工作树的 scripts/（只取脚本，其余走真基线，保证两侧只差本次改动）
mkdir -p "$AFTER/lunwen/clab-lab/scripts"
cp "$REPO"/lunwen/clab-lab/scripts/edge_*.sh "$AFTER/lunwen/clab-lab/scripts/"
# 两侧都要有拓扑文件（内容也取真基线，保证 TOFO_HASH 只差路径）
( cd "$REPO" && git show "$BASE:lunwen/clab-lab/asscor.clab.yml" ) > "$AFTER/lunwen/clab-lab/asscor.clab.yml"
for d in "$BEFORE/lunwen/clab-lab" "$AFTER/lunwen/clab-lab"; do
  cp "$REPO/lunwen/clab-lab/asscor.clab.yml" "$d/asscor.clab.yml" 2>/dev/null || true
done
echo "  基线 edge_reset.sh sha256: $(sha256sum "$BEFORE/lunwen/clab-lab/scripts/edge_reset.sh" | awk '{print $1}')"
echo "  工作区 edge_reset.sh sha256: $(sha256sum "$AFTER/lunwen/clab-lab/scripts/edge_reset.sh" | awk '{print $1}')"

# ---------------------------------------------------------------------------
# 假 CLI：clab / docker / curl（两侧共用同一份）
# ---------------------------------------------------------------------------
cat > "$BIN/clab" <<'SH'
#!/bin/bash
printf 'clab %s\n' "$*" >> "$REPLAY_LOG"
case "$1" in
  inspect)
    if [ "${REPLAY_INSPECT_FAIL:-0}" = "1" ]; then
      echo "fake-clab: cannot reach docker daemon" >&2; exit 1
    fi
    # 内容从**文件**读（不把 JSON 放在命令行/环境变量里：本机实测，含引号的 JSON 在
    # `wsl.exe bash -lc "…"` 这一层会被剥掉引号，夹具会拿到 `{asc-asscor:[state:running]}`
    # 这种坏 JSON —— 那会让两侧"一致地失败"，得到一个漂亮但无意义的假绿）。
    #
    # 写**两处**：抽象后的实现把 inspect 的输出落在可覆盖的目录（`EDGEEXP_LAB_TMP`），抽象前
    # 写死 `/tmp/edgeexp-clab-inspect.json`；本夹具跑在私有 /tmp 命名空间里，两处都写才能让
    # **两侧**读到同一份输入（否则比的是"谁读到了文件"，不是"命令与处置是否等价"）。
    printf '%s' "$(cat "${REPLAY_INSPECT_FILE:-/dev/null}")" > "$REPLAY_TMP/edgeexp-clab-inspect.json"
    printf '%s' "$(cat "${REPLAY_INSPECT_FILE:-/dev/null}")" > /tmp/edgeexp-clab-inspect.json
    exit 0 ;;
  destroy) exit "${REPLAY_DESTROY_RC:-0}" ;;
  deploy)  exit "${REPLAY_DEPLOY_RC:-0}" ;;
esac
exit 0
SH
cat > "$BIN/docker" <<'SH'
#!/bin/bash
printf 'docker %s\n' "$*" >> "$REPLAY_LOG"
# 只有这两条要给出**内容**（其余只看调用形状）：
#   · `ip -4 -o addr show eth0` —— edge_reset.sh 用它推管理网网关；推不出来 ⇒ 候选地址为空 ⇒
#     在到达 docker cp / agent 启动之前就失败（等价性仍成立，但覆盖不到那几条命令）；
#   · `ip route` —— 默认网关（探测的第二个候选）。
if [ "$1" = "exec" ] && [ "${*: -3}" = "-o addr show eth0" ]; then
  printf '2: eth0    inet 10.217.208.42/24 brd 10.217.208.255 scope global eth0\n'
fi
if [ "$1" = "exec" ] && [ "${*: -1}" = "route" ]; then
  printf 'default via 10.217.208.1 dev eth0 proto static\n10.217.208.0/24 dev eth0 proto kernel scope link\n'
fi
exit "${REPLAY_DOCKER_RC:-0}"
SH
cat > "$BIN/curl" <<'SH'
#!/bin/bash
printf 'curl %s\n' "$*" >> "$REPLAY_LOG"
# `edge_reset.sh` 的 ensure_caldera 用 abilities 端点探活（`-fsS` 要求**非空且合法**的响应体，
# 故这里必须回一个 JSON 数组，而不是只给退出码 0）。
if [[ "$*" == *"/api/v2/abilities"* ]]; then printf '[]\n'; exit 0; fi
if [ "${REPLAY_CURL_OK:-0}" = "1" ] && [[ "$*" == *"/api/v2/agents"* ]]; then
  printf '[{"host":"host1","trusted":true,"paw":"PAW-T4D","last_seen":"%s"}]\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  exit 0
fi
printf '\n'
exit 0
SH
chmod +x "$BIN"/clab "$BIN"/docker "$BIN"/curl

# 归一化：把两侧各自己的临时路径与时钟换成占位符，并把"哪一行报的"折成同一个占位符 ——
# 后者是**必须**的：抽象把命令搬进了 `edge_lab.sh`，于是同一条错误会以不同的 `file:line` 前缀
# 出现（`edge_reset.sh: line 97` vs `edge_lab.sh: line 193`）。那是**搬动的直接后果**，
# 不是行为差异；判据是"命令/输出/退出码逐行等价"，行号不在其中（本脚本把这条如实写出来）。
normalize() { # $1=文件 $2=该侧的 root 路径
  sed -E \
    -e "s#$2#<ROOT>#g" \
    -e 's#^[^:]+: line [0-9]+:#<SH>: line <N>:#' \
    -e 's#[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z#<TS>#g' \
    -e 's#(restarted|等待|总) [0-9]+s#\1 <N>s#g' \
    -e 's#elapsed_s": [0-9]+#elapsed_s": <N>#g' \
    -e 's#: [0-9]+s#: <N>s#g' \
    "$1"
}

# 私有 /tmp：`edge_reset.sh` 把两处诊断日志写到**写死的** `/tmp/edgeexp-clab-*.{log,json}`
# （抽象前后都是写死的；本机 /tmp 里躺着历史上 root 写下的同名文件 ⇒ 会以一个与"命令序列变了"
# 完全无关的 Permission denied 变红 —— 那正是假证据的形态）。故每次运行都在**私有 /tmp
# 命名空间**里跑（`unshare -rm` + bind mount 到一个空目录），而不是去改脚本的路径。
EMPTY_TMP=/home/clab/empty-tmp
mkdir -p "$EMPTY_TMP"
rm -rf "$EMPTY_TMP"/* 2>/dev/null
if ! unshare -rm true 2>/dev/null; then
  echo "本夹具需要 unshare -rm（私有 /tmp）；本机不可用 —— 夹具无法给出可信结果" >&2
  exit 2
fi
run_isolated() { # $1=命令（在私有 /tmp 里执行）
  unshare -rm bash -c "mount --bind $EMPTY_TMP /tmp && $1"
}

# 场景**配置文件**：每个场景一个目录，里面是可以含引号/空格的内容（不经过命令行与环境变量）。
scenario_file() { # $1=场景名 $2=文件名 $3=内容
  mkdir -p "$WORK/scen/$1"
  printf '%s\n' "$3" > "$WORK/scen/$1/$2"
}
scenario_file normal     inspect.json '{"asc-asscor":[{"name":"asc-asscor-host1","state":"running"}]}'
scenario_file agenttimeout inspect.json '{"asc-asscor":[{"name":"asc-asscor-host1","state":"running"}]}'

run_case() { # $1=名称 $2=产物期望（yes=必须写出 / no=必须不写） $3..=额外的 KEY=VALUE
  local name="$1"; shift
  local want_artifact="$1"; shift
  echo "############ 场景：$name（产物期望：$want_artifact）"
  local extra="$*"
  for side in before after; do
    local root="$WORK/$side"
    local lab="$root/lunwen/clab-lab"
    local log="$WORK/$side-$name.log"
    local tmp="$WORK/$side-$name-tmp"
    mkdir -p "$tmp"
    : > "$log"
    run_isolated "env -i PATH='$BIN:/usr/bin:/bin' HOME='$WORK' \
      REPLAY_LOG='$log' REPLAY_TMP='$tmp' \
      REPLAY_INSPECT_FILE='$WORK/scen/$name/inspect.json' \
      EDGEEXP_DATA_DIR='$tmp/data' EDGEEXP_TOPOLOGY='$lab/asscor.clab.yml' \
      EDGEEXP_CALDERA_BOOT_S=1 EDGEEXP_NODE_WAIT_S=1 EDGEEXP_AGENT_WAIT_S=4 \
      $extra \
      bash '$lab/scripts/edge_reset.sh' S0-baseline" \
      > "$WORK/$side-$name.out" 2> "$WORK/$side-$name.err"
    echo $? > "$WORK/$side-$name.rc"
    normalize "$WORK/$side-$name.out" "$root" > "$WORK/$side-$name.out.norm"
    normalize "$WORK/$side-$name.err" "$root" > "$WORK/$side-$name.err.norm"
    # 调用日志里的路径也归一化（拓扑路径两侧不同）
    normalize "$log" "$root" > "$WORK/$side-$name.log.norm"
  done
  local a b
  a="$(cat "$WORK/before-$name.rc")"; b="$(cat "$WORK/after-$name.rc")"
  if [ "$a" = "$b" ]; then ok "退出码相同（$a）"; else bad "退出码不同：before=$a after=$b"; fi
  if diff -q "$WORK/before-$name.log.norm" "$WORK/after-$name.log.norm" >/dev/null; then
    ok "假 CLI 调用序列逐行相同（$(wc -l < "$WORK/after-$name.log.norm") 条）"
  else
    bad "调用序列不同："; diff -u "$WORK/before-$name.log.norm" "$WORK/after-$name.log.norm" | sed 's/^/     /'
  fi
  if diff -q "$WORK/before-$name.out.norm" "$WORK/after-$name.out.norm" >/dev/null; then
    ok "stdout 逐行相同"
  else
    bad "stdout 不同："; diff -u "$WORK/before-$name.out.norm" "$WORK/after-$name.out.norm" | sed 's/^/     /'
  fi
  if diff -q "$WORK/before-$name.err.norm" "$WORK/after-$name.err.norm" >/dev/null; then
    ok "stderr 逐行相同"
  else
    bad "stderr 不同："; diff -u "$WORK/before-$name.err.norm" "$WORK/after-$name.err.norm" | sed 's/^/     /'
  fi
  # 产物断言**按场景期望**判定（Fix round 1 复审 Minor-新-3）：
  # 旧写法把"两侧都没有写产物"在**任何**场景都算 ok，于是"两侧一致地死在启动前"（rc=127）
  # 也能拿到 PASS=21/FAIL=0 + "residual: 全绿" —— 一条漂亮的全绿假象。
  # 现在：该有产物的场景（A / deployfail 之外的正常路径）**必须**有；该失败的场景**必须**没有。
  local fa="$WORK/before-$name-tmp/data/run.d/reset-S0-baseline.json"
  local fb="$WORK/after-$name-tmp/data/run.d/reset-S0-baseline.json"
  local ha=no hb=no
  [ -f "$fa" ] && ha=yes
  [ -f "$fb" ] && hb=yes
  if [ "$ha" != "$hb" ]; then
    bad "产物不一致：before=$ha after=$hb"
  elif [ "$ha" != "$want_artifact" ]; then
    bad "产物与**场景期望**不符：期望 $want_artifact、实际 $ha（该场景的语义见 run_case 的调用点）"
  else
    ok "产物符合场景期望（$want_artifact，两侧一致）"
  fi
  # 正向控制（Minor-新-3）：假 CLI 至少得被调用过 —— 否则"两侧一致"只是"两侧都没跑起来"。
  local calls
  calls="$(wc -l < "$WORK/after-$name.log.norm")"
  if [ "$want_artifact" = "yes" ]; then
    if [ "$calls" -ge 10 ]; then
      ok "正向控制：正常路径确实跑到了被测代码（假 CLI 调用 $calls 条 ≥ 10）"
    else
      bad "正向控制失败：正常路径只有 $calls 条假 CLI 调用（≤ 9）—— 很可能脚本根本没跑起来（例如夹具根落在私有 /tmp 里）"
    fi
  fi
}

echo
echo "############ 场景 A：正常路径（destroy ok + deploy ok + 节点 running + agent 回连）"
run_case normal yes REPLAY_CURL_OK=1
echo "  抽象后的调用序列原文："
sed 's/^/    /' "$WORK/after-normal.log.norm"

echo
echo "############ 场景 B：I9 补断言（destroy 失败 + inspect 也失败 ⇒ 整轮失败）"
run_case i9 no \
  REPLAY_DESTROY_RC=1 REPLAY_INSPECT_FAIL=1

echo
echo "############ 场景 C：agent 没回连（超时失败，走失败时的 tail 分支）"
run_case agenttimeout no

echo
echo "############ 场景 E：deploy 失败（关键路径**不做任何容错**——Fix round 1 复审 Minor-新-4）"
#
# 为什么必须有这个场景：四个旧场景里 `REPLAY_DEPLOY_RC` 从未被设置（默认 0）⇒ `deploy` 永远成功
# ⇒ "把 `lab_up` 改成 `deploy … || true`"这个变异在夹具里**不改变任何行为**（实测 21/21 仍全绿）。
# 也就是说 brief 明写的"关键路径不做任何容错"这条不变式当时**没有任何钉子**。
# 本场景让 deploy 返回 1：两侧都必须**非零退出**、**不写产物**、并且**不再往下走**
# （判据：调用序列里不得出现 `clab inspect`/`docker` —— deploy 之后的步骤一条都不许跑）。
run_case deployfail no REPLAY_DEPLOY_RC=1
for side in before after; do
  log="$WORK/$side-deployfail.log.norm"
  if grep -q '^clab inspect' "$log" || grep -q '^docker ' "$log"; then
    bad "$side：deploy 失败后仍继续往下跑（调用序列里有 inspect/docker）—— 关键路径被加了容错"
  else
    ok "$side：deploy 失败后一条后续命令都没发（容错未出现）"
  fi
  if grep -q '^clab deploy' "$log"; then ok "$side：确实发出了 deploy（场景有效）"
  else bad "$side：场景无效 —— 连 deploy 都没发出"; fi
done

echo
echo "############ 场景 D：拓扑文件缺失（最早的失败分支）"
# 这个场景要一个两侧都存在的"缺失路径"：临时把拓扑复制品删掉再跑
for side in before after; do
  mv "$WORK/$side/lunwen/clab-lab/asscor.clab.yml" "$WORK/$side/lunwen/clab-lab/asscor.clab.yml.bak"
done
run_case notopo no
for side in before after; do
  mv "$WORK/$side/lunwen/clab-lab/asscor.clab.yml.bak" "$WORK/$side/lunwen/clab-lab/asscor.clab.yml"
done

echo
echo "############ 残留的基质命令字面（判定：只允许出现在**注释行**或**消息文本**里）"
#
# 判据刻意不是"文件里 grep 不到 clab/docker/lxc"：错误串与日志里**必须**保留这些词
# （`edge_reset: clab destroy 完成` 这类消息是既有排障手册的锚点，改名会让手册对不上）。
# 要堵的是"调用脚本里还有一条**真的在跑的**基质命令"。故这里只认**命令位置**的出现：
# 行首（可带空白/`(`/`{`/`;`）或管道后面，且**不是**紧跟双引号（消息文本里的 `clab destroy`
# 正是 `"…clab destroy 完成"` 这个形状）。
RESIDUAL=0
for f in "$AFTER"/lunwen/clab-lab/scripts/edge_reset.sh "$AFTER"/lunwen/clab-lab/scripts/edge_attack.sh \
         "$AFTER"/lunwen/clab-lab/scripts/edge_collect.sh "$AFTER"/lunwen/clab-lab/scripts/edge_matrix.sh \
         "$AFTER"/lunwen/clab-lab/scripts/edge_probe.sh; do
  # 只看**真的在跑的**基质命令：
  #   · 整行是注释（`: ` 后跟 `#`）⇒ 跳过；
  #   · 出现位置前面是 `"` 或 `'`（消息文本里，如 `"edge_reset: clab destroy 完成"`）⇒ 跳过；
  #   · 出现位置前面是 `$`（`${lab_substrate}` 这类变量名里含 clab 的情形）⇒ 跳过。
  hits="$(grep -nE '(clab|docker|lxc)[[:space:]]' "$f" \
          | grep -vE ':[[:space:]]*#' \
          | grep -vE "\"[^\"]*(clab|docker|lxc)[[:space:]]" \
          | grep -vE "'[^']*(clab|docker|lxc)[[:space:]]" \
          | grep -vE 'edge_[a-z_]+:' || true)"
  if [ -n "$hits" ]; then
    echo "  $f:"; echo "$hits" | sed 's/^/     /'; RESIDUAL=$((RESIDUAL+1))
  fi
done
if [ "$RESIDUAL" -eq 0 ]; then
  ok "五个调用脚本的代码位置已无基质命令字面（只剩注释行与消息文本）"
else
  bad "仍有 $RESIDUAL 个文件在**命令位置**出现基质命令字面"
fi

echo
echo "############ 汇总"
echo "  PASS=$PASS FAIL=$FAIL（夹具与产物保留在 $WORK）"
[ "$FAIL" -eq 0 ] || exit 1
echo "residual: lab-diff 全绿"
