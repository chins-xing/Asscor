#!/usr/bin/env bash
# ============================================================================
# ASSCOR 底座一致性检查  main-base-consistency-check.sh   (v3，双侧登记)
#
# 运行上下文：**在本仓库的工作区里跑**，默认对照 `main`，HEAD = 当前检出的分支。
#   在 ARC 工作区跑 -> 检查「ARC 相对 main 的底座漂移」   （本项目的用法）
#   在 main 工作区跑 -> BASE_REF=ASSCOR-Research-Core 反向检查
#
# 裁定（用户 2026-09-13「乙」）：
#   底座路径集合 减去「有意差异清单」 之后，main 与 ARC 必须逐字节相同；
#   清单内的差异视为**有意**，逐条核对 —— 且**两侧都比对**。
#
# v3 相对 v2 的关键变化（用户 2026-09-13 要求补上「双侧登记」）：
#   v2 只登记 ARC 侧 blob sha ⇒ 若 **main 侧**被改写（例如有人换掉 main 版
#   internal/config/configs_templates_test.go），检查只会报「登记一致」、发现不了。
#   v3 的清单格式为：<arc_sha>  <main_sha|ABSENT>  <path>  # 理由
#     · 两侧都有的文件记 main 侧 blob sha；
#     · 只在 ARC 有的文件记字面量 ABSENT（表示「main 上不存在」）；
#     · 任一侧与登记不符都报红（ABSENT 变成存在也算不符）=> 补上那个缺口。
#
# 判据（三态）：
#   红 : ①出现**清单之外**的底座漂移（逐条列出，并标注是否属 A 类「纯产品侧，应上 main」）
#        ②清单条目的 ARC 侧 blob ≠ 登记 sha（登记失效）
#        ③清单条目的 **main 侧 blob ≠ 登记 sha**（main 侧被改写 / 凭空出现）
#        ④清单行缺少 main 侧登记（旧格式）
#   黄 : 清单外无差异，且清单内差异全部存在、两侧都与登记一致 -> 符合裁定（乙）的可接受终态
#   绿 : 清单外无差异，且清单内**已无任何 active 差异**（清单已清空/全部已同步）-> 底座完全一致
#
# 退出码：0=绿  3=黄  1=红
# ============================================================================
set -uo pipefail

BASE_REF="${BASE_REF:-main}"
MANIFEST="${MANIFEST:-}"
SHOW_ALL="${SHOW_ALL:-0}"

BASE=(
  api pluginsdk optional deploy scripts
  cmd/agent cmd/asscor cmd/kernel
  internal
  configs
  ssam-lib prism-lib
  .github
  config.ini agent.ini go.mod go.sum Dockerfile .dockerignore
  README.md README_EN.md LICENSE CONTRIBUTING.md
  .gitignore .gitattributes
)
EXCL=(
  ':!internal/edgefactor' ':!internal/edgeexp'
  ':!internal/attackerstate' ':!internal/defensecycle'
  ':!internal/engagement' ':!internal/predictor'
  ':!cmd/edgescen' ':!cmd/edgecompare' ':!cmd/exprunner'
  ':!cmd/decoyd' ':!cmd/tracecheck'
  ':!configs/edgeexp'
  # 本套判据**自己**（检查脚本 + 它的输入清单）不是"底座"，而是研究线的分支治理工具
  # —— 两分支共有但内容不同的清单不适用于它们，它们是**只在 ARC 侧存在**的新文件。
  # 若把它们留在漂移面里，清单就必须登记自己，而登记内容里含自己的 sha ⇒
  # **改一次清单、sha 就变一次、永远追不上**（实测：连追 8 轮仍不收敛）。
  # 故在这里显式排除；理由是"它们不是底座"，不是为了把红项藏起来。
  # （`scripts/build.sh` 是**真底座**，仍留在面里并另行登记。）
  ':!scripts/check-main-base-consistency.sh'
  ':!scripts/main-base-drift-manifest.txt'
)
# A 类：纯产品侧底座变更（裁定②「第一时间进 main」）—— 用于给红项打标签
A_CLASS=(
  .gitattributes
  configs/config.bank.ini configs/config.datacenter.ini configs/config.edu.ini
  configs/config.enterprise.ini configs/config.gov.ini configs/config.hospital.ini
  configs/config.testing.ini
)

blob() { # ref path -> sha 或 MISSING
  # 注意：`git rev-parse <rev>:<path>` 在**路径不存在**时会把实参原样打到 stdout 并 rc=128
  # （`fatal: path ... exists on disk, but not in '<ref>'`）⇒ 若只靠 `|| echo MISSING`，
  # 命令替换会把那份残留 stdout 一起捕获，导致"不存在"被误判成"存在"。
  # 故必须用 `--verify --quiet`（失败时**不输出**）后再回落到 MISSING。
  local v
  if v=$(git rev-parse --verify --quiet "$1:$2"); then printf '%s' "$v"; else printf 'MISSING'; fi
}

echo "=== ASSCOR 底座一致性检查（裁定：乙 / 有意差异清单·双侧登记） ==="
echo "对照分支 : $BASE_REF  ($(git rev-parse --short "$BASE_REF"))"
echo "当前 HEAD: $(git rev-parse --abbrev-ref HEAD) ($(git rev-parse --short HEAD))"
echo "底座路径 : ${#BASE[@]} 正 / ${#EXCL[@]} 负"
echo

drifted=$(git diff --name-only "$BASE_REF" HEAD -- "${BASE[@]}" "${EXCL[@]}" | sort | grep . || true)
manifest_paths=""
[ -n "$MANIFEST" ] && [ -f "$MANIFEST" ] && manifest_paths=$(grep -v '^[[:space:]]*#' "$MANIFEST" | awk 'NF>=3{print $3}' | sort)

echo "--- 底座漂移（$BASE_REF vs HEAD）: $(printf '%s\n' "$drifted" | grep -c . || echo 0) 个 ---"

unexplained=""
while IFS= read -r p; do
  [ -z "$p" ] && continue
  if ! printf '%s\n' "$manifest_paths" | grep -qxF "$p"; then unexplained="$unexplained$p"$'\n'; fi
done <<< "$drifted"

n_unexp=$(printf '%s\n' "$unexplained" | grep -c . || true)
if [ "$SHOW_ALL" = "1" ] || [ "$n_unexp" -gt 0 ]; then
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    tag="未知来源"
    printf '%s\n' "${A_CLASS[@]}" | grep -qxF "$p" && tag="A 类（纯产品侧 ⇒ 应 cherry-pick 上 main）"
    if printf '%s\n' "$manifest_paths" | grep -qxF "$p"; then
      echo "    [清单内]  $p"
    else
      echo "    [未解释]  $p   <-- $tag"
    fi
  done <<< "$drifted"
  echo
fi

# --- 清单核对（双侧） ---
if [ -z "$MANIFEST" ] || [ ! -f "$MANIFEST" ]; then
  echo "[SKIP] 未提供有意差异清单（MANIFEST 未设置）=> 只报漂移面"
  [ "$n_unexp" -eq 0 ] && exit 0 || exit 1
fi

echo "--- 有意差异清单核对（双侧）: $MANIFEST ---"
active=0; stale=0; mismatch_arc=0; mismatch_main=0; unregistered=0
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  case "$(printf '%s' "$line" | tr -d '[:space:]')" in '') continue ;; esac
  set -- $line
  f1="${1:-}"; f2="${2:-}"; f3="${3:-}"
  # 旧格式（两列）检测：第 2 个字段看起来像路径
  if [ -z "$f3" ] || printf '%s' "$f2" | grep -q '/'; then
    unregistered=$((unregistered+1))
    echo "    [缺登记]   ${f2:-$f1}   清单行缺少 main 侧登记（旧式单侧格式）—— 无法发现 main 侧被改写"
    continue
  fi
  arc_reg="$f1"; main_reg="$f2"; path="$f3"
  arc_actual=$(blob HEAD "$path")
  main_actual=$(blob "$BASE_REF" "$path")

  bad=""
  [ "$arc_actual" != "$arc_reg" ] && bad="${bad}ARC侧(登记${arc_reg:0:12} 实际${arc_actual:0:12}) "
  if [ "$main_reg" = "ABSENT" ]; then
    [ "$main_actual" != "MISSING" ] && bad="${bad}main侧(登记ABSENT 实际存在${main_actual:0:12}) "
  else
    [ "$main_actual" != "$main_reg" ] && bad="${bad}main侧(登记${main_reg:0:12} 实际${main_actual:0:12}) "
  fi

  if [ -n "$bad" ]; then
    if printf '%s' "$bad" | grep -q 'main侧'; then mismatch_main=$((mismatch_main+1)); else mismatch_arc=$((mismatch_arc+1)); fi
    echo "    [登记失效] $path   $bad"
    continue
  fi

  if printf '%s\n' "$drifted" | grep -qxF "$path"; then
    active=$((active+1)); echo "    [登记一致] $path   （ARC 侧 ${arc_actual:0:12} / main 侧 ${main_actual:0:12}）"
  else
    stale=$((stale+1)); echo "    [已同步]   $path   （两侧不再有差异 => 可从清单移除）"
  fi
done < "$MANIFEST"

n_manifest=$(printf '%s\n' "$manifest_paths" | grep -c . || true)

echo
echo "=== 结论 ==="
echo "    清单条目 = $n_manifest    active = $active    stale = $stale"
echo "    登记失效: ARC 侧 = $mismatch_arc    main 侧 = $mismatch_main    缺 main 侧登记 = $unregistered"
echo "    清单外漂移（未解释） = $n_unexp"
if [ "$n_unexp" -gt 0 ] || [ "$mismatch_arc" -gt 0 ] || [ "$mismatch_main" -gt 0 ] || [ "$unregistered" -gt 0 ]; then
  if [ "$n_unexp" -gt 0 ]; then
    echo "    红项逐条："
    while IFS= read -r p; do [ -z "$p" ] && continue; echo "      - $p"; done <<< "$unexplained"
  fi
  [ "$mismatch_main" -gt 0 ] && echo "    注意：**main 侧**与登记不符 —— 这正是 v3 补上的缺口（main 侧被改写 / 凭空出现）"
  echo "    => 红"
  exit 1
elif [ "$active" -eq 0 ]; then
  echo "    => 绿（底座完全一致，清单已无 active 差异）"
  exit 0
else
  echo "    => 黄（清单外逐字节一致；清单内 $active 条有意差异，**两侧均与登记一致**）"
  exit 3
fi
