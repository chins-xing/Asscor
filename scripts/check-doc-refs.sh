#!/usr/bin/env bash
# ============================================================================
# check-doc-refs.sh — 文档引用完整性检查（v2：逐文件存在性）
#
# 扫描所有被跟踪的文本文件，抽出形如 `docs/...` 的路径（含反引号与
# Markdown 链接里的），对解析出的**完整路径**做存在性断言：
#   · 以 `/` 结尾的引用（目录引用）必须 `test -e` 且是目录；
#   · 其余引用（含带扩展名的文件）必须 `test -e`（文件或目录均可）。
#   ⇒ “目录存在、文件不存在”（如 `docs/1-current/design/NO_SUCH_FILE.md`）
#      **必须报红**，这正是 v1 按“最长已知前缀”判定时的盲区。
#
# 占位符按设计跳过：`docs/...`、`docs/**`、`docs/a-<x>.json`、
# `docs/{a,b}/...` 等（含 `*` `?` `<` `>` `{` `}` `…` 或字面 `...`）。
#
# 输出：`SCANNED_FILES` / `DOC_REFS` / `SKIPPED_LINES` / `DANGLING: N`；
# 退出码 0 当且仅当 N == 0（1 = 有断链；2 = 环境错误）。
#
# 例外（按设计跳过）：
#   1. docs/MIGRATION_MAP.md —— 它是迁移记录，按设计保留旧路径；
#   2. lunwen/paper/attacker-cognitive-loop-paper.tex —— 论文冻结，不改。
#
# 用法（仓库根目录）：
#   bash scripts/check-doc-refs.sh
#   bash scripts/check-doc-refs.sh --selftest
#     → 自测：在临时 git 仓库里造“合法引用 + 目录在/文件不在”的引用，
#       断言 DANGLING=1、rc=1（证明加严后的门禁确实会红）。
# ============================================================================
set -u

if [[ "${1:-}" == "--selftest" ]]; then
  SELFTEST=1
else
  SELFTEST=0
fi

if [[ -n "${DOC_REFS_ROOT:-}" ]]; then
  ROOT="$DOC_REFS_ROOT"
else
  ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "FATAL: not inside a git work tree (and DOC_REFS_ROOT is unset)" >&2
    echo "DANGLING: 0"
    exit 2
  }
fi
cd "$ROOT" || {
  echo "FATAL: cannot cd to $ROOT" >&2
  echo "DANGLING: 0"
  exit 2
}

EXCLUDED_FILES=(
  "docs/MIGRATION_MAP.md"
  "lunwen/paper/attacker-cognitive-loop-paper.tex"
  # 检查器自身：注释与 --selftest 夹具里的 `docs/...` 是示例路径，
  # 它们只存在于临时仓库，不能当成对本仓库的引用断言。
  "scripts/check-doc-refs.sh"
)

# ---- 已知存在的路径集合 -----------------------------------------------------
# 被跟踪文件 + 它们的所有目录前缀；带空格的文件名额外登记 %20 形式。
TRACKED=()
while IFS= read -r p; do
  TRACKED+=("$p")
done < <(git ls-files)

KNOWN=("docs/")
for p in "${TRACKED[@]}"; do
  case "$p" in
    docs/*) ;;
    *) continue ;;
  esac
  KNOWN+=("$p")
  if [[ "$p" == *" "* ]]; then
    KNOWN+=("${p// /%20}")
  fi
  d="$p"
  while [[ "$d" == */* ]]; do
    d="${d%/*}"
    [[ -z "$d" ]] && break
    KNOWN+=("$d/")
  done
done

is_excluded() {
  local f="$1" e
  for e in "${EXCLUDED_FILES[@]}"; do
    [[ "$f" == "$e" ]] && return 0
  done
  return 1
}

# 在 rest（以 docs/ 开头）中找最长已知前缀；返回匹配到的已知路径。
match_known() {
  local rest="$1" best="" k
  for k in "${KNOWN[@]}"; do
    if [[ "$rest" == "$k"* ]]; then
      if (( ${#k} > ${#best} )); then
        best="$k"
      fi
    fi
  done
  printf '%s' "$best"
}

# 检查一个引用是否成立；不成立时把候选路径写入全局 CAND。
# 返回 0 = 存在（或是占位符/裸目录），1 = 断链。
CAND=""
check_ref() {
  local rest="$1" best raw token probe
  CAND=""
  best="$(match_known "$rest")"

  if [[ -z "$best" ]]; then
    CAND="${rest%%[[:space:]]*}"
    return 1
  fi

  # 命中一个完整文件（含带空格文件的 %20 形式）⇒ 必然存在（来自 git ls-files）。
  if [[ "$best" != */ ]]; then
    return 0
  fi

  # 命中的是目录前缀 ⇒ 取出该目录之后的那个路径分量再判存在性。
  raw="${rest#"$best"}"
  raw="${raw%%$'\t'*}"
  raw="${raw%%[[:space:]]*}"
  raw="${raw%%[\`\"\'|\)\]\，\。\；\、\（\）]*}"

  # 占位符 / 省略号：按设计跳过（不当成具体路径断言）。
  case "$raw" in
    *"<"*|*">"*|*"{"*|*"}"*|*"*"*|*"?"*|*"..."*|*"…"*) return 0 ;;
  esac

  # 去掉锚点与尾随标点（`.md,` / `.md.` / `.md;` 之类）。
  raw="${raw%%#*}"
  token="$raw"
  while [[ -n "$token" ]]; do
    case "${token: -1}" in
      "."|","|":"|";"|"!"|"?") token="${token%?}" ;;
      *) break ;;
    esac
  done

  CAND="${best}${token}"
  if [[ -z "$token" ]]; then
    # 裸目录引用：`docs/.../`
    [[ -d "${best%/}" ]]
    return $?
  fi

  # 带空格的文件在文档里可能写成 %20。
  probe="${CAND//%20/ }"
  [[ -e "$probe" ]]
}

# ---- 自测（--selftest）-----------------------------------------------------
# 在临时 git 仓库里验证两件事：
#   ① 只含合法引用的仓库 ⇒ DANGLING: 0、rc=0；
#   ② 额外的“目录存在、文件不存在”引用 ⇒ DANGLING: 1、rc=1，且断链行点名该文件。
run_selftest() {
  local tmp rc out root2
  tmp="$(mktemp -d)" || { echo "SELFTEST: FAIL (mktemp)" >&2; exit 1; }
  trap 'rm -rf "$tmp"' EXIT

  (
    cd "$tmp" || exit 2
    git init -q .
    mkdir -p docs/1-current/design
    : > docs/1-current/design/EXISTS.md
    cat > README.md <<'EOF'
Valid file: `docs/1-current/design/EXISTS.md`.
Valid dir: `docs/1-current/design/`.
Placeholder: `docs/1-current/design/<name>.md`.
EOF
    git add README.md docs/1-current/design/EXISTS.md
    git -c user.email=selftest@example.invalid -c user.name=selftest commit -qm selftest
  ) || { echo "SELFTEST: FAIL (setup)" >&2; exit 1; }

  out="$(DOC_REFS_ROOT="$tmp" bash "$0" 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]] || ! grep -qx 'DANGLING: 0' <<<"$out"; then
    echo "SELFTEST: FAIL (clean case must be rc=0 / DANGLING: 0)" >&2
    echo "$out" >&2
    exit 1
  fi

  # 追加一条“目录存在、文件不存在”的引用（I-13 的回归用例）。
  cat >> "$tmp/README.md" <<'EOF'
Missing file in an existing dir: `docs/1-current/design/NO_SUCH_FILE.md`.
EOF
  (
    cd "$tmp" || exit 2
    git add README.md
    git -c user.email=selftest@example.invalid -c user.name=selftest commit -qm selftest-missing
  ) || { echo "SELFTEST: FAIL (setup-missing)" >&2; exit 1; }

  out="$(DOC_REFS_ROOT="$tmp" bash "$0" 2>&1)"; rc=$?
  if [[ "$rc" -ne 1 ]]; then
    echo "SELFTEST: FAIL (dangling case must exit 1, got $rc)" >&2
    echo "$out" >&2
    exit 1
  fi
  if ! grep -qx 'DANGLING: 1' <<<"$out"; then
    echo "SELFTEST: FAIL (dangling count must be exactly 1)" >&2
    echo "$out" >&2
    exit 1
  fi
  if ! grep -q 'NO_SUCH_FILE.md' <<<"$out"; then
    echo "SELFTEST: FAIL (dangling line must name NO_SUCH_FILE.md)" >&2
    echo "$out" >&2
    exit 1
  fi

  echo "SELFTEST: PASS (clean=0; dir-exists-file-missing=1)"
  exit 0
}

if (( SELFTEST == 1 )); then
  run_selftest
fi

# ---- 主扫描 ----------------------------------------------------------------
scanned_files=0
refs=0
dangling=0
skipped_lines=0
declare -A seen_file=()

while IFS= read -r hit; do
  file="${hit%%:*}"
  restline="${hit#*:}"
  lineno="${restline%%:*}"
  text="${restline#*:}"

  if is_excluded "$file"; then
    skipped_lines=$((skipped_lines + 1))
    continue
  fi

  if [[ -z "${seen_file[$file]:-}" ]]; then
    seen_file["$file"]=1
    scanned_files=$((scanned_files + 1))
  fi

  tmp="$text"
  while [[ "$tmp" == *docs/* ]]; do
    prefix="${tmp%%docs/*}"
    rest="${tmp#"$prefix"}"
    refs=$((refs + 1))

    if ! check_ref "$rest"; then
      printf 'DANGLING: %s:%s: %s\n' "$file" "$lineno" "$CAND"
      dangling=$((dangling + 1))
    fi

    tmp="${rest#docs/}"
  done
done < <(git grep -n -I -e 'docs/' -- . || true)

echo "SCANNED_FILES: $scanned_files"
echo "DOC_REFS: $refs"
echo "SKIPPED_LINES: $skipped_lines"
echo "DANGLING: $dangling"
(( dangling == 0 )) || exit 1
exit 0
