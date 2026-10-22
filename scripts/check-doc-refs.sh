#!/usr/bin/env bash
# ============================================================================
# check-doc-refs.sh — 文档引用完整性检查
#
# 扫描所有被跟踪的文本文件，抽出形如 `docs/...` 的路径（含反引号与
# Markdown 链接里的），断言每个路径在磁盘上存在。
#
# 输出：`DANGLING: N`；退出码 0 当且仅当 N == 0。
#
# 例外（按设计跳过）：
#   1. docs/MIGRATION_MAP.md —— 它是迁移记录，按设计保留旧路径；
#   2. lunwen/paper/attacker-cognitive-loop-paper.tex —— 论文冻结，不改。
#   3. 省略号/通配符占位（`docs/...`、`docs/**`）不作为具体路径断言。
#
# 用法（仓库根目录）：
#   bash scripts/check-doc-refs.sh
# ============================================================================
set -u

cd "$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "FATAL: not inside a git work tree" >&2
  echo "DANGLING: 0"
  exit 2
}

EXCLUDED_FILES=(
  "docs/MIGRATION_MAP.md"
  "lunwen/paper/attacker-cognitive-loop-paper.tex"
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

    best="$(match_known "$rest")"
    ok=0
    if [[ -n "$best" ]]; then
      if [[ "$best" == "docs/" ]]; then
        # 仅命中 docs/ 本身：只有后面紧跟分隔符/空白时才认可；
        # 否则说明它是一段更长的、不存在的路径。
        after="${rest#docs/}"
        case "$after" in
          ""|" "*|$'\t'*|")"*|"]"*|"}"*|$'\x60'*|"'"*|'"'*|"<"*|">"*|"|"*|","*|";"*|"。"*|"，"*|"；"*|"、"*|"..."*|"…"*|"*"*)
            ok=1
            ;;
        esac
      else
        ok=1
      fi
    fi

    if (( ! ok )); then
      cand="$rest"
      cand="${cand%%[[:space:]]*}"
      cand="${cand%%[\`\"\'<>|\)\]\，\。\；\、]*}"
      printf 'DANGLING: %s:%s: %s\n' "$file" "$lineno" "$cand"
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
