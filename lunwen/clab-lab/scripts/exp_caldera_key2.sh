#!/bin/bash
# ============================================================================
# exp_caldera_key2.sh —— **就地**核对 C2 口令（只在 Caldera 宿主上跑；不连 API）
# ============================================================================
#
# Task 14 脱敏（D2）改了**两处**东西，都因为原文件里带着"口令的可用材料"：
#   ① `for key in <候选表>; do` —— 候选表里第一个就**是那个默认口令的明文本身**（它同时被
#      写死在另外 17 个被跟踪的文件里）。现在候选口令**不再写死**，改为从环境变量 /
#      未跟踪的本地配置读（`EDGEEXP_CALDERA_CANDIDATES`，空格分隔）。
#   ② 文件里内联着 `api_key_red` 的 **argon2id 哈希原文**（一条 PHC 串）
#      —— 那是口令的**校验材料**：拿到它就能离线爆破，而本文件同时给出了候选明文
#      ⇒ 等于"靶子 + 答案"一起提交。现在哈希**就地**从 `/opt/caldera/conf/default.yml` 读，
#      仓库里一个字都不留。
#   ③ 原来那段"给已知口令生成新哈希"把**新口令的明文**写死在文件里 —— 也已移除：
#      新口令只在**运行时**给（`EDGEEXP_CALDERA_NEWKEY`），不落盘、不进仓库。
#
# 用法（在 Caldera 宿主上）：
#   EDGEEXP_CALDERA_CANDIDATES='k1 k2' bash exp_caldera_key2.sh     # 核对若干候选
#   EDGEEXP_CALDERA_KEY='<口令>'        bash exp_caldera_key2.sh     # 只核对一个
#   EDGEEXP_CALDERA_NEWKEY='<新口令>'   bash exp_caldera_key2.sh     # 顺带生成新哈希
#
# ⚠️ 这是**一次性排查脚本**（历史产物），不是跑批链路的一部分；缺材料时**响亮失败**，
#    不猜、不降级 —— 与 scripts/edge_c2_key.sh 的三条红线同一条纪律。
# ============================================================================
set -uo pipefail

echo "=== test candidate keys against api_key_red ==="
cd /opt/caldera || { echo "exp_caldera_key2: 没有 /opt/caldera（本脚本只在 Caldera 宿主上有效）" >&2; exit 2; }

# --- 候选口令：环境变量 → 未跟踪的本地配置 → 响亮失败 -----------------------------
CAND="${EDGEEXP_CALDERA_CANDIDATES:-${EDGEEXP_CALDERA_KEY:-}}"
_local_env="${EDGEEXP_LOCAL_ENV:-${HOME:-/root}/.config/asscor/edgeexp.local.env}"
if [ -z "$CAND" ] && [ -r "$_local_env" ]; then
  # shellcheck disable=SC1090  # 路径由环境变量决定，故意的（未跟踪的本地文件）
  . "$_local_env"
  CAND="${EDGEEXP_CALDERA_CANDIDATES:-${EDGEEXP_CALDERA_KEY:-}}"
fi
if [ -z "$CAND" ]; then
  {
    echo "exp_caldera_key2: **缺少候选口令** —— 仓库不再提供任何明文候选（原 candidate 表里的"
    echo "  第一个就是真口令的明文，已移除）。"
    echo "  修法：① EDGEEXP_CALDERA_CANDIDATES='k1 k2 …' bash $0；"
    echo "        ② 或写进未跟踪的本地配置 $_local_env（EDGEEXP_CALDERA_CANDIDATES=… / EDGEEXP_CALDERA_KEY=…）。"
  } >&2
  exit 2
fi

# --- 哈希：**就地**读 Caldera 自己的配置（不再内联进仓库）--------------------------
HASH="$(python3 - <<'PY'
import re
cfg = '/opt/caldera/conf/default.yml'
try:
    txt = open(cfg, encoding='utf-8').read()
except OSError as exc:
    raise SystemExit('exp_caldera_key2: 读不到 %s（%s）' % (cfg, exc))
m = re.findall(r'^\s*api_key\w*\s*:\s*(.+?)\s*$', txt, re.M)
if not m:
    raise SystemExit('exp_caldera_key2: %s 里没有 api_key* 字段' % cfg)
print(m[0].strip().strip('"').strip("'"))
PY
)"
if [ -z "$HASH" ]; then
  echo "exp_caldera_key2: 读不到 api_key_red 的哈希（/opt/caldera/conf/default.yml）" >&2
  exit 2
fi
echo "（哈希来源：/opt/caldera/conf/default.yml 的 api_key* 字段；**不打印**其内容）"

for key in $CAND; do
  result=$(/opt/caldera/venv/bin/python -c "
from app.utility.config_util import verify_hash
h = '''$HASH'''
print(verify_hash(h, '''$key'''))
" 2>&1)
  echo "key='$key' -> $result"
done

echo "=== generate new api_key_red hash for a known key ==="
if [ -n "${EDGEEXP_CALDERA_NEWKEY:-}" ]; then
  /opt/caldera/venv/bin/python -c "
from passlib.hash import argon2
print(argon2.using(rounds=3, salt_size=16).hash('''$EDGEEXP_CALDERA_NEWKEY'''))
" 2>&1
else
  echo "（未给 EDGEEXP_CALDERA_NEWKEY ⇒ 跳过。原来这里把**一个写死的新口令**放在文件里"
  echo "  （第二处明文），已按脱敏铁律移除：新口令只在运行时给，不落盘、不进仓库）"
fi
echo DONE
