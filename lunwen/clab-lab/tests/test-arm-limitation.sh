#!/bin/bash
# test-arm-limitation.sh —— 「两臂同读数同分数、只差标签」这条 limitation 的**机器判据**
# （Task 20 Step 3；Task 19 报告 §6.3 的 concern 3）
#
# ============================================================================
# 这条判据守的是什么（**先读这段，比断言本身重要**）
# ============================================================================
# 论文级的 limitation：「同一场景的两条臂（`meta.policy_on` = "0" / "1"）的**链读数与分数逐项相同**，
# **只有 ground truth 标签不同**」。它在三处文档里写着（白皮书 §5.3 / 操作手册 §4.6 / 审计归档 B.5），
# 但在本任务之前**没有任何机器判据守着** —— 只要有人改到臂的评分路径，
# **什么都不会红**，而限制条件会被悄悄推翻。
#
# ⇒ 本判据守的是「**这条 limitation 依然成立**」这个**事实**，不是"分数必须相等"这条审美。
#    **如果它将来变红：那是提示你去更新文档（limitation 不再成立 / 论点要重写），
#    不是叫你把断言放松掉。** 放松断言 = 把论文的一条结论从"有钉子"退回"靠人记得"。
#
# ============================================================================
# 它断言什么（3 条硬判据 + 3 条加固，全部对**仓内已入库的真实数据**）
# ============================================================================
# 数据：lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl（33 条）
#   22 条 targeted_ttp = 11 个场景 × 2 条臂；11 条 recon_playbook
#   臂的身份写在 `meta.policy_on`（**字符串** "0"/"1"，不是布尔）
#   场景名 = `scenario_id` 去掉尾号；尾号是**实例号** `NN=(REPEAT-1)*NARMS+臂+1`
#            ⇒ REPEAT=1 时 off 臂 `-01`、on 臂 `-02`
#
#   判据 1（任务要求）：**标签随臂翻转** —— 每个 targeted 场景**恰好 2 条记录**（"0" 与 "1" 各一条，
#                       11×2=22），且 policy_on=0 ⇒ `compromised=True`；policy_on=1 ⇒ `False`
#   判据 2（任务要求）：**链读数逐项相同** —— 同场景两臂的链因子序列（**去重后**）完全相同
#   判据 3（任务要求）：**分数相同** —— 同场景两臂的 `observed.final_score` 相同
#   判据 4（加固）：**原始链条目序列**（**未**去重）也相同 —— 去重会掩掉"某一臂多挂了重复条目"这类差异
#   判据 5（加固）：**除标签外逐项相同** —— 整个 `observed`（`chain`/`checks`/`domain_scores`/
#                   `effective_weights`/`final_score`…，忽略 `ts`）逐项相同。
#                   这一条才是白皮书/手册里 `ALL-IDENTICAL-EXCEPT-LABEL: 11/11` 那句话的本体
#   判据 6（源指纹）：默认数据集（即未用 `T20_ARM_RECORDS` 覆盖时）的 sha256 必须等于**文档里记的**那个值
#
# 纪律：**只读、离线** —— 不碰 clab / LXD / 容器 / VM / Caldera，不写仓库（临时目录在 $HOME）。
#       **本判据不修改任何数据**；红→绿演示见 Task 20 报告（在一次性克隆上做，仓库数据 sha256 前后相同）。
#
# 故意留的接缝：`T20_ARM_RECORDS=<另一个 jsonl>` 可换数据源（用于"最小变异 ⇒ 必须变红"的演示）。
#   用了它会在输出里**大声**声明"正在用替代数据源"，且判据 6 会说明"不钉指纹" —— 免得这个接缝
#   变成"偷偷绕过判据"的后门。
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$TESTS_DIR/../../.." && pwd)}"
DEFAULT_RECORDS="$REPO/lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl"
RECORDS="${T20_ARM_RECORDS:-$DEFAULT_RECORDS}"
WORK="${HOME:-/root}/t20-arm-limitation"
rm -rf "$WORK"; mkdir -p "$WORK"

[ -f "$RECORDS" ] || { echo "找不到数据集 $RECORDS" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "本判据需要 python3" >&2; exit 2; }

if [ "$RECORDS" != "$DEFAULT_RECORDS" ]; then
  echo "⚠️⚠️ 正在使用**替代数据源**（T20_ARM_RECORDS）：$RECORDS"
  echo "     这**不是**入库的那 33 条数据集 —— 只在「证明判据会红」时这样用。"
fi
echo "  数据集 : $RECORDS"
echo "  期望    : 33 条（targeted_ttp 22 + recon_playbook 11）；11 个场景 × 2 臂"
echo

python3 - "$RECORDS" "$DEFAULT_RECORDS" <<'PY' > "$WORK/out.txt" 2>&1
# -*- coding: utf-8 -*-
"""三条硬判据 + 三条加固，逐条打印 `  ok  ` / `  FAIL ` 行（bash 侧按行计数）。"""
import collections, hashlib, json, os, sys

path, default_path = sys.argv[1], sys.argv[2]
PINNED = "82d37eade414327ba3bdaee8d96d419e84eba64eba80264947f1807531f5b468"

def ok(b, msg):
    print(("  ok   " if b else "  FAIL ") + msg)
    return bool(b)

raw = open(path, "rb").read()
sha = hashlib.sha256(raw).hexdigest()
print("  源指纹 : sha256 %s" % sha)
recs = [json.loads(l) for l in raw.decode("utf-8").splitlines() if l.strip()]

# ---------- 判据 1：标签随臂翻转（含"恰好两条臂"这条计数断言）------------------
cnt = collections.Counter(r.get("ground_truth", {}).get("basis") for r in recs)

def scname(sid):
    """`<场景名>-<实例号 NN>` → `<场景名>`（尾号只在**全是数字**时才去掉）。"""
    head, sep, tail = sid.rpartition("-")
    return head if (sep and tail.isdigit() and head) else sid

groups = collections.OrderedDict()
for r in recs:
    if r.get("ground_truth", {}).get("basis") != "targeted_ttp":
        continue
    groups.setdefault(scname(r.get("scenario_id", "")), []).append(r)

ok1a = ok(len(recs) == 33 and cnt.get("targeted_ttp") == 22 and cnt.get("recon_playbook") == 11,
          "记录条数与口径：33 条 = targeted_ttp 22 + recon_playbook 11（实测 %d 条；%s）"
          % (len(recs), dict(cnt)))

def by_arm(rs):
    d = collections.OrderedDict()
    for r in rs:
        d.setdefault(r.get("meta", {}).get("policy_on"), []).append(r)
    return d

bad_cnt = ["%s=%d" % (k, len(v)) for k, v in groups.items() if len(v) != 2]
ok1b = ok(len(groups) == 11 and not bad_cnt,
          "targeted_ttp 恰好是 11 个场景 × 2 条臂 = 22 条（实测 %d 个场景%s）"
          % (len(groups), "" if not bad_cnt else "；不是 2 条的：" + ", ".join(bad_cnt)))

bad_arm = ["%s→%s" % (k, [r.get("meta", {}).get("policy_on") for r in v])
           for k, v in groups.items()
           if sorted(r.get("meta", {}).get("policy_on") for r in v) != ["0", "1"]]
ok1c = ok(not bad_arm,
          "每个场景的两臂恰好是 `meta.policy_on` **字符串** \"0\"/\"1\" 各一条（11/11）"
          + ("" if not bad_arm else "；异常：" + "; ".join(bad_arm)))

bad_lab = []
for name, rs in groups.items():
    d = by_arm(rs)
    off, on = (d.get("0") or [None])[0], (d.get("1") or [None])[0]
    if off is None or on is None:
        bad_lab.append("%s:缺臂" % name)
        continue
    c_off = off.get("ground_truth", {}).get("compromised")
    c_on = on.get("ground_truth", {}).get("compromised")
    if c_off is not True or c_on is not False:
        bad_lab.append("%s: off=%r on=%r" % (name, c_off, c_on))
ok1d = ok(not bad_lab,
          "★判据1 标签随臂翻转：policy_on=0 ⇒ compromised=True ｜ policy_on=1 ⇒ False（11/11）"
          + ("" if not bad_lab else "；违反：" + "; ".join(bad_lab)))

# ---------- 判据 2：链读数逐项相同（去重后 + 未去重）--------------------------
def chain_of(r):
    return [e.get("factor") for e in (r.get("observed", {}).get("edge_factor_chain") or [])]

def dedup(seq):
    out = []
    for x in seq:
        if x not in out:
            out.append(x)
    return out

bad_ded, bad_raw = [], []
for name, rs in groups.items():
    d = by_arm(rs)
    off, on = (d.get("0") or [None])[0], (d.get("1") or [None])[0]
    if off is None or on is None:
        bad_ded.append("%s:缺臂" % name); bad_raw.append("%s:缺臂" % name)
        continue
    a, b = dedup(chain_of(off)), dedup(chain_of(on))
    if a != b:
        bad_ded.append("%s: %s ≠ %s" % (name, a, b))
    if chain_of(off) != chain_of(on):
        bad_raw.append("%s: %s ≠ %s" % (name, chain_of(off), chain_of(on)))
ok2 = ok(not bad_ded,
         "★判据2 链因子序列（**去重后**）两臂逐项相同（11/11）"
         + ("" if not bad_ded else "；违反：" + "; ".join(bad_ded)))
ok4 = ok(not bad_raw,
         "加固 原始链**条目**序列（未去重）也逐项相同（11/11）"
         + ("" if not bad_raw else "；违反：" + "; ".join(bad_raw)))

# ---------- 判据 3：分数相同 -------------------------------------------------
bad_sc = []
for name, rs in groups.items():
    d = by_arm(rs)
    off, on = (d.get("0") or [None])[0], (d.get("1") or [None])[0]
    if off is None or on is None:
        bad_sc.append("%s:缺臂" % name)
        continue
    s_off = off.get("observed", {}).get("final_score")
    s_on = on.get("observed", {}).get("final_score")
    if s_off != s_on:
        bad_sc.append("%s: off=%r on=%r" % (name, s_off, s_on))
ok3 = ok(not bad_sc,
         "★判据3 两臂 `observed.final_score` 相同（11/11）"
         + ("" if not bad_sc else "；违反：" + "; ".join(bad_sc)))

# ---------- 加固：除标签外**逐项**相同（忽略 ts）------------------------------
def strip_ts(o):
    if isinstance(o, dict):
        return {k: strip_ts(v) for k, v in sorted(o.items()) if k != "ts"}
    if isinstance(o, list):
        return [strip_ts(x) for x in o]
    return o

bad_obs = []
for name, rs in groups.items():
    d = by_arm(rs)
    off, on = (d.get("0") or [None])[0], (d.get("1") or [None])[0]
    if off is None or on is None:
        bad_obs.append("%s:缺臂" % name); continue
    if strip_ts(off.get("observed")) != strip_ts(on.get("observed")):
        bad_obs.append(name)
ok5 = ok(not bad_obs,
         "加固 整个 `observed` 除 `ts` 外逐项相同（chain/checks/domain_scores/"
         "effective_weights/final_score…）—— 这就是 `ALL-IDENTICAL-EXCEPT-LABEL: 11/11`（11/11）"
         + ("" if not bad_obs else "；违反：" + "; ".join(bad_obs)))

# ---------- 加固：源指纹 ------------------------------------------------------
if os.path.realpath(path) == os.path.realpath(default_path):
    ok6 = ok(sha == PINNED,
             "加固 默认数据集指纹 == 文档里记的那个值（期望 %s…，实测 %s…）"
             % (PINNED[:16], sha[:16])
             + ("" if sha == PINNED else "；**数据被换过了** ⇒ 先核对文档与数据哪个才是权威"))
else:
    ok6 = ok(True,
             "加固 源指纹：**使用替代数据源**（T20_ARM_RECORDS）⇒ 不做指纹断言；本文件 sha256 = %s…"
             % sha[:16])

# ---------- 逐场景明细（信息行，不计数）--------------------------------------
print()
print("  逐场景明细（场景 ｜ off/on 标签 ｜ 分数 ｜ 去重链）：")
for name, rs in groups.items():
    d = by_arm(rs)
    off, on = (d.get("0") or [None])[0], (d.get("1") or [None])[0]
    if off is None or on is None:
        print("    %-30s 缺臂" % name); continue
    print("    %-30s off=%-5s on=%-5s  %-7s  %s"
          % (name,
             off.get("ground_truth", {}).get("compromised"),
             on.get("ground_truth", {}).get("compromised"),
             off.get("observed", {}).get("final_score"),
             ",".join(dedup(chain_of(off)))))

allok = all([ok1a, ok1b, ok1c, ok1d, ok2, ok3, ok4, ok5, ok6])
if not allok:
    print()
    print("  ⇒ 红：上面有 FAIL。**先读本脚本头部那段**：这条判据守的是「limitation 依然成立」这个事实；")
    print("    变红通常意味着**文档要更新**（两臂真的分开了 ⇒ 论点要重写），**不是**叫你把断言放松。")
sys.exit(0 if allok else 1)
PY
RC=$?
cat "$WORK/out.txt"

PASS=$(grep -c '^  ok ' "$WORK/out.txt" || true)
FAIL=$(grep -c '^  FAIL' "$WORK/out.txt" || true)
echo
echo "############ 汇总"
echo "  PASS=$PASS FAIL=$FAIL（本判据条数固定 9：3 条硬判据 + 3 条加固 + 3 条计数/源指纹）"
if [ "$RC" -ne 0 ] || [ "$PASS" -ne 9 ] || [ "$FAIL" -ne 0 ]; then
  echo "test-arm-limitation: 未通过（rc=$RC PASS=$PASS FAIL=$FAIL）" >&2
  exit 1
fi
echo "residual: 两臂同读数同分数、只差标签 —— 这条 limitation 的机器判据全绿"
