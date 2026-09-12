#!/bin/bash
# ============================================================================
# edge_spec_lib.sh —— `-factors` / `-weights` 的**唯一**推导实现（被 source 的函数库）
# ============================================================================
#
# 这不是可执行脚本，而是被 `edge_matrix.sh` 与 `edge_threshold_sensitivity.sh` **共用**的
# 函数库：没有副作用（只读配置、只往 stdout 打印），source 进来即可用。
#
# 为什么抽出来（spec §5.4.6 的纪律：`f_i` 的单一来源是**配置**，不在脚本里抄第二份）：
# 门禁①（默认阈值的候选对比）与阈值敏感性行（`-threshold <值>`）必须用**同一份**
# `-factors`/`-weights`，否则"两份报告只在阈值上不同"这句话就不成立 —— 而漂移的表现形式
# 是"两份报告用了不同的因子权重"，从报告文本里看不出来。
#
# 解析口径（与引擎 `ParamsFromConfig` / 生效权重表同构，逐条都有出处）：
#   · 内置六因子取 [edge_factors]，其中**只有** `two_factor_failure` 会被
#     [edge_factors.level4_override] 覆盖（解析层只认这一个键：config.go 的
#     `sections["edge_factors.level4_override"]` 分支写死了它），其余五个键即使写在
#     该段里也不会被消费 —— 这里必须同构，否则会算出引擎从不使用的 f；
#   · [edge_factors.custom] 里**不与内置同名**的条目进入因子集（出厂模板里那 7 行
#     因此只有 `EF-3FA=0.82` 是新的；EF-3FA 是**普通因子**，必须进 -factors，
#     漏掉它会让工具**静默丢弃**链上那条惩罚）；
#   · 四核心域取 [weights]，`kernel_security` 取 [extension_weights]（引擎的口径）。
#
# 键名与空白按解析器同构处理：段名小写化、键名 trim+小写、注释行（# / ;）不算声明。
# 缺键/非数字一律**响亮失败**（return 1），不静默补值。
# ============================================================================

# derive_factors_spec <config.ini> —— 打印 `ID=f,ID=f,…`
derive_factors_spec() {
  local cfg="${1:-}"
  if [ -z "$cfg" ]; then
    echo "edge_spec_lib: derive_factors_spec 需要配置路径参数" >&2
    return 2
  fi
  if [ ! -f "$cfg" ]; then
    echo "edge_spec_lib: 配置不存在: $cfg" >&2
    return 1
  fi
  python3 - "$cfg" <<'PY'
import sys
sections, current = {}, 'global'
for raw in open(sys.argv[1], encoding='utf-8'):
    line = raw.strip()
    if not line or line.startswith('#') or line.startswith(';'):
        continue
    if line.startswith('[') and line.endswith(']'):
        current = line[1:-1].strip().lower(); sections.setdefault(current, {}); continue
    if '=' not in line:
        continue
    k, v = line.split('=', 1)
    sections.setdefault(current, {})[k.strip().lower()] = v.strip()
ef = sections.get('edge_factors', {})
lvl = sections.get('edge_factors.level4_override', {})
custom = sections.get('edge_factors.custom', {})
mapping = [('EF-002FA', 'two_factor_failure'), ('EF-SYNCOOKIE', 'syn_cookie_disabled'),
           ('EF-SELINUX', 'selinux_disabled'), ('EF-APPARMOR', 'apparmor_disabled'),
           ('EF-NO-SIEM', 'no_siem'), ('EF-NO-IDS', 'no_ids')]
out, seen = [], set()
for fid, key in mapping:
    # 解析层**只对 `two_factor_failure`** 读 [edge_factors.level4_override]（config.go:290-294
    # 那个分支写死了这一个键），其余五个键即使出现在该段里也不会被消费 —— 这里必须同构，
    # 否则会算出一个引擎从不使用的 f（Fix round 2 指出的 I4 不精确处）。
    val = lvl.get(key, ef.get(key)) if key == 'two_factor_failure' else ef.get(key)
    if val is None:
        raise SystemExit(f'edge_spec_lib: 配置 {sys.argv[1]} 缺 [edge_factors] {key}')
    out.append(f'{fid}={val}')
    seen.add(fid.upper())
for raw_id, val in custom.items():
    fid = raw_id.strip().upper()
    if not fid or fid in seen:
        continue
    try:
        f = float(val)
    except ValueError:
        raise SystemExit(f'edge_spec_lib: [edge_factors.custom] {raw_id} = {val!r} 不是数字')
    out.append(f'{fid}={f}')
    seen.add(fid)
print(','.join(out))
PY
}

# derive_weights_spec <config.ini> —— 打印 `domain=w,…`（生效权重表）
derive_weights_spec() {
  local cfg="${1:-}"
  if [ -z "$cfg" ]; then
    echo "edge_spec_lib: derive_weights_spec 需要配置路径参数" >&2
    return 2
  fi
  if [ ! -f "$cfg" ]; then
    echo "edge_spec_lib: 配置不存在: $cfg" >&2
    return 1
  fi
  python3 - "$cfg" <<'PY'
import sys
sections, current = {}, 'global'
for raw in open(sys.argv[1], encoding='utf-8'):
    line = raw.strip()
    if not line or line.startswith('#') or line.startswith(';'):
        continue
    if line.startswith('[') and line.endswith(']'):
        current = line[1:-1].strip().lower(); sections.setdefault(current, {}); continue
    if '=' not in line:
        continue
    k, v = line.split('=', 1)
    sections.setdefault(current, {})[k.strip().lower()] = v.strip()
out = []
for dom in ('attack_surface', 'business_continuity', 'operation_trust', 'resilience', 'kernel_security'):
    for sec in ('weights', 'extension_weights'):
        val = sections.get(sec, {}).get(dom)
        if val is not None:
            out.append(f'{dom}={val}'); break
print(','.join(out))
PY
}
