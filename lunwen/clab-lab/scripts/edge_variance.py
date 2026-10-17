#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# edge_variance.py —— 重复性与方差（Task 5 / Task 21）
# ============================================================================
#
# 输入：**同一基质、同一 config、同一剧本哈希**下的同一场景 × 同一臂的 N 次重复记录
#       （JSONL，契约见 `internal/edgeexp/record.go`）。可以给多个文件（两段批次各一份）。
#
# 输出（任务书 Step 2/Step 3 的四层）：
#   ① **数值层**：`final_score`、五个域分、每条被观测因子的 `effective_factor`
#      的**极差（max−min）与标准差**（**样本**标准差，n−1；本批 n=3，n=1 时 σ 记 None）；
#   ② **判定层**：`observed.acceptable` 是否翻转（并额外核对"阈值判定"
#      `final_score >= observed.threshold` 的结论是否与 `acceptable` 同向 —— 两者不同向说明
#      这条记录的阈值语义与预期不一致，必须看见）；
#   ③ **标签层**：`ground_truth.compromised` 是否翻转（决定"标签可重复性"）；
#   ④ **门禁层**：链因子集（**含同 ID 重复条目**）是否 N 次相同 —— 形状变了就是**环境敏感**。
#
# 口径（**必须随报告一起读**）：
#   · **重复样本不是独立样本**：同一宿主状态的重复，用来估方差/稳定性，
#     **不得**当成 N 个独立样本虚增决策层 N。决策层 N 一律写成
#     `N=<条数>（<场景数> 场景 × <重复数> 次）`。
#   · **不取平均掩盖翻转**：判定/标签/链形状任何一处翻转，都在报告里**单独列成一节**，
#     并把该场景×臂标成「环境敏感」。平均值只用于描述数值层，不用于结论层。
#   · 场景/臂/重复三件事分别从 `scenario_id`（`<场景>-<实例号两位>`）、
#     `meta.policy_on`、`meta.repeat` 读 —— 后者**只在重复号 >1 时写**（第 1 遍缺席 = 1）。
#
# 用法：
#   python3 edge_variance.py --records A.jsonl [--records B.jsonl] \
#                            [--baseline records-dl360-qemu-20261016.jsonl] \
#                            [--json out.json] [--md variance-report.md] \
#                            [--preamble 手写的结论.md] [--strict-exit]
#
# 退出码：0 = 报告已产出（**不**因判定翻转而失败：翻转是**结论**，不是脚本错误）；
#         2 = 输入/口径错误（缺文件、同一(场景,臂,重复) 出现两条、域分键不一致等）。
#         `--strict-exit` 时，只要存在判定/标签/链翻转就退出 3（供门禁使用）。
# ============================================================================
import argparse
import json
import os
import re
import statistics
import sys
import time
from collections import OrderedDict, defaultdict

# 引擎的五个域（顺序与 ssam 的权重表一致；报告列序也按它）
DOMAINS = ['attack_surface', 'business_continuity', 'kernel_security',
           'operation_trust', 'resilience']
DOMAIN_ZH = {
    'attack_surface': '攻击面',
    'business_continuity': '业务连续性',
    'kernel_security': '内核安全',
    'operation_trust': '运营信任',
    'resilience': '韧性',
}
SID_SUFFIX_RE = re.compile(r'-(\d{2})$')


# ---------------------------------------------------------------------------
# 读记录 + 派生字段
# ---------------------------------------------------------------------------
def load_records(paths):
    """逐行读 JSONL；坏行**响亮失败**（静默跳过会让"少了一条重复"读成"方差很小"）。"""
    recs = []
    for path in paths:
        if not os.path.isfile(path):
            sys.exit(f'edge_variance: 记录文件不存在：{path}')
        with open(path, encoding='utf-8') as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception as exc:  # noqa: BLE001 —— 消息里要带行号
                    sys.exit(f'edge_variance: {path}:{lineno} 不是合法 JSON：{exc}')
                rec['_src'] = path
                rec['_lineno'] = lineno
                recs.append(rec)
    return recs


def split_scenario_id(sid):
    """`<场景>-<实例号两位>` ⇒ (场景, 实例号)。实例号只在报告里当"这一条是哪一次"的旁证。"""
    m = SID_SUFFIX_RE.search(sid or '')
    if not m:
        return (sid or '', None)
    return (sid[:m.start()], int(m.group(1)))


def arm_of(rec):
    """臂 = `meta.policy_on`（'0' = 策略不在 / '1' = 策略在）。

    缺席时按 recon 口径记 '1'（历史上 recon 场景本来就是"策略在"），并把 `arm_source`
    记成 'default' —— 报告里能看见"这条臂是从哪读来的"，不许静默补值。
    """
    meta = rec.get('meta') or {}
    raw = meta.get('policy_on')
    pol = str(raw).strip() if raw is not None else ''
    if pol in ('0', '1'):
        return pol, 'meta.policy_on'
    return '1', 'default'


def repeat_of(rec):
    """重复号 = `meta.repeat`（**只在 >1 时写**）⇒ 缺席 = 第 1 遍。"""
    meta = rec.get('meta') or {}
    raw = meta.get('repeat')
    try:
        r = int(raw) if raw is not None else 1
    except (TypeError, ValueError):
        return 1, 'bad-meta.repeat'
    return (r if r >= 1 else 1), ('meta.repeat' if raw is not None else 'absent=1')


def chain_of(rec):
    """链：按记录里的**顺序**取 (factor, trigger_check, c_trigger) 与 `effective_factor`。

    **不去重**：出厂配置的 `[edge_factors.custom]` 与内置同名 ⇒ 同一条链里会出现同 ID 两条，
    这正是门禁⓪ 要在真实记录上核对的事实（"每个因子恰好出现两次"**只是这批矩阵的观测**，
    不是不变量）。故数值层按 `(因子, 出现序号)` 记键，形状层按**有序三元组序列**比。
    """
    chain = ((rec.get('observed') or {}).get('edge_factor_chain')) or []
    seq = []
    occ = defaultdict(int)
    ef = OrderedDict()
    for ob in chain:
        fid = (ob.get('factor') or '').strip().upper()
        trig = (ob.get('trigger_check') or '').strip().upper()
        try:
            ctr = float(ob.get('c_trigger'))
        except (TypeError, ValueError):
            ctr = None
        try:
            eff = float(ob.get('effective_factor'))
        except (TypeError, ValueError):
            eff = None
        occ[fid] += 1
        key = f'{fid}#{occ[fid]}'
        seq.append((fid, trig, ctr))
        ef[key] = eff
    return seq, ef


def derive(rec):
    obs = rec.get('observed') or {}
    gt = rec.get('ground_truth') or {}
    scen, inst = split_scenario_id(rec.get('scenario_id'))
    arm, arm_src = arm_of(rec)
    rep, rep_src = repeat_of(rec)
    seq, ef = chain_of(rec)
    dom = obs.get('domain_scores') or {}
    try:
        score = float(obs.get('final_score'))
    except (TypeError, ValueError):
        score = None
    try:
        thr = float(obs.get('threshold')) if obs.get('threshold') is not None else None
    except (TypeError, ValueError):
        thr = None
    return {
        'sid': rec.get('scenario_id'),
        'instance': inst,
        'scenario': scen,
        'arm': arm,
        'arm_source': arm_src,
        'repeat': rep,
        'repeat_source': rep_src,
        'final_score': score,
        'acceptable': bool(obs.get('acceptable')),
        'threshold': thr,
        'decision_by_threshold': (None if (score is None or thr is None) else (score >= thr)),
        'domains': {d: (float(dom[d]) if dom.get(d) is not None else None) for d in DOMAINS},
        'domain_keys_extra': sorted(set(dom) - set(DOMAINS)),
        'compromised': bool(gt.get('compromised')),
        'label_basis': gt.get('basis'),
        'chain_seq': seq,
        'checks': {(c.get('id') or '').strip().upper():
                   (bool(c.get('passed')), float(c.get('delta') or 0.0))
                   for c in (obs.get('checks') or [])},
        'chain_multiset': tuple(sorted(seq, key=lambda t: (t[0], t[1],
                                                          -1.0 if t[2] is None else t[2]))),
        'ef': ef,
        'env': (rec.get('meta') or {}).get('env'),
        'repeat_meta': (rec.get('meta') or {}).get('repeat'),
        # 输入指纹（Step 1 的"其余参数完全一致"要靠它们证明，不是靠"我记得一样"）
        'config_hash': (rec.get('meta') or {}).get('config_hash'),
        'playbook_hash': (rec.get('meta') or {}).get('playbook_hash'),
        'expected_chain': tuple((rec.get('meta') or {}).get('expected_chain_factors') or ()),
        'expected_baseline': tuple((rec.get('meta') or {}).get('expected_baseline_factors') or ()),
        'observation_target': (rec.get('meta') or {}).get('observation_target'),
        'src': f"{os.path.basename(rec['_src'])}:{rec['_lineno']}",
        'timestamp': (rec.get('meta') or {}).get('timestamp'),
    }


# ---------------------------------------------------------------------------
# 统计
# ---------------------------------------------------------------------------
def stats(values):
    """极差 = max−min；σ = **样本**标准差（n−1）。n<2 时 σ/极差记 None（**不是 0**）。"""
    vals = [v for v in values if v is not None]
    missing = len(values) - len(vals)
    if not vals:
        return {'n': 0, 'values': values, 'missing': missing,
                'min': None, 'max': None, 'range': None, 'stdev': None, 'mean': None}
    return {
        'n': len(vals),
        'values': values,
        'missing': missing,
        'min': min(vals),
        'max': max(vals),
        'range': (max(vals) - min(vals)),
        'stdev': (statistics.stdev(vals) if len(vals) >= 2 else None),
        'mean': (sum(vals) / len(vals)),
    }


def fmt(v, nd=2):
    if v is None:
        return '—'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, float):
        return f'{v:.{nd}f}'
    return str(v)


def fmt_values(values, nd=2):
    return ' / '.join(fmt(v, nd) for v in values)


def arm_label(arm):
    return '策略不在(policy_on=0)' if arm == '0' else '策略在(policy_on=1)'


GLOBAL_FINGERPRINTS = OrderedDict([
    ('config_hash', '采集配置指纹 `meta.config_hash`'),
    ('playbook_hash', '剧本哈希 `meta.playbook_hash`'),
    ('observation_target', '观测主体 `meta.observation_target`'),
])
# **按场景**才该唯一的指纹：不同场景的注入集本来就不同（S1-apparmor 注入 1 个因子、
# S4-all 注入 5 个）⇒ 把它们当"全批唯一"去比会得到一条**假警报**。
# 正确的判据是：**同一个场景的每次重复（且两个臂）必须声明同一个注入集/基线集**。
PER_SCENARIO_FINGERPRINTS = OrderedDict([
    ('expected_chain', '注入集 `meta.expected_chain_factors`'),
    ('expected_baseline', '基线集 `meta.expected_baseline_factors`'),
])


def _fingerprint_value(v):
    if isinstance(v, tuple):
        return ','.join(v) if v else '（空）'
    return str(v)


def diff_fingerprints(inputs):
    """批内**不唯一**的指纹（全批项取值 >1，或某场景的按场景项取值 >1）。

    空列表 = 这批真是"同一条件"下的重复。返回的是人可读的条目名。
    """
    bad = []
    inputs = inputs or {}
    for key, node in (inputs.get('global') or {}).items():
        if len(node.get('values') or {}) > 1:
            bad.append(f"{node['label']}（全批 {len(node['values'])} 个取值）")
    for key, node in (inputs.get('per_scenario') or {}).items():
        for scen in node.get('varying_scenarios') or []:
            bad.append(f"{node['label']} 在场景 {scen} 内不唯一")
    return bad


def input_fingerprints(der):
    """Step 1 的"其余参数与主批完全一致（同一 config、同一剧本哈希）"—— 用记录自带的指纹证明。

    两类判据（口径不同，见上两处常量的注释）：
      · **全批唯一**：`config_hash` / `playbook_hash` / `observation_target`；
      · **按场景唯一**：注入集 / 基线集 —— 同一场景的重复之间必须声明同一份集合。
    任何一个不满足就说明"重复"其实换了条件（那已经不是重复样本了），报告要喊出来。
    """
    out = OrderedDict()
    glob = OrderedDict()
    for key, label in GLOBAL_FINGERPRINTS.items():
        counter = OrderedDict()
        for d in der:
            counter[str(_fingerprint_value(d.get(key)))] = \
                counter.get(str(_fingerprint_value(d.get(key))), 0) + 1
        glob[key] = {'label': label, 'values': counter}
    out['global'] = glob

    per = OrderedDict()
    for key, label in PER_SCENARIO_FINGERPRINTS.items():
        by_scen = OrderedDict()
        for d in der:
            by_scen.setdefault(d['scenario'], set()).add(str(_fingerprint_value(d.get(key))))
        varying = [s for s, vals in by_scen.items() if len(vals) > 1]
        per[key] = {
            'label': label,
            'scenarios': len(by_scen),
            'varying_scenarios': varying,
            'distinct_values': sorted({v for vals in by_scen.values() for v in vals}),
        }
    out['per_scenario'] = per
    return out


# ---------------------------------------------------------------------------
# 组装：分组 / 逐组指标 / 翻转判定
# ---------------------------------------------------------------------------
def build(recs):
    der = [derive(r) for r in recs]
    groups = OrderedDict()
    for d in der:
        groups.setdefault((d['scenario'], d['arm']), []).append(d)

    out_groups = []
    for (scen, arm), items in sorted(groups.items()):
        # 同一 (场景, 臂, 重复) 出现两条 ⇒ **口径错误**（不能靠"平均一下"糊过去）
        seen = {}
        for d in items:
            if d['repeat'] in seen:
                sys.exit(f"edge_variance: 场景 {scen} 臂 {arm} 重复 {d['repeat']} 出现两条记录："
                         f"{seen[d['repeat']]['src']} 与 {d['src']} —— 先把重复号口径理清再分析")
            seen[d['repeat']] = d
        items = sorted(items, key=lambda x: x['repeat'])

        fs = [d['final_score'] for d in items]
        domains = {dom: stats([d['domains'][dom] for d in items]) for dom in DOMAINS}
        # 因子：键 = `因子#出现序号`（同 ID 多条目按序分开，见 chain_of 的说明）
        ef_keys = []
        for d in items:
            for k in d['ef']:
                if k not in ef_keys:
                    ef_keys.append(k)
        factors = OrderedDict()
        for k in sorted(ef_keys):
            factors[k] = stats([d['ef'].get(k) for d in items])

        acceptable_vals = [d['acceptable'] for d in items]
        thr_vals = [d['decision_by_threshold'] for d in items]
        comp_vals = [d['compromised'] for d in items]
        chain_multisets = {json.dumps(d['chain_multiset'], ensure_ascii=False) for d in items}
        chain_seqs = {json.dumps(d['chain_seq'], ensure_ascii=False) for d in items}
        ef_sigs = {json.dumps(d['ef'], ensure_ascii=False, sort_keys=True) for d in items}

        flags = {
            # 判定翻转 = `acceptable` 在 N 次里取值不唯一
            'decision_flip': len(set(acceptable_vals)) > 1,
            'decision_values': acceptable_vals,
            # 阈值判定（score >= threshold）与 `acceptable` 是否同向 —— 不同向要人看
            'threshold_matches_acceptable': all(
                (t is None) or (t == a) for t, a in zip(thr_vals, acceptable_vals)),
            'threshold_values': thr_vals,
            'label_flip': len(set(comp_vals)) > 1,
            'label_values': comp_vals,
            # 链形状：因子集（含同 ID 重复条目）N 次相同？
            'chain_multiset_same': len(chain_multisets) == 1,
            'chain_sequence_same': len(chain_seqs) == 1,
            'factor_values_same': len(ef_sigs) == 1,
        }
        out_groups.append({
            'scenario': scen,
            'arm': arm,
            'arm_label': arm_label(arm),
            'repeats': [d['repeat'] for d in items],
            'n': len(items),
            'records': [{'scenario_id': d['sid'], 'instance': d['instance'],
                         'repeat': d['repeat'], 'repeat_source': d['repeat_source'],
                         'arm_source': d['arm_source'], 'env': d['env'], 'src': d['src'],
                         'timestamp': d['timestamp']} for d in items],
            'final_score': stats(fs),
            'domains': domains,
            'factors': factors,
            'flags': flags,
            'threshold': items[0]['threshold'],
            'extra_domain_keys': sorted({k for d in items for k in d['domain_keys_extra']}),
            'label_basis': items[0]['label_basis'],
            'chain_multiset': json.loads(next(iter(chain_multisets))),
            'chain_seq_per_repeat': [json.loads(json.dumps(d['chain_seq'], ensure_ascii=False))
                                     for d in items],
        })
    return der, out_groups


def cross_arm(der):
    """「两臂同读数同分数、只差标签」这条 **limitation** 在**本次重复批**上的机器判据。

    为什么要在重复批上再验一遍：那条 limitation 是**文档级承诺**（两臂只差策略、其余逐项相同），
    而重复样本是"同一条件采样多次"⇒ 它同时也是**最强的反例来源**。若某场景某次重复里两臂的
    分数/域分/链真的分开了，这里的判据会红 —— 那是**提示去更新文档**，
    **不是**去放松 `test-arm-limitation.sh` 的断言。
    """
    by = {}
    for d in der:
        by.setdefault((d['scenario'], d['repeat']), {})[d['arm']] = d
    rows = []
    for (scen, rep), arms in sorted(by.items()):
        if '0' not in arms or '1' not in arms:
            continue
        a, b = arms['0'], arms['1']
        rows.append({
            'scenario': scen,
            'repeat': rep,
            'score_equal': (a['final_score'] == b['final_score']),
            'domains_equal': (a['domains'] == b['domains']),
            'chain_equal': (a['chain_seq'] == b['chain_seq']),
            'factor_values_equal': (a['ef'] == b['ef']),
            'label_opposite': (a['compromised'] != b['compromised']),
        })
    return rows


def compare_baseline(groups, der, baseline_paths):
    """与 REPEAT=1 主批对照：每个场景×臂，主批那一条的判定/标签/分数/链/失败检查集，
    与 N 次重复**逐次**比。

    **为什么要多比一列"失败检查集之差"**（Task 21 实测踩到）：同一场景在两次不同生命周期的
    VM 上可能只差**一条检查**（例如日志类检查 `OT-018`），而 `final_score` 会因此整体偏移。
    没有这一列，读者只能看到"分数全不同"，然后把原因归给"重复抖动"——那是**错的归因**。
    `observed.checks` 只落盘失败项，故两边的检查字典都只含失败项：差集就是"哪条检查换了状态"。
    """
    if not baseline_paths:
        return None
    base = [derive(r) for r in load_records(baseline_paths)]
    bmap = {}
    for d in base:
        key = (d['scenario'], d['arm'], d['repeat'])
        if key in bmap:
            sys.exit(f"edge_variance: 主批里 {d['scenario']} 臂 {d['arm']} 重复 {d['repeat']} "
                     '出现两条 —— 主批应当是 REPEAT=1')
        bmap[key] = d
    mine = {}
    for d in der:
        mine[(d['scenario'], d['arm'], d['repeat'])] = d
    rows = []
    for g in groups:
        b = bmap.get((g['scenario'], g['arm'], 1))
        row = {'scenario': g['scenario'], 'arm': g['arm'], 'baseline_present': bool(b)}
        if b:
            base_chain = json.loads(json.dumps(b['chain_multiset'], ensure_ascii=False))
            row.update({
                'baseline_final_score': b['final_score'],
                'baseline_acceptable': b['acceptable'],
                'baseline_compromised': b['compromised'],
                'baseline_chain_multiset': base_chain,
                'baseline_check_count': len(b['checks']),
                'repeats_vs_baseline': [],
            })
            union = set()
            for rep in g['repeats']:
                mine_rec = mine.get((g['scenario'], g['arm'], rep))
                diff_ids = []
                if mine_rec is not None:
                    keys = set(mine_rec['checks']) | set(b['checks'])
                    diff_ids = sorted(k for k in keys
                                      if mine_rec['checks'].get(k) != b['checks'].get(k))
                    union |= set(diff_ids)
                row['repeats_vs_baseline'].append({
                    'repeat': rep,
                    'decision_same': (mine_rec['acceptable'] == b['acceptable']) if mine_rec else None,
                    'label_same': (mine_rec['compromised'] == b['compromised']) if mine_rec else None,
                    'score_same': (mine_rec['final_score'] == b['final_score']) if mine_rec else None,
                    'chain_same': (json.dumps(mine_rec['chain_multiset'], ensure_ascii=False)
                                   == json.dumps(base_chain, ensure_ascii=False)) if mine_rec else None,
                    'check_diff_ids': diff_ids,
                    'check_count_delta': ((len(mine_rec['checks']) - len(b['checks']))
                                          if mine_rec else None),
                })
            row['union_check_diff'] = sorted(union)
            row['any_decision_disagreement'] = any(
                not x['decision_same'] for x in row['repeats_vs_baseline'])
            row['any_label_disagreement'] = any(
                not x['label_same'] for x in row['repeats_vs_baseline'])
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def render_md(groups, baseline_rows, meta, preamble=None, cross_rows=None):
    L = []
    add = L.append
    n_records = meta['n_records']
    n_scen = meta['n_scenarios']
    reps = meta['repeat_numbers']
    repeat_counts = sorted({g['n'] for g in groups})
    n_rep = meta['n_repeats_max']
    add(f"# 重复性与方差报告 —— {meta['title']}")
    add('')
    add(f"生成时间（UTC）：{meta['generated_at']}")
    add('')
    add('| 项目 | 值 |')
    add('|---|---|')
    add(f"| 记录文件 | {'<br>'.join(f'`{p}`' for p in meta['records'])} |")
    if meta.get('baseline'):
        add(f"| 对照（REPEAT=1 主批） | {'<br>'.join(f'`{p}`' for p in meta['baseline'])} |")
    add(f"| 记录条数 | {n_records} |")
    add(f"| 场景数 × 臂数 | {n_scen} 场景 × {meta['n_arms']} 臂 = {len(groups)} 个(场景,臂)组 |")
    add(f"| 每组的重复号 | {', '.join(str(r) for r in reps)}"
        f"（每组条数：{', '.join(str(c) for c in repeat_counts)}） |")
    add(f"| 决策阈值 | {fmt(meta.get('threshold'))}（取记录 `observed.threshold`；本批逐条一致） |")
    add('')
    add('> **口径声明（必读）**：**重复样本不是独立样本**。这里的 N 次是**同一宿主状态的重复**，'
        '用来估方差与稳定性；**不得**当成 N 个独立样本去虚增决策层 N。'
        f"决策层 N 一律写成 `N={n_records}（{n_scen} 场景 × {n_rep} 次重复"
        f"{'，含每场景两臂' if meta['n_arms'] > 1 else ''}）`。"
        '报告的结论层**不使用平均值**：任何一个场景只要在 N 次里出现判定/标签/链形状翻转，'
        '就单独列进「判定翻转（环境敏感）」一节，**不隐去、不取平均掩盖**。')
    add('')
    add('> **数值层口径**：极差 = `max − min`；标准差 = **样本**标准差（分母 n−1）。'
        'n=1 时极差与标准差都记 `—`（**不是 0**：一条记录既没有极差也没有标准差，'
        '写成 0 会让"没测"看起来像"完全不抖"）。域分是整数、`final_score` 两位小数。')
    add('')

    if preamble:
        add('---')
        add('')
        add(preamble.rstrip())
        add('')
        add('---')
        add('')

    # ---- 输入指纹 ----
    add('## 0.1 输入指纹（证明这 N 次真是"同一条件"）')
    add('')
    inputs = meta.get('inputs') or {}
    add('**全批唯一项**（这批记录只有一种取值才叫"同一轮批"）：')
    add('')
    add('| 指纹 | 取值 | 条数 |')
    add('|---|---|---|')
    for key, node in (inputs.get('global') or {}).items():
        for v, n in node['values'].items():
            shown = v if len(v) <= 72 else v[:69] + '…'
            add(f"| {node['label']} | `{shown}` | {n} |")
    add('')
    add('**按场景唯一项**（不同场景的注入集本来就不同 ⇒ 判据是「同一场景的每次重复/两个臂」'
        '必须声明同一份集合）：')
    add('')
    add('| 指纹 | 覆盖场景数 | 各场景内唯一？ | 批内出现过的取值个数 |')
    add('|---|---|---|---|')
    for key, node in (inputs.get('per_scenario') or {}).items():
        ok = not node['varying_scenarios']
        add(f"| {node['label']} | {node['scenarios']} | {'是' if ok else '**否**：'}"
            + ('' if ok else '、'.join(node['varying_scenarios']))
            + f" | {len(node['distinct_values'])} |")
    add('')
    diffs = meta.get('input_diffs') or []
    if diffs:
        add(f"**⚠️ 有 {len(diffs)} 项指纹不满足上面的判据**：" + '；'.join(diffs)
            + ' —— 这说明"重复"之间换了条件，方差里混进了条件差异，报告不得把它读成"抖动"。')
    else:
        add('**两类判据都满足** ⇒ 这些重复确实是"同一 config、同一剧本哈希、同一观测主体、'
            '且同一场景内注入集/基线集不变"下的重复采样。')
    add('')
    add('> 为什么要分两类：把"注入集"当全批唯一去比，会因为**不同场景本来就注入不同因子**'
        '（S1-apparmor 1 个、S4-all 5 个）报出假警报；反过来，只比全批而不管场景内部，'
        '又会漏掉"同一场景的第 2 次换了注入集"这类真正的口径错误。')
    add('')

    # ---- 主表 ----
    add('## 1. 逐场景 × 逐臂：`final_score` 与判定/标签/链')
    add('')
    add('| 场景 | 臂 | `final_score`（按重复号顺序） | 极差 | 标准差 | 判定（acceptable） '
        '| 判定翻转 | 标签（compromised） | 标签翻转 | 链形状相同 |')
    add('|---|---|---|---|---|---|---|---|---|---|')
    for g in groups:
        fs = g['final_score']
        add('| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} |'.format(
            g['scenario'], g['arm_label'], fmt_values(fs['values']), fmt(fs['range']),
            fmt(fs['stdev'], 3),
            fmt_values(g['flags']['decision_values']),
            '**是**' if g['flags']['decision_flip'] else '否',
            fmt_values(g['flags']['label_values']),
            '**是**' if g['flags']['label_flip'] else '否',
            ('是' if g['flags']['chain_multiset_same'] else '**否**')
            + ('' if g['flags']['chain_sequence_same'] else '（顺序不同）')))
    add('')

    # ---- 域分 ----
    add('## 2. 五个域分的极差与标准差（逐场景 × 逐臂）')
    add('')
    add('| 场景 | 臂 | ' + ' | '.join(f"{DOMAIN_ZH[d]} 各次 / 极差 / σ" for d in DOMAINS) + ' |')
    add('|---|---|' + '---|' * len(DOMAINS))
    for g in groups:
        cells = []
        for dom in DOMAINS:
            s = g['domains'][dom]
            cells.append(f"{fmt_values(s['values'], 0)} / {fmt(s['range'], 0)} / "
                         f"{fmt(s['stdev'], 2)}")
        add(f"| `{g['scenario']}` | {g['arm_label']} | " + ' | '.join(cells) + ' |')
    add('')
    add('> 域分是**整数**（引擎按整数域累加后取整）⇒ 极差只能取整数；'
        '标准差是这些整数在 n 次重复上的样本标准差，保留两位小数仅为可读。')
    add('')

    # ---- 因子层 ----
    add('## 3. 被观测因子的 `effective_factor` 极差与标准差')
    add('')
    add('链上因子的键写成 `因子#出现序号`：出厂配置把同名因子又写进 `[edge_factors.custom]`，'
        '故同一条链里**同一 ID 会出现两条**（`EF-SELINUX#1` / `EF-SELINUX#2`），'
        '两条的 `effective_factor` **不一定相同**（例如 `EF-002FA#1=0.70`、`EF-002FA#2=0.85`）。'
        '把同 ID 的几条合并成一个数会制造一个引擎从未计算过的量 —— 故按出现序号分开记。')
    add('')
    add('| 场景 | 臂 | 因子#序号 | 各次值 | 极差 | 标准差 |')
    add('|---|---|---|---|---|---|')
    n_zero = 0
    for g in groups:
        for key, s in g['factors'].items():
            rng = s['range']
            if rng == 0:
                n_zero += 1
            mark = '' if (rng or 0) == 0 else ' **≠0**'
            add(f"| `{g['scenario']}` | {g['arm_label']} | `{key}` | "
                f"{fmt_values(s['values'], 4)} | {fmt(rng, 4)}{mark} | {fmt(s['stdev'], 4)} |")
    add('')
    add(f"> 共 {sum(len(g['factors']) for g in groups)} 个 `(场景,臂,因子#序号)` 键；"
        f"其中极差为 0 的有 {n_zero} 个（逐行都在上表里，没有省略）。")
    add('')

    # ---- 环境敏感 ----
    add('## 4. **判定翻转的场景（环境敏感）**')
    add('')
    flip_dec = [g for g in groups if g['flags']['decision_flip']]
    if not flip_dec:
        add('**本批没有场景在重复之间发生判定翻转**'
            '（`observed.acceptable` 在 n 次重复里取值唯一）。')
        add('')
        add('⇒ 就"决策层判定"而言，这批重复在观测到的所有场景×臂上是**稳定**的；'
            '这**不等于**"环境没有抖动"：数值层与链形状层的抖动见 §1/§2/§3，'
            f"且样本量只有 {n_rep} 次重复 × {n_scen} 个场景，"
            '不能外推成"任意环境都稳定"。')
    else:
        add('以下场景×臂**在重复之间发生了判定翻转**（同一条件、同一剧本、同一采集配置，'
            '只是重复采样），一律标为**环境敏感**；**一个都没有隐去、也没有用平均值掩盖**：')
        add('')
        add('| 场景 | 臂 | 判定取值（按重复号顺序） | `final_score` 各次值 | 极差 | 阈值 |')
        add('|---|---|---|---|---|---|')
        for g in flip_dec:
            add(f"| `{g['scenario']}` | {g['arm_label']} | "
                f"{fmt_values(g['flags']['decision_values'])} | "
                f"{fmt_values(g['final_score']['values'])} | {fmt(g['final_score']['range'])} | "
                f"{fmt(g['threshold'])} |")
        add('')
        add('对每个这样的场景，**不得**只用平均值下结论：判定在重复之间就翻转过，'
            '任何"该场景的结论是 X"的陈述都必须写成"在 n 次里有 k 次是 X"。')
    add('')

    flip_lab = [g for g in groups if g['flags']['label_flip']]
    add('### 4b. 标签翻转（`ground_truth.compromised`）')
    add('')
    if not flip_lab:
        add('**没有场景×臂在重复之间发生标签翻转** —— 同一条件的目标 TTP 客观结果在 n 次里一致'
            '（标签可重复）。')
    else:
        add('| 场景 | 臂 | `compromised` 取值（按重复号顺序） |')
        add('|---|---|---|')
        for g in flip_lab:
            add(f"| `{g['scenario']}` | {g['arm_label']} | "
                f"{fmt_values(g['flags']['label_values'])} |")
        add('')
        add('标签翻转比判定翻转更严重：它说明"同一次攻击在客观层就成功了/没成功"都不稳定，'
            '该场景的监督信号不可用于拟合。')
    add('')

    flip_chain = [g for g in groups if not g['flags']['chain_multiset_same']]
    add('### 4c. 链形状翻转（门禁层）')
    add('')
    if not flip_chain:
        add('**没有场景×臂在重复之间改变链的因子集**（含同 ID 重复条目）。')
    else:
        add('下表逐次列出因子集（**不隐去任何一次**）：')
        add('')
        add('| 场景 | 臂 | 各次的链（因子 + 触发检查，按记录顺序） |')
        add('|---|---|---|')
        for g in flip_chain:
            per = '<br>'.join(
                f"第{i + 1}次：" + ' → '.join(f'{f}({t})' for f, t, _c in seq)
                for i, seq in enumerate(g['chain_seq_per_repeat']))
            add(f"| `{g['scenario']}` | {g['arm_label']} | {per} |")
        add('')
        add('链形状变了 ⇒ 该场景×臂**环境敏感**：因子集是场景声明与基线活跃集的联合，'
            '形状变化意味着基线活跃集或触发面在重复之间变了。')
    add('')
    order_diff = [g for g in groups
                  if g['flags']['chain_multiset_same'] and not g['flags']['chain_sequence_same']]
    add(f"链**顺序**在重复之间不同的场景×臂：{len(order_diff)} 个" +
        ('（' + '、'.join(f"`{g['scenario']}`/{g['arm_label']}" for g in order_diff) + '）'
         if order_diff else '（无）') + '。')
    add('')
    add('> 顺序层与因子集层分开报：因子集相同而顺序不同，意味着耦合项的 `ts` 基准随条目顺序变，'
        '属环境敏感的一种，不能用"因子集相同"一句盖过去。')
    add('')

    # ---- 两臂一致性（limitation 的重复批复核）----
    add('')
    add('## 4d. 两臂一致性：「同读数、同分数、只差标签」这条 limitation 在重复批上的复核')
    add('')
    if not cross_rows:
        add('（本批没有"同一场景两臂并存"的记录 ⇒ 这一节跳过。）')
    else:
        agg = OrderedDict()
        for r in cross_rows:
            a = agg.setdefault(r['scenario'], {'n': 0, 'score': True, 'dom': True,
                                               'chain': True, 'ef': True, 'label': True})
            a['n'] += 1
            a['score'] &= r['score_equal']
            a['dom'] &= r['domains_equal']
            a['chain'] &= r['chain_equal']
            a['ef'] &= r['factor_values_equal']
            a['label'] &= r['label_opposite']
        add('| 场景 | 两臂并存的重复数 | `final_score` 全同 | 五域分全同 | 链条目全同 | 因子值全同 | 标签全反 |')
        add('|---|---|---|---|---|---|---|')
        for scen, a in agg.items():
            mark = '' if (a['score'] and a['dom'] and a['chain'] and a['ef'] and a['label']) else ' ❌'
            add(f"| `{scen}` | {a['n']} | {'是' if a['score'] else '**否**'} "
                f"| {'是' if a['dom'] else '**否**'} | {'是' if a['chain'] else '**否**'} "
                f"| {'是' if a['ef'] else '**否**'} | {'是' if a['label'] else '**否**'}{mark} |")
        add('')
        all_ok = all(r['score_equal'] and r['domains_equal'] and r['chain_equal']
                     and r['factor_values_equal'] and r['label_opposite'] for r in cross_rows)
        if all_ok:
            add('**结论：limitation 在本次重复批上仍然成立** —— 每一个场景的每一次重复里，'
                '两臂的链条目、因子 `effective_factor`、五个域分与 `final_score` **全部相同**，'
                '只有 `ground_truth.compromised`（标签）相反。')
            add('')
            add('> 这不是"两臂等价"的证据，而是"**只差策略**"的证据：分数相同 = 分数对策略不敏感，'
                '标签相反 = 客观攻击结果对策略敏感。`test-arm-limitation.sh` 仍然守着这条，'
                '**本报告不据此放松任何断言**。')
        else:
            bad = [f"`{r['scenario']}`（重复 {r['repeat']}）" for r in cross_rows
                   if not (r['score_equal'] and r['domains_equal'] and r['chain_equal']
                           and r['factor_values_equal'] and r['label_opposite'])]
            add(f"**⚠️ limitation 在本次重复批上**不再**逐项成立**：{len(bad)} 个 (场景,重复) 组合"
                '出现了两臂之间的差异（' + '、'.join(bad) + '）。')
            add('')
            add('处置口径（任务书 §4 ⚠️ ② 的原话）：**不许撤 limitation、不许放松断言** —— '
                '这里如实列出差异，并由人去更新文档里的 limitation 措辞'
                '（"重复样本让两臂在中位/多数情况下同读数"是**另一个命题**，需要单独表述）。')
    add('')

    # ---- 与主批对照 ----
    add('## 5. 与 REPEAT=1 主批的对照')
    add('')
    if not baseline_rows:
        add('（本次未给 `--baseline`，这一节跳过。）')
    else:
        add('列含义：网格按重复号顺序给出"同 / **反**"，与主批那一条逐次比对；'
            '最后一列是**失败检查集之差**（`observed.checks` 只落盘失败项 ⇒ 差集就是'
            '"哪条检查换了状态"，它才是分数不同的**原因**列）。')
        add('')
        add('| 场景 | 臂 | 主批 `final_score` / 判定 / 标签 | 与主批**判定** '
            '| 与主批**标签** | 与主批**分数** | 与主批**链** | 与主批失败检查集之差 |')
        add('|---|---|---|---|---|---|---|---|')
        miss = [r for r in baseline_rows if not r['baseline_present']]
        for r in baseline_rows:
            if not r['baseline_present']:
                add(f"| `{r['scenario']}` | {arm_label(r['arm'])} | **主批里没有这一组** "
                    '| — | — | — | — | — |')
                continue
            rv = r['repeats_vs_baseline']
            diffs = sorted({i for x in rv for i in (x.get('check_diff_ids') or [])})
            add('| `{}` | {} | {} / {} / {} | {} | {} | {} | {} | {} |'.format(
                r['scenario'], arm_label(r['arm']),
                fmt(r['baseline_final_score']), fmt(r['baseline_acceptable']),
                fmt(r['baseline_compromised']),
                ' '.join(('同' if x['decision_same'] else '**反**') for x in rv),
                ' '.join(('同' if x['label_same'] else '**反**') for x in rv),
                ' '.join(('同' if x['score_same'] else '**异**') for x in rv),
                ' '.join(('同' if x['chain_same'] else '**异**') for x in rv),
                ('**' + '、'.join(diffs) + '**') if diffs else '无（逐条相同）'))
        add('')
        opp_dec = [r for r in baseline_rows if r.get('any_decision_disagreement')]
        opp_lab = [r for r in baseline_rows if r.get('any_label_disagreement')]
        add(f"- 与主批**判定相反**的场景×臂：{len(opp_dec)} 个" +
            ('（' + '、'.join(f"`{r['scenario']}`/{arm_label(r['arm'])}" for r in opp_dec) + '）'
             if opp_dec else '（无）'))
        add(f"- 与主批**标签相反**的场景×臂：{len(opp_lab)} 个" +
            ('（' + '、'.join(f"`{r['scenario']}`/{arm_label(r['arm'])}" for r in opp_lab) + '）'
             if opp_lab else '（无）'))
        # 分数相同 / 不同的**原因**：按"失败检查集之差"聚合
        none_diff = [r for r in baseline_rows if r['baseline_present'] and not r['union_check_diff']]
        with_diff = [r for r in baseline_rows if r['baseline_present'] and r['union_check_diff']]
        if with_diff:
            ids = sorted({i for r in with_diff for i in r['union_check_diff']})
            score_diff = [r for r in with_diff if any(not x['score_same'] for x in r['repeats_vs_baseline'])]
            add(f"- 与主批**失败检查集不同**的场景×臂：{len(with_diff)} 个，"
                f'差异项并集 = `{", ".join(ids)}`；其中 {len(score_diff)} 个的 `final_score` 也随之不同'
                + ('（⇒ 分数差异的**原因**已定位到这些检查，不是重复抖动）' if score_diff else ''))
            if none_diff:
                add(f"- 与主批**失败检查集逐条相同**的场景×臂：{len(none_diff)} 个"
                    '（分数仍可能因链/spc 口径相同而相同；若分数不同而检查集相同，说明差异在'
                    '**引擎侧口径**，必须单独查，不能归给"抖动"）')
        else:
            add(f"- 与主批**失败检查集逐条相同**的场景×臂：{len(none_diff)} 个"
                '（⇒ `final_score` 的差异（若有）不来自检查层）')
        if miss:
            add(f"- 只在重复批次里出现、主批没有的场景×臂：{len(miss)} 个"
                '（主批是 REPEAT=1 的一段；重复批次若覆盖了主批之外的场景属正常，报告不得隐去）')
        add('')
        add('> 与主批的对照是**同基质、同 config、同剧本哈希**下的对照；'
            '若某次重复与主批结论相反，那本身就是"判定不稳"的证据，'
            '不能因为它只是"n 次里的一次"而丢掉。')
    add('')

    # ---- 方法学 ----
    add('## 6. 方法学备注（怎么复现、哪些数不能怎么用）')
    add('')
    add('1. **重复轴与臂是两个独立维度**：`scenario_id` 尾号是**实例号**'
        '`NN = (REPEAT−1)×NARMS + 臂 + 1`（NARMS = 该场景的实例数，targeted 开臂时 = 2），'
        '臂的身份写在 `meta.policy_on`，重复号写在 `meta.repeat`（**只在 >1 时写**）。'
        '故同一份记录文件可以承载 1..N 各一遍，且各次的 `scenario_id` 互不重叠。')
    add('2. **重复样本不是独立样本**（再强调一次）：各次重复共用同一宿主状态、同一 VM、'
        '同一 Caldera、同一剧本；n=3 的样本标准差只能当"抖动尺度"的估计，'
        '**不能**当独立同分布样本去算置信区间或做显著性检验；决策层 N 的写法见本文开头。')
    add('3. **因子层的键按出现序号分**（§3）：同 ID 多条是配置层的真实形态，'
        '合并会制造引擎从未计算的量。')
    add('4. **复现命令**：`python3 lunwen/clab-lab/scripts/edge_variance.py '
        '--records <本批记录> [--baseline <主批记录>] --json <out.json> --md <report.md>`；'
        '跑批侧的口径（一份文件承载 1..N、门禁判据）见操作手册「重复轴」一节。')
    add('')
    return '\n'.join(L) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description='重复性与方差（对同一场景×同一臂的 N 次重复）')
    ap.add_argument('--records', action='append', default=[],
                    help='重复批次的记录 JSONL（可重复给，多个文件按并集分析）')
    ap.add_argument('--baseline', action='append', default=[],
                    help='REPEAT=1 的主批记录（可重复给），用于 §5 对照')
    ap.add_argument('--json', dest='json_out', default='', help='机器可读的完整结果写到这里')
    ap.add_argument('--md', dest='md_out', default='', help='Markdown 报告写到这里')
    ap.add_argument('--preamble', default='', help='插入报告开头的 Markdown 文件（手写结论/口径）')
    ap.add_argument('--title', default='方向② 边缘因子重复性（每场景 3 次）')
    ap.add_argument('--strict-exit', action='store_true',
                    help='存在判定/标签/链翻转时退出 3（默认 0：翻转是结论，不是脚本错误）')
    args = ap.parse_args(argv)

    if not args.records:
        sys.exit('edge_variance: 至少要给一个 --records（重复批次的记录文件）')
    recs = load_records(args.records)
    der, groups = build(recs)
    baseline_rows = compare_baseline(groups, der, args.baseline) if args.baseline else None
    cross_rows = cross_arm(der)

    repeat_numbers = sorted({d['repeat'] for d in der})
    thresholds = {g['threshold'] for g in groups}
    fingerprints = input_fingerprints(der)
    meta_info = {
        'title': args.title,
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'records': args.records,
        'baseline': args.baseline or None,
        'n_records': len(recs),
        'n_scenarios': len({g['scenario'] for g in groups}),
        'n_arms': len({g['arm'] for g in groups}),
        'repeat_numbers': repeat_numbers,
        'n_repeats_max': (max(g['n'] for g in groups) if groups else 0),
        'threshold': (next(iter(thresholds)) if len(thresholds) == 1 else None),
        'extra_domain_keys': sorted({k for g in groups for k in g['extra_domain_keys']}),
        'arm_sources': sorted({r['arm_source'] for g in groups for r in g['records']}),
        'repeat_sources': sorted({r['repeat_source'] for g in groups for r in g['records']}),
        'inputs': fingerprints,
        'input_diffs': diff_fingerprints(fingerprints),
    }
    if meta_info['input_diffs']:
        print('edge_variance: ⚠️ 输入指纹不满足"同一条件"判据：'
              f"{'；'.join(meta_info['input_diffs'])}（报告里会单独喊出来）")
    if len(thresholds) != 1:
        sys.exit(f'edge_variance: 记录的 `observed.threshold` 不唯一（{sorted(thresholds)}）—— '
                 '同一批重复必须是同一阈值，否则判定层不可比')
    if meta_info['extra_domain_keys']:
        sys.exit(f"edge_variance: 出现五域之外的域分键 {meta_info['extra_domain_keys']} —— "
                 '域集合变了，报告会把方差算到错的列上')

    preamble = None
    if args.preamble:
        if not os.path.isfile(args.preamble):
            sys.exit(f'edge_variance: --preamble 文件不存在：{args.preamble}')
        with open(args.preamble, encoding='utf-8') as fh:
            preamble = fh.read()

    md = render_md(groups, baseline_rows, meta_info, preamble, cross_rows)
    payload = {
        'meta': meta_info,
        'declaration': {
            'repeat_samples_are_not_independent': True,
            'decision_layer_n': f"N={len(recs)}（{meta_info['n_scenarios']} 场景 × "
                                f"{meta_info['n_repeats_max']} 次重复"
                                f"{'，含每场景两臂' if meta_info['n_arms'] > 1 else ''}）",
            'stdev': '样本标准差（分母 n−1）；n=1 时记 None',
            'range': 'max − min；n=1 时记 None',
        },
        'groups': groups,
        'cross_arm_limitation': {
            'rows': cross_rows,
            'holds_everywhere': (None if not cross_rows else all(
                r['score_equal'] and r['domains_equal'] and r['chain_equal']
                and r['factor_values_equal'] and r['label_opposite'] for r in cross_rows)),
        },
        'flips': {
            'decision': [g['scenario'] + '/' + g['arm'] for g in groups
                         if g['flags']['decision_flip']],
            'label': [g['scenario'] + '/' + g['arm'] for g in groups
                      if g['flags']['label_flip']],
            'chain_multiset': [g['scenario'] + '/' + g['arm'] for g in groups
                               if not g['flags']['chain_multiset_same']],
            'chain_sequence': [g['scenario'] + '/' + g['arm'] for g in groups
                               if not g['flags']['chain_sequence_same']],
            'factor_values': [g['scenario'] + '/' + g['arm'] for g in groups
                              if not g['flags']['factor_values_same']],
            'threshold_mismatch': [g['scenario'] + '/' + g['arm'] for g in groups
                                   if not g['flags']['threshold_matches_acceptable']],
        },
        'baseline_comparison': baseline_rows,
    }

    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write('\n')
    if args.md_out:
        with open(args.md_out, 'w', encoding='utf-8') as fh:
            fh.write(md)

    # 控制台摘要：口径 + 翻转清单（不做平均）
    print(f"edge_variance: 记录 {len(recs)} 条 / {meta_info['n_scenarios']} 场景 / "
          f"重复号 {repeat_numbers} / 阈值 {fmt(meta_info['threshold'])}")
    print(f"edge_variance: 决策层 {payload['declaration']['decision_layer_n']}"
          '（重复样本不是独立样本）')
    for kind in ('decision', 'label', 'chain_multiset', 'chain_sequence', 'factor_values',
                 'threshold_mismatch'):
        items = payload['flips'][kind]
        print(f"edge_variance: 翻转[{kind}] = {len(items)}"
              + (f"：{', '.join(items)}" if items else '（无）'))
    if args.json_out:
        print(f'edge_variance: JSON → {args.json_out}')
    if args.md_out:
        print(f'edge_variance: Markdown → {args.md_out}')

    bad = (payload['flips']['decision'] or payload['flips']['label']
           or payload['flips']['chain_multiset'] or payload['flips']['threshold_mismatch'])
    if args.strict_exit and bad:
        return 3
    return 0


if __name__ == '__main__':
    sys.exit(main())
