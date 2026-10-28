# 重复性与方差报告 —— 方向② 边缘因子重复性（每场景 3 次）

生成时间（UTC）：2026-10-18T17:19:11Z

| 项目 | 值 |
|---|---|
| 记录文件 | `records-t21-qemu-rpt-targeted.jsonl`<br>`records-t21-qemu-rpt-nontargeted.jsonl` |
| 对照（REPEAT=1 主批） | `records-dl360-qemu-20261016.jsonl` |
| 记录条数 | 99 |
| 场景数 × 臂数 | 22 场景 = 11 个两臂组 + 11 个单臂组 ⇒ 33 个(场景,臂)组 |
| 段 | `records-t21-qemu-rpt-targeted.jsonl`（66 条）<br>`records-t21-qemu-rpt-nontargeted.jsonl`（33 条） |
| 每组的重复号 | 1, 2, 3（每组条数：3） |
| 决策阈值 | 80.00（取记录 `observed.threshold`；逐条一致 —— 按段核对：`records-t21-qemu-rpt-targeted.jsonl`=80.00；`records-t21-qemu-rpt-nontargeted.jsonl`=80.00） |

> **路径口径（Minor-2 修正）**：上表打的是**入库文件名** —— 三份数据集都在 `lunwen/clab-lab/data/edgefactors/` 下，正文引用一律用文件名（否则同一批数据会因为「运行时路径」与「入库文件名」两种写法被读成两批）。本次分析实际读取的路径见下面一行，它只服务于复现，不是报告口径。

> 本次调用的原始路径（复现用）：`lunwen/clab-lab/data/edgefactors/records-t21-qemu-rpt-targeted.jsonl`、`lunwen/clab-lab/data/edgefactors/records-t21-qemu-rpt-nontargeted.jsonl`；对照 `lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl`。

> **口径声明（必读）**：**重复样本不是独立样本**。这里的 N 次是**同一宿主状态的重复**，用来估方差与稳定性；**不得**当成 N 个独立样本去虚增决策层 N。决策层 N 一律写成 `N=99（22 场景 × 3 次重复，含 11 个两臂组、11 个单臂组）`。报告的结论层**不使用平均值**：任何一个场景只要在 N 次里出现判定/标签/链形状翻转，就单独列进「判定翻转（环境敏感）」一节，**不隐去、不取平均掩盖**。

> **用途边界（必读）**：「零方差」测的是**基质稳定性与评分确定性** —— 同一份输入在同一台基质上重复采样，分数/域分/因子值逐项不变（确定性），且基质本身不抖（稳定性）。它**不是** **模型噪声**的估计：模型（候选参数）在这些重复里根本没变，方差里不含任何模型随机性。真正的环境敏感性不体现在"同一批的重复之间"，而体现在**批与批之间**（不同生命周期的 VM/宿主状态 ⇒ 见 §5 与主批的对照）。

> **数值层口径**：极差 = `max − min`；标准差 = **样本**标准差（分母 n−1）。n=1 时极差与标准差都记 `—`（**不是 0**：一条记录既没有极差也没有标准差，写成 0 会让"没测"看起来像"完全不抖"）。域分是整数、`final_score` 两位小数。

---

## 0. 结论先说

> 本节的“结论”是**手写**的（由 `--preamble` 插入），下面的 §0.1–§6 是脚本按记录算出来的。
> 两者若冲突，以**脚本算出来的数**为准，并回来修这一节。
> 复现命令见 §6 第 4 条（`--preamble` 就是本文件）。

- **样本**：两段合计 **99 条** = targeted 段（11 场景 × 2 臂 × 3 轮 = **66 条**）+ 非 targeted 段
  （11 场景 × 1 臂 × 3 轮 = **33 条**），基质 `qemu`（VM 910），两段各一份记录文件。
  两段**设计上就用不同剧本**：targeted 段用 TTP pair 剧本（`playbook_hash = e585b846…`）、
  非 targeted 段用固定 Discovery 侦察剧本（`b112ca3c…`）⇒ **段内各自唯一**，
  合并后出现 2 个取值是本报告合并两段的必然结果，**不是**“重复之间换了条件”（判据见 §0.1）。

- **结论 ①（批内零方差，两段都是）**：targeted 段 **22** 个 `(场景, 臂)` 组、非 targeted 段 **11** 个组，
  每一组的 `final_score`、五个域分、以及每条被观测因子的 `effective_factor` 在**三遍重复之间逐项相同**
  （极差 `0`、样本标准差 `0.000`，§1–§3 逐行列出、没有省略）。**判定**（`observed.acceptable`）
  在两段里都没有翻转；**链**的因子集与条目顺序也都没有翻转（§4/§4c）。

- **补充事实（不弱化）**：非 targeted 段有 **1** 个**标签**翻转 —— `S2-syn-cookie-no-ids`／策略在
  （`true / false / true`）。它与“分数零方差”并不矛盾：分数是**部署评分**（确定性），
  标签是**客观攻击结果**。**定性按客观层四个字段判，不靠“时间相关”这类猜测**（第一次审计
  Important-4 的纠正）：逐次取值是 `ttps_achieved 36 → 0 → 36`、`nodes_affected 1 → 0 → 1`、
  `time_to_compromise_s 5 → 0 → 4`、`block_effective false → true → false`，而三次的
  `observed.checks`（去 `ts`）**逐字段完全相同**（各 43 条）⇒ 中间那一次是**攻击侧根本没有执行**
  （一条 TTP 都没打成、受影响节点 0），**既不是“测量抖动”，也不是“防护拦住了”**；
  分数那三项完全相同则是打分输入相同的必然结果（§4b-1 逐次列表）。
  ⚠️ **`block_effective=true` 在侦察口径下只是 `len(successes)==0`**（`edge_attack.sh:948`）——
  “攻击侧没执行”同样让 `successes` 为空 ⇒ 它**不是**“防护生效”的证据，极易被引成“策略拦住了”；
  引用它时必须同时给出 `ttps_achieved` 与 `nodes_affected`。
  如实写在 §4b，**不隐去、不取平均**：这一组的监督信号不可用于拟合。

- **结论 ②（跨批环境敏感，判据按段）**：与 `REPEAT=1` 主批（`records-dl360-qemu-20261016.jsonl`，
  同基质、同 config、同剧本哈希）对照，
  - **targeted 段**：决策/标签/链 **22/22 相同**，`final_score` **22/22 不同**；
  - **非 targeted 段**：决策 **11/11 相同**、链 **11/11 相同**、标签 **10/11 相同**
    （差的那 1 个就是上面 §4b 的重复内翻转）、`final_score` **11/11 不同**；
  - 两段的分数差异**原因都定位到唯一一条检查** —— `OT-018`（日志类检查）：主批那次失败、
    重复批三次都通过，而 `observed.checks` **只落失败项** ⇒ 重复批比主批少一条，
    `final_score` 因此整体偏移。⇒ 这是**环境状态差**（宿主的日志内容/生命周期不同），
    **不是**重复抖动。逐组证据见 §5 的「与主批失败检查集之差」列与「逐段小计」。

- **用途边界（引用时必须带上）**：「零方差」测的是**基质稳定性与评分确定性** —— 同一份输入在同一台
  基质上重复采样，分数/域分/因子值逐项不变（确定性），且基质本身不抖（稳定性）。
  它**不是模型噪声**的估计（候选参数在重复里根本没变）；真正的环境敏感性体现在
  **批与批之间**（§5），而不是同一批的重复之间。样本量只有 3 次重复 ⇒ **本次 3 次重复里
  未观测到任何抖动**；但 **n=3 给不出方差的界**（3 个点的非参数上界不存在，样本标准差 0
  也不是上界估计），更不足以据此外推，**重复样本不是独立样本**，不得据此算置信区间或做显著性检验。

---

## 0.1 输入指纹（证明这 N 次真是"同一条件"）

> **判据按段做**（Task 22 纠正的假警报）：一份报告可以把多个**记录文件**（段）合并分析，而不同段**本来就可以用不同剧本**（本批：`targeted` 段用 TTP pair 剧本、非 targeted 段用固定 Discovery 侦察剧本 —— 这是**设计如此**，不是"换了条件"）。故"唯一"的判据只在**段内**成立：把段合并起来数取值个数，必然把段间差异读成"漂移"。

**段内唯一项**（每个段的每种指纹只允许一种取值）：

| 段（记录文件） | 条数 | 指纹 | 段内取值个数 | 段内取值 |
|---|---|---|---|---|
| `records-t21-qemu-rpt-targeted.jsonl` | 66 | 采集配置指纹 `meta.config_hash` | 1 | `dd334cd724ba0c4c`（66 条） |
| `records-t21-qemu-rpt-targeted.jsonl` | 66 | 剧本哈希 `meta.playbook_hash` | 1 | `sha256:e585b8465faab05d236e39b19cc99addfbf4adc0fa2fc8891c4ee278bef60f19`（66 条） |
| `records-t21-qemu-rpt-targeted.jsonl` | 66 | 观测主体 `meta.observation_target` | 1 | `node:asc-vm910 (substrate=qemu, hostname=asc-vm910)`（66 条） |
| `records-t21-qemu-rpt-nontargeted.jsonl` | 33 | 采集配置指纹 `meta.config_hash` | 1 | `dd334cd724ba0c4c`（33 条） |
| `records-t21-qemu-rpt-nontargeted.jsonl` | 33 | 剧本哈希 `meta.playbook_hash` | 1 | `sha256:b112ca3c2c888d439993a9a0ae0f972f73ac60b65d44dff1d12e2f5bb8a254cf`（33 条） |
| `records-t21-qemu-rpt-nontargeted.jsonl` | 33 | 观测主体 `meta.observation_target` | 1 | `node:asc-vm910 (substrate=qemu, hostname=asc-vm910)`（33 条） |

**跨段取值（只作可读性，不参与判据）**：合并后有 剧本哈希 `meta.playbook_hash`（2 个取值） —— 它们来自**段与段之间**的差异（各段的剧本/条件本来就不同），**不是**"重复之间换了条件"。段内是否唯一见上表。

**段内按场景唯一项**（不同场景的注入集本来就不同 ⇒ 判据是「同一段里同一场景的每次重复/两个臂」必须声明同一份集合）：

| 段（记录文件） | 指纹 | 覆盖场景数 | 各场景内唯一？ | 段内出现过的取值个数 |
|---|---|---|---|---|
| `records-t21-qemu-rpt-targeted.jsonl` | 注入集 `meta.expected_chain_factors` | 11 | 是 | 7 |
| `records-t21-qemu-rpt-targeted.jsonl` | 基线集 `meta.expected_baseline_factors` | 11 | 是 | 1 |
| `records-t21-qemu-rpt-nontargeted.jsonl` | 注入集 `meta.expected_chain_factors` | 11 | 是 | 10 |
| `records-t21-qemu-rpt-nontargeted.jsonl` | 基线集 `meta.expected_baseline_factors` | 11 | 是 | 1 |

**两段内部的判据都满足** ⇒ 这些重复确实是"同一 config、同一剧本哈希、同一观测主体、且同一场景内注入集/基线集不变"下的重复采样。

> 为什么要分三类：把"注入集"当段内唯一去比，会因为**不同场景本来就注入不同因子**（S1-apparmor 1 个、S4-all 5 个）报出假警报；把"剧本哈希"当**跨段**唯一去比，会因为**两段设计上就用不同剧本**报出假警报；反过来，只比跨段而不管段内，又会漏掉"同一段里第 2 次换了剧本"这类真正的口径错误。

## 1. 逐场景 × 逐臂：`final_score` 与判定/标签/链

| 场景 | 臂 | `final_score`（按重复号顺序） | 极差 | 标准差 | 判定（acceptable） | 判定翻转 | 标签（compromised） | 标签翻转 | 链形状相同 |
|---|---|---|---|---|---|---|---|---|---|
| `S0-baseline` | 策略在(policy_on=1) | 65.16 / 65.16 / 65.16 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S1-2fa` | 策略在(policy_on=1) | 59.01 / 59.01 / 59.01 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S1-apparmor` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S1-apparmor` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S1-no-ids` | 策略在(policy_on=1) | 65.16 / 65.16 / 65.16 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S1-no-siem` | 策略在(policy_on=1) | 62.28 / 62.28 / 62.28 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S1-selinux` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S1-selinux` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S1-syn-cookie` | 策略在(policy_on=1) | 58.52 / 58.52 / 58.52 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | 53.54 / 53.54 / 53.54 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | 53.54 / 53.54 / 53.54 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-no-siem-no-ids` | 策略在(policy_on=1) | 62.28 / 62.28 / 62.28 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | 54.82 / 54.82 / 54.82 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | 54.82 / 54.82 / 54.82 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | 58.52 / 58.52 / 58.52 | 0.00 | 0.000 | false / false / false | 否 | true / false / true | **是** | 是 |
| `S2-syn-cookie-no-siem` | 策略在(policy_on=1) | 56.91 / 56.91 / 56.91 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | 53.42 / 53.42 / 53.42 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | 53.42 / 53.42 / 53.42 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | 53.54 / 53.54 / 53.54 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | 53.54 / 53.54 / 53.54 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | 54.82 / 54.82 / 54.82 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | 54.82 / 54.82 / 54.82 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S3-syn-cookie-no-siem-no-ids` | 策略在(policy_on=1) | 56.91 / 56.91 / 56.91 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S4-all` | 策略不在(policy_on=0) | 51.62 / 51.62 / 51.62 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S4-all` | 策略在(policy_on=1) | 51.62 / 51.62 / 51.62 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S5-2fa-only` | 策略在(policy_on=1) | 59.01 / 59.01 / 59.01 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S5-cascade-3fa` | 策略在(policy_on=1) | 57.40 / 57.40 / 57.40 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |

## 2. 五个域分的极差与标准差（逐场景 × 逐臂）

| 场景 | 臂 | 攻击面 各次 / 极差 / σ | 业务连续性 各次 / 极差 / σ | 内核安全 各次 / 极差 / σ | 运营信任 各次 / 极差 / σ | 韧性 各次 / 极差 / σ |
|---|---|---|---|---|---|---|
| `S0-baseline` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-2fa` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-apparmor` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-apparmor` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-no-siem` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-selinux` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-selinux` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-syn-cookie` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-no-siem-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-syn-cookie-no-siem` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-syn-cookie-no-siem-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S4-all` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S4-all` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S5-2fa-only` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S5-cascade-3fa` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 29 / 29 / 29 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |

> 域分是**整数**（引擎按整数域累加后取整）⇒ 极差只能取整数；标准差是这些整数在 n 次重复上的样本标准差，保留两位小数仅为可读。

## 3. 被观测因子的 `effective_factor` 极差与标准差

链上因子的键写成 `因子#出现序号`：出厂配置把同名因子又写进 `[edge_factors.custom]`，故同一条链里**同一 ID 会出现两条**（`EF-SELINUX#1` / `EF-SELINUX#2`），两条的 `effective_factor` **不一定相同**（例如 `EF-002FA#1=0.70`、`EF-002FA#2=0.85`）。把同 ID 的几条合并成一个数会制造一个引擎从未计算过的量 —— 故按出现序号分开记。

| 场景 | 臂 | 因子#序号 | 各次值 | 极差 | 标准差 |
|---|---|---|---|---|---|
| `S0-baseline` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S0-baseline` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-2fa` | 策略在(policy_on=1) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S1-2fa` | 策略在(policy_on=1) | `EF-002FA#2` | 0.8500 / 0.8500 / 0.8500 | 0.0000 | 0.0000 |
| `S1-2fa` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-2fa` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S1-apparmor` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S1-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-no-siem` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-no-siem` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-no-siem` | 策略在(policy_on=1) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S1-no-siem` | 策略在(policy_on=1) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S1-selinux` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S1-syn-cookie` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-syn-cookie` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S1-syn-cookie` | 策略在(policy_on=1) | `EF-SYNCOOKIE#1` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S1-syn-cookie` | 策略在(policy_on=1) | `EF-SYNCOOKIE#2` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | `EF-002FA#2` | 0.8500 / 0.8500 / 0.8500 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | `EF-002FA#2` | 0.8500 / 0.8500 / 0.8500 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S2-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | `EF-SYNCOOKIE#1` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | `EF-SYNCOOKIE#2` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-siem` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-siem` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-siem` | 策略在(policy_on=1) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-siem` | 策略在(policy_on=1) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-siem` | 策略在(policy_on=1) | `EF-SYNCOOKIE#1` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S2-syn-cookie-no-siem` | 策略在(policy_on=1) | `EF-SYNCOOKIE#2` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | `EF-3FA#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | `EF-3FA#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | `EF-002FA#2` | 0.8500 / 0.8500 / 0.8500 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | `EF-002FA#2` | 0.8500 / 0.8500 / 0.8500 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S3-syn-cookie-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-syn-cookie-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S3-syn-cookie-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S3-syn-cookie-no-siem-no-ids` | 策略在(policy_on=1) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S3-syn-cookie-no-siem-no-ids` | 策略在(policy_on=1) | `EF-SYNCOOKIE#1` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S3-syn-cookie-no-siem-no-ids` | 策略在(policy_on=1) | `EF-SYNCOOKIE#2` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-002FA#2` | 0.8500 / 0.8500 / 0.8500 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-SYNCOOKIE#1` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S4-all` | 策略不在(policy_on=0) | `EF-SYNCOOKIE#2` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-002FA#2` | 0.8500 / 0.8500 / 0.8500 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-APPARMOR#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-APPARMOR#2` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-NO-SIEM#1` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-NO-SIEM#2` | 0.9000 / 0.9000 / 0.9000 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-SELINUX#1` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-SELINUX#2` | 0.8000 / 0.8000 / 0.8000 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-SYNCOOKIE#1` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S4-all` | 策略在(policy_on=1) | `EF-SYNCOOKIE#2` | 0.7500 / 0.7500 / 0.7500 | 0.0000 | 0.0000 |
| `S5-2fa-only` | 策略在(policy_on=1) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S5-2fa-only` | 策略在(policy_on=1) | `EF-002FA#2` | 0.8500 / 0.8500 / 0.8500 | 0.0000 | 0.0000 |
| `S5-2fa-only` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S5-2fa-only` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S5-cascade-3fa` | 策略在(policy_on=1) | `EF-002FA#1` | 0.7000 / 0.7000 / 0.7000 | 0.0000 | 0.0000 |
| `S5-cascade-3fa` | 策略在(policy_on=1) | `EF-002FA#2` | 0.8500 / 0.8500 / 0.8500 | 0.0000 | 0.0000 |
| `S5-cascade-3fa` | 策略在(policy_on=1) | `EF-3FA#1` | 0.8200 / 0.8200 / 0.8200 | 0.0000 | 0.0000 |
| `S5-cascade-3fa` | 策略在(policy_on=1) | `EF-NO-IDS#1` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |
| `S5-cascade-3fa` | 策略在(policy_on=1) | `EF-NO-IDS#2` | 0.8800 / 0.8800 / 0.8800 | 0.0000 | 0.0000 |

> 共 209 个 `(场景,臂,因子#序号)` 键；其中极差为 0 的有 209 个（逐行都在上表里，没有省略）。

## 4. **判定翻转的场景（环境敏感）**

**本批没有场景在重复之间发生判定翻转**（`observed.acceptable` 在 n 次重复里取值唯一）。

⇒ 就"决策层判定"而言，这批重复在观测到的所有场景×臂上是**稳定**的；这**不等于**"环境没有抖动"：数值层与链形状层的抖动见 §1/§2/§3，且样本量只有 3 次重复 × 22 个场景，不能外推成"任意环境都稳定"。

### 4b. 标签翻转（`ground_truth.compromised`）

| 场景 | 臂 | `compromised` 取值（按重复号顺序） |
|---|---|---|
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | true / false / true |

标签翻转比判定翻转更严重：它说明"同一次攻击在客观层就成功了/没成功"都不稳定，该场景的监督信号不可用于拟合。

#### 4b-1 定性证据：逐次的客观层四个字段（这一节才是「标签为什么翻」的判据）

> 只看 `compromised` 一个 bool，「某次没打成」这件事有**三种**完全不同的成因：**攻击侧没执行** / **被防护拦住** / **测量或评分抖动**。它们在数据上不同形，下面四个字段一起看才能分开 —— 这是本节存在的唯一理由。

| 场景 | 臂 | 第几次 | `compromised` | `ttps_achieved` | `nodes_affected` | `time_to_compromise_s` | `block_effective` | 打分输入（`observed.checks`，不含 `ts`）与本组第 1 次相同？ |
|---|---|---|---|---|---|---|---|---|
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | 1 | true | 36 | 1 | 5 | false | **是** |
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | 2 | false | 0 | 0 | 0 | true | **是** |
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | 3 | true | 36 | 1 | 4 | false | **是** |

> **定性（按上表四个字段算出来的，不是按「时间相关」猜的）**：`compromised=false` 的那 **1** 次里，**每一次**都满足 `ttps_achieved == 0` **且** `nodes_affected == 0` ⇒ 那几次是**攻击侧根本没有执行**（一条目标 TTP 都没打成、受影响节点为 0），**不是**「被防护拦住」，**也不是**「测量抖动」。

> 作为对照，同一组里 `compromised=true` 的那几次：`ttps_achieved = 36, 36`、`nodes_affected = 1, 1`。

> ⚠️ **`block_effective=true` 在本段不是「防护生效」的证据**：侦察口径（`recon_playbook`）下它的定义只是 `len(successes) == 0`（`edge_attack.sh:948`）—— 而「攻击侧没执行」同样让 `successes` 为空 ⇒ 这个字段在 recon 口径下**只是「没有成功」**，不等于「策略拦住了」。引用这一列时**必须**同时给出 `ttps_achieved` 与 `nodes_affected`，否则读者会把非执行读成防护。

> 打分侧与标签侧必须分开读：上表最后一列说明这几次的**打分输入逐字段相同**（`observed.checks` 只落失败项、且不含 `ts`），故 `final_score` 本来就该相同 —— 「分数零方差」与「标签翻转」可以同时成立，它们描述的是两个不同的层。

### 4c. 链形状翻转（门禁层）

**没有场景×臂在重复之间改变链的因子集**（含同 ID 重复条目）。

链**顺序**在重复之间不同的场景×臂：0 个（无）。

> 顺序层与因子集层分开报：因子集相同而顺序不同，意味着耦合项的 `ts` 基准随条目顺序变，属环境敏感的一种，不能用"因子集相同"一句盖过去。


## 4d. 两臂一致性：「同读数、同分数、只差标签」这条 limitation 在重复批上的复核

| 场景 | 两臂并存的重复数 | `final_score` 全同 | 五域分全同 | 链条目全同 | 因子值全同 | 标签全反 |
|---|---|---|---|---|---|---|
| `S1-apparmor` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S1-selinux` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S2-2fa-selinux` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S2-apparmor-no-ids` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S2-selinux-apparmor` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S2-selinux-no-ids` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S2-selinux-no-siem` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S3-3fa-selinux-apparmor` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S3-selinux-apparmor-2fa` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S3-selinux-no-siem-no-ids` | 3 | 是 | 是 | 是 | 是 | 是 |
| `S4-all` | 3 | 是 | 是 | 是 | 是 | 是 |

**结论：limitation 在本次重复批上仍然成立** —— 每一个场景的每一次重复里，两臂的链条目、因子 `effective_factor`、五个域分与 `final_score` **全部相同**，只有 `ground_truth.compromised`（标签）相反。

> 这不是"两臂等价"的证据，而是"**只差策略**"的证据：分数相同 = 分数对策略不敏感，标签相反 = 客观攻击结果对策略敏感。`test-arm-limitation.sh` 仍然守着这条，**本报告不据此放松任何断言**。

## 5. 与 REPEAT=1 主批的对照

列含义：网格按重复号顺序给出"同 / **反**"，与主批那一条逐次比对；最后一列是**失败检查集之差**（`observed.checks` 只落盘失败项 ⇒ 差集就是"哪条检查换了状态"，它才是分数不同的**原因**列）。

| 场景 | 臂 | 主批 `final_score` / 判定 / 标签 | 与主批**判定** | 与主批**标签** | 与主批**分数** | 与主批**链** | 与主批失败检查集之差 |
|---|---|---|---|---|---|---|---|
| `S0-baseline` | 策略在(policy_on=1) | 64.63 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-2fa` | 策略在(policy_on=1) | 58.70 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-apparmor` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-apparmor` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-no-ids` | 策略在(policy_on=1) | 64.63 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-no-siem` | 策略在(policy_on=1) | 61.84 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-selinux` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-selinux` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-syn-cookie` | 策略在(policy_on=1) | 58.23 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | 53.41 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-2fa-selinux` | 策略在(policy_on=1) | 53.41 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-no-siem-no-ids` | 策略在(policy_on=1) | 61.84 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | 54.64 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | 54.64 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-syn-cookie-no-ids` | 策略在(policy_on=1) | 58.23 / false / true | 同 同 同 | 同 **反** 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-syn-cookie-no-siem` | 策略在(policy_on=1) | 56.67 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | 53.29 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | 53.29 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | 53.41 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | 53.41 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | 54.64 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | 54.64 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-syn-cookie-no-siem-no-ids` | 策略在(policy_on=1) | 56.67 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S4-all` | 策略不在(policy_on=0) | 51.55 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S4-all` | 策略在(policy_on=1) | 51.55 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S5-2fa-only` | 策略在(policy_on=1) | 58.70 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S5-cascade-3fa` | 策略在(policy_on=1) | 57.14 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |

- 与主批**判定相反**的场景×臂：0 个（无）
- 与主批**标签相反**的场景×臂：1 个（`S2-syn-cookie-no-ids`/策略在(policy_on=1)）
- 与主批**失败检查集不同**的场景×臂：33 个，差异项并集 = `OT-018`；其中 33 个的 `final_score` 也随之不同（⇒ 分数差异的**原因**已定位到这些检查，不是重复抖动）

**逐段小计**（判据按段做：段与段之间可以不同，合并后的总数不进结论）：

| 段（记录文件） | 组数 | 判定相同 | 标签相同 | 链相同 | 分数不同 | 失败检查集之差（并集） |
|---|---|---|---|---|---|---|
| `records-t21-qemu-rpt-nontargeted.jsonl` | 11 | 11/11 | 10/11 | 11/11 | 11/11 | `OT-018` |
| `records-t21-qemu-rpt-targeted.jsonl` | 22 | 22/22 | 22/22 | 22/22 | 22/22 | `OT-018` |

> 读法：**每一个段**的"判定/标签/链相同"与"分数不同"都是**该段自己**的结论。把两段的计数加在一起再写成"22/22"是错误的 —— 那会把一个段的口径冒充成两段的；反过来，段与段之间的差异（不同剧本、不同策略状态）**本来就不是**重复抖动。

> 与主批的对照是**同基质、同 config、同剧本哈希**下的对照；若某次重复与主批结论相反，那本身就是"判定不稳"的证据，不能因为它只是"n 次里的一次"而丢掉。

## 6. 方法学备注（怎么复现、哪些数不能怎么用）

1. **重复轴与臂是两个独立维度**：`scenario_id` 尾号是**实例号**`NN = (REPEAT−1)×NARMS + 臂 + 1`（NARMS = 该场景的实例数，targeted 开臂时 = 2），臂的身份写在 `meta.policy_on`，重复号写在 `meta.repeat`（**只在 >1 时写**）。故同一份记录文件可以承载 1..N 各一遍，且各次的 `scenario_id` 互不重叠。
2. **重复样本不是独立样本**（再强调一次）：各次重复共用同一宿主状态、同一 VM、同一 Caldera、同一剧本；n 次全同只能说「**本次 n 次重复里未观测到抖动**」，**给不出方差的界**（n 小时非参数上界不存在，样本标准差 0 也不是上界估计），**不能**当独立同分布样本去算置信区间或做显著性检验；决策层 N 的写法见本文开头。
3. **因子层的键按出现序号分**（§3）：同 ID 多条是配置层的真实形态，合并会制造引擎从未计算的量。
4. **复现命令**：`python3 lunwen/clab-lab/scripts/edge_variance.py --records <本批记录> [--records <第二段记录>] [--baseline <主批记录>] [--preamble <手写结论.md>] --json <out.json> --md <report.md>`；**多段合并时判据一律按段做**（§0.1：段内唯一才算"同一条件"，跨段不同是设计与合并的必然）；跑批侧的口径（一份文件承载 1..N、门禁判据）见操作手册「重复轴」一节。

