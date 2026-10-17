# 重复性与方差报告 —— 方向② 边缘因子重复性（每场景 3 次）

生成时间（UTC）：2026-10-17T23:02:51Z

| 项目 | 值 |
|---|---|
| 记录文件 | `lunwen/clab-lab/data/edgefactors/records-t21-qemu-rpt-targeted.jsonl` |
| 对照（REPEAT=1 主批） | `lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl` |
| 记录条数 | 66 |
| 场景数 × 臂数 | 11 场景 × 2 臂 = 22 个(场景,臂)组 |
| 每组的重复号 | 1, 2, 3（每组条数：3） |
| 决策阈值 | 80.00（取记录 `observed.threshold`；本批逐条一致） |

> **口径声明（必读）**：**重复样本不是独立样本**。这里的 N 次是**同一宿主状态的重复**，用来估方差与稳定性；**不得**当成 N 个独立样本去虚增决策层 N。决策层 N 一律写成 `N=66（11 场景 × 3 次重复，含每场景两臂）`。报告的结论层**不使用平均值**：任何一个场景只要在 N 次里出现判定/标签/链形状翻转，就单独列进「判定翻转（环境敏感）」一节，**不隐去、不取平均掩盖**。

> **数值层口径**：极差 = `max − min`；标准差 = **样本**标准差（分母 n−1）。n=1 时极差与标准差都记 `—`（**不是 0**：一条记录既没有极差也没有标准差，写成 0 会让"没测"看起来像"完全不抖"）。域分是整数、`final_score` 两位小数。

---

## 0. 结论先说（**本版只覆盖 targeted 段**）

> **非 targeted 段（11 场景 × 3 轮 = 33 条，约 15 h）的实测状态**写在
> `.superpowers/sdd/2026-09-12-edge-factor-coupling-milestone-b/task-21-repeat-variance-report.md`
> 的 §2.5 与 §7（**不写成跑过了**）。它跑完后，把它的记录文件加进同一条命令重跑本脚本即可并入：
> `python3 lunwen/clab-lab/scripts/edge_variance.py --records <targeted> --records <nontargeted> --baseline <主批> ...`

- **样本**：targeted 段的 **11 个场景 × 2 条臂 × 3 次重复 = 66 条**记录（VM 基质 `qemu`，
  同一 `config_hash`、同一 `playbook_hash`、同一观测主体 `asc-vm910`；两段各一份记录文件）。
- **数值层：零方差。** 22 个 `(场景, 臂)` 组里，`final_score`、五个域分、以及每条被观测因子的
  `effective_factor` 在三遍之间**逐项相同**（极差 0、样本标准差 0.000）。
- **判定层 / 标签层 / 门禁层：无翻转。** 22 个组的 `observed.acceptable`、
  `ground_truth.compromised`、链因子集（含同 ID 的两条目）、链条目**顺序**在三遍之间全部一致
  ⇒ **本段没有"环境敏感"场景**（§4 的那一节因此是"无"，不是"被省略"）。
- **两臂一致性（limitation 复核）**：22 个组全部满足"**同读数、同分数、只差标签**"（§4d）
  ⇒ 这条 limitation 在重复批上**仍然成立**，本报告不据此放松任何断言。
- **与 `REPEAT=1` 主批的关系**：判定/标签/链 22/22 **相同**；`final_score` 22/22 **不同**，
  而逐组核对后，**与主批的唯一差异是一条检查**——`OT-018`（敏感数据最小化）在两次 VM 上
  通过状态不同（主批失败、本批通过；`observed.checks` 只落盘失败项，故本批比主批少一条）。
  ⇒ 这是**环境状态差**（日志内容），不是重复抖动；`variance-report` 的这一节据实分开写。

**怎么读"零方差"（别读错）**：这些数值是**整数域分 + 两位小数总分**的聚合结果，
"三遍相同"只能说"**在这台 VM、这三次重复、这个观测精度内，抖动不可分辨**"。
它**不是**"确定性"的证明，也**不能**外推成"任意环境/任意次数都稳定"；
样本量只有 3 次重复 × 11 个场景，且**重复样本不是独立样本**（见开头的口径声明）。

---

## 0.1 输入指纹（证明这 N 次真是"同一条件"）

**全批唯一项**（这批记录只有一种取值才叫"同一轮批"）：

| 指纹 | 取值 | 条数 |
|---|---|---|
| 采集配置指纹 `meta.config_hash` | `dd334cd724ba0c4c` | 66 |
| 剧本哈希 `meta.playbook_hash` | `sha256:e585b8465faab05d236e39b19cc99addfbf4adc0fa2fc8891c4ee278bef60f19` | 66 |
| 观测主体 `meta.observation_target` | `node:asc-vm910 (substrate=qemu, hostname=asc-vm910)` | 66 |

**按场景唯一项**（不同场景的注入集本来就不同 ⇒ 判据是「同一场景的每次重复/两个臂」必须声明同一份集合）：

| 指纹 | 覆盖场景数 | 各场景内唯一？ | 批内出现过的取值个数 |
|---|---|---|---|
| 注入集 `meta.expected_chain_factors` | 11 | 是 | 7 |
| 基线集 `meta.expected_baseline_factors` | 11 | 是 | 1 |

**两类判据都满足** ⇒ 这些重复确实是"同一 config、同一剧本哈希、同一观测主体、且同一场景内注入集/基线集不变"下的重复采样。

> 为什么要分两类：把"注入集"当全批唯一去比，会因为**不同场景本来就注入不同因子**（S1-apparmor 1 个、S4-all 5 个）报出假警报；反过来，只比全批而不管场景内部，又会漏掉"同一场景的第 2 次换了注入集"这类真正的口径错误。

## 1. 逐场景 × 逐臂：`final_score` 与判定/标签/链

| 场景 | 臂 | `final_score`（按重复号顺序） | 极差 | 标准差 | 判定（acceptable） | 判定翻转 | 标签（compromised） | 标签翻转 | 链形状相同 |
|---|---|---|---|---|---|---|---|---|---|
| `S1-apparmor` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S1-apparmor` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S1-selinux` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S1-selinux` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | 53.54 / 53.54 / 53.54 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | 53.54 / 53.54 / 53.54 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | 55.96 / 55.96 / 55.96 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | 54.82 / 54.82 / 54.82 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | 54.82 / 54.82 / 54.82 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | 53.42 / 53.42 / 53.42 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | 53.42 / 53.42 / 53.42 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | 53.54 / 53.54 / 53.54 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | 53.54 / 53.54 / 53.54 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | 54.82 / 54.82 / 54.82 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | 54.82 / 54.82 / 54.82 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |
| `S4-all` | 策略不在(policy_on=0) | 51.62 / 51.62 / 51.62 | 0.00 | 0.000 | false / false / false | 否 | true / true / true | 否 | 是 |
| `S4-all` | 策略在(policy_on=1) | 51.62 / 51.62 / 51.62 | 0.00 | 0.000 | false / false / false | 否 | false / false / false | 否 | 是 |

## 2. 五个域分的极差与标准差（逐场景 × 逐臂）

| 场景 | 臂 | 攻击面 各次 / 极差 / σ | 业务连续性 各次 / 极差 / σ | 内核安全 各次 / 极差 / σ | 运营信任 各次 / 极差 / σ | 韧性 各次 / 极差 / σ |
|---|---|---|---|---|---|---|
| `S1-apparmor` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-apparmor` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-selinux` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S1-selinux` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-2fa-selinux` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S4-all` | 策略不在(policy_on=0) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |
| `S4-all` | 策略在(policy_on=1) | 44 / 44 / 44 / 0 / 0.00 | 60 / 60 / 60 / 0 / 0.00 | 54 / 54 / 54 / 0 / 0.00 | 14 / 14 / 14 / 0 / 0.00 | 0 / 0 / 0 / 0 / 0.00 |

> 域分是**整数**（引擎按整数域累加后取整）⇒ 极差只能取整数；标准差是这些整数在 n 次重复上的样本标准差，保留两位小数仅为可读。

## 3. 被观测因子的 `effective_factor` 极差与标准差

链上因子的键写成 `因子#出现序号`：出厂配置把同名因子又写进 `[edge_factors.custom]`，故同一条链里**同一 ID 会出现两条**（`EF-SELINUX#1` / `EF-SELINUX#2`），两条的 `effective_factor` **不一定相同**（例如 `EF-002FA#1=0.70`、`EF-002FA#2=0.85`）。把同 ID 的几条合并成一个数会制造一个引擎从未计算过的量 —— 故按出现序号分开记。

| 场景 | 臂 | 因子#序号 | 各次值 | 极差 | 标准差 |
|---|---|---|---|---|---|
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

> 共 164 个 `(场景,臂,因子#序号)` 键；其中极差为 0 的有 164 个（逐行都在上表里，没有省略）。

## 4. **判定翻转的场景（环境敏感）**

**本批没有场景在重复之间发生判定翻转**（`observed.acceptable` 在 n 次重复里取值唯一）。

⇒ 就"决策层判定"而言，这批重复在观测到的所有场景×臂上是**稳定**的；这**不等于**"环境没有抖动"：数值层与链形状层的抖动见 §1/§2/§3，且样本量只有 3 次重复 × 11 个场景，不能外推成"任意环境都稳定"。

### 4b. 标签翻转（`ground_truth.compromised`）

**没有场景×臂在重复之间发生标签翻转** —— 同一条件的目标 TTP 客观结果在 n 次里一致（标签可重复）。

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
| `S1-apparmor` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-apparmor` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-selinux` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S1-selinux` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-2fa-selinux` | 策略不在(policy_on=0) | 53.41 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-2fa-selinux` | 策略在(policy_on=1) | 53.41 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-apparmor-no-ids` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-apparmor-no-ids` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-apparmor` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-apparmor` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-no-ids` | 策略不在(policy_on=0) | 55.73 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-no-ids` | 策略在(policy_on=1) | 55.73 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-no-siem` | 策略不在(policy_on=0) | 54.64 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S2-selinux-no-siem` | 策略在(policy_on=1) | 54.64 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-3fa-selinux-apparmor` | 策略不在(policy_on=0) | 53.29 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-3fa-selinux-apparmor` | 策略在(policy_on=1) | 53.29 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-selinux-apparmor-2fa` | 策略不在(policy_on=0) | 53.41 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-selinux-apparmor-2fa` | 策略在(policy_on=1) | 53.41 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-selinux-no-siem-no-ids` | 策略不在(policy_on=0) | 54.64 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S3-selinux-no-siem-no-ids` | 策略在(policy_on=1) | 54.64 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S4-all` | 策略不在(policy_on=0) | 51.55 / false / true | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |
| `S4-all` | 策略在(policy_on=1) | 51.55 / false / false | 同 同 同 | 同 同 同 | **异** **异** **异** | 同 同 同 | **OT-018** |

- 与主批**判定相反**的场景×臂：0 个（无）
- 与主批**标签相反**的场景×臂：0 个（无）
- 与主批**失败检查集不同**的场景×臂：22 个，差异项并集 = `OT-018`；其中 22 个的 `final_score` 也随之不同（⇒ 分数差异的**原因**已定位到这些检查，不是重复抖动）

> 与主批的对照是**同基质、同 config、同剧本哈希**下的对照；若某次重复与主批结论相反，那本身就是"判定不稳"的证据，不能因为它只是"n 次里的一次"而丢掉。

## 6. 方法学备注（怎么复现、哪些数不能怎么用）

1. **重复轴与臂是两个独立维度**：`scenario_id` 尾号是**实例号**`NN = (REPEAT−1)×NARMS + 臂 + 1`（NARMS = 该场景的实例数，targeted 开臂时 = 2），臂的身份写在 `meta.policy_on`，重复号写在 `meta.repeat`（**只在 >1 时写**）。故同一份记录文件可以承载 1..N 各一遍，且各次的 `scenario_id` 互不重叠。
2. **重复样本不是独立样本**（再强调一次）：各次重复共用同一宿主状态、同一 VM、同一 Caldera、同一剧本；n=3 的样本标准差只能当"抖动尺度"的估计，**不能**当独立同分布样本去算置信区间或做显著性检验；决策层 N 的写法见本文开头。
3. **因子层的键按出现序号分**（§3）：同 ID 多条是配置层的真实形态，合并会制造引擎从未计算的量。
4. **复现命令**：`python3 lunwen/clab-lab/scripts/edge_variance.py --records <本批记录> [--baseline <主批记录>] --json <out.json> --md <report.md>`；跑批侧的口径（一份文件承载 1..N、门禁判据）见操作手册「重复轴」一节。

