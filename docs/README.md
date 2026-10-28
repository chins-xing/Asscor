# ASSCOR 文档索引与分类规则

> **编号 = 权威顺序。任何冲突以 `1-current/` 为准；`4-archive/` 里的结论一律作废，只能当史料读。**
>
> **⭐ 文档与代码不一致时：以代码为唯一权威（自 2026-10-23 生效）。** 处理方式固定为：
> ① **改文档**去匹配代码；② **不得**用文档反向定义行为（"文档写了所以代码应该这样"不成立）；
> ③ 若确认是**代码错了**，必须单独走代码变更（带测试与评审），**不能**顺手把文档改成"期望值"来掩盖；
> ④ 历史记录（`3-audits/history/`、`4-archive/`）里的旧值**不追改**，但必须能看出它已属于史料。
>
> **⭐ 文档面向外部读者，不记录沟通过程（自 2026-10-23 生效）。** 具体：
> ① **不写决策者人称与对话引述**（不把决策记成"某人说了什么"的形式）；决策写成**规则本身**
> （"`main` 与 ARC 永不整体同步"），必要时只标注**生效日期**（日期是项目事实，不是对话记录）；
> ② **不用第一人称叙述**（把"我发现/我设的/config 不是证据"改成无主语句式）；
> ③ 面向操作者的操作说明可以正常使用"你/操作者"，那是读者角色，不是对话对象；
> ④ 决策的**理由与依据必须保留** —— 去掉的只是"谁在什么对话里说的"这一层。

本目录采用**文件夹分离**做标准化分类：文档按"是否仍与代码/现行结论一致"落到唯一一类目录，
不靠在文件名或正文里加"废弃/旧版"标注来区分。废弃文档必须整体移入 `4-archive/` 的对应子目录，
不得散落在现行目录中误导读者。每份文档的旧路径、新路径与分类理由见 [MIGRATION_MAP.md](MIGRATION_MAP.md)。

本目录采用**文件夹分离**做标准化分类：文档按"是否仍与代码/现行结论一致"落到唯一一类目录，
不靠在文件名或正文里加"废弃/旧版"标注来区分。废弃文档必须整体移入 `4-archive/` 的对应子目录，
不得散落在现行目录中误导读者。每份文档的旧路径、新路径与分类理由见 [MIGRATION_MAP.md](MIGRATION_MAP.md)。

## 一、目标结构与分类规则

```
docs/
  README.md                    # 本文件：分类规则 + 索引 + 新增流程
  MIGRATION_MAP.md             # 旧 → 新 逐条映射 + 每份的分类理由
  1-current/                   # 现行有效：与代码一致，可对外引用
    design/                    # 设计文档："现在为什么这么设计"
    whitepapers/               # 白皮书：系统级/模块级技术说明
    guides/                    # 使用 / 扩展 / 接入类操作指南
    reference/                 # 规范、映射手册、清单、路线图、资产归属、架构审查
  2-experiments/               # 实验口径与数据说明（现行；绑定数据集）
  3-audits/                    # 审计判决 + 债务清单（现行；以最新 *-verdict.md 为准）
  4-archive/                   # 已废弃：结论作废，仅供史料
    plans/                     # 历史实施计划（含已执行/已废弃的规划）
    designs/                   # 被取代的设计文档
    releases/                  # 旧发布说明
    reviews/                   # 历史评审、历史债务总览等被取代的记录
  en/                          # 英文文档（目前只有 1-current/，暂无 4-archive/ 归档）
```

判定口径：

| 目录 | 收什么 | 判据 |
|---|---|---|
| `1-current/design/` | 现行设计 | 设计结论仍被代码实现或仍作为现行约束；无后续设计/审计推翻 |
| `1-current/whitepapers/` | 白皮书 | 系统级/模块级技术说明，描述的能力仍在代码中 |
| `1-current/guides/` | 使用/扩展/接入指南 | 按文中步骤可在当前分支复现 |
| `1-current/reference/` | 规范/映射/清单/路线图/资产/架构审查 | 工具性参考；结论未被后续文档明确取代 |
| `2-experiments/` | 实验口径、数据说明、实验产物 | 绑定当前实验数据集；不是历史结论 |
| `3-audits/` | 审计报告、债务清单 | 审计判决与待办；内部 `archive/`、`history/` 保留原结构 |
| `4-archive/plans/` | 历史实施计划 | 已执行完、已废弃或已被后续计划取代 |
| `4-archive/designs/` | 被取代的设计 | 有后续设计/审计明确推翻，或描述的系统已不存在 |
| `4-archive/releases/` | 旧发布说明 | 版本已发布且被更新版本取代 |
| `4-archive/reviews/` | 历史评审/历史总览 | 结论已被后续审计或维护中的清单取代 |
| `en/` | 英文文档 | 目前只镜像现行层 `en/1-current/`；尚无英文归档文档 |

`3-audits/` 的取舍规则：**以最新 `*-verdict.md` 为准**；`archive/` 与 `history/` 只作过程记录，
其中与最新判决冲突的结论一律以最新判决为准。

## 二、现行文档索引（`1-current/`）

### 设计（`1-current/design/`）

| 文档 | 说明 |
|---|---|
| [BLACKBOX_RECALLER_DESIGN.md](1-current/design/BLACKBOX_RECALLER_DESIGN.md) | 黑盒阵列只作可选扩展的架构决策 |
| [CONFIDENCE_MODEL_DESIGN_2026-09-08.md](1-current/design/CONFIDENCE_MODEL_DESIGN_2026-09-08.md) | 情报可信度原生变量设计（已实现，标定后置） |
| [EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md](1-current/design/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md) | 方向② 边缘因子耦合与变量化设计 |
| [ENTROPY_EXTENSION_DESIGN_2026-09-08.md](1-current/design/ENTROPY_EXTENSION_DESIGN_2026-09-08.md) | 方向③ 熵扩展包设计（未实现，设计现行） |
| [MITRE_ENGAGE_LIGHTWEIGHT_DESIGN.md](1-current/design/MITRE_ENGAGE_LIGHTWEIGHT_DESIGN.md) | MITRE Engage 轻量化扩展包设计 |
| [2026-06-09-prism-ir-design.md](1-current/design/2026-06-09-prism-ir-design.md) | Prism IR 设计（已实现） |
| [2026-08-21-secure-mode-design.md](1-current/design/2026-08-21-secure-mode-design.md) | Secure Mode 模块设计（已实现） |
| [SRD_V2.3_PLAN_2026-10-27.md](1-current/design/SRD_V2.3_PLAN_2026-10-27.md) | SRD v2.3 计划：域内 ACL / 状态化建模 / CLI 查询 / 跨环境 ROC |

### 白皮书（`1-current/whitepapers/`）

| 文档 | 说明 |
|---|---|
| [项目篇章-系统安全可接受性模型.md](1-current/whitepapers/项目篇章-系统安全可接受性模型.md) | SSAM 理论基础与核心概念 |
| [工程实现白皮书.md](1-current/whitepapers/工程实现白皮书.md) | ASSCOR 工程架构与实现细节 |
| [SPC安全态势计算模块技术白皮书.md](1-current/whitepapers/SPC安全态势计算模块技术白皮书.md) | 安全态势计算模块公式与数据源 |
| [APT攻击分析与检测增强白皮书.md](1-current/whitepapers/APT攻击分析与检测增强白皮书.md) | ATT&CK V19 集成与 APT 检测增强 |
| [ASSCOR 扩展体系白皮书.md](1-current/whitepapers/ASSCOR%20扩展体系白皮书.md) | 插件/扩展/适配器体系 |
| [ASSCOR 扩展白皮书：内核安全域.md](1-current/whitepapers/ASSCOR%20扩展白皮书：内核安全域.md) | kernel_security 域的设计与实现 |
| [SSAM与SRD算法可移植性白皮书.md](1-current/whitepapers/SSAM与SRD算法可移植性白皮书.md) | 算法跨项目可移植性论述 |
| [Systemic Risk Dynamics（SRD）白皮书.md](1-current/whitepapers/Systemic%20Risk%20Dynamics（SRD）白皮书.md) | Prism/SRD 风险传播模型 |
| [Secure Mode 安全模式白皮书.md](1-current/whitepapers/Secure%20Mode%20安全模式白皮书.md) | Secure Mode 设计与实现 |

### 指南（`1-current/guides/`）

| 文档 | 说明 |
|---|---|
| [ASSCOR 使用手册.md](1-current/guides/ASSCOR%20使用手册.md) | 用户操作指南与配置说明 |
| [ASSCOR 扩展开发指南.md](1-current/guides/ASSCOR%20扩展开发指南.md) | 面向使用者的扩展编写实战指南 |

### 参考（`1-current/reference/`）

| 文档 | 说明 |
|---|---|
| [ASSCOR 外部接入源完整清单.md](1-current/reference/ASSCOR%20外部接入源完整清单.md) | 外部工具适配器清单 |
| [SSAM接口规范与接入指南.md](1-current/reference/SSAM接口规范与接入指南.md) | SSAM Provider 接口规范与集成 |
| [等级保护检查项映射手册.md](1-current/reference/等级保护检查项映射手册.md) | GB/T 22239-2019 等保映射 |
| [ASSCOR-Research-Core.md](1-current/reference/ASSCOR-Research-Core.md) | 研究分支定位与里程碑 |
| [ASSET_OWNERSHIP.md](1-current/reference/ASSET_OWNERSHIP.md) | `main` vs `ASSCOR-Research-Core` 资产归属 |
| [ROADMAP_v0.2.0_to_v1.0.0.md](1-current/reference/ROADMAP_v0.2.0_to_v1.0.0.md) | v0.2.3 → v1.0.0 路线图 |
| [TOPO_INFRASTRUCTURE_BLUEPRINT_2026-08-16.md](1-current/reference/TOPO_INFRASTRUCTURE_BLUEPRINT_2026-08-16.md) | 拓扑与传播层基础设施蓝图 |
| [SRD_CONFIGURATION.md](1-current/reference/SRD_CONFIGURATION.md) | SRD `[srd]` 配置参考（参数/默认值/验证/回退） |
| [SRD_v2.2_RELEASE_NOTES.md](1-current/reference/SRD_v2.2_RELEASE_NOTES.md) | SRD v2.2 发布说明（能力/证据/升级/限制） |
| [asscor-architecture-review/](1-current/reference/asscor-architecture-review/) | 20 章英文架构审查（现行结论） |
| [asscor-architecture-review-zh/](1-current/reference/asscor-architecture-review-zh/) | 20 章中文架构审查（同上） |

## 三、实验（`2-experiments/`）

| 入口 | 说明 |
|---|---|
| [EDGE_FACTOR_EXPERIMENT_ENVIRONMENT_WHITEPAPER.md](2-experiments/EDGE_FACTOR_EXPERIMENT_ENVIRONMENT_WHITEPAPER.md) | 方向② 实验环境画像 |
| [EDGE_FACTOR_EXPERIMENT_OPERATIONS_MANUAL.md](2-experiments/EDGE_FACTOR_EXPERIMENT_OPERATIONS_MANUAL.md) | 方向② 实验操作手册 |
| [EDGE_FACTOR_EXPERIMENT_AUDIT_LEDGER.md](2-experiments/EDGE_FACTOR_EXPERIMENT_AUDIT_LEDGER.md) | 方向② 口径迁移与处置台账 |
| [variance-report.md](2-experiments/variance-report.md) | 重复性与方差报告 |
| [CONFIDENCE_SENSITIVITY_2026-10-22.md](2-experiments/CONFIDENCE_SENSITIVITY_2026-10-22.md) | 方向① 先验敏感性（非标定） |
| [clab-lab/](2-experiments/clab-lab/) | 实验脚手架数据（`data/*.jsonl`） |
| [srd-bench/v23-t2-stateful-20261028.md](2-experiments/srd-bench/v23-t2-stateful-20261028.md) | SRD v2.3 T2 状态化（单向可达，layered AUC 1.000） |
| [srd-bench/v23-t1-intra-subnet-20261028.md](2-experiments/srd-bench/v23-t1-intra-subnet-20261028.md) | SRD v2.3 T1 域内主机级 ACL（layered AUC 1.000） |
| [srd-bench/v22-facts-dataset-20261027.md](2-experiments/srd-bench/v22-facts-dataset-20261027.md) | SRD v2.2 事实数据集（L1/入向，layered 0.959 vs flat 0.462） |

## 四、审计（`3-audits/`）

索引见 [3-audits/README.md](3-audits/README.md)。**以最新 `*-verdict.md` 为准**；
`3-audits/archive/` 与 `3-audits/history/` 是过程记录，冲突时以最新判决为准。

## 五、已废弃（`4-archive/`，结论一律作废）

| 子目录 | 内容 |
|---|---|
| [plans/](4-archive/plans/) | 历史实施计划（7 份：ATT&CK 分离、剩余架构、旧 v0.3.0 规划、4 份 superpowers 计划） |
| [designs/](4-archive/designs/) | 被取代的设计（当前无；规则见该目录 README） |
| [releases/](4-archive/releases/) | v0.2.2 / v0.2.3 发布说明 |
| [reviews/](4-archive/reviews/) | 历史债务总览 |

> `4-archive/` 里的任何结论都不得作为当前实现依据；需要引用时先去 `1-current/` 找对应现行版本。

## 六、英文文档（`en/`）

索引见 [en/README.md](en/README.md)。

## 七、新增文档流程

1. **先判定"现行 vs 废弃"**：结论仍与代码一致、且没有后续设计/审计推翻 ⇒ 现行。
2. **现行文档**按类型落入 `1-current/{design,whitepapers,guides,reference}/`；
   实验口径与数据说明落 `2-experiments/`；审计落 `3-audits/`。
3. **废弃文档**必须整体移入 `4-archive/{plans,designs,releases,reviews}/`，
   禁止留在 `1-current/` 或平铺在 `docs/` 下；被取代的原因写入 [MIGRATION_MAP.md](MIGRATION_MAP.md)。
4. 文件名保持稳定，不要用文件名表达"废弃"；目录已表达权威顺序。
5. 移动后**必须**更新所有引用（代码注释/测试常量/配置/脚本/其他文档），
   并跑一次引用完整性检查（见下节）。
6. 在 [MIGRATION_MAP.md](MIGRATION_MAP.md) 追加一行"旧路径 → 新路径 → 分类 → 理由"。

## 八、引用完整性检查

迁移或新增/移动文档后，在仓库根目录执行：

```bash
bash scripts/check-doc-refs.sh
```

脚本扫描**所有被跟踪文本文件**里形如 `docs/...` 的路径（含反引号与 Markdown 链接），
对解析出的**完整路径**逐条断言存在性：目录引用按目录判定，文件引用必须真的存在
（例如 `docs/1-current/design/` 目录存在、但其中编造的 `NO_SUCH_FILE.md` 不存在 ⇒ 报红）。
`...`、`*`、`<name>` 等占位符按设计跳过。输出 `DANGLING: N`，`rc=0` 当且仅当 `N=0`。
唯一例外是 [MIGRATION_MAP.md](MIGRATION_MAP.md) 本身（它按设计记录历史旧路径）与冻结的论文
`lunwen/paper/attacker-cognitive-loop-paper.tex`（论文不改，历史路径保留），脚本会在输出中说明跳过数。

可跑自测（在临时 git 仓库里造“目录在、文件不在”的引用，断言必须 `DANGLING: 1`、`rc=1`）：

```bash
bash scripts/check-doc-refs.sh --selftest
# → SELFTEST: PASS (clean=0; dir-exists-file-missing=1)
```
