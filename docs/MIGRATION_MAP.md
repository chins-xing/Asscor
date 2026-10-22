# 文档迁移映射表（旧 → 新）

> 本表是 `docs/` 文件夹分离迁移的**可追溯记录**。旧路径按设计保留在此处，仅供追溯；
> 现行引用一律使用新路径。分类规则见 [README.md](README.md)。
>
> 迁移方式：全部使用 `git mv`（保留文件历史）；未删除、未合并任何文档内容，未改动技术结论。

## 一、平铺文档（`docs/*.md`）逐条

迁移后 `docs/` 平铺层只剩 `README.md` 与 `MIGRATION_MAP.md`。

| 旧路径 | 新路径 | 分类 | 一句理由 |
|---|---|---|---|
| `docs/APT攻击分析与检测增强白皮书.md` | `docs/1-current/whitepapers/APT攻击分析与检测增强白皮书.md` | 现行白皮书 | ATT&CK V19/APT 检测能力仍在代码中，白皮书描述现行实现 |
| `docs/ASSCOR 使用手册.md` | `docs/1-current/guides/ASSCOR 使用手册.md` | 现行指南 | 面向当前分支的操作步骤，可直接复现 |
| `docs/ASSCOR 外部接入源完整清单.md` | `docs/1-current/reference/ASSCOR 外部接入源完整清单.md` | 现行参考 | 外部适配器清单，供接入时查阅 |
| `docs/ASSCOR 扩展体系白皮书.md` | `docs/1-current/whitepapers/ASSCOR 扩展体系白皮书.md` | 现行白皮书 | 扩展体系仍在演进且与代码一致 |
| `docs/ASSCOR 扩展开发指南.md` | `docs/1-current/guides/ASSCOR 扩展开发指南.md` | 现行指南 | 扩展编写实战指南，面向当前 SDK |
| `docs/ASSCOR 扩展白皮书：内核安全域.md` | `docs/1-current/whitepapers/ASSCOR 扩展白皮书：内核安全域.md` | 现行白皮书 | `kernel_security` 域的设计与实现仍现行 |
| `docs/ASSCOR-Research-Core.md` | `docs/1-current/reference/ASSCOR-Research-Core.md` | 现行参考 | 研究分支定位与里程碑，当前分支仍在用 |
| `docs/ASSET_OWNERSHIP.md` | `docs/1-current/reference/ASSET_OWNERSHIP.md` | 现行参考 | 两分支资产归属表（2026-10-15 重取快照），维护中 |
| `docs/ATTACK_MODULE_SEPARATION_PLAN.md` | `docs/4-archive/plans/ATTACK_MODULE_SEPARATION_PLAN.md` | 历史计划 | 2026-08-02 实施计划；`optional/algorithms/packages/attck-ext-pack/` 已落地，计划执行完毕 |
| `docs/BLACKBOX_RECALLER_DESIGN.md` | `docs/1-current/design/BLACKBOX_RECALLER_DESIGN.md` | 现行设计 | 七轮审计收敛后的裁定（黑盒只作可选扩展）仍是现行架构约束 |
| `docs/CONFIDENCE_MODEL_DESIGN_2026-09-08.md` | `docs/1-current/design/CONFIDENCE_MODEL_DESIGN_2026-09-08.md` | 现行设计 | 已实现（B-1/B-2 + I-1…I-12 修复落地），标定后置不影响设计现行 |
| `docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md` | `docs/1-current/design/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md` | 现行设计 | 方向② 已实现并收口，设计仍是现行口径 |
| `docs/ENTROPY_EXTENSION_DESIGN_2026-09-08.md` | `docs/1-current/design/ENTROPY_EXTENSION_DESIGN_2026-09-08.md` | 现行设计 | 设计已定稿、等待实现；"未实现"不等于"废弃"，且无后续设计推翻 |
| `docs/MITRE_ENGAGE_LIGHTWEIGHT_DESIGN.md` | `docs/1-current/design/MITRE_ENGAGE_LIGHTWEIGHT_DESIGN.md` | 现行设计 | `optional/adversary/packages/mitre-engage/` 已存在，设计描述现行实现 |
| `docs/RELEASE_v0.2.2.md` | `docs/4-archive/releases/RELEASE_v0.2.2.md` | 旧发布说明 | v0.2.2 已被 v0.2.3 取代，仅作发布史料 |
| `docs/RELEASE_v0.2.3.md` | `docs/4-archive/releases/RELEASE_v0.2.3.md` | 旧发布说明 | v0.2.3 是已发布版本，发布说明按规则归档 |
| `docs/REMAINING_ARCHITECTURE_PLAN.md` | `docs/4-archive/plans/REMAINING_ARCHITECTURE_PLAN.md` | 历史计划 | 2026-08-12 的剩余项规划；后续审计/债务清单已按新口径维护，进度表述过期 |
| `docs/ROADMAP_v0.2.0_to_v1.0.0.md` | `docs/1-current/reference/ROADMAP_v0.2.0_to_v1.0.0.md` | 现行参考 | 通往 v1.0.0 的路线图，未被后续路线图取代 |
| `docs/SPC安全态势计算模块技术白皮书.md` | `docs/1-current/whitepapers/SPC安全态势计算模块技术白皮书.md` | 现行白皮书 | SPC 模块与公式仍在代码中 |
| `docs/SSAM与SRD算法可移植性白皮书.md` | `docs/1-current/whitepapers/SSAM与SRD算法可移植性白皮书.md` | 现行白皮书 | 算法可移植性结论未变 |
| `docs/SSAM接口规范与接入指南.md` | `docs/1-current/reference/SSAM接口规范与接入指南.md` | 现行参考 | 规范类文档；SSAM 2.0 接口仍现行 |
| `docs/Secure Mode 安全模式白皮书.md` | `docs/1-current/whitepapers/Secure Mode 安全模式白皮书.md` | 现行白皮书 | `internal/securemode/` 已实现，白皮书描述现行能力 |
| `docs/Systemic Risk Dynamics（SRD）白皮书.md` | `docs/1-current/whitepapers/Systemic Risk Dynamics（SRD）白皮书.md` | 现行白皮书 | SRD/Prism 理论与引擎规范仍现行 |
| `docs/TECH_DEBT_OVERVIEW.md` | `docs/4-archive/reviews/TECH_DEBT_OVERVIEW.md` | 历史记录 | 2026-08-12 债务总览已被维护中的 `docs/3-audits/TECHNICAL_DEBT_BACKLOG_2026-09-08.md` 取代 |
| `docs/TOPO_INFRASTRUCTURE_BLUEPRINT_2026-08-16.md` | `docs/1-current/reference/TOPO_INFRASTRUCTURE_BLUEPRINT_2026-08-16.md` | 现行参考 | 研究分支的拓扑层蓝图；ASSCOR-Research-Core.md 仍以其为演进依据（M1/M2 未完成） |
| `docs/VERSION_v0.3.0_PLAN.md` | `docs/4-archive/plans/VERSION_v0.3.0_PLAN.md` | 历史计划 | 文件自述"已废弃（2026-08-14）"，12 项任务已并入 v0.2.3 |
| `docs/工程实现白皮书.md` | `docs/1-current/whitepapers/工程实现白皮书.md` | 现行白皮书 | 工程架构与实现细节，仍与代码一致 |
| `docs/等级保护检查项映射手册.md` | `docs/1-current/reference/等级保护检查项映射手册.md` | 现行参考 | 等保映射手册，工具性参考 |
| `docs/项目篇章-系统安全可接受性模型.md` | `docs/1-current/whitepapers/项目篇章-系统安全可接受性模型.md` | 现行白皮书 | SSAM 理论基础与核心概念，未变 |

## 二、子目录整体迁移

| 旧路径 | 新路径 | 分类 | 一句理由 |
|---|---|---|---|
| `docs/audits/**`（82 个文件） | `docs/3-audits/**`（内部结构逐字保留） | 现行审计 | 审计判决与债务清单按规则整体保留；`archive/`/`history/` 是过程记录，冲突时以最新 `*-verdict.md` 为准 |
| `docs/experiments/**`（9 个文件） | `docs/2-experiments/**` | 现行实验口径 | 方向② 的环境、手册、台账、方差报告与数据集说明，绑定现行实验 |
| `docs/clab-lab/data/**`（3 个文件） | `docs/2-experiments/clab-lab/data/**` | 现行实验数据 | 实验数据资产，随实验文档同层存放 |
| `docs/superpowers/plans/**`（4 个文件） | `docs/4-archive/plans/**` | 历史计划 | 计划执行完即存档；现行口径不在这里 |
| `docs/superpowers/specs/2026-06-09-prism-ir-design.md` | `docs/1-current/design/2026-06-09-prism-ir-design.md` | 现行设计 | 文件自述"状态：已实现"，Prism IR 仍在代码中 |
| `docs/superpowers/specs/2026-08-21-secure-mode-design.md` | `docs/1-current/design/2026-08-21-secure-mode-design.md` | 现行设计 | Secure Mode 已实现，设计继续作为模块说明 |
| `docs/en/*`（5 个文件 + `README_EN.md`） | `docs/en/1-current/{whitepapers,guides,reference}/...` + `docs/en/README.md` | 英文文档 | 英文版按同样的现行/归档分层镜像；索引随之迁移 |
| `docs/asscor-architecture-review/**`（20 章） | `docs/1-current/reference/asscor-architecture-review/**` | 现行参考 | 20 章是概念层架构审查（2026-07-08）：定位/分层/概念模型结论未被后续设计或审计明确推翻；具体债务项以 `3-audits/` 最新判决为准 |
| `docs/asscor-architecture-review-zh/**`（20 章） | `docs/1-current/reference/asscor-architecture-review-zh/**` | 现行参考 | 同上（中文对照版） |

### 2.1 英文文档逐条

| 旧路径 | 新路径 | 分类 | 一句理由 |
|---|---|---|---|
| `docs/en/engineering-whitepaper.md` | `docs/en/1-current/whitepapers/engineering-whitepaper.md` | 现行白皮书（英） | 工程实现白皮书的英文版 |
| `docs/en/secure-mode-whitepaper.md` | `docs/en/1-current/whitepapers/secure-mode-whitepaper.md` | 现行白皮书（英） | Secure Mode 白皮书英文版 |
| `docs/en/srd-whitepaper.md` | `docs/en/1-current/whitepapers/srd-whitepaper.md` | 现行白皮书（英） | SRD 白皮书英文版 |
| `docs/en/ssam-interface-spec.md` | `docs/en/1-current/reference/ssam-interface-spec.md` | 现行参考（英） | SSAM 接口规范英文版 |
| `docs/en/user-manual.md` | `docs/en/1-current/guides/user-manual.md` | 现行指南（英） | 用户手册英文版 |
| `docs/README_EN.md` | `docs/en/README.md` | 英文索引 | 英文文档索引迁入 `en/` 并改指向新分层 |

## 三、判断说明（"先判后放"的依据）

1. **架构审查（英/中）判为现行**：两套 20 章文档审查的是项目定位、概念模型与分层边界，
   不以某个版本的实现细节为结论；`2026-07-03` 之后的审计（耦合/内核膨胀/Secure Mode 复审等）
   补充的是债务与实现问题，没有文档声明取代该审查。故落 `1-current/reference/`。
2. **`TECH_DEBT_OVERVIEW.md` 判为废弃**：`docs/3-audits/TECHNICAL_DEBT_BACKLOG_2026-09-08.md`
   明确"每轮关闭/新增后更新本文档并提交"，是仍在维护的债务口径；旧总览的 85/87、剩余 2 项
   已过期，继续留在现行目录会误导。故落 `4-archive/reviews/`。
3. **`ATTACK_MODULE_SEPARATION_PLAN.md` 判为历史计划**：目标是 ATT&CK 模块分离为扩展包；
   `optional/algorithms/packages/attck-ext-pack/` 已存在且带 build tag，说明计划已执行。
4. **`VERSION_v0.3.0_PLAN.md` 判为历史计划**：文件首段自述"已废弃（2026-08-14）"，直接按废弃处理。
5. **`ENTROPY_EXTENSION_DESIGN_2026-09-08.md` 判为现行设计**：文件状态为"设计已定稿，等待实现"；
   未实现不是废弃，且没有后续设计/审计否定它。其实施计划按规则归档到 `4-archive/plans/`。
6. **`TOPO_INFRASTRUCTURE_BLUEPRINT_2026-08-16.md` 判为现行参考**：`ASSCOR-Research-Core.md`
   把它列为演进依据，且 M1/M2 仍未完成，属于现行蓝图而非历史结论。
7. **`4-archive/designs/` 当前没有文档**：现存设计均未被明确取代；该目录保留规则说明，
   供后续真正被取代的设计迁入。

## 四、完整逐文件清单

- 平铺文档：见 §一（29 份；另有 `README.md` 原地重写、`README_EN.md` 见 §2.1）。
- 子目录文档：迁移时内部相对路径逐字保留，旧路径前缀替换如下，可据此推出每一份文件：
  - `docs/audits/` → `docs/3-audits/`
  - `docs/experiments/` → `docs/2-experiments/`
  - `docs/clab-lab/` → `docs/2-experiments/clab-lab/`
  - `docs/superpowers/plans/` → `docs/4-archive/plans/`
  - `docs/superpowers/specs/` → `docs/1-current/design/`
  - `docs/asscor-architecture-review/` → `docs/1-current/reference/asscor-architecture-review/`
  - `docs/asscor-architecture-review-zh/` → `docs/1-current/reference/asscor-architecture-review-zh/`
- 迁移后的完整清单以 `git ls-files docs` 为准；本表与之一一对应。
