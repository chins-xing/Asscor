# ASSCOR 历史债务与未完成项清单（2026-09-08）

**版本基线**: main v0.2.3（`0682d6d`）+ ASSCOR-Research-Core（`ab33d72`）
**来源综合**: SECURITY_ISSUES_AUDIT_2026-09-08（34 项）· COUPLING_AUDIT_2026-09-03 · Secure Mode 各轮审查 deferred · 研究方向需求（2026-09-08）
**维护**: 每轮关闭/新增后更新本文档并提交（两分支各自归档）

---

## 〇、状态总览（截至 2026-09-08）

| 类别 | 总数 | 已关闭 | 剩余 |
|---|---|---|---|
| 安全审计 Critical | 3（C-1/C-2/C-3） | **3** ✅ | 0 |
| 安全审计 High（main H-1..H-5 + ARC RC-H1/RC-H3） | 8 | **8** ✅ | 0 |
| 安全审计 Medium/Low（main M/L + ARC RC-M/RC-L） | 23 | M-1..M-6/L-1/L-3/L-4/L-5/RC-L1/RC-L2/RC-L3/RC-L5/RC-M1/RC-M2/RC-M3/RC-M5 + RC-H2(High 并入上) | **0 需修**（RC-M4 并入②、RC-L4 研究期接受；L-2 长期另计） |
| 耦合审计（COUPLING 2026-09-03） | 8（C1/C2/F2..F7） | **8** ✅（268cca9、0eb456e、429539e、d64e4e8、6b3bd0a） | 0 |
| Secure Mode deferred minors | 12+ | 全部（23ca6cd..d9c23d9） | **0** ✅ |
| 研究方向 | 2 | ①（可信度原生变量） | **②**（边缘因子向量图变量化） |
| 工程债（论文/拆包/超时等） | — | — | 见 §五 |

**Secure Mode、安全审计与耦合审计（C1/C2/F2–F7）已全闭合**；剩余集中于研究方向② 与工程债。

> 更新记录：2026-09-08 推进批次1（ARC f2edcb0 / main 8840dbf）关闭 L-3/L-4/L-5 + M-2 + M-3；批次2（main c621df2 / ARC ea52d73）关闭 M-4/M-6/L-1(version)/L-6；批次3（ARC b6c3161）关闭 RC-L3；批次4（main 664165d / ARC a8d17ed）关闭 RC-M5/RC-L1/RC-L5；批次5（ARC 0a462df / main 同步）关闭 RC-M3（SecureMaxNoUnlock 可配 + 预告告警）。安全审计 Medium/Low 23 项全部处理完毕（RC-M4 并入方向②、RC-L4 研究期接受、L-2 长期）。批次6（ARC 0eb456e/429539e/d64e4e8/6b3bd0a）关闭耦合 F4–F7（孤儿/tag 归属、ACL 引擎 tag 门控、config 纯解析化、comms SPI 注入）。耦合审计 8 项全部处理完毕。同日归档新方向③ 熵扩展包设计与实现计划（b737c18，**仅设计+计划，未实现**），CLI 定位重构独立为方向④。剩余 = 方向② + 方向③（待执行）+ 方向④ + 工程债。

---

## 一、安全审计 Medium/Low 剩余（SECURITY_ISSUES_AUDIT_2026-09-08，main 通用）

| 编号 | 项 | 位置 | 修复方向 | 备注 |
|---|---|---|---|---|
| ~~M-2~~ | runCommand 冗余分支 | `internal/agent/agent.go` | ✅ 已闭（f2edcb0） | 统一 ParseCommand 单路径 |
| ~~M-3~~ | HMAC 密钥相对路径 | `internal/commander/commander.go`、`internal/integrity/sign.go` | ✅ 已闭（f2edcb0） | 密钥目录注入 cert_dir |
| M-4 | agent.ini 明文 hmac_key | `cmd/agent/main.go loadConfigFile` | 废弃配置字段，强制环境变量/密钥文件 | |
| M-6 | 配置数值无范围校验 | `internal/config/config.go` | Parse 阶段权重/阈值/因子范围校验+告警 | |
| L-1 | 安全关键包零测试 | `internal/integrity`/`resilience`/`topology`/`version`/`api/v1` | 补单元测试 | C-1 已补 algo 测试，其余待 |
| L-2 | 大包拆包 | `internal/attck`(8.3k行)/`kernel`(7.7k)/`engine`(6k)/`cli`(5.9k)/`adapter`(5.6k) | 按子领域拆分 | 长期 |
| ~~L-3~~ | Docker HEALTHCHECK 误匹配 | Dockerfile | ✅ 已闭（f2edcb0） | kill -0 1 |
| ~~L-4~~ | Dockerfile 未用 wget | Dockerfile | ✅ 已闭（f2edcb0） | 移除 |
| ~~L-5~~ | config.ini 版本号滞后 | config.ini（标注 v0.2.1） | ✅ 已闭（f2edcb0） | v0.2.3 |
| L-6 | 扩展安装权限未最小化 | `internal/extmgr/extension_installer.go` | 统一 0755/0644 清特殊位 | |

## 二、安全审计 RC 剩余（ARC securemode/研究专属）

| 编号 | 项 | 位置 | 修复方向 | 备注 |
|---|---|---|---|---|
| ~~RC-M3~~ | 自恢复阈值短+静默丢配置 | `internal/agent/securemode.go` | ✅ 已闭（0a462df） | SecureMaxNoUnlock 可配(agent.ini secure_max_no_unlock) + threshold-1 预告告警 + 恢复指引; SecureModeNoSecret 仍立即短路 |
| RC-M4 | 研究引擎权重全硬编码 | `internal/predictor`/`engagement`/`attackerstate` | 权重参数化+实验配置注入 | 与方向②耦合，可并入 |
| ~~RC-M5~~ | exprunner 命令注入风险 | `cmd/exprunner/main.go dockerExec` | ✅ 已闭（664165d） | shellSafe 插值元字符校验 + 端口范围 |
| ~~RC-L1~~ | decoyd 无访问控制 | `cmd/decoyd/main.go` | ✅ 已闭（664165d） | hits 上限 100k + accept 错误分类 |
| ~~RC-L3~~ | argon2id t 偏低 | `internal/securemode/crypt.go` | ✅ 已闭（b6c3161） | t1→t2 + 支持集兼容旧文件 |
| RC-L4 | 研究模块状态无持久化 | attackerstate/defensecycle/engagement/predictor | 持久化接口 | 研究阶段可接受，需文档标注 |
| ~~RC-L5~~ | 新模块无测试 | agentinstall/semver/decoyd/exprunner | ✅ 已闭（a8d17ed 等） | agentinstall unit 内容/decoyd/exprunner 已补；semver 本有；tracecheck 工具性弱留档 |

> 不采纳：RC-M6（仓库内容分离——lunwen 白名单跟踪为项目决策）。

## 三、耦合审计 Minor 剩余（COUPLING_AUDIT_2026-09-03；C1/C2/F2/F3 已修 268cca9，F4–F7 已闭 0eb456e/429539e/d64e4e8/6b3bd0a —— 全部关闭）

| 编号 | 项 | 方向 |
|---|---|---|
| ~~F4~~ | comms 消费方式不统一（直接函数调用 vs kernel SPI） | ✅ 已闭（6b3bd0a）：securemode 经新增 kernel.SecureModeAgentSecrets 接口注入；topology/resilience 判定为 kernel 直调地基库保留直调（就地注释） |
| ~~F5~~ | 孤儿包 `internal/oscal`/`semver`/`adapterhub`（0 import）；`historicalstore` 默认-on 无 tag | ✅ 已闭（0eb456e）：oscal 加 tag `oscal`、historicalstore 加 tag `persistence`（均入 MODULE_TAGS 保 CI 覆盖）；adapterhub 自 b29d502 已 tag `adapter` 维持；semver 已被 optional/pkgmgr 引用非孤儿 |
| ~~F6~~ | config→checks 反向依赖（地基层向上依赖检查注册表） | ✅ 已闭（d64e4e8）：config 纯解析化（RegisterUserChecks 移除）、CU- 前缀下沉 model、注册显式于 kernel 装配根 |
| ~~F7~~ | ACL 四包默认-on 无 tag（attackerstate/predictor/engagement/defensecycle） | ✅ 已闭（429539e）：四包加 `//go:build tracecheck||expr`（实验工具 tag 门控，论文/文档命令零改动），MODULE_TAGS 增 expr 保覆盖 |

## 四、研究方向

| # | 内容 | 状态 |
|---|---|---|
| ① | SSAM/SRD 情报可信度作为算法层原生变量（贝叶斯置信区间） | ✅ **已完成（审计 14 项已修），但标定仍后置**（2026-10-22 修复复核，提交链 `34b89c6`(B-1) → `929b454`(B-2) → `1a54c67`(I-12) → `e9d12ff`/`4e5db9c`(I-2) → `9a3f348`(I-10) → `78c2a1d`(I-9) → `e10977d`(I-5) → `36a5b2c`(I-8) → `cee657f`(I-1/I-4/I-6) → `7b307f2`(I-7) → `ac1bd29`(I-3 敏感性表)）。审计的 2 Blocker + 12 Important 全部闭环：外部 adapter 透传 `Source`/`Confidence` 使来源表对第三方扫描器生效；`accept_by_lower_bound` 已被插件/库/legacy/kernel 所有判定点消费；legacy 也写 σ/CI/`EvidenceConfidence`；`c` 归一只有一份；`checkrx` 按字节字典序；坏值 fail-fast；未知 `algorithm` 加载即错；`σ_final` 按 intrinsic 权重 0.5 折算且区间只钳下界。**唯一有意行为变更**：`passed=false && Delta>=0` 的检查两边统一跳过（旧 legacy 会累加正 delta）。**仍未兑现**：实验标定 / CI 覆盖率验证 —— 出厂 `user=0.90`/`adapter=0.80` 是**先验**，对外不得声称"已标定"。详见 `docs/1-current/design/CONFIDENCE_MODEL_DESIGN_2026-09-08.md` §7.7 与审计判决书后续复审 |
| ② | 边缘因子耦合放大缺理论边界 → 基于真实数据的**向量图** + 边缘因子**变量化**（非常量进算法） | ✅ **里程碑 B 已完成（2026-10-21）**：A（Task 1–10 + 2 独立任务，五轮复审闭环）已交付统一框架/四候选/配置注入/内仓钩子/溯源字段/离线工具。B 在 2026-09-12 **当时**的状态是「进行中」：采集器（`cmd/edgescen`）、共享 JSONL 契约（`internal/edgeexp`）、实验模板与场景矩阵脚本已就位，但**全量扫描被当时的宿主前提阻塞**（见 §七 C1）。**该阻塞已解除**：Task 13/17 把基质换到 qemu VM 并对齐取数权限，Task 19 入库 33/33 全量批次（22 targeted + 11 recon）、Task 21 完成重复轴 99 条（66 + 33）、Task 24 给出拟合 NULL / 不可辨识结论；门禁①/② 全绿。证据：台账 H.1/H.5/H.7/H.8 |
| ③ | **熵扩展包**：行为/网络/基线三熵（瞬时熵相对零点的偏移，独立于评分体系）+ 独立收集器四面采集 + 时序情报存储（保密/完整/可用）+ 审计链 | 🗄 **已归档，未实现**（设计 `docs/1-current/design/ENTROPY_EXTENSION_DESIGN_2026-09-08.md`、计划 `docs/4-archive/plans/2026-09-08-entropy-pack.md`，提交 b737c18；里程碑 A Task 1–12 待执行；retention 分段链语义待定） |
| ④ | **CLI 定位重构**：剥离运维属性（Install/Uninstall/Upgrade/systemd），CLI 仅作为高危操作的唯一入口（熵包零点打点/重置、模式切换、密钥与导出等） | ❌ 未开始（待方向③ 落地后与熵命令一并收敛） |

## 五、工程/研究债（非审计项）

| 项 | 说明 |
|---|---|
| 论文数字验证 | trace/敏感性表必须经 `cmd/tracecheck`（tag tracecheck）对照真实引擎验证；含 intent=unknown→maintain +3.0 陷阱 |
| E1–E9 上限标注 | 100% 意图追踪须保留"理想环境上限"限定，不得回退 |
| 扩展检查 sh -c 无超时 | `extmgr.buildExtCheckFunc` 命令分支无 context 超时（H-3 修路径未修执行超时） |
| gofmt 门禁 | CI 已加（本清单后 0682d6d/ab33d72 修复两分支），后续提交须过 |

## 六、建议下一批处理顺序

1. **快清项**（1-2 行级）：L-3/L-4/L-5、RC-L5 部分
2. **中等**：M-2、M-3、M-4、RC-L3
3. **设计类**：方向②（大）、RC-M4（并入方向②）
4. **不采纳/可延**：RC-M6（项目决策）、RC-L4、L-2
5. **已归档待执行**：方向③ 熵扩展包（设计与实现计划已入库）；方向④ CLI 定位重构

---

## 七、里程碑 B（方向② 实验执行）实测发现与债务（2026-09-12）

来源：里程碑 B Task 1–4/3B 的实现与多轮独立评审、以及一次**真实 WSL2 Containerlab + Caldera 冒烟**（3 场景，共 1322s）。
记账口径：**只有实测确证的才写成事实**，静态推断一律标注。

### C1（**当时的实验设计级阻塞**；已解除，保留为史料）

> **状态（2026-10-22 对账，第二次审计 Important-4）**：**已解除**。下面记的是 **2026-09-12 当时**
> 的阻塞：采集器评估的是**开发机**、注入是 no-op、标签单类别 ⇒ 全量扫描不可执行。当时列出的
> A/B/C 三个选项与"C1 待定案"都**只是当时的状态**，**不要再当现行阻塞引用**。
> **解除方式**：Task 13/17 把基质换到 **qemu VM**（`observation_target` 让采集器观察被攻击的那台
> VM）并**对齐取数权限**（root 等价，见操作手册 §5.3.2 第 4 条）；Task 19 入库 33/33 全量批次
> （22 targeted + 11 recon，门禁①/② 全绿，台账 H.1/H.5），Task 21/22 完成重复轴 99 条
> （台账 H.7），Task 24 给出拟合 NULL/不可辨识结论（台账 H.8）。下列原始记录仅用于解释
> "当初为什么阻塞"，**不是**未关闭项。

- **分数侧塌缩（当时）**：采集器评估的是**开发机**，而该宿主上六个因子的触发检查**本就全部失败**（55 项失败、总分 52.21）⇒ "注入检查失败"是 no-op ⇒ 冒烟的 `S0-baseline`/`S5-cascade-3fa`/`R-no-ids` 三条记录**除场景名/时间戳外逐字段相同**；按此宿主的自然失败集推算，**25 场景只买到 2 个不同数据点**（20 条相同 + 5 条注入 `EF-SYNCOOKIE` 的变体），而全量扫描需 3.1–7.5h。
- **标签侧是结构性的（当时）**：注入完全发生在采集器**本地**的检查集里，矩阵脚本**从不改动被攻击节点的防护**（`edge_reset` 只重建实验室、`edge_attack` 只推进剧本）⇒ 三条记录 `compromised=true / block_effective=false / nodes_affected=1` 恒定 ⇒ **单类别标签**，漏判率/误阻断率/AUC 与 logistic 拟合全部退化。
- **更深一层（管线正确性，现在仍然成立）**：观察对象必须是**被注入/被攻击的那台机器**，否则"记录描述部署行为"这一前提不成立。这条**不是**阻塞、而是现行口径；VM 批次已按它执行。
- **当时的选项（2026-09-12 列出，已由"换基质"取代）**：**(A)** 硬化基线宿主；**(B)** 反转设计；**(C)** 缩小矩阵。
- 相关：`docs/4-archive/plans/2026-09-12-edge-factor-coupling-milestone-b.md` 的 Task 4 门禁与 §5.4 手册；等价采样矩阵实现在 `lunwen/clab-lab/scripts/edge_matrix.sh`。
- **解除判据（可复核）**：`records-dl360-qemu-20261016.jsonl` = 33 条（`sha256 82d37ead…f5b468`），`substrate=qemu`；重复轴 targeted 66 + nontargeted 33；台账 H.1/H.5/H.7/H.8。

### 已实测确证的技术事实（可写进论文，需按注记口径）

| # | 事实 | 证据 |
|---|---|---|
| B-1 | 出厂 `configs/*.ini` 的 `[edge_factors.custom]` 与内置因子同名 ⇒ **引擎确实把同一因子乘两次**，链上出现重复 ID（冒烟三条记录均 11 条链 / 6 个 ID，重复对分别带 0.70（内置）与 0.85（custom）两个不同观测值） | 门禁⓪ 在真实记录上实测；11 条链复算重现记录分数。**边界**：`EF-SYNCOOKIE` 的重复**未观测到**（宿主 `tcp_syncookies=1`，该因子未激活）；结论不适用于**不带** `[edge_factors.custom]` 重复段的配置 |
| B-2 | **C 候选在 18/25 个非顺序场景上与 V 数值等价**（单条链只有一个 `ts` ⇒ 时间窗恒假 ⇒ 耦合项消失）；C 的全部信号只来自 **7 个顺序场景** | 采集器的 `ts` 基准实现 + 链模型 `from.ts.Before(to.ts)`；那 18 条记录是**对照**不是信号 |
| B-3 | 顺序记录里"取评估时刻"的条目**不是设计顺序**（注入在前、自然失败在后由环境造成） | S5 真机记录：注入 03:07:17Z/03:07:20Z，其余 8 条取采集时刻 |
| B-4 | 级联因子 `c_trigger = 0` ⇒ `EffectiveFactor(0.82,0) = 1` ⇒ **V/G/C 下无惩罚**，而 legacy 真的乘 0.82 | spec §10.2；S5 组对照 |
| B-5 | `threat_coeff` 无上界 ⇒ 总分**可能 >100**（`T=1.4, base=100, E=1.0 ⇒ 108`），而 `ssam-lib/ir.go` 要求 `final_score ∈ [0,100]` | 引擎既有口径；**论文表格出现 >100 必须加脚注** |
| B-6 | `EF-3FA` 应作为**普通因子**进入 `-factors`（模板已声明 `vector.EF-3FA`；**省略**它会让离线工具静默丢弃该链上惩罚，并砍掉 C 候选唯一的级联边 `EF-3FA→EF-002FA`） | Task 4 评审实测；离线复跑：含 `EF-3FA=0.82` ⇒ 门禁① exit 0（3/3）；省略 ⇒ exit 1 |

### 不得夸大的口径（报告/论文均适用）

- **n=3 的排序层指标不可引用**：`legacy/vector/graph` 的 Spearman 系数恰为 0 是 `pearson` 对常量输入返回 0 所致；`Kendall=-1.000` 在 n=3 跳过并列对后只是两次比较的产物；`AUC=0` 对每个候选都成立是**单类别退化**。诚实表述是"**chain ≠ vector 恰好出现在有时间结构的地方**"，并以工具自己打印的"本次比较无区分力：未选模"为准。
- **拟合优化的是分数的线性化代理**（`design()` 用标量汇总 `a_i=(1−eff_i)·Σ_d v_i[d]`，真实评分是逐域 `L_d`/`P_d`），故"拟合更优 ⇒ 决策层更好"不成立；权威判据是用该参数跑离线重算后比决策层指标。
- **合成数据的可恢复性 ≠ 真实场景的可辨识性**；`±0.25` 不是真实数据上的精度承诺。
- **排序层与标签同源**（未攻陷样本 severity 恒 0，而 `compromised` 又是 AUC 标签）⇒ Spearman/Kendall 与 AUC 高度相关，不得当独立证据。`time_to_compromise_s` 缺失曾使 `severityOf` 给出**最大**加成（`1000/(0+1)`）⇒ 采集器现已要求该字段必填。

### 工程债（新增，均可独立于 C1 关闭）

| 项 | 状态 |
|---|---|
| 出厂模板 `scoring_engine` 写在 `[extension_weights]`、解析器只在 `[weights]` 读 ⇒ **静默 no-op** | ✅ 已闭（7 份模板 + 2 条回归断言） |
| `lunwen/clab-lab/kernel-config.ini` 的 `threshold` 写在解析器不读的段（且无 `[acceptability]` 段）⇒ 该值从未生效、`Default()` 的 80.0 只是巧合 | ✅ 已闭（`22f4d33`；两层判据：段位 + **等值探针**"改文件值 ⇒ 解析结果必须跟着变"，评审独立做内容层变异 ⇒ 断言确实会红） |
| §5.4 要求的 `threshold = 60.0` 敏感性行**当时无法执行**（工具原先无阈值覆盖） | ✅ 已闭（`a1ac836`；显式 opt-in，评审实跑复现数值与报告逐位一致） |
| Task 4 的 7 条单行项（重复 echo、兜底来源字符串、零碎片时空洞为真的路径断言、干跑跳过谓词的重复拷贝、跑扫描前重建 `build/edgescen`、`checks_ts_mismatch` 语义未触发、跨 00:00 UTC 端到端未复现） | ⏳ deferred（随解决 C1 的那次提交一并落地）。注：**"跑扫描前重建 `build/edgescen`" 已于 2026-09-12 17:00 完成**（`edgescen` + `edgecompare` 均以 HEAD 重建，WSL 实测 `-list` 25 组） |
| 仓库根 `.gitattributes` 仅覆盖 `*.sh`（`text eol=lf`）；**Go 文件的行尾策略仍待定** | ⏳ 待定案（`*.go text eol=lf` 属仓库级决策） |
| **阈值敏感性行可能在 `-threshold == 记录自带阈值` 时产出"零信息产物"**（表格与主对比逐位相同，报告头却写"覆盖值被忽略"）而**照常 exit 0** ⇒ 看起来做了敏感性分析 | ⏳ deferred（配置清理评审 M1；最小修法：抽样读一条记录的 `observed.threshold`，相等时打醒目警告并写进产物横幅与 `sensitivity.json.warning`；**不**建议 exit 2 —— 用它核对主对比是合法用法） |
| 7 份出厂模板的 `[webui]` 段**内核解析器不读**（属观察项，未追踪到实际消费者） | ⏳ deferred（配置清理评审 M4） |
| `internal/config` 的 `[adapters]` 与 `[management_adapters]` 写**同一 key 空间**，谁赢取决于 Go map 迭代序（实测同内容连续 `Parse` 10 次：9 次 `CCC/DDD`、1 次 `AAA/BBB`；lab 现配置两段同值故不可观测） | ⏳ deferred（配置清理评审 M7，**不属**该轮改动；换配置即显形且无日志） |
| `lunwen/EXPERIMENT_MANUAL.md:90,191` 路径写成 `configs/kernel-config.ini`（实为 `lunwen/clab-lab/kernel-config.ini`），键位描述已过时 | ⏳ deferred（配置清理评审 M6） |
| `cmd/edgecompare/report.go:237-238` 注释声称"AUC 全等"**与输出自相矛盾**（实测 chain `AUC=0.000`/`Spearman=-0.866`，其余为 0）；真正判据是"FN/FP 全等，AUC 也分不出严格更优" | ⏳ deferred（配置清理评审 M3，纯注释） |
| **测试方法论教训**（配置清理评审实测）：`internal/config` 部分键带**值域守卫**（如 `[attck] beacon_threshold/attribution_threshold` ∈ `(0,1]`，`config.go:525,529`）⇒ 用域外值（如 `7`）做"等值探针"会**静默跳过**、把**有效**的键误判成"不生效"。**对带守卫的键，等值探针必须用域内值。** | 📝 口径（后续所有配置类断言适用） |
| 解析层**任何段**都不读 `[heartbeat]`（`enabled`/`timeout_sec`；60s 来自模块内置默认）⇒ 挪段救不活；本轮只钉成断言 + 写进 §5.4.8 | ✅ 已闭（`22f4d33` 侧；lab 配置文件**缺一行警示注释**记 deferred，防读者误以为生效 —— 配置清理评审 M2） |

### 第二次审计收口新增债（2026-10-22，Task 26 登记）

> 来源：`audit-2-direction2-verdict.md` + Task 26 收口复核。**只登记、不擅自处理**；每条都给了可复核的依据。
> 不为了"看起来全绿"而关闭任何一条。

| # | 项 | 依据 / 判据 | 现状与处置 |
|---|---|---|---|
| D-1 | **`gofmt -l` 起点上就有 15 个既有文件**（`prism-lib/*` 9 个、`ssam-lib/*` 5 个、`lunwen/attachment/scripts/exprunner-main.go` 1 个） | 按**入库内容（LF）**复算（`build/fit24/gofmt_check.py`：498 个跟踪 `.go`，把 CRLF 归一后整树跑 `gofmt -l`）⇒ **15 行**；文件清单见操作手册 §7 第 6 条 | ✅ **已修（2026-10-24，ARC e308422 / main 7acb200）**：15 个文件全部 gofmt -w，语义中性（git diff -w 后仅 prism-lib/prism_test.go 的 UTF-8 BOM 被去掉）。判据按**入库内容（LF）**复算：git -c core.autocrlf=false archive HEAD | tar -x -C /tmp/… && gofmt -l ⇒ **0 行**（505 个 .go）。⚠️ 直接在工作树跑 gofmt -l 仍会报 5 个 CRLF 假阳性 —— 归零只认 archive 口径 |
| D-2 | **门禁⓪「只报不判死」是否收紧** | 链上重复条目如实报出但不拦；收紧 = 判据变更（台账 B.1 / 操作手册 §7 第 8 条） | ⏳ **维持现状**：Task 18 已修消费侧折叠、链与配置不动；**收紧需先定案**（会改判据语义） |
| D-3 | **`-group-by` 缺省仍是 `row`（逐行）** | `cmd/edgecompare/fit.go` 的 `fs.String("group-by", "", …)` + `fitGroups` 的 `case "", "row"`；手册 §5.5 / 设计 D10 已写明风险 | ⏳ **有意保留历史口径**：改缺省会让既有命令的输出口径静默改变；报告头已强制写明单位。是否翻转缺省**待定案** |
| D-4 | **`edge_probe.sh` 在 qemu 上不是 root 等价** | 探针经 `lab_target_exec`（登录用户 `asc`）执行，而取数是 root 等价 ⇒ `condition_probes[].condition_holds` 与 `checks[]` 可能不一致（如 `EF-APPARMOR` 走 `aa-status`，`asc` 下 rc=4）；操作手册 §7 第 12 条 | ⏳ **未改**：改它要动 `edge_probe.sh` 与 20 条离线判据（判据语义变更）。对 S 组不阻断，但它**不是**一致证据 |
| D-5 | **19 个"半跟踪"历史文件**（3 个 `attack-*.json`、3 份 `records-wsl-clab-14-20260912-smoke*.jsonl`、13 个 `run.d/` 碎片） | 操作手册 §4.6：`git ls-files lunwen/clab-lab/data` = 146、`git status --ignored` = 33，其中 19 个是"同类兄弟已入库、这几个没入" | ⏳ **待定是否补录**：现行规则（Task 20 起白名单 + 规则入库）已不让**新**数据依赖记忆；这 19 个是规则化之前的存量，补录会改历史证据集，需维护者确认 |
| D-6 | **`PP-01`：σ 上界 `[0,100]` 不成立** | `ssam-lib/formulas_v2.go` 的 `SSAMV20Formula` 无 100 钳位、`exposureCoeff`/`threatCoeff` 只设下界；台账 F.1 | ✅ **已结案（2026-10-23）**：按「文档与代码不一致时以代码为唯一权威」⇒ **不加钳位**，论文三份与文档统一写"名义 0–100、上界不设"；论文附 `108 → [88.4,127.6]` 算例 |
| D-7 | **`AL-02`：台账 F1/F2/F3 的脱敏口径仍未定**（管理 VLAN 网段/主机名、实验数据里的实验代号、真名+邮箱） | 台账 F.1；Part F 的 F4–F7 已执行 | ⏳ **未定案**：引用 F1/F2/F3 结论前先确认新口径；Task 26 未动这三项 |
| D-8 | **VIF 误判这个教训（工具口径）：秩亏 ≠ 每列都 ∞** | 第二次审计 Important-1：`build/fit24/analysis.py` 旧 `vif_values()` 把"正规方程出现 `<1e-14` 主元"判成该列 `inf`；秩亏时对**每列**触发 ⇒ 误报"12 列全 ∞"（真值：11 列 ∞、`EF-3FA` = 12/11）。修法：用 MGS/QR 求 LS 投影后按 `1/(1−R²)` 算 | 📝 **已修脚本并重跑产物**（诊断文件是重跑产生）；教训固化为口径：**共线性诊断必须按定义算 R²，不能把"求解器奇异"当成"该列被完全解释"** |

