# ASSCOR 边缘因子耦合与变量化设计（方向②）

- **日期**：2026-09-08
- **分支**：ASSCOR-Research-Core（原文括注「实现需同步 main」**已于 2026-09-13 撤销**：
  两分支正式分叉、永不整体同步，只有点名的关键模块单独移植 —— 见 §8 P7 的存档标记与台账 A.1）
- **状态**：设计定稿（所有取舍经作者逐项确认），等待实现计划
- **关联**：债务清单 §四 ②（边缘因子耦合放大缺理论边界）+ RC-M4（ACL 硬编码权重参数化，本轮只参数化、标定后置）；方向① 设计 `docs/CONFIDENCE_MODEL_DESIGN_2026-09-08.md`（本方向不改其语义）
- **实验环境**（**2026-10-19 更新**；环境画像见
  `docs/experiments/EDGE_FACTOR_EXPERIMENT_ENVIRONMENT_WHITEPAPER.md`）：
  - **`qemu` = 生产基质**：dl360gen9 上的 QEMU/KVM VM（全量批次 33 实例、重复轴 99 条都跑在这里；
    判据见 §10.4B 结论零）；
  - **`pve` = 快速验证**：dl360gen9 的 PVE CT（`CT 904` = `asc-tgt-c2` 保留为"快速验证"那一格的现成靶机）；
  - **`lxd` = 驱动保留、宿主已退场**：原远程 A-1 已于 **2026-10-19** 退为备份端（数据归档至 dl360gen9 的
    `/RAID-Mirror/from-a1/`、即将重置）⇒ **现无可用宿主**；
  - **`clab`**（WSL2 Containerlab，14 节点拓扑）= **开发与离线**（门禁、离线夹具、`edgecompare` 复算）。
  历次迁移与每次的理由见 `docs/experiments/EDGE_FACTOR_EXPERIMENT_AUDIT_LEDGER.md` Part C。
  > ⛔ **失效（仅存档）**：本条目 **2026-10-15 版**写的是「当前基质是 **dl360gen9 / PVE CT**
  > （`EDGEEXP_SUBSTRATE=pve`）；…远程 A-1/LXD 保留为可选基质」。生产基质自 Task 13/17 起已是 `qemu`，
  > 且 A-1 已退场（不是"可选基质"）⇒ 那是读全文"当前口径"的错误入口。
  > 原文见本文件 git 历史；**现行口径**以上面四行与 §10.4B 结论零为准。

> ### 阅读须知：本文档中的内部标识与凭据口径
>
> 1. **本文档出现的网段（管理 VLAN）、主机名与实验代号是内部实验环境的标识**。
>    它们都是 RFC1918 私有网段内的固定标识或团队自有实验机型号，**不构成外部可寻址信息**
>    （该管理 VLAN 实测与外网不互通）。之所以保留具体值而不是整体替换，
>    是因为它们散布在**必须带具体地址才能读懂**的踩坑注释里
>    （例如"容器的默认网关是路由器、不是宿主"）。
>    **新写的文档**一律使用 `<pve-host-ip>` / `<mgmt-vlan-cidr>` / `<lab-tag>` 之类的占位符。
> 2. **凭据（C2 的 API 口令）不写入本仓库**：由**未跟踪的本地配置**经环境变量提供。
>    本文中凡需要口令处一律写占位符 `<c2-key>`。
> 3. **带外管理控制器绝对不许访问**（不登录、不探测、不扫描、不改配置、不重启），
>    其地址**从未**写入本仓库。
> 4. 完整口径与处置台账见 `docs/experiments/EDGE_FACTOR_EXPERIMENT_AUDIT_LEDGER.md` Part E。

---

## 1. 概述与目标

把边缘因子的**耦合放大**从朴素连乘升级为**可配置、可拟合、有理论边界**的合成框架，并用真实攻防实验选择"最贴近真实"的参数化；同时把研究引擎的硬编码权重参数化（RC-M4 只参数化）。

### 1.1 现状与病根

| 现状 | 位置 | 问题 |
|---|---|---|
| 边缘因子合成 = 朴素连乘 `result *= f.Factor` | `ssam-lib/ast.go:195`（`evalProductChain`）、`ssam-lib/SSAM-README.md:74` | ① **无下界**：因子越多乘积越小，评分可被压到任意低；② **独立假设无依据**：同源因子（SELinux+AppArmor、无 SIEM+无 IDS）实际强相关，连乘把相关性当独立重复惩罚；③ **粒度错**：因子乘在总分上，无法表达"某因子主要打击哪个域" |
| 因子权重是常量 0.85/0.75/0.80/… | `config.ini [edge_factors]`、`[edge_factors.custom]` | 权重无数据来源，不可标定 |
| 因子→触发检查映射硬编码 | `internal/engine/ssam/adapter.go`（EF-001→两因素、RS-005→SYN cookie…） | 不可实验化替换 |
| ACL 引擎权重硬编码（RC-M4） | `predictor.go:119` `s += 3.0`、`temperature = 1.0`；`engagement` 的 `α β γ δ`（`DefaultParams`）；`attackerstate` 映射表 | 研究参数无法经实验配置注入 |

### 1.2 目标

1. **统一合成框架**：单公式表达"因子作用 + 耦合 + 饱和"，替代无界连乘，并给出**可证边界**。
2. **四候选共存**：`M0 现状乘性`、`V 逐域向量`、`G 耦合图`、`C 时序链` 在同一实现中可切换、可离线并行比较。
3. **变量化**：因子权重、因子→域向量、耦合系数、饱和参数、ACL 引擎权重全部经配置注入，代码无常量。
4. **真实数据选优**：以真实攻防实验的客观结果为主判据，选出最贴近真实的参数化，产出参数文件与对比报告。
5. **向后兼容**：默认配置与历史评分**逐位一致**；新模型仅实验启用。

---

## 2. 判定标准与实验范式

### 2.1 主判据（作者确认）

| 层 | 客观事实 | 模型侧对齐物 | 指标 | 权重 |
|---|---|---|---|---|
| **决策层** | 该配置下攻击是否被拦住 / 节点是否被攻陷 | 模型的可接受性判定（`score ≥ threshold`，或区间下界规则） | **漏判率**（模型说安全但实际被攻陷）、**误阻断率**、决策一致率 | **主判据（胜负依据）** |
| 排序层 | 场景按实际受损程度排序（攻陷耗时、达成 TTP 数、受影响节点数） | 模型分数排序 | Spearman ρ、Kendall τ | 辅助 |
| 数值层 | 每场景"是否被攻陷"的二值标签 | 模型分数 | AUC（分数越低越危险） | 辅助 |

**标签语义（2026-09-12 用户裁定 = L2，**实验执行前必须遵守**）**：

- 客观标签 `compromised` 在本方向实验中定义为"**该场景的*目标 TTP* 是否成功**"，**不是**"主机被攻陷"；记录与论文**必须**逐条写明这一语义。
- **为什么必须这样定义**（A-1 实测，控制侧在**六个控制全在**的硬化容器上跑固定剧本 `Discovery`）：`links=14`、`status={0:13, -3:1}` ⇒ `successes=13` ⇒ `compromised=true`、`block_effective=false`。`Discovery` 全是只读侦察能力（列用户、看进程），**任何**本实验的控制集都不会阻止它 ⇒ 用"是否被攻陷"作标签在真实环境里**恒为真、无方差**，决策层指标不可算。
- **目标 TTP 的选择（用户裁定）**：只做"**AppArmor 自定义限制策略 + 撞策略的 TTP**"一侧 —— 在目标容器上加一条**真实**的限制性策略，并用一条会撞它的 ability：策略加载 ⇒ 该 ability 被拒（`compromised=false`）、策略卸载 ⇒ 成功（`compromised=true`）。**禁止**用"只改标签"制造方差。
- **可算范围**：决策层指标（漏判率/误阻断率/AUC）**只对带目标 TTP 的记录可算**；其余因子的场景**只作分数侧**，其标签**不得**用固定侦察剧本的恒真结果顶替（记录里要用标签依据标记区分，见 §5.1）。
- **分数侧的诚实口径**：容器内 `aa-status` 恒报 profiles loaded ⇒ `OT-005` 在真机上**不会**翻成失败，场景"该防护缺失"仍按既有机制**合成注入**；报告/论文**不得**写成"真机上该检查真的失败了"。

### 2.2 对比范式：离线重算为主

实验**只记录原始观测与客观结果**；四候选模型在离线用**同一份真实数据**重算分数与决策。理由：一次实验即可比较全部候选，可反复调参与回归，且**离线与在线共用同一份实现**（方案 A 的核心价值）。

### 2.3 因子激活的注入方式

- **主方式**：注入**检查失败**（`config`/`user_check` 层），因为引擎中的因子本就**由检查失败触发**，这是引擎真实链路的代理，可控且可复现。
- **对照方式**：对能真实关闭的防护（停 IDS、去 SIEM 集成、去 2FA）做少量"真实缺失"场景，检验代理与真实缺失是否同向。
- 明确声明：容器内 SELinux/AppArmor 无法真正关闭，相关场景只能由检查失败代理 → 结论表述中必须标注这一代理关系。

---

## 3. 统一数学框架与四候选

### 3.1 公式

对域 `d`、激活因子集 `A`：

```
f_i        ∈ (0,1]      因子 i 的标量权重（现状值）
c_trigger_i∈ [0,1]      触发检查的可信度（方向① 已提供）
effective_f_i = 1 − (1 − f_i) · c_trigger_i        # 方向① 语义，保持不变
a_i[d]     = (1 − effective_f_i) · v_i[d]           # 因子 i 对域 d 的作用强度
L_d        = Σ_{i∈A} a_i[d] + Σ_{(i,j)∈E} c_ij · a_i[d] · a_j[d]
P_d        = P_floor + (1 − P_floor) · exp(−λ_d · L_d)     # 指数饱和
Score_d'   = Base_d · P_d
```

- `v_i[d] ≥ 0`：因子 i 对域 d 的作用权重。**完全未配置向量**的因子走 fallback（等价于作用于全部域、强度 1）——该 fallback 只存在于代码默认路径，**不写进配置、不参与校验**；一旦配置了 `vector.<id>`，就必须满足 `Σ_d v_i[d] ≤ 1`（典型做法是归一化，如 5 域各 0.2）。
- **运行时校验（Task 2 裁定，不得静默退化）**：
  - `EffectiveFactor == 0` 表示"调用方未提供有效因子值"→ 回落到配置权重 `f_i`；两者都缺则**报错**（不按"无惩罚"静默处理）；
  - `model = chain` 要求每个激活因子都带时间戳：任一 `TS` 为零值即**报错**（chain 语义依赖时间，不得静默退化为 vector）；
  - `λ_d` 必须覆盖**本次合成的域**，缺失即**报错**（不再静默取 `λ = 1.0`，否则参数不完整无法溯源）。
  - 例外：`legacy` 模型不读 `λ`（走乘性连乘路径），故豁免该校验。
  - 另注：`Validate(domains)` 以**传入的域列表**为准 —— 配置里出现请求域之外的 `λ` 或 `vector` 键会被拒绝；因此装配层应始终以完整域列表校验配置，或对配置做一致裁剪。
  - `Vectors` 中已声明的因子必须**覆盖请求域**（缺域即报错）；未声明者才走"全 1"fallback —— 避免"已声明但部分/为空"被静默当作零惩罚。
- `c_ij ≥ 0`：耦合系数（`G` 对称共现；`C` 有向 + 时序窗口）。
- `P_floor ∈ (0,1)`、`λ_d > 0`：饱和参数；`P_floor` 直接决定**惩罚上限 `1 − P_floor`**。
- 全域总分由既有的域加权聚合完成（`WeightConfig`），本框架只改域分修正环节。

### 3.2 四候选 = 同一公式的四种"边集"

| 候选 | `v_i[d]` | 耦合项 `E` | 针对的病根 |
|---|---|---|---|
| **M0 legacy** | 不参与（走原乘性连乘路径） | 无 | 现状基线（逐位一致） |
| **V 逐域向量** | 数据拟合（因子主要打击哪个域） | 无（`c=0`） | 病根 ③ 粒度错 |
| **G 耦合图** | 同 V | 对称 `c_ij`（共现放大 / 冗余抑制）；先验边有实证（`selinux×apparmor` 同触发 `OT-005`） | 病根 ② 独立假设 |
| **C 时序链** | 同 V | 有向 `c_ji` + 时序窗口 `Δt_max` | 无时间维；现实依据 = 既有 `EF-3FA → EF-002FA` 硬编码级联 |

三者不是三种口味，而是**同一回归的三个嵌套模型**：仅主效应（V）→ + 对称交互（G）→ + 时序交互（C）；M0 作为现状参照。

### 3.3 与现状、方向① 的关系

- **方向①（可信度）语义完全保留**：先按 `c_trigger` 衰减得到 `effective_f_i`，再进本框架；方向① 的测试与"`c=1` 与现状一致"性质不受影响。
- **M0 分支**：`model=legacy` 时仍走 `evalProductChain`，与历史评分逐位一致（硬门禁）。

### 3.4 形式化性质与证明

设 `a_i[d] ≥ 0`、`c_ij ≥ 0`、`λ_d > 0`、`0 < P_floor < 1`。

**P1 有界性**：`P_d ∈ (P_floor, 1]`。
*证明*：`L_d ≥ 0`（各项非负）⇒ `exp(−λ_d L_d) ∈ (0, 1]` ⇒ `P_d ∈ (P_floor, 1]`；`L_d = 0`（无因子激活）时 `P_d = 1`。∎
*工程含义*：单个域最多被衰减到 `1 − P_floor`，即**惩罚有上限**，彻底消除"因子越多分数越低到任意值"的无界塌缩。

**P2 单调性**：`∂P_d/∂f_i < 0`（因子值越低，惩罚越重）。
*证明*：`∂L_d/∂a_k = 1 + Σ_{j≠k} c_kj a_j[d] ≥ 1 > 0`；`∂P_d/∂L_d = −λ_d(1−P_floor)exp(−λ_d L_d) < 0` ⇒ `∂P_d/∂a_k < 0`。又 `a_k = (1 − effective_f_k) v_k[d]` 关于 `f_k` 严格递增（`c_trigger<1` 时）⇒ `∂P_d/∂f_k > 0`，即 `f_k` 越小 `P_d` 越小（惩罚越重）。∎

**P3 超模性与耦合放大**：`L_d` 关于 `a` 是**超模函数**，且联合惩罚不低于各因子单独惩罚之和。
*证明*：`∂²L_d/∂a_i∂a_j = c_ij ≥ 0` ⇒ `L_d` 超模。超模函数的增量性质给出
`L_d(A) − L_d(∅) ≥ Σ_{i∈A} [L_d({i}) − L_d(∅)]`，即**共存惩罚 ≥ 单因子惩罚之和**（`c_ij>0` 时严格大于）。`c_ij = 0` 时退化为可加。∎
*工程含义*：这是"耦合放大"的精确数学表达，且放大速率由 `c_ij` 控制；`c_ij < 0`（冗余）会破坏 P2，故本设计**限定 `c_ij ≥ 0`**，冗余/重叠通过 `v_i[d]` 的归一化（`Σ_d v_i[d] ≤ 1`）吸收。
*注意*：`P_d` 本身经凹增变换，其超模性不自动成立，故 P3 陈述在 `L_d` 上（精确、可测）。

**P4 兼容性**：默认配置（`model=legacy`）与历史评分**逐位一致**。
*性质*：这是分支选择 + 测试锚定的工程性质，非数学等价（两模型形式不同）；由"全默认配置评分逐位一致"测试保证。

**P5 极限行为**：`|A|` 增大或 `a_i[d]` 增大时 `L_d` 单调不减且无上界，`P_d → P_floor⁺`（不越过边界）。

### 3.5 拟合方法与可辨识性（诚实边界）

把 `L` 视作线性预测子、"是否被攻陷"为使标签 `y ∈ {0,1}`：

```
logit P(y=1) = β0 + Σ β_i a_i + Σ_{(i,j)∈E_prior} β_ij a_i a_j
```

- **V**：仅主效应 `β_i`；**G**：+对称交互；**C**：+时序交互（特征按激活时间窗口构造）。
- 拟合：L2 / L1 正则的 logistic 回归 + 交叉验证（留一场景 or k-fold）；模型选择以**决策层主判据**为准。
- **可辨识性限制（必须如实报告）**：场景数 22–25，而主效应 6 项 + 全部对称交互 15 项 = 21 个参数 ⇒ 全交互模型**参数多于样本**。因此：
  1. 交互项只用**先验候选边集** `E_prior`（`selinux×apparmor` 有实证依据——二者**共用触发检查 OT-005**；`no_siem×no_ids` 同域监测缺失；`two_factor×no_siem` 次之。默认 ≤ 5 条）；
  2. 采用 L1 正则 + 交叉验证，并报告**参数不确定度**（自助法区间）；
  3. 结论表述为"'哪些边显著 + 决策层指标改善多少'"，而非声称精确权重；
  4. **重复轴提供重复样本，提高可辨识性**（现行在 **VM 基质**上：两段共 **99 条**，台账 H.6；
     原文写的是"A-1 每场景重复 3 次"，A-1 已于 2026-10-19 退为备份端、即将重置）；场景矩阵可后续扩充（S2 全 15 组）。

---

## 4. 变量化与参数注入

配置段（实验模板放 `configs/edgeexp/`，不污染生产 `config.ini`）：

```ini
[edge_factors.model]
model = legacy
p_floor = 0.50
lambda.attack_surface = 1.0
lambda.operation_trust = 1.0
vector.EF-002FA = 0.9,0.4,1.0,0.3,0.2
coupling.EF-SELINUX.EF-APPARMOR = 0.35
chain.window_seconds = 300
```

写法说明（实现为准）：
- 键名一律用**小写段名 + 点号分隔**：`lambda.<domain>`、`vector.<FACTOR-ID>`、`coupling.<FROM>.<TO>`、`trigger.<FACTOR-ID>`；
- 因子 ID 与触发检查 ID 在解析时统一归一化为**大写**（与引擎 `FactorID` 一致），配置里写大写或小写都可；
- `vector.<id>` 的值必须是**恰好 5 个**逗号分隔数字，按域顺序 `attack_surface, business_continuity, operation_trust, resilience, kernel_security` 映射；
- 解析器只支持**整行注释**（行首 `#` 或 `;`），不支持行内注释；`model` 等键只能写在 `[edge_factors.model]` 段，写进 `[edge_factors]` 会报错。

规则：

1. **默认 legacy**：不写该段即走 M0，历史逐位一致；V/G/C 参数只能来自拟合产物或实验配置。语义分工（评审裁定）：**"默认 legacy" 由配置装载层表达**——`[edge_factors.model]` 段缺席时，调用方走 legacy 路径、**不构造**新模型参数；`edgefactor.Params` 的零值（`Model == ""`）被 `Validate` **刻意拒绝**，不提供零值兜底，避免装配层漏写 `model` 却静默按某个模型计分。
2. **键面无歧义**：配置解析统一把因子/触发名归一化为大写，装配层据此与引擎 `FactorID` 对齐；任何「查不到即回落」的路径都必须给出明确日志或错误，禁止静默退化为默认强度。
3. **ACL 权重一并参数化（RC-M4）**：`w_int`、`temperature`、`α β γ δ`、`attackerstate` 映射改为实验配置注入，**不改算法语义**；其标定排在本轮之后。
3. **参数校验 fail-fast**：`v` 维度不符、`f∉(0,1]`、`c<0`、`λ≤0`、`p_floor∉(0,1)`、`Σ_d v_i[d] > 1`、非有限值 直接拒绝启动（与方向① 坏正则 fail-fast 同款纪律）；此外有运行时校验（见 §3.1 的"运行时校验"要点）。
4. **可追溯**：`EdgeFactorResult` 增加 `ModelID` 与 `ParamsHash`；离线重算与在线评分都写入，报告与审计可复现。
5. **触发映射可配**：因子→触发检查映射从 `adapter.go` 的硬编码改为配置表（默认值保持等价）。可覆盖的键必须覆盖**全部真实产出的因子**（六个内置因子 + `EF-3FA` + `[edge_factors.custom]` 的键）；出现该集合之外的 `trigger.<id>` **报错**（拼错的键此前会被静默丢弃，与本方向"不静默"纪律冲突）。
6. **自定义因子同样进入模型**：`[edge_factors.custom]` 的因子必须进入 `Params.Factors`（权重取配置），这样它们的 `vector.<id>` / `coupling.<id>.*` 才能通过"键 ⊆ `Factors`"的校验 —— 否则"变量化"对自定义因子不完整。
7. **未启用路径不构造模型参数**：`[edge_factors.model]` 段缺席时，装配层返回的 `Params` **不得**填入 `p_floor`/`λ`/`vector`/`coupling` 之类的"看起来可用"的值（模型字段保持零值），并统一让 `Model == legacy` （包括出错返回路径）；`p_floor=0` 在误用时由 `Validate` 明确拒绝。

---

## 5. 实验设计与场景矩阵

因子集 = **6 个直接触发因子**（`two_factor_failure`、`syn_cookie_disabled`、`selinux_disabled`、`apparmor_disabled`、`no_siem`、`no_ids`）**+ 1 个级联因子**（`EF-3FA`，现状 `CascadeTo=EF-002FA` / `CascadeOnly=true`，见附录 B）。

> 级联因子不是补充设定，而是**既有的硬编码耦合**：`EF-3FA`（3FA 未满足）本身不直接乘分，而是级联到 `EF-002FA`。它就是 C 模型（时序链）要建模的真实对象，因此单列 S5 组。

| 组 | 数量 | 内容 | 目的 |
|---|---|---|---|
| S0 | 1 | 无因子（基线） | 参照 |
| S1 | 6 | 单因子各自激活 | 主效应 `β_i` |
| S2 | 8 | 两两共存（15 组中优先同源/可疑耦合） | 对称交互 `c_ij` |
| S3 | 4 | 三因子共存（含高耦合三方组） | 高阶与饱和行为 |
| S4 | 1 | 全因子共存 | 上限与 P_floor 验证 |
| S5 | 2 | **级联组**：`EF-3FA` 级联到 `EF-002FA`（对照：仅 `EF-002FA` 单独激活） | C 模型核心：级联 vs 独立 |
| R | 3 | 真实缺失对照（停 IDS / 去 SIEM / 去 2FA） | 代理真实性检验 |

- **每场景 1 轮 × WSL（主战场）+ A-1 每场景 3 次重复**（重复性/方差）；共 **S0–S5 = 22 场景 + R = 3 真实缺失对照**。
  > ⛔ **失效（仅存档）**：这是 **2026-09-08 的排法**（WSL 当主战场 + A-1 做重复），**从未按此执行、也不会再执行** ——
  > 主战场不是 WSL（生产基质是 `qemu`），重复也不在 A-1（A-1 于 2026-10-19 退为备份端）。
  > **实际执行序列**：`pve` CT targeted 小批 **11 条** → `qemu` VM 22 场景 / **33 实例** → 重复轴 **99 条**
  > （台账 C.2 与 H.6）。原文以下**保留仅为史料**（它解释为什么矩阵脚本一开始写死 `clab` 的建毁语义），
  > **不据此排矩阵**。
- 固定攻击剧本（Caldera），拓扑与剧本哈希入档；清除环境依赖的顺序（clab `destroy+deploy`，不用 `--reconfigure`）。

### 5.1 采集 schema（每场景一条 JSONL）

> 下面这条记录为可读性做了缩进；**JSONL 里必须压成单行**（一行一条记录，读取层按行切分）。
> Windows 上写作/重定向产生的**文件头 UTF-8 BOM 会被剥离**（否则第一条记录只会报
> `invalid character 'ï'`，指不到真正原因），但别依赖它 —— 行内的 U+FEFF 仍按坏数据拒绝。
> 本节 schema 与读取层、以及示例自身的数值自洽性，由 `cmd/edgecompare/docs_schema_test.go`
> 直接对照本示例强制执行：**文档漏字段、示例数值自相矛盾、或读取层单方面收紧**，该测试即红。
> 读取层对**其它**必填项的"放宽"方向由 `internal/edgeexp` 的逐字段定向用例覆盖
> （`scenario_id`/`threshold`/`domain_scores`/`chain[].factor`/`c_trigger`/`effective_factor`/
> `compromised` 各有独立的"缺失必拒"用例；`ts` 不在其列 —— 空串是**合法**的，被拒的是
> **非空但非 RFC3339** 的值）。这些用例同时保留在 `cmd/edgecompare/load_test.go`（逐字未改），
> 作为"契约搬迁未改变行为"的证据。

```json
{
  "scenario_id": "S2-selinux-apparmor-01",
  "factors": ["EF-SELINUX", "EF-APPARMOR"],
  "injection": "check_fail",
  "observed": {
    "domain_scores": {"attack_surface": 82.0, "business_continuity": 75.0,
                      "operation_trust": 68.0, "resilience": 71.0, "kernel_security": 55.0},
    "final_score": 80.02, "acceptable": true, "threshold": 60.0,
    "spc_score": 0.93, "threat_coeff": 1.4,
    "checks": [{"id": "OT-005", "domain": "operation_trust", "passed": false,
                "delta": -15.0, "confidence": 0.9, "ts": "2026-09-08T10:00:03Z"}],
    "edge_factor_chain": [
      {"factor": "EF-SELINUX", "trigger_check": "OT-005",
       "c_trigger": 0.9, "effective_factor": 0.82, "ts": "2026-09-08T10:00:03Z"},
      {"factor": "EF-APPARMOR", "trigger_check": "OT-005",
       "c_trigger": 0.9, "effective_factor": 0.838, "ts": "2026-09-08T10:00:03Z"}]
  },
  "ground_truth": {
    "compromised": true, "time_to_compromise_s": 213, "ttps_achieved": 4,
    "nodes_affected": 3, "block_effective": false
  },
  "meta": {"env": "wsl-clab-14", "playbook_hash": "…", "config_hash": "…",
           "run": 1, "timestamp": "2026-09-08T10:02:11Z"}
}
```

> **示例里的每个值都必须自洽**：`factors` / `edge_factor_chain[].factor` 用**规范因子 ID**（`EF-SELINUX`，不是展示名 `selinux_disabled` —— 写错会让离线重算查不到 `Vectors` 而静默走"全 1"fallback，改变 V/G/C 的惩罚强度）；`trigger_check` 与该因子在**当前部署实际解析出的**触发检查一致（出厂表 `EF-SELINUX`/`EF-APPARMOR` 共用 `OT-005`，这正是 S2 组要建模的同源耦合；用 `trigger.<FACTOR-ID>` 覆盖过的部署以后者为准），且当 `c_trigger > 0` 时该检查必须以 `passed = false` 出现在 `checks[]` 里；`checks[].delta` 逐字取自登记表（`OT-005 = -15`）；`effective_factor` 是策略层衰减后的观测值（出厂 `f_selinux=0.80`、`f_apparmor=0.82`，`1−(1−f)·c` 取 `c=0.9` ⇒ 0.82 / 0.838）；`final_score = 80.02` 是在**五域等权**下由记录自身输入复算出来的（`docs_schema_test.go` 会对本示例做这条 round-trip 断言，数值自相矛盾即红）。
>
> **这些是"记录构造要求"，不是读取层契约**：`trigger_check` / `checks[]` / `delta` / `meta` 读取层都**不校验**，离线工具`Synthesize` 也**不消费** `trigger_check`（它只用于溯源）—— 写错不会有任何门禁报错，只会让报告与论文证据失真。故本节把它们写清楚，并由 `docs_schema_test.go` 对本示例逐条钉住。
>
> `meta` 的四个可选溯源字段（`omitempty`，读取层不要求）：`weight_source` 只讲**权重口径**（`observed.effective_weights` 从哪来，以 `config_hash` 为锚点）；`ts_source` 只讲**链条目 `ts` 的基准**（独立字段 —— 此前 ts 基准被续写在 `weight_source` 末段，一个字段讲两件事；混用基准会造出"没人设计、也没人报告"的顺序，而数据看起来完全正常，故它必须有自己的槽位）；`assembly_error` 记装配期的非致命异常；`observation_target` 记**这次评估发生在哪台机器**（Task 4C，见 §5.3.1）。
>
> **`meta.skipped_checks`（Task 4D Fix round 2，additive）**：`[{id, reason}]`，由采集器写，
> 列出**被跳过的检查** —— 即框架把"**只因读不到证据**（EACCES/EPERM）而失败"的检查转成的
> skip（`passed=true`、`Δ=0`；`internal/model` 的 `skipResult` / `IsSkippedDetail`）。
> `reason` 存的是**检查自己给出的原文**（例如 `skipped — requires root privileges (无法读取/etc/shadow:
> open /etc/shadow: permission denied)`），不是自编的分类 —— 排障需要"哪条路径读不到、被谁拒的"。
> **用途（引用时必须照此）**：把"**评估器变瞎**"与"**安全变好**"分开。`observed.checks[]` 只落
> **失败**项（语义未改），而"条件（策略/权限/文件存在性）让证据读不到 ⇒ 该检查被跳过 ⇒ **不扣分**
> ⇒ 分数被推高"这件事在记录里原本**完全不可见**：A-1 的实测里 AppArmor 拒读 `/etc/shadow` 使
> `AS-012`（Δ=−6）被跳过 ⇒ 失败检查 42→41、总分 68.78→69.72，而两条记录的 `checks[]` 看不出差别。
> 因此：**任何"条件 ⇒ 分数上升"的结论都必须并排给出"失败集 + 跳过集"**；只有当跳过集在两组之间
> 不变时，"分数上升"才可以被读成安全姿态的变化；跳过集出现差异时，分数差里混着"评估器可观测性"
> 这一项，**不得**当作安全提升。该字段**不参与任何判据**（非必填、不进评分、`Validate` 不校验），
> 缺席时 JSON 里不出现（`omitempty` ⇒ 既有记录与夹具逐字节不变）。

**必填字段（缺失即整条记录 fail-fast，读取层 `internal/edgeexp.Validate`）**

> 契约现在**只有一份实现**：`internal/edgeexp`（无 build tag），生产者（采集器 `cmd/edgescen`）与消费者（`cmd/edgecompare`）共用它 —— 此前"文档示例与读取层各写一份"已经漂移过一次（示例被自己的解析器拒绝）。读取层只做**存在性 + 值域**校验；**规范因子 ID、触发关系交叉、生效权重落盘**属于**记录构造要求**，由生产侧的 `ValidateConstruction` / `CheckTriggerCrossReference` / `CheckEffectiveWeightsRecorded` 强制（读取层刻意宽容：消费方在装配时归一 ID，例如既有的 `"  ef-selinux  "` 夹具仍可读）。另：`effective_weights` 的存在性判法是 `len(...) > 0` —— 空 map 会序列化成 `"effective_weights":null`。

离线重算的判据是**部署行为**，故记录必须带齐复现判定线所需的全部输入。JSON 的"零值"与"没写"在 Go 结构体里同形，下列字段一旦缺失就会被静默读成 0 并改变结论，因此一律按"存在性 + 值域"双重拒绝：

| 字段 | 值域 | 缺失/越界的后果 |
|---|---|---|
| `scenario_id` | 非空 | 空串无法把记录归因到场景，指标会失去可追溯性 |
| `observed.threshold` | `> 0` | 0 ⇒ `score >= threshold` 恒真 ⇒ 决策层退化为"全放行"（漏判率 = 攻陷数/N、误阻断率恒 0） |
| `observed.spc_score` | `(0,1]` | 0 是引擎的"未设置"哨兵（按 1.0 计）⇒ 静默变成"无暴露面惩罚" |
| `observed.threat_coeff` | `> 0`（**无上界**，实测配置出现过 1.4） | 0 同为"未设置"哨兵 ⇒ 静默按 1.0 计 |
| `observed.domain_scores` | 非空、域名非空 | 没有域分就无从重算总分 |
| `observed.edge_factor_chain[].factor` | 非空 | 空因子 ID 无法归因，且会让链上条目静默失配 |
| `observed.edge_factor_chain[].c_trigger` | `[0,1]` | 0 是"仅由级联激活、自身触发检查未失败"的**既有合法取值**（S5 组会产出），故下界取 0；被拒的是**缺失** |
| `observed.edge_factor_chain[].effective_factor` | `(0,1]` | 0 是 `Synthesize` 的"未提供"哨兵 ⇒ 静默回落到配置权重 |
| `observed.edge_factor_chain[].ts` / `observed.checks[].ts` | 空串合法（= 缺席）；非空必须 **RFC3339** | 非空但解析不了一律拒绝（`"..."` 这种占位写法会被拒）；`ts` 是 chain 模型的**唯一**时间来源 — 在线引擎的结果类型没有时间字段，故 chain 只能离线评估（spec §10.1） |
| `ground_truth.compromised` | 必须显式出现 | 缺失 ⇒ 标签静默当成"未攻陷" |
| `ground_truth.basis` | **additive、可选**（Task 4D Step 5）；取值 `targeted_ttp` / `recon_playbook` | 说明这条标签**从哪来**：`targeted_ttp` = 该场景的**目标 TTP** 成败（**决策层指标只吃这一类**）、`recon_playbook` = 固定侦察剧本 `Discovery` 的结果（在任何姿态下都成功，只作背景测量）。**不得**给没有目标 TTP 的场景编造标签，也不得让两类混进同一个指标集（spec §2.1 的 L2 口径） |

`spc_score` / `threat_coeff` 的来源是引擎 `AssessmentOutput.SPCScore` 与 `[threat] coefficient`（引擎总分 = `round2(0.5·base + 30·E + 20·T)`）。**注意**：仓内 `internal/attck/attck.go` 中存在同名字段但写的是 `predictedRisk.EnhancedThreat`（**另一个量**），采集器取错会让离线分数整体偏移而门禁全绿 —— 故本节的示例记录带一条 round-trip 钉桩（`observed.final_score` 必须能被 `cmd/edgecompare` 用记录自身输入复算出来，已验证），采集器落地时必须对自采数据做同样的事。

**round-trip 的前提是"复算所用的输入全都确定"** —— 它包含三件事，缺任何一件"复算"就没有定义：

1. **候选声明的因子集 == 记录里出现的因子集**：离线只惩罚候选（`params.Factors`）声明的因子，记录里有而候选没声明的会被**静默丢掉**（实测：同一条示例记录，只声明 `EF-SELINUX` 算出 84.68，声明两个才是 80.02）。这正是 CLI 的 `-factors` 覆盖校验存在的原因，也是采集器必须把每个场景实际激活的因子完整写进 `factors` / `edge_factor_chain` 的原因。
2. **权重表（必须落进记录本体）**：记录里**没有**权重字段，而离线重算必须知道"哪些域参与聚合、各占多少权重"。Task 1 的实现者实测到两个坑：①legacy 的内在层加权用的是 `DynamicScoringEngine` 的**动态权重**（0 权重域会被填默认值并 `Normalize(100)`）⇒ "部分权重"配置下"配置权重 ≠ 生效权重"，只凭配置复算会有系统偏差；②`DomainScores` 的四个核心域字段恒存在，记录**无法区分**"该域参与聚合但值为 0"与"该域不在聚合里"，多域加权的浮点顺序因此不可完全复现。故采集器必须在记录里写出**引擎实际生效的逐域权重**（`observed.effective_weights`，键集即"参与聚合的域"），离线复算以它为准、不再依赖 `-weights` 猜；`meta.weight_source`（`config_hash` 为锚点）用于说明这份权重从哪来。这两条都是**记录构造要求**（读取层不校验）。**`cmd/edgecompare` 侧的落地口径（Task 3B）**：`-weights` 只是**回退表** —— 记录自带 `effective_weights` 时以记录为准（`recordWeights`），没带该字段时（历史数据集/手写夹具）才用它，且后者与消费该字段之前逐位一致。另一条同源口径：离线装域分切片的顺序取**域名字典序**，与在线 `ssam.ComputeDomainScoresBayes` 的输出顺序一致 —— 顺序漂移在不可精确表示的乘积上差 1 ulp，而落在取整半格上的 base 会因此让 `round2` 差 0.01（本节下面那组 35/25/25/15/10 的数就压在 `81.075` 这一半格上）。
   本节示例的 80.02 指的是**五域等权**下的值；同一份记录在出厂 `configs/config.ini` 的 `[weights]`（35/25/25/15/10）下是 **81.08**（注意这一组数值恰落在取整半格上，`81.075 → 81.08` 只差浮点噪声，故它只作示例说明、不作断言值）。
3. **因子 ID 与触发关系自洽**：
   - `trigger_check` 必须是该因子在**当前部署实际解析出的**触发检查上，**不是**"出厂表值"——否则覆盖过的部署会被误判。**两条机制别混为一谈**：①**内置因子**（`EF-SELINUX` 等）经 `config.ResolveEdgeFactorTriggerMap` 解析 = 出厂表 + `[edge_factors.model]` 的 `trigger.<FACTOR-ID>` 覆盖；②`[edge_factors.custom]` 的自定义因子由 `[edge_factors.custom_triggers]` 提供其 `TriggerCheck`（`ConfigToEdgeFactors`），再被 `trigger.<FACTOR-ID>` 覆盖 —— 它们**不在** `ResolveEdgeFactorTriggerMap` 的表里。另注意：出厂 `config.ini` / `configs/*.ini` **没有** `[edge_factors.model]` 段，各配置里的触发值写在 `[edge_factors.custom_triggers]`（例如 `config.ini` 的 `EF-SELINUX = OT-005`），不要把这两处当成同一份覆盖；
   - 当 `c_trigger > 0` 时，该触发检查（通常）必须以 `passed = false` 出现在 `checks[]` 里。**两类豁免**：①`c_trigger = 0` —— "未被自身触发检查匹配到失败检查"的既有形态，纯级联因子（`EF-3FA → EF-002FA`）就靠它，这类因子的激活原因**不是**某个检查失败；②**legacy 无模型段路径**：该路径还保留 *identity 分支*（检查 ID 恰等于因子 ID 时直接激活该因子）与级联写值，此时 `trigger_check` 是"该因子**登记的**触发检查"，**未必**是真正失败的那个检查（例如 identity 检查 `EF-002FA` 失败时，链上写的是登记值 `EF-001`）。故这条交叉校验**只对插件路径（V/G/C，激活与 `TriggerCheck` 同源）成立**；**任何消费者都不得用 `trigger_check` 反推 `checks[]`** —— `checks[]` 的真实要求是"落盘引擎的全部失败检查"（见下一条）；
   - `checks[]` 的**穷尽性从未被 schema 要求**（示例也只是一个子集）。采集器必须落盘引擎的**全部失败检查** —— 这是额外约定（读取层不校验），也是上一条交叉校验能成立的前提；
   - `checks[].delta` 必须**逐字**取自引擎的检查登记表（`OT-005` 为 `-15`）—— 离线不消费 `delta`，但它出现在报告与论文证据里，写错就是溯源造假。

### 5.2 离线重算流程（`cmd/edgecompare`）

1. 读 JSONL → 装配离线评估所需的输入（域分与权重、因子激活与触发链、`spc_score`/`threat_coeff`、链上时间戳）；
2. 对每个候选模型 × 参数组重算域分、总分与接受性判定；
3. 计算三层指标（决策一致率/漏判率/误阻断率；Spearman/Kendall；AUC）；
4. 交叉验证选模型，输出报告（Markdown + JSON）与**可直接粘贴的 config 参数段**；
5. `--fit` 模式：拟合主效应与先验交互边，输出参数 + 自助法不确定度。

> **参数段的可复现性（Task 9 遗留 (c)，里程碑 B 必须遵守）**：`RenderConfigSection` 只导出
> **模型级**参数（`[edge_factors.model]`：model/p_floor/lambda/vector/coupling/chain.window），
> 而因子权重 `f_i` 的单一来源是 `[edge_factors]`（含 `[edge_factors.custom]`）。故一份"可复现的
> 候选"= **该段 + 对应配置的 `[edge_factors]` 段 + 数据集 JSONL（含权重口径，见 §5.1 前提 2）**；
> 只发这一段会让别人复算出不同的分数。报告与论文附件里这三样必须一起给出。

### 5.3 环境分工

> ⛔ **失效（仅存档）**：**仅**下方「2026-09-12 用户裁定」段与那张两行表描述的是
> **2026-09-12 – 2026-10-12 的基质分工**（A-1/LXD 主场 + WSL2 开发离线）。之后基质搬了两次
> （CT → VM，台账 C.2 行 ③④），`EDGEEXP_SUBSTRATE` 的取值已是四套 `clab|lxd|pve|qemu`
> （`edge_lab.sh` 的基质分派），且 A-1 已于 2026-10-19 退为备份端（数据归档 `/RAID-Mirror/from-a1/`、即将重置）。
> **现行基质分工见 §10.4B 结论零与台账 C.1**；**裁定段与两行表保留仅为史料**（它解释"当初为什么用远程机"），
> **不据此选基质**。⚠️ **本节以下两段仍然现行有效，不受本条标记影响**：
> ① 表后的「两条环境的**共同前提**」（`edge_lab.sh` 是唯一基质调用点、判据只有一份实现）；
> ② 表后的「A-1 上**不要**跑的」（Caldera 不得重启/重装等边界）。另 **§5.3.1（观测主体）也仍然现行有效**。
> 第二次审计 Minor-2 把原来的"节级 ⛔"收窄到这里这一层（条目级），避免读者把这两段也当史料。

> **2026-09-12 用户裁定（Task 4D 起生效）**：实验基质搬到 **A-1 远程服务器（LXD，环境真实）**
> ——"我需要用时间换工程质量"。下表已按这次裁定重排：**A-1/LXD 是实验主场**，
> WSL2 Containerlab 退为**开发与离线**（门禁、离线夹具、离线比较、论文复算都在那里做）。
> 脚本侧的唯一开关是 `EDGEEXP_SUBSTRATE=clab|lxd`（默认 `clab` = 今天的行为，见 §5.4.2）。

| 环境 | 角色 | 注意 |
|---|---|---|
| **A-1（Ubuntu 24.04 / LXD 5.21.7 LTS）** | **实验主场**：22+3 场景 + 每场景 3 次重复 | 基质 `lxd`；既有实例集合（**不建/不毁拓扑**，见 §5.4.2 第 2 条「lxd 前置条件」）；存储池 zfs 8.23 GiB、网桥 `lxdbr0` = `10.217.208.1/24` |
| WSL2 Containerlab（14 节点拓扑） | **开发与离线**：门禁、离线夹具、`edgecompare` 离线比较、论文复算 | 基质 `clab`；`clab destroy+deploy` 只在这里；`.wslconfig` 限内存 8GB |

两条环境的**共同前提**：门禁与判据只有一份实现（`edge_lab.sh` 是唯一的基质调用点，
`cmd/edgescen` 的 `-target` 是唯一的取数入口）—— 换基质只换"命令发到哪"，不换"什么算成功"。
A-1 上**不要**跑的：攻击（Caldera 已在跑，`/opt/caldera`，API `:8888`，**不得重启/重装**）、
对 `probe-ot005` 的任何配置改动（它是控制侧的对照容器）。

#### 5.3.1 观测主体（Task 4C 建立，Task 4D 扩到两种基质）

**口径**：一条记录里的 `observed.checks[]` 描述的是**哪台机器**，必须能被记录本身判定 ——
因为被攻节点是被测目标（ground truth 的 `compromised` 来自它上面的 Caldera agent），
而采集器默认跑在宿主上。

| 项 | 取值 | 落盘位置 |
|---|---|---|
| 默认（不声明目标） | **本机**（跑 `edgescen` 的那台）—— 与 2026-09 之前逐位一致 | `meta.observation_target` **缺席**（`omitempty`，记录字节不变） |
| 容器内（`--target <容器名>` 或 `--target docker:<容器>`） | 该容器内部（同一份二进制经 `docker cp` + `docker exec` 执行） | `meta.observation_target = "node:<容器> (hostname=<节点内 hostname>)"`（**逐字不变**） |
| LXD 实例内（`--target lxd:<实例>`，Task 4D） | A-1 上的既有实例内部（同一份二进制经 `lxc file push` + `lxc exec --env … --` 执行） | `meta.observation_target = "node:<实例> (substrate=lxd, hostname=<节点内 hostname>)"` |

为什么 lxd 侧**多印** `substrate=lxd`、而 docker 侧一个字节都不动：`docker exec host1` 与
`lxc exec host1 --` 两种观测在数据上本来完全同形，而"这批数据采自哪种基质"正是 Task 4D 要回答的
问题；反过来，docker 是默认基质，改它的取值会让 Task 4C 已落盘的记录与既有断言全部失效。

**"逐字不变"的准确范围（Fix round 1 收窄）**：docker 侧**命令序列与 `meta.observation_target`
逐字不变**（`docker cp` / `docker exec -e` 的参数、顺序、观测主体字符串都有用例钉住，其中一条
期望值逐字抄自 `97581d8`）；**错误串在 Step 2 一度变过、Fix round 1 已逐字恢复**，并由
`TestDockerErrorStringsMatchTask4CBytes` 钉住 —— 该用例的期望值同样抄自 97581d8 的字面量
（不是从当前实现反推），因此能抓住"两条路径一起变"的情形。

为什么必须是新字段而不是复用现有的：`meta.env` 是**操作者手填的标签**（默认值 `wsl-clab-14`，
与"这份检查集真的来自那台机器"无关 —— 采错机器时它恰恰会照抄那个默认值），`meta.config_hash`
是**配置文件**的指纹、`meta.playbook_hash`/`timestamp`/`run` 同理，都与运行位置正交。
2026-09 的一次真实冒烟就采成了 WSL 开发机（输出路径 `/mnt/f/...` 是铁证），而记录字段完全正常
—— 那次事故在本表的口径下**会**被 `edge_collect.sh` 的 `observation_subject` 核对拦下。

四条纪律（Task 4D 起，第 4 条是新的）：

1. **默认路径逐位不变**：不声明目标时不传 `--target`，取数仍走 `runHostChecks()`（有显式用例钉住：
   逐要素相等 + "一个 docker 子进程都没起"）。
2. **绝不静默回落本机**：目标缺失、基质 CLI 不可用、取回的检查集为空、信封标记/主机名缺失
   —— 一律响亮失败。回落是最危险的形态：记录看起来是节点数据、实际是宿主数据。
3. **同一轮数据必须来自同一台机器**：`edge_collect.sh` 会核对"harness 产物里
   `condition_probes[].probe_target`"与"记录 `meta.observation_target`"是否指向同一个节点
   （R 组的证据与 `checks[]` 的观测分属两台机器时整轮失败）。
4. **绝不静默换成另一种基质**（Task 4D）：`-target` 的基质前缀只认 `docker:` / `lxd:`，
   裸名字按 `docker` 处理；看着像基质前缀却不在白名单（`unknown:host1`）**在起任何子进程之前**
   报错。把 `lxd:probe-ot005` 当容器名交给 docker，会以 `No such container: lxd:probe-ot005`
   失败 —— 错误指向一个不存在的容器，而真正的原因（基质拼错）完全看不出来。

### 5.4 实验执行手册（Task 4 交付）

本节是**照着做就能复现**的执行面：脚本、参数、命令、门禁与失败语义。任何一条与脚本实现不一致，
以脚本为准并回头改本节 —— 手册与实现漂移过一次就会让"这份记录是怎么采的"永远说不清。

#### 5.4.1 交付物与落盘位置

| 交付物 | 路径 | 说明 |
|---|---|---|
| 实验模板 ×4 | `configs/edgeexp/{m0-baseline,vector,graph,chain}.ini` | 四份**只差** `[edge_factors.model]` 段；采集恒用 `m0-baseline.ini` |
| 复位脚本 | `lunwen/clab-lab/scripts/edge_reset.sh` | Caldera 就绪 + 毁/建拓扑（`clab` 基质：`clab destroy --cleanup` + `clab deploy`）+ sandcat agent 回连。**lxd 基质下建/毁拓扑不适用**（既有实例上不建不毁，见 §5.4.2 第 2 条「lxd 前置条件」；原文引的"第 6 条"是漂移前的旧编号，第 6 条现在是"观测主体"） |
| 攻击脚本 | `lunwen/clab-lab/scripts/edge_attack.sh <scenario> <out.json>` | 相位推进 + 固定剧本 + 客观结果（ground truth 的唯一来源）；`EDGEEXP_TARGET` 声明被攻节点后，条件探针在**该节点内**执行 |
| 节点内条件探针 | `lunwen/clab-lab/scripts/edge_probe.sh <节点名>` | 被 `edge_attack.sh` source；**在节点内**执行 §5.4.7 的六因子条件判据（经基质层下发，见下一行），退出码 0=条件成立 / 1=不成立 / **2=探针没跑成**。见 §5.3.1 与 §5.4.9 |
| **基质层**（Task 4D） | `lunwen/clab-lab/scripts/edge_lab.sh` | **唯一**的基质调用点（被上面四个脚本 source）：`EDGEEXP_SUBSTRATE=clab|lxd` 选择；接口 `lab_up`/`lab_down`/`lab_target_exec(_detached)`/`lab_push`/`lab_node_ip`/`lab_node_running`/`lab_inspect`/`lab_list`/`lab_node_counts`/`lab_target_spec`/`lab_require_bins`。调用脚本的**代码位置**不得再出现 `clab`/`docker`/`lxc` 命令字面（日志与错误消息里的 `clab destroy 完成` 这类词保留 —— 它们是既有排障手册的锚点）；两层 CLI 各有名字：拓扑级 `lab_topology_bin`、目标级 `lab_target_bin`（Fix round 1 / I-1：一个变量两义会让覆盖失效并带偏另一层） |
| 采集脚本 | `lunwen/clab-lab/scripts/edge_collect.sh <scenario> <config.ini> <attack.json> <run>` | 一条记录 + **因子集相等断言** + 门禁⓪ + 时钟核对 + 门禁② 残差 + **观测主体核对**（`EDGEEXP_TARGET` ⇒ 记录必须带 `meta.observation_target`，且与 harness 的探针节点一致） |
| 矩阵驱动 | `lunwen/clab-lab/scripts/edge_matrix.sh [场景…]` | 25 场景全量（无参数）或冒烟子集（给了场景名）；名单与 `edgescen -list` 逐项核对；干跑（`EDGEEXP_DRY_RUN=1`）会打印**基质**与解析后的 `-target` 语法 |
| 阈值敏感性驱动 | `lunwen/clab-lab/scripts/edge_threshold_sensitivity.sh` | §5.4.6 的强制行；**只读**记录 + 配置 + 离线工具（不碰 clab/Caldera），故随时可补跑；**默认不跑**（`EDGEEXP_SENSITIVITY_THRESHOLDS` 显式开启） |
| `-factors`/`-weights` 推导 | `lunwen/clab-lab/scripts/edge_spec_lib.sh` | 被矩阵与敏感性驱动**共用**的函数库（单一来源：不在两个脚本里各抄一份 Python，否则两份报告可能用了不同的因子权重而看不出来） |
| 记录 | `lunwen/clab-lab/data/edgefactors/records-<env>-<date>.jsonl` | 每场景**一条**；门禁①/② 直接跑这份**全量**文件 |
| 被拒记录留档 | `.../data/edgefactors/run.d/rejected-<scenario>.jsonl` | 断言失败时该条记录**从数据集回滚**、但必须留痕的那一行 |
| 运行级证据 | `.../data/edgefactors/run.json`（+ `run-<run-id>.json` 副本） | 拓扑/剧本/配置哈希（两种精度）、权重口径、逐场景耗时、因子集相等断言、门禁⓪①②、时钟核对、记录条数（**含文件总行数**）、`threshold_sensitivity`（未跑时为 `null`） |
| 阈值敏感性产物 | `.../data/edgefactors/sensitivity/{report-threshold-<T>.md, .raw.md, .log, sensitivity.json}` | **显式 opt-in**（`EDGEEXP_SENSITIVITY_THRESHOLDS=60`）才产生；覆盖部署判定线，**不是**主对比报告，见 §5.4.6 |

#### 5.4.2 前置条件

0. **先选基质**（Task 4D 起基质之间"环境"完全不同，只有产物的**门禁**是同一套；下表按
   Task 13/17 之后的**四套**取值补齐 —— 原表只有 `clab`/`lxd` 两行，`pve`/`qemu` 在这一节整体缺席）：

   | 基质 | 怎么选 | 环境是什么 | 干什么 |
   |---|---|---|---|
   | `clab`（默认，= 今天的行为） | 什么都不用设，或显式 `export EDGEEXP_SUBSTRATE=clab` | WSL2 的 Containerlab 拓扑（14 节点） | **开发与离线**：离线夹具、门禁、`edgecompare` 离线比较、论文复算 |
   | `pve` | `export EDGEEXP_SUBSTRATE=pve` | dl360gen9 上的 **PVE CT（LXC 容器）**；既有 `CT 904`（`asc-tgt-c2`） | **快速验证 / 轻量模拟 / 临时短期任务**（§10.4B 结论零）。基线活跃集由**基质层**写死并导出 `EDGEEXP_BASELINE_FACTORS=EF-SELINUX,EF-APPARMOR`（§10.4 结论一） |
   | `qemu` | `export EDGEEXP_SUBSTRATE=qemu`（**另需**操作手册 §2.5 的 VM 专用七格：`EDGEEXP_VM_SSH_*` / `EDGEEXP_VM_GUEST_IFACE` 等） | dl360gen9 上的 **PVE VM（QEMU/KVM，如 `asc-vm910`）** | **生产基质**：长线任务、全量批次、重复轴（§10.4B 结论零）。基线活跃集**没有默认值** —— 跑批前必须**显式**给 `EDGEEXP_BASELINE_FACTORS` + `EDGEEXP_BASELINE_FACTORS_SOURCE`（§10.4B 结论二） |
   | `lxd`（**宿主已退场**） | `export EDGEEXP_SUBSTRATE=lxd`（+ 另给 `EDGEEXP_LXC_BIN`） | 原 **A-1 上既有的 LXD 实例集合** —— 该宿主 **2026-10-19 已退为备份端、即将重置**（数据归档 `/RAID-Mirror/from-a1/`）⇒ **现无可用宿主** | 驱动保留、**无可跑环境**。历史用途是"实验主场"（原文见 §5.3 的存档标记） |

   两条配套纪律：**① 基质名拼错会直接失败**（`EDGEEXP_SUBSTRATE=clabb` 在 source 基质层时中止
   调用方，**带不带 `set -e` 都一样**（Fix round 1 / M-4：非交互 shell 下库会结束调用方的 shell），
   不静默退回 `clab` —— 一次"以为在 A-1 上跑、其实在 WSL 上跑"的整轮矩阵，记录里的 `env` 标签
   看起来完全正常）；**② `-target` 的语法由基质决定**，调用脚本只给**节点名**
   （`EDGEEXP_TARGET`），前缀由 `lab_target_spec` 唯一地加（clab: 裸容器名；lxd: `lxd:<实例>`）——
   两处各拼一次前缀会让 `observation_subject` 门禁以"记录声称 X、声明 Y"的名义把每条记录判死。

1. **（clab 基质）WSL2 `Containerlab` 发行版**：Docker + `clab`，拓扑 `lunwen/clab-lab/asscor.clab.yml`
   —— 实测 **18 个节点容器**（`asc-asscor-{edge0,host1..host12,r1..r5}`，拓扑里 `prefix: asc`）。
   **攻击侧只部署一个 sandcat agent（默认 `host1`）**，这直接决定了客观结果的口径：
   `nodes_affected ≡ 1`（多节点横向不在本手册的范围内）。
2. **（lxd 基质）A-1 上的既有实例**：LXD `5.21.7 LTS`、storage pool `default`（zfs）、
   网桥 `lxdbr0` = `10.217.208.1/24`。
   > ⚠️ **适用范围**：本条只在**原 A-1 宿主**上成立。该宿主 **2026-10-19 已退为备份端、即将重置**
   > （数据归档至 dl360gen9 的 `/RAID-Mirror/from-a1/`）⇒ `asc-tgt-1` / `probe-ot005` 这些实例
   > **不再存在**，本条**不可照做**。现行生产基质是 `qemu`（见上表第 0 条与 §10.4B 结论零）。
   **两个已实测的坑**：
   - **镜像必须用 `lxc launch ubuntu:24.04`**，`lxc launch images:ubuntu/24.04` **会失败**
     （`images:` remote 已不再提供该别名）；
   - `ssh_exec` 在 **~600 s** 会打断前台长命令（`lxc launch` 就这么失败过一次）⇒ **长操作一律
     `nohup … > /root/x.log 2>&1 &` + 轮询日志**，不要指望一次前台 ssh 调用能等完。
3. **Caldera v5** 在 `/opt/caldera`。`edge_reset.sh` 会自己**确保它在跑**：
   `./venv/bin/python server.py --fresh -P sandcat,stockpile,atomic`。
   `-P sandcat,stockpile,atomic` 必须显式给出 —— 缺插件列表时 `sandcat.go-linux` payload 不会被生成，
   而"没有 payload"会在第 4 步以一个看起来像网络问题的错误出现。
   **实验基质上它已经在跑**（API `http://127.0.0.1:8888`，key 见下方口径）：**不要重启、不要重装**。

   > **凭据口径（脱敏）**：C2 的 API 口令**不写入本仓库**。它由**未跟踪的本地配置**提供，
   > 环境变量名是 `EDGEEXP_CALDERA_KEY`（URL 是 `EDGEEXP_CALDERA_URL`）。
   > **缺 key 时跑批前置会响亮失败** —— **不允许**回落成"没 key 也继续"。
   > 原因与处置见 `docs/experiments/EDGE_FACTOR_EXPERIMENT_AUDIT_LEDGER.md` 的脱敏处置台账。
4. **两个 Linux 工具**（交叉编译，脚本默认读 `build/`）：
   ```bash
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags 'expr,engine,checks' -o build/edgescen  ./cmd/edgescen
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags edgeexp                -o build/edgecompare ./cmd/edgecompare
   ```
   `edgescen` 的最小 tag 集是 **`expr,engine,checks`**（三个都不可省：`engine` 给评分链、`checks` 给真实
   检查登记表、`expr` 是实验工具的构建约束）。A-1 上只需要 `edgescen`（`edgecompare` 是离线工具）。
5. **模板纳入回归门禁**：`go test ./internal/config/ -run TestEdgeExpConfigTemplatesLoad` 必须绿 ——
   模板装不上要在 `go test` 阶段就红，而不是在 lab 上跑完一轮采集之后。
6. **观测主体：把被攻节点的名字交给整条管线**（Task 4C / I-9）：

   ```bash
   export EDGEEXP_TARGET=asc-asscor-host1     # clab：容器名（拓扑默认 prefix=asc、agent 在 host1）
   export EDGEEXP_TARGET=probe-ot005          # lxd：实例名（前缀由 lab_target_spec 加）
   ```

   `edge_matrix.sh` **默认**就是 clab 的那个名字并 export 给子脚本；只有单独调 `edge_attack.sh` /
   `edge_collect.sh` 时才需要手工 export（只给 `edge_collect.sh` 设而不给 `edge_attack.sh` 设
   会被采集端的 `observation_subject` 门禁拒掉，见 §5.3.1 第 3 条）。

   **它与 `EDGEEXP_TARGET_HOST` 不是一回事**（两个名字近似、含义与取值都不同，别混）：

   | 变量 | 含义 | 取值 | 谁用 |
   |---|---|---|---|
   | `EDGEEXP_TARGET` | **观测主体**：评估在哪个**节点**内做 | clab: 容器名 `asc-asscor-host1`；lxd: 实例名 `probe-ot005` | `edge_attack.sh`（节点内条件探针）、`edge_collect.sh`（`edgescen --target`） |
   | `EDGEEXP_TARGET_HOST` | **复位脚本的攻击目标**：`edge_reset.sh` 把 agent 部到哪台**节点**上 | 节点名 `host1`（`edge_reset.sh`） | `edge_reset.sh`（**只在 clab 基质下有"部 agent"这个动作**） |

   置空（`EDGEEXP_TARGET=`）即退回"在本机评估"的旧形态：S 组照常（`condition_probes` 如实留空，
   **不是**证据），**R 组会硬失败**（它的语义就是"在目标节点上真的没有这个防护"）。

#### 5.4.3 四份模板只差模型段

| 模板 | `model` | 该段额外内容 | 用途 |
|---|---|---|---|
| `m0-baseline.ini` | `legacy` | `p_floor`、λ、向量、`trigger.*` | **唯一用于采集**：让引擎装载模型、产出观测链（显式 legacy 与"不写段"评分逐位一致，但只有装载过的路径才盖溯源戳） |
| `vector.ini` | `vector` | + 向量（逐域） | 离线候选 V |
| `graph.ini` | `graph` | + 5 条**对称**先验边 | 离线候选 G |
| `chain.ini` | `chain` | + 5 条**有向**先验边 + `chain.window_seconds = 300` | 离线候选 C（**在线不可执行**，装配期 fail-fast） |

四份模板共享同一部署骨架（`[weights]`/`[extension_weights]`/`[acceptability]`/`[threat]`/`[edge_factors]`/
`[edge_factors.custom]`/`[edge_factors.custom_triggers]`）—— 这些段的**键值逐项相同**（注释与标题行不同，
由 `TestEdgeExpTemplatesShareDeploymentSkeleton` 钉住），因此候选之间的分数差异只能归因于模型参数。
两条容易踩的键面纪律：

- **`[weights] scoring_engine` 必须留空**。填 `legacy` 会关掉插件评分引擎的装配，而那条路径**永远不盖
  溯源戳** ⇒ `edgescen` 以"引擎没有装载边缘因子合成模型"拒绝写出记录。这不是可以绕过的开关。
- **`[edge_factors.custom]` 刻意保留出厂 `config.ini` 的同名重复条目**（内置六因子 + `EF-3FA` 又写一遍）。
  删掉它们等于把门禁⓪ 要观测的现象从实验里剔除；副作用是 `EF-3FA` 在出厂配置里**不是** `CascadeOnly`
  的那一条，会作为普通因子（`EF-3FA = 0.82`）上链 —— 它因此必须进 `-factors`，见 5.4.6。

#### 5.4.4 执行

```bash
# 全量 25 场景（S0–S5 = 22 + R = 3；矩阵脚本自带"场景数必须是 25"的断言，
# 并与 `edgescen -list` 的场景名单**逐项相等**核对）
cd lunwen/clab-lab
bash scripts/edge_matrix.sh

# 冒烟子集（只跑列出的场景；用于管线自检与耗时测量，**不产生结论数据**）
bash scripts/edge_matrix.sh S0-baseline S5-cascade-3fa R-no-ids
```

单场景三步（矩阵脚本内部就是这三条，可单独重跑）：

```bash
bash scripts/edge_reset.sh  "$s"                                          # 干净环境
bash scripts/edge_attack.sh "$s" "data/edgefactors/attack-$s.json"        # 相位 + 攻击 + 客观结果
bash scripts/edge_collect.sh "$s" ../../configs/edgeexp/m0-baseline.ini \
     "data/edgefactors/attack-$s.json" 1                                  # 一条记录 + 门禁
```

（路径从 `lunwen/clab-lab` 起算：配置在仓库根，故是 `../../configs/…`。）

有用的开关（环境变量）：`EDGEEXP_RUN_ID`（运行标识，进 `run.json`）、`EDGEEXP_RECORDS`（记录文件，
冒烟/重跑请换名；**矩阵会把它钉死并导出给子脚本**，见 5.4.5 第 12 条）、
**`EDGEEXP_DRY_RUN=1`（干跑：只打印计划、立即退出 0，不做任何 lab 动作、不写任何文件）**、
`EDGEEXP_RESUME=1`（续跑：跳过目标文件里已有记录的场景，跳过的场景写进 `run.json` 的
`scenarios_skipped_resume`；**它不是干跑** —— 对没有记录的场景照样跑三步，见 5.4.5 第 13 条）、
`EDGEEXP_RUN_INDEX`（重复号，**>1 时必须同时显式给 `EDGEEXP_ENV`**，否则 A-1 的重复样本会被打上
`wsl-clab-14` 混进主数据集）、`EDGEEXP_ATTACK_TIMEOUT_S`（等 operation 终态的上限，默认 1800）、
`EDGEEXP_PHASE_GAP_S`（相位间隔，默认 3，**不得小于 1**）、
**`EDGEEXP_TARGET`（观测主体：被攻节点的容器名，矩阵默认 `asc-asscor-host1`；置空 = 本机评估，
此时 R 组会硬失败 —— 与下面那个 `EDGEEXP_TARGET_HOST` **不是一回事**，对照表见 §5.4.2 第 5 条）**、
`EDGEEXP_TARGET_HOST`（**复位脚本的**攻击目标节点，默认 `host1`）、
**`EDGEEXP_SENSITIVITY_THRESHOLDS`（阈值敏感性行：给定阈值列表才跑，例 `60` 或 `60,70`；**默认不跑**，
默认路径与默认对比不受影响，见 §5.4.6）**、`EDGEEXP_SENSITIVITY_DIR`（敏感性产物目录，默认
`data/edgefactors/sensitivity/`）。
想先看一遍"这轮到底会跑什么"，永远先跑
`EDGEEXP_DRY_RUN=1 bash scripts/edge_matrix.sh`（它打印记录文件、配置、`-factors`/`-weights`、
逐场景 collect/skip 与"子脚本继承到的 `EDGEEXP_RECORDS`"）。

#### 5.4.5 纪律（每条都对应一次实测事故）

1. **每场景一条记录**。四个候选的差异**完全**由离线 `edgecompare` 覆盖（记录里的域分是域级修正前的
   基分、链与 E/T 与候选无关、`Evaluate` 从不读 `final_score`），而 `chain` **在线不可执行** ——
   拿 `chain.ini` 采集必然被拒。每场景采 4 次等于把同一个信息采 4 遍，只会让"记录条数 == 场景数"失去意义。
2. **复位必须 `clab destroy --cleanup` + `clab deploy`，**不用** `--reconfigure`**（后者不重建 veth，
   上一场景的接口状态会带进下一场景）。`destroy` 的失败被容忍（没部署过时本该失败），但**被容忍之后
   必须补一条断言**：`clab inspect` 报告该拓扑 0 个节点，否则"干净环境"的前提不成立、整轮失败
   （destroy 因真实原因失败而 deploy 只做 reconcile 是最难发现的污染）。`deploy` 无容错。
3. **失败要响亮**：`edgescen` 非零退出、记录增量 ≠ 1、**链上的因子集与场景声明不相等**、注入时刻不早于
   采集时刻、注入检查没落进 `checks[]`、顺序场景相位落在同一秒、R 组真实缺失不成立、
   operation 一个 link 都没发出 —— 一律非零退出，**不跳过继续**。
4. **因子集相等断言（不是包含）**：采集器自己只要求 `链 ⊇ 期望集`，于是"声明空集的 S0 基线采到六个
   因子"可以静默通过 —— 整轮实验的因子塌缩就是这样藏起来的。`edge_collect.sh` 现在要求
   链上的因子集（归一 ID）与场景声明的集合**逐项相等**，多一个少一个都整轮失败；断言在记录落盘之后
   才可能判，故失败时**回滚这一条**（文件回到采集前的行数）并把该行留档到 `run.d/rejected-*.jsonl`。
   **级联场景的期望集必须同时含级联源与级联目标**（Fix round 2）：采集器那条"`EF-3FA` → 级联目标"
   的替换规则是给**最小值**（⊇）用的，用作**相等**判据就会把合法的 `EF-3FA` 判成多余项 ——
   出厂模板的 `[edge_factors.custom]` 里还有一条 `EF-3FA = 0.82`（**不是** `CascadeOnly`），
   它会作为普通因子自己上链。故 `S5-cascade-3fa` 的期望集是 `{EF-3FA, EF-002FA}`、
   `S3-3fa-selinux-apparmor` 是 `{EF-3FA, EF-002FA, EF-SELINUX, EF-APPARMOR}`；"源"**只在配置真的
   声明了自定义 `EF-3FA` 时**才期望（把那条去掉后自动退回只有级联目标，不会变成镜像方向的误拒）。
   **级联目标本身只有一份真源**（Fix round 3）：采集器 `edgescen -list` 直接输出
   `级联目标=<CascadeTo>`，harness 消费它；本脚本里那张表退化为"旧二进制时的兜底"并会**响亮警告**，
   两者冲突（都给出且不一致）则直接报错。
   查当前推导结果（只推导、不碰 Caldera 与拓扑）：
   `EDGEEXP_PRINT_EXPECTED=1 bash scripts/edge_attack.sh <scenario> /tmp/x.json`。
5. **记录条数门禁判死整轮**：`文件总行数 == 本次选中场景数` 是**硬闸门**，不只是 `run.json` 里的一个
   布尔值 —— 少一条说明有场景没采成，多一条说明文件里混进了别的场景的记录，两者都会让
   "每场景一条"这句结论失效。被回滚的记录**不计入**"本次写入"。
6. **产物必须是本轮的、且必须齐**：`harness` 产物（`expected_chain_factors` / 注入时刻 / 剧本哈希 /
   客观结果）在**调用 `edgescen` 之前**就做预检与新鲜度核对（`attack.started_at/finished_at` +
   文件 mtime vs 矩阵导出的本轮起始时刻）—— 陈旧或缺字段的产物会静默提供上一轮的证据，
   而时钟核对照样通过。采集前的失败**不写任何记录**；采集后的失败一律**回滚 + 留档**。
7. **幂等**：`edge_collect.sh` 发现目标 JSONL 里已有同场景记录时拒绝再写（重跑请换 `EDGEEXP_RECORDS`
   或归档旧文件；**续跑整轮矩阵**用 `EDGEEXP_RESUME=1`）。矩阵脚本每轮清空逐场景碎片，
   避免上一轮的片段混进本轮的 `run.json`。
8. **时间结构**：顺序注入场景的相位间隔必须让注入时刻落在**不同秒** —— 链上 `ts` 由
   `recordChain` 用 `time.RFC3339` 格式化（秒精度），秒内差异会被抹平，C 候选随之退化成 V，
   而记录看起来完全正常。同时注入场景**不带**时间结构是设计（同刻注入 ⇒ C ≡ V，是反向对照，不是缺陷）。
9. **注入时刻 < 采集时刻**由 `edge_collect.sh` 逐条核对并写进 `run.json`
   （采集时间是记录装配时刻 `meta.timestamp`，这是记录里唯一的采集时间戳），同时逐条比对
   "harness 报的注入时刻"与"记录 `checks[].ts`"是否逐位一致 —— 后者是"harness 的时间真的落进记录"的证据。
   零注入场景（S0 / R 组）如实记为 `status: n/a`，**不写"通过"**（空集上的核对恒真，写通过会让人以为
   这里做过一次有效核对）。
10. **配置指纹**：记录 `meta.config_hash` 必须等于本次采集配置的 sha256 前 16 位（`run.json` 里另有
    完整 64 位的 `config_hash_full`）—— "这份记录是这份配置采的"必须可核对，否则报告的权重口径
    可能指向另一份配置；不等即回滚。
11. **shell 脚本必须 LF 检出**：仓库根有 `.gitattributes`（`*.sh text eol=lf`）。此前
    `core.autocrlf=true` 且无该文件，Windows 侧一次 checkout 就会把脚本写成 CRLF，
    含 `then/do/fi/done` 的脚本**直接解析失败**。改脚本前先 `git ls-files --eol <脚本>` 确认 `w/lf`。
12. **整轮只写一份记录文件**：矩阵把解析出的记录路径 `export EDGEEXP_RECORDS` 给子脚本。
    父子脚本各自算 `date -u +%Y%m%d` 时，一次跨 **00:00 UTC** 的 sweep（3–7 小时，很容易跨）
    会让子脚本写明天的文件、父脚本数今天的文件 —— 数据集被劈成两半，而条数门禁要跑完几小时才报错。
    `run.json` 的 `records_file_agreement` 会逐场景核对"子脚本实际写的路径 == 父脚本解析的路径"。
13. **`EDGEEXP_RESUME` 不是干跑**：它只跳过"文件里已有记录"的场景，对**没有**记录的场景照样
    执行 reset+attack+collect（曾因此误触发过一次真实复位）。先看计划请用
    **`EDGEEXP_DRY_RUN=1`** —— 它打印记录文件、配置、`-factors`/`-weights`、逐场景 collect/skip
    与子脚本继承到的 `EDGEEXP_RECORDS`，然后在第一个 `edge_reset.sh` **之前**退出 0，
    不调用 `clab`、不碰 Caldera、不往数据目录写任何东西。

#### 5.4.6 门禁

**门禁⓪（重复因子条目，实测）**：按**归一化**因子 ID 统计每条真实记录链上的条目数，计数与具体 ID 写进
`run.json`（`gate0_duplicate_factors`）与实验报告。只统计真实记录，**不做静态推断** —— 若某配置下没有
重复条目，结论必须如实写成"未观察到重复条目"，不得据静态溯源宣称"引擎会重复乘"。

**门禁①（离线工具读**全量**记录、无 fail-fast）**：

```bash
build/edgecompare -records data/edgefactors/records-wsl-clab-14-<date>.jsonl \
  -candidate legacy=configs/edgeexp/m0-baseline.ini -candidate vector=configs/edgeexp/vector.ini \
  -candidate graph=configs/edgeexp/graph.ini       -candidate chain=configs/edgeexp/chain.ini \
  -factors "$(由采集配置解析：内置六因子取 [edge_factors]（EF-002FA 经 level4_override）+ [edge_factors.custom] 中不与内置同名的条目 ⇒ 含 EF-3FA=0.82)" \
  -weights "$(由采集配置解析的生效权重表)"
```

三条硬约束：**候选名必须是模型名**（`legacy|vector|graph|chain`，`report.go` 只接受这四个；
`-candidate m0=…` 会报"未知模型"）；**`-factors` 必填且必须覆盖链上用到的每一个因子**；
**门禁① 跑全量记录**（不切子集）。`edge_matrix.sh` 自动从采集配置解析 `-factors` / `-weights`
（`f_i` 的单一来源是配置，不在脚本里抄第二份）。

**`EF-3FA` 的处理（2026-09-12 Fix round 1 修正）**：出厂 `[edge_factors.custom]` 的 `EF-3FA = 0.82`
加上四份模板都声明的 `vector.EF-3FA`，使 `EF-3FA` 是一个**普通因子**（只有硬编码那一条是
`CascadeOnly`），它会合法地出现在链上 ⇒ **必须**进 `-factors`（写 `EF-3FA=0.82`；链上条目自带观测值，
离线复算以观测量为准）。此前"不写 `EF-3FA`"的理由（"会给 V/G/C 一个引擎从未施加的 `fallback`
向量惩罚"）**不成立**：fallback 只对"候选未声明向量"的因子生效，而四份模板都声明了 `vector.EF-3FA`。
真正会发生的是**相反的**事 —— **漏掉链上用到的因子会让工具静默丢弃那条惩罚**（分数被抬高、
漏判率被低估，报告里看不出少了谁），而且 C 候选唯一那条级联边（`chain.ini` 的
`EF-3FA → EF-002FA`）会随之失效。**唯一禁止的动作**：为了让门禁变绿而**静默塞值**
（塞一个与部署无关的 `f`）—— 那是改指标，不是修数据。

**门禁②（round-trip）**：权威实现是 `edgescen` 装配点的**进程内自检** —— 用记录自身的输入
（域分 + `observed.effective_weights` + `spc_score` + `threat_coeff` + 链上 `effective_factor`）
复算 `final_score`，不通过即**拒绝写出该条记录**。故操作层面上它等价于"记录条数 == 场景数"，
残差同时落进 `run.json` 的 `gate2_round_trip`（逐场景）与 `run.d/collect-*.json`。
**门禁② 只在采集模型下执行**（`-candidate legacy=m0-baseline.ini`）：记录是用 legacy 采的，
而 `vector/graph/chain` **合法地**给出不同分数 —— 对四个候选都跑门禁② 会在每一条合法记录上变红。
跨候选的分数差异是**候选比较**要研究的东西，不是数据缺陷。
离线复算的口径以**记录自带的** `observed.effective_weights` 为准，`-weights` 只是回退表
（记录没带该字段时生效）。
离线的这一半（`edgecompare` 复核）失败只记 **warning**：记录根本写不出来就没得复核，
门禁② 的实质已由进程内自检承担（`run.json` 的 `gate2_offline_compare` 如实标出）。

**阈值敏感性**：`[acceptability] threshold = 80.0` 是部署的真实判定线（GB/T 22239-2019 Level 3）；
lab 侧对应的键在 `lunwen/clab-lab/kernel-config.ini` 的 `[acceptability]` 段（**不是** `[weights]` 段 ——
解析器只在 `[acceptability]` 里读它，写错段位是静默 no-op，见 §5.4.11）。
若该线让全部记录落进"不可接受"（漏判样本为 0 或误阻断样本为 0），报告必须**另附一行
`threshold = 60.0`（设计文档示例值）的敏感性结果**并明确标注那是敏感性分析 —— 换阈值改结论这件事
必须写在脸上，不能只报一组数字。

**执行方式（2026-09-12 起为可复现的一步）**：`cmd/edgecompare` 提供 `-threshold <值>`
（> 0；0 = 用记录自带的 `observed.threshold`），而**驱动脚本**
`lunwen/clab-lab/scripts/edge_threshold_sensitivity.sh` 把它变成本手册里的一条命令 ——
同一份记录、同一组候选、**同一份** `-factors`/`-weights`（与门禁① 共用 `edge_spec_lib.sh` 的推导实现），
只换判定线：

```bash
# 敏感性行（唯一入口；只读记录 + 配置 + 离线工具，不调 clab、不碰 Caldera、不起容器）
cd lunwen/clab-lab
EDGEEXP_SENSITIVITY_THRESHOLDS=60 bash scripts/edge_threshold_sensitivity.sh

# 多个阈值：EDGEEXP_SENSITIVITY_THRESHOLDS=60,70
# 记录/配置/产物目录可覆盖：EDGEEXP_RECORDS=… EDGEEXP_CONFIG=… EDGEEXP_SENSITIVITY_DIR=…
```

**三件事必须成立**（否则这条行会被误当成主结论）：

1. **显式 opt-in，默认路径不变**：不给出 `EDGEEXP_SENSITIVITY_THRESHOLDS` 时，矩阵与离线比较的
   行为与本文档改动前**逐项相同**（矩阵只在给出该开关时才调用它；`run.json` 的
   `threshold_sensitivity` 为 `null` = 本轮没跑）。缺开关时脚本以**用法错误**（exit 2）拒绝，
   不静默什么都不做 —— 静默 no-op 正是这一节要防的东西。
2. **换阈值这件事写在脸上**：产物文件名带阈值（`report-threshold-60.md`），文件头有敏感性横幅
   （声明它**不是**主对比报告），报告正文由工具打印「**阈值 = 敏感性分析覆盖值 `-threshold = 60`**」
   （并**不再**打印"阈值 = 引擎决策线"，两句同时出现会读成自相矛盾），stderr 另提示一次。
   汇总 `sensitivity.json` 带 `artifact_role: threshold-sensitivity` 与
   `is_primary_comparison: false`。**主对比**是不带 `-threshold` 的那次运行（矩阵的
   `run.d/gate-gate1.json` 与 `run.d/.gate1.out`）。
3. **可核对"只差阈值"**：`sensitivity.json` 记下记录文件、条数、配置与其完整 sha256、
   两个 spec 与逐阈值产物路径 —— 与门禁① 的输入逐项相同，唯一差别是判定线。

**产物路径**（默认 `data/edgefactors/sensitivity/`）：

| 文件 | 内容 |
|---|---|
| `report-threshold-<T>.md` | 敏感性横幅 + `edgecompare` **逐字**输出（引用用这一份） |
| `report-threshold-<T>.raw.md` | 工具原始 stdout（不含横幅，逐字对照用） |
| `report-threshold-<T>.log` | 工具 stderr（含"已覆盖 observed.threshold"提示） |
| `sensitivity.json` | 汇总：run-id、记录/配置/指纹、两个 spec、逐阈值结果；**矩阵调用时并进 `run.json` 的 `threshold_sensitivity`** |

**为什么这条行不是形式主义（2026-09-12 冒烟记录的实测）**：3 条冒烟记录全部
`observed.threshold = 80`、`ground_truth.compromised = true`（正是 lab 配置的判定线）。
**主对比（判定线 80）**：四个候选的决策层指标**逐位相同**（一致率 1.000／漏判率 0.000／误阻断率 0.000）
⇒ 工具如实给出「**本次比较无区分力：未选模**」，没有任何模型被选中。
**敏感性行（`-threshold 60`）**：`legacy` 一致率 1.000／漏判率 0.000，而 `vector`/`graph`/`chain`
漏判率均为 **1.000** ⇒ 这一行**才**有区分力（选定 `legacy`）。
也就是说：判定线不动时这段数据**什么都说明不了**，换一条线结论就出来了 —— 这恰好是"换阈值改结论
必须写在脸上"的实证，也是这行必须在报告里另附（而非替换主行）的原因。

该开关只在候选对比模式下有意义：配合 `-fit` 或自检模式使用是**用法错误**（不是静默忽略）。

#### 5.4.7 诚实边界（写进论文时必须保留）

1. **S 组的因子激活是"检查失败代理"**（§2.3 的主方式）：harness 的相位只是**记录观测时刻并推进场景**，
   它**不**去按场景把宿主上"非本场景"的检查弄成通过。宿主上本来就在失败的检查照样计入 —— 这是
   "如实采集"的直接后果，也是这些记录能被复算的前提。
2. **容器内 SELinux/AppArmor 无法真正关闭**（§2.3 明写）：相关场景只能由检查失败代理，
   harness 会把该因子条件的真实探测结果（`condition_probes[].condition_holds`）如实写进 harness 产物，
   S 组**不**因条件不成立而阻断（那正是代理关系本身）。
3. **R 组（真实缺失）必须真的成立**：探针发现防护仍在位时**整轮失败**，不得用"注入失败"顶上
   —— 那会把对照面变成伪造的 ground truth。
4. **攻击剧本固定且哈希入档**：默认 `Discovery`（`0f4c3c67-845e-49a0-927e-90ed33c044e0`，
   12 条 ability；剧本名与 ID 会对不上时报错）。客观结果的口径：
   `compromised`/`block_effective` 按"观察窗内成功执行的 ability 数为 0 / > 0"（`link.status == 0`，
   状态码语义取自 Caldera `c_link.py` 的 states 表：`SUCCESS=0`、`EXECUTE=-3`、`DISCARD=-2`、
   `HIGH_VIZ=-5`、`ERROR=1`、`TIMEOUT=124`）。观察窗超时时 `operation.window_timeout = true`，
   此时 `ttps_achieved` 是**窗内已达成**的下界，报告必须按这个口径写。
   > **⚠️ 这里写的"任意 link 成功即 compromised"是 L2 裁定之前的旧口径（Minor ③）**：2026-09-12 起
   > `compromised` 的判据改为「**该场景的目标 TTP 是否成功**」，对照/侦察 link 只进 `control`
   > （通道健康度）**不参与标签**；记录带 `ground_truth.basis`（`targeted_ttp` / `recon_playbook`），
   > 决策层指标只对前者可算。**现行口径以 §5.4.13（口径 1/2）为准**，本项保留只为说明 harness 的
   > 历史行为 —— 引用"任意 link 成功"这句话时必须同时标注它已被取代，且 `Discovery` 这类固定剧本
   > 的记录（`basis=recon_playbook`）**不得**进决策层指标。
5. **采集器评的是"`meta.observation_target` 指出的那台机器"**（Task 4C 起可声明，见 §5.3.1）：
   真实检查结果来自 `internal/checks` 在**该机器上**的执行 —— 声明 `--target <容器>` 时就是在被攻
   节点内部（同一份二进制经 `docker cp`/`docker exec` 跑），不声明时是跑 `edgescen` 的这台主机。
   攻击侧（clab 节点上的 sandcat agent）只提供客观结果。**2026-09 之前的记录没有这个字段**，
   当时实际采的是 WSL 开发机（勘测实测），那批记录描述的不是被攻节点，引用时必须如此标注。
   R 组的"真实缺失"自 Task 4C 起**只在被攻节点内**核实（`condition_probes[].probe_host` 自证），
   且 `condition_probes` 为空数组时不得声称"已核实"（`edge_collect.sh` 会拒绝这种记录）。
   **节点内评估与宿主评估的实测差异见 §5.4.9**（不是缺陷，但对"哪台机器更严格"这件事有直接影响）。
6. **重复轴**是排序层方差用的（§5.3），不属于本手册的四脚本管线。**现行重复轴在 VM 基质上**
   （`edge_repeat.sh`，台账 H.6：两段共 99 条）—— 本条原文写的是「A-1 的 3 次重复」、例子取值
   `EDGEEXP_ENV=a1-ubuntu`，那是已退场的 A-1 宿主（2026-10-19 退为备份端），**纪律本身不变**。
   重复运行时**必须同时**换
   `EDGEEXP_RUN_INDEX`（`run` 号）、`EDGEEXP_ENV`（VM 批次用过的取值形状，例如 `EDGEEXP_ENV=<lab-tag>-qemu`）与
   `EDGEEXP_RECORDS`（让每轮的记录各自成文件；两段批次的产物见
   `lunwen/clab-lab/data/edgefactors/records-t21-qemu-rpt-{targeted,nontargeted}.jsonl`）。**`run>1` 而不给 `EDGEEXP_ENV` 会被直接拒绝** ——
   否则重复样本会被打上 `wsl-clab-14` 的标签混进主战场数据集，而那正是"重复性实验"最容易被读错的地方。
7. **先验边集里只有两条有直接证据，其余是假设**（措辞必须区分）：`EF-SELINUX ↔ EF-APPARMOR` 有实证
   （两者**共用触发检查 `OT-005`** → 同一次检查失败会同时激活），`EF-002FA ↔ EF-3FA` 有实证
   （既有的硬编码级联 `EF-3FA → EF-002FA`）。其余三条（`EF-NO-SIEM ↔ EF-NO-IDS`、
   `EF-SELINUX ↔ EF-002FA`、`EF-SYNCOOKIE ↔ EF-NO-IDS`）**是同域/同类的先验假设，尚无直接证据** ——
   报告与论文里必须这样标注，不得把它们写成"已证实存在的耦合"。

#### 5.4.8（**空缺**，历史原因 —— 编号不做重排）

> ⚠️ **这不是丢了一节**：小节编号从本节位置直接跳到 §5.4.9。为了不让历次报告/评审里
> "见 §5.4.9 / §5.4.10 …" 的引用全部漂移，**不做重编号**，只在此处显式声明 §5.4.8 空缺。

#### 5.4.9 节点内评估 vs 宿主评估的实测差异（Task 4C Step 4，已知差异不是缺陷）

> ⚠️ **适用范围**：本节全部读数取自 **2026-09-12 的 WSL2 Containerlab（14 节点拓扑）**，
> 身份是 `clab` vs `root`（同一台 WSL 开发机 + `host1` 容器）。**基质换到 `pve`/`qemu` 后这些数字不适用**
> （不同内核面、不同身份、不同检查集）。同一条教训"身份差异会伪造成机器差异"在 VM 上的实测
> 见 §10.4B 现行「结论四」（80 条检查里 10 条双向翻转）。本节的数值**仍是那次测量的真值**，不要改。

**实验**（勘测 §3(c) 的最便宜实验，2026-09-12 实测）：把同一份**旧** `build/edgescen`
`docker cp` 进 `asc-asscor-host1` 后 `docker exec` 跑一次 `S0-baseline`（无攻击、不重建拓扑），
与在 WSL 宿主上跑同一份二进制的结果逐条做差。配置同为 `m0-baseline.ini`（两边
`config_hash = dd334cd724ba0c4c` 相同）。随后用新二进制的 `-emit-checks`（只输出检查结果、
不装载配置、不写记录）补了两次对照，以区分**机器差异**与**身份差异**。

**第一个发现：两次采集同时变了两件事。** 宿主路径在 **用户 `clab`** 身份下跑（`edgescen`
是 WSL 里手工启动的），节点路径在 **`root`** 身份下跑（`docker exec` 默认 root）。
`/root` 下的路径因此一边"读不到"、一边"读得到"，而 `statAllowPerm` 把"无权限"与"不存在"
当作**不同**结论 ⇒ 12 条差异里有 6 条根本不是机器造成的。三个口径的失败检查数：

| 口径 | 身份 | 机器 | 失败检查数 |
|---|---|---|---|
| H-clab（现有宿主路径的实际口径） | `clab` | WSL2 开发机 | **49** |
| H-root（身份对齐对照） | `root` | WSL2 开发机 | **55** |
| N-root（节点内） | `root` | `host1` 容器 | **55** |

**权威的机器差异（身份同为 root，`H-root` vs `N-root`）**：共 80 条检查注册、两轮各 55 条失败，
其中 **51 条**两边都失败，两边**各有 4 条**只在单侧失败（51 + 4 = 55 ✓；
`46` 是**另一对**口径的交集 —— `H-clab ∩ N-root`，即 §5.2 那次"宿主 vs 节点"的实际比较，
Fix round 1 / I-6 把它从本段移走）——

| 只在宿主失败（节点内通过） | 实测成因 |
|---|---|
| `AS-004` 最小防火墙规则 | 宿主有 `iptables`（`INPUT` 策略 `ACCEPT` ⇒ 判失败）；节点**没有 `iptables`** ⇒ 检查走"命令不可用"的回退分支**判通过** |
| `AS-005` 网络服务暴露面 | 宿主有对外监听（`0.0.0.0:8888`、`8022`、`2222`、`10.255.255.254:53`…）；节点只有一个 `127.0.0.11:36801`（Docker 内嵌 DNS） |
| `OT-006` 敏感文件标记 | 宿主 `/opt /home` 下有可被其他用户读的 `.git`（`/opt/caldera/.git`、`/home/clab/.pyenv/.git`…）；节点一个都没有 |
| `RS-013` 容器运行时安全 | 宿主有 `/var/run/docker.sock`（且 `/etc/docker/daemon.json` 无 seccomp/apparmor/userns-remap ⇒ 判失败）；节点没有 docker.sock ⇒ 整段检查跳过**判通过** |

| 只在节点失败（本机通过） | 实测成因 |
|---|---|
| `AC-001` 网络分段验证 | 节点**没有 `iptables`** 且该检查**没有**回退分支 ⇒ "无法验证网络分段"判失败（与 `AS-004` 互为镜像：**同一台机器、同一个缺失工具，一个判通过一个判失败**） |
| `AS-003` 强认证策略 | 节点镜像**没有 `/etc/ssh/sshd_config`**（宿主有） |
| `AS-009` 加密协议强制 | 节点**没有 `systemctl`** ⇒ `systemctl is-active sshd` 不命中 ⇒ "SSH未运行"判失败（宿主 `sshd` 为 `active`） |
| `KS-006` 内核模块最小化 | 节点**没有 `lsmod`** ⇒ "无法执行 lsmod"判失败（宿主 18 个已加载模块，未超 150 的基线） |

**身份差异（同一台机器，`clab` vs `root`）的机制**（Fix round 1 / I-6b 按实测改正）：

只 `clab` 失败 1 条（`AC-001`），只 `root` 失败 7 条（`AC-002`/`AS-004`/`AS-012`/`BC-006`/
`OT-004`/`OT-008`/`OT-020`）。这 7 条的机制**不是**"只有 root 才真的去看 `/root/...`、
看了才发现没有"，而是 `internal/model/model.go:89-113` 的两条**通用**规则：

1. `Privilege == PrivRoot && euid != 0` ⇒ `skipResult("skipped — requires root privileges")`，
   而 `skipResult` 的 `Passed: true` —— **算通过**；
2. 检查自身返回失败、但 detail 命中 `IsPermissionDeniedDetail` ⇒ 同样转成 `skipResult`
   —— **也算通过**。

实测（`isolation/H-clab.json`）**恰好 5 条**带 `skipped` 标记且都是 FAIL→PASS：
`AC-002`/`AS-012`/`BC-006`/`OT-008`/`OT-020`（其中 `AS-012`/`OT-008`/`OT-020` 是规则 1
根本没执行、`AC-002`/`BC-006` 是规则 2 把 EACCES 型失败转成跳过）；剩下 2 条
（`OT-004`、`AS-004`）是检查**自有**的"工具不可用即通过"回退分支，不在 skipped 名单里。

⇒ 正确口径：**非 root 运行时，`PrivRoot` 检查与"权限不足"型失败都会被静默计为"通过"**，
于是 `H-clab` 的 49 条失败是**系统性少报**的。这比"看了才发现没有"更锋利，也把结论定死：
**"宿主 vs 节点"必须在同一身份下比**，而"把宿主路径固定成 `sudo`"是**唯一可行**的做法
（不是"二选一"）。对 Step 4 那两次采集而言，交叉口径（`H-clab` vs `N-root`）因此是
**只在宿主失败 3 条**（`AS-005`/`OT-006`/`RS-013`）、**只在节点失败 9 条**
（`AC-002`/`AS-003`/`AS-009`/`AS-012`/`BC-006`/`KS-006`/`OT-004`/`OT-008`/`OT-020`）。

**逐条三态（唯一不会被分类措辞误导的形态）**：

| 检查 | clab | root | 节点 | 性质 |
|---|---|---|---|---|
| `AC-001` | 失败 | 通过 | 失败 | **交互项**：两边都失败但成因不同（clab 无权限 / 节点无 iptables） |
| `AS-004` | 通过 | 失败 | 通过 | **交互项**：同一条 iptables 缺失让它在节点里走回退分支判通过 |
| `AC-002` `AS-012` `BC-006` `OT-008` `OT-020` | 通过 | 失败 | 失败 | **纯身份效应**（5 条：`PrivRoot` 跳过 / EACCES 转跳过 —— 都算通过） |
| `OT-004` | 通过 | 失败 | 失败 | **纯身份效应**（1 条：检查自有的"npm 配置需 root 权限"分支） |
| `AS-003` `AS-009` `KS-006` | 通过 | 通过 | 失败 | 纯机器效应（镜像更空 / 无 `systemctl`、`lsmod`） |
| `AS-005` `OT-006` `RS-013` | 失败 | 失败 | 通过 | 纯机器效应（宿主有 docker.sock、对外监听、可读 `.git`） |

⇒ 身份轴上是 **6 条纯身份 + 2 条交互（`AC-001`/`AS-004`）= 8 条**受影响
（原始集合依据：`ident_root ∩ machine_host = {AS-004}`、`ident_clab ∩ machine_node = {AC-001}`；
Fix round 1 / I-6 把这个数字从"7 纯身份 + 1 交互"改正 —— 后者与本表自己的标注相矛盾）。

> ⚠️ **这两份差异不是正交分解**：`AC-001` 同时出现在"只在节点失败"与"只 clab 失败"里，
> `AS-004` 同时出现在"只在宿主失败"与"只 root 失败"里。把"机器差异 4+4"与"身份差异 1+7"
> 当成互不相干的两份清单相加会重复计算这两条 —— 它们是两个变量**都在起作用**的交互项。

**结论（对实验结论有直接影响，不是"修一下就好"）**：

1. **勘测预言的 `RS-006` 那条成立**：节点**没有 `systemctl`**（实测），故 `RS-006` 只剩
   `ps -eo comm` 进程名分支 —— 它的 systemd 分支在容器内**恒不命中**。与勘测的差别是方向：
   勘测担心"工具缺失让一批检查由失败翻成通过"，实测**两个方向都有**（`AS-004` 缺 `iptables`
   判通过，`AC-001` 缺同一个工具判失败），净结果是失败数恰好相等（55 vs 55）、
   节点总分更低（52.13 vs 52.65）—— 但这**恰好说明"哪台机器更严格"不是一句可以说清的话**。
2. **"工具缺失"在检查层有两种相反语义，而这会直接污染结论**：`AS-004`（有回退）
   缺 `iptables` ⇒ 判**通过**；`AC-001`（无回退）缺同一个工具 ⇒ 判**失败**。
   于是"换观测主体"既能让分数变好也能变坏，且**两种都发生在同一台节点上**。
   ⇒ 任何"硬化基线"的动作都必须同时补齐检查所依赖的工具（至少 `iptables`/`procps`/`iproute2`/
   `systemctl`），否则域分变化无法归因到安全姿态。
3. **宿主路径的身份是实验设计的一部分，必须写清**：现有宿主路径以 `clab` 身份跑，
   而那台机器上 8 条检查的结论在 root 下会翻转（**6 条纯身份 + 2 条交互**，见上面的机制）。
   节点内路径以 `root` 跑。两者比较时"49 vs 55"里混着身份效应 —— **要谈机器差异只能用身份对齐的
   55 vs 55**（失败数恰好相等是巧合：两边各有 4 条独有），而"把宿主固定成 `sudo`"是**唯一可行**的
   做法（不是"二选一"：`PrivRoot` 跳过这条机制无法靠文档声明消除）。
4. **两边因子集与观测链条数一致**（11 条 / 6 个因子，H-clab 那一轮总分 52.65、N-root 52.13，
   域分 attack_surface 68/52、business_continuity 70/60、kernel_security 29/24、
   operation_trust 0/0、resilience 0/0）：换观测主体只改变**检查结果**，
   不改变评分链路本身 —— 这正是 §5.3.1 第 3 条要守住的东西。
5. **基线不是"有控制可移除"的状态**：节点侧 55 条失败、总分 52.13（阈值 80）、
   域分 `operation_trust = 0`、`resilience = 0` ⇒ "注入检查失败"对本来就失败的检查是空操作
   这条结论不变（`RS-005` 除外，它两边都通过）。
6. **记录写不出失败原因**：`observed.checks[]` 只有 `id/domain/passed/delta/confidence/ts`，
   检查的 `detail`（"无法执行 lsmod"这类）**没有落盘** ⇒ 本节的成因必须靠另跑 `-emit-checks`
   或直接探输入才能确认。要在报告里逐条解释成因，得先补这个字段。
   > **【Task 4D Fix round 2 的部分收口】** 与"失败原因"相邻、但后果更严重的一类已经补上：
   > **被跳过的检查**现在写进 `meta.skipped_checks`（`[{id, reason}]`，additive、`omitempty`；
   > 见 §5.1 的字段说明）。它解决的不是"失败为什么失败"，而是"**这条检查压根没给结论**" ——
   > 框架把"只因读不到证据而失败"转成 skip（`passed=true`、`Δ=0`），于是"条件让证据读不到 ⇒
   > 分数被推高"与"安全真的变好"在记录里原本**完全同形**（A-1 实测：AppArmor 拒读 `/etc/shadow`
   > ⇒ `AS-012` 被跳过 ⇒ 总分 68.78→69.72）。`observed.checks[]` 的语义（只落失败项）**没有改**，
   > 那份 `detail` 仍然不落盘。

**未在本次实验中确定的事**：`RS-005`（`tcp_syncookies`）在容器内 `sysctl -w` 是否真的向下；
攻击侧结果是否随观测主体改变；`KS-*` 系列在容器与 WSL 内核间的完整差异（只审了发生差异的 8 条）。
另外，**未声明观测主体时 R 组的失败是有意设计**（Task 4C / I-9）：R 组的语义是"在目标节点上真的没有
这个防护"，没有节点侧证据就不能声称已核实 —— 故照 §5.4.2 第 5 条 export `EDGEEXP_TARGET`
（或直接用 `edge_matrix.sh` 的默认值 `asc-asscor-host1`）是跑 R 组的**前提**，不是可选项。

#### 5.4.9B A-1/LXD 基质的取数实测（Task 4D Step 1/2，**只完成取数这一半**）

**这一节只写实测确证的事实**；§5.4.10 列出还**没有**跑过的部分（Step 3/3B/4/5 另批派发）。
实验日期 2026-09-13（UTC），目标实例 `probe-ot005`（A-1 上控制侧的**对照容器**：已装六个控制 +
一个 sandcat agent；本次只做 `lxc file push` + `lxc exec` 这类只读取数，**未改它的配置、未重启**）。

| 判据 | 实测结果 |
|---|---|
| 同一份二进制送进实例并取回检查集 | `lxc file push` → `lxc exec --env EDGESCEN_NODE_NONCE=<32 位 hex> <实例> -- /tmp/edgescen-<pid> -emit-checks`，信封可用 |
| 信封 `hostname` | **`probe-ot005`**（节点内进程自报） |
| 信封 `checks` 条数（注册） | **80** |
| 信封中 `passed=false` 条数（失败） | **42** |
| 六个触发检查 | `OT-005`/`RS-005`/`RS-006`/`RS-007`/`EF-001`/`EF-002` **全部 `passed=True`** ⇒ 该基线记录里六个因子**全不激活**（与控制侧实测一致） |
| 记录侧（`--target lxd:probe-ot005` 走完整 CLI） | `meta.observation_target = "node:probe-ot005 (substrate=lxd, hostname=probe-ot005)"`；`checks[]` = **42** 条；总分 **68.78**（阈值 80）；round-trip 复算 = 记录（残差 0） |
| 实例不存在（`lxd:no-such-instance-4d`） | rc=1，stderr = `…lxc file push … 失败: Error: Failed to fetch instance "no-such-instance-4d" …: Instance not found`，**不写记录** |
| nonce 不匹配（旁路把下发的 nonce 换成别次运行的值） | rc=1，stderr = `节点内进程回显的 nonce 与本次运行下发的不同（本次请求 32 字节）—— 这份信封来自另一次运行/另一个进程，不能当作本次观测`，**不写记录** |
| 未知基质前缀（`unknown:probe-ot005`） | rc=1，在起任何子进程之前报错，**不写记录** |
| 裸名字在 A-1 上（= docker 语义、该机没有 docker） | rc=1，`exec: "docker": executable file not found in $PATH`，**不写记录**（不静默回落本机） |

**这一节**证明的是"取数这条路径在真实 LXD 上真的能用、失败真的响亮"；
**它不证明** §5.3 那张表的其余部分（建/毁环境、攻击、矩阵、重复样本）在 A-1 上成立 —— 那些动作
在本次任务里**没有跑**（见 §5.4.10）。

#### 5.4.10 A-1/LXD 上的跑通状态（逐项如实标注；"未跑"不得按"已验证"引用）

> 📌 **本节是 A-1/LXD 基质在 2026-09-13 前后的**历史状态快照**，其内容对**该基质**仍然成立。
> 但从 **2026-10-13 起实验基质已迁到 dl360gen9 / PVE CT**，本节里的"未跑"**不再代表当前基质的状态** ——
> 当前基质的进度见本文件 §5.4.11 之后的各节与附录 D；历次迁移与理由见
> `docs/experiments/EDGE_FACTOR_EXPERIMENT_AUDIT_LEDGER.md` Part C。
> **引用"未跑"时请写清基质**，否则会把"A-1 上没跑"误读成"整个方向没跑"。
>
> ⛔ **2026-10-19 补充**：A-1 已退为备份端（数据归档至 dl360gen9 的 `/RAID-Mirror/from-a1/`、即将重置）
> ⇒ 本节所有"未跑"项**已无后续**，**不构成"待办"**（"没有后续"与"等着去跑"是两回事）。
> 另：上面抬头原说"已迁到 PVE CT"，现行**生产**基质是 `qemu`（§10.4B 结论零）。

Task 4D 这一批只交付 Step 1（基质抽象）+ Step 2（`-target` 的 lxd 驱动）。下面这些**全部未跑**
（Step 3/3B/4/5 另批派发），任何报告与论文引用都必须按"未跑"写：

> **【Step 3/3B 更新（2026-09-13）】** 第二批已交付 Step 3（`asc-tgt-1` 硬化基线 + 基线记录）
> 与 Step 3B（真实 AppArmor 策略 + 目标 TTP 两侧对照）—— 见 §5.4.13。下表里"未跑"的两行
> （`edge_reset.sh` 的 lxd 路径、`edge_probe.sh` 的 lxd 路径）**仍然未跑**；新增两条已知限制：
> ①A-1 无 auditd ⇒ 内核 AppArmor 拒绝记录默认被丢弃（要临时放宽 `printk_ratelimit` 才看得到）；
> ②Step 3B 的目标 TTP 是**自建 ability**（如实记录在报告里），不是现成剧本里的一条。
>
> **【Step 4-B2/B3 更新（2026-09-13）】** 下表**逐行**按实测改写（见 §5.4.14）：单场景
> **reset → attack → collect 已在 A-1 的 LXD 基质上真跑通**（三个条件、三条记录），
> `edge_reset.sh` 的 lxd 路径**已跑通**（含"会话断开后进程仍在跑"这一条：`setsid` 拉起的 sandcat
> 跨了三轮脚本退出仍在跳），攻击与 `(host, 活 pid)` 判据**已在 A-1 上成立**。
> **仍然未跑**的：完整 22 场景矩阵、`edge_probe.sh` 的 lxd 路径（S0 无注入 ⇒ 没触发探针）、
> R 组（真实缺失对照）在 A-1 上、每场景 3 次重复样本、`edgecompare` 拿 A-1 记录跑一次。

| 状态 | 原来的"未跑"项 | 现状 / 为什么 |
|---|---|---|
| ✅ 已跑通（单场景） | `EDGEEXP_SUBSTRATE=lxd` 的 **reset → attack → collect** | A-1 上真跑通（`S0-baseline` × 3 个条件、3 条记录）；`lab_up`/`lab_down` 在 lxd 下仍**故意响亮失败**（不建/不毁实例），复位语义改为"把既有实例准备成实验条件"（§5.4.13/§5.4.14）。**完整 22 场景矩阵仍未跑** |
| ✅ 已跑通 | `edge_reset.sh` 的 lxd 路径（Caldera 就绪 + 部 sandcat agent） | 已跑通，且**"会话断开后进程仍在跑"这条已在真实 LXD 实例上验证**（`setsid` 拉起的 sandcat 跨了三轮脚本退出仍在跳）；过程中修掉 4 处实测缺陷（§5.4.14） |
| ❌ 未跑 | `edge_probe.sh` 的 lxd 路径（六因子条件探针在实例内执行） | S0-baseline **无注入相位 ⇒ 没有探针可做**，本轮的三个条件一次都没触发它 ⇒ **仍未跑**（判据体依赖节点内 `bash`/`grep`/`iptables`，需一个 S1/S2 场景才会被执行到） |
| ⚠️ 部分已跑 | 攻击（Caldera operation）在 A-1 上的成立性 | **攻击侧已成立**（自建 pair adversary，策略在/不在两侧的 link status 实测翻转）；**R 组（真实缺失对照）仍未跑** |
| ❌ 未跑 | 每场景 3 次重复样本（`EDGEEXP_RUN_INDEX>1` + `EDGEEXP_ENV`） | 依赖完整矩阵 |
| ❌ 未跑 | `edgecompare` 离线比较在 LXD 记录上的行为 | 离线工具与基质无关，A-1 的（真实）记录**尚未拿 `edgecompare` 跑过一次** —— 试点只做了单条记录的分数/标签读数 |

#### 5.4.11 lab 配置的键位纪律（每个键都要写在解析器**会读**的段里）

`lunwen/clab-lab/kernel-config.ini` 曾经把 `threshold = 80.0` 写在 `[weights]` 段，而该文件**没有**
`[acceptability]` 段 —— 解析器只在 `[acceptability]` 里读这个键（`internal/config/config.go` 的
`sections["acceptability"]` 分支），于是取值是**静默 no-op**：`cfg.Threshold` 之所以是 80.0，
只是因为 `config.Default()` 恰好也是 80.0（把文件里的值原地改成 61.5，解析结果仍是 80.0 即证）。
这与出厂模板把 `scoring_engine` 写进 `[extension_weights]` 是**同一类**缺陷（§5.4.6 的判定线就来自
这个键，所以它落在实验的输入面上）。现已挪进 `[acceptability]`：**有效值改动前 = 内置默认 80.0
（文件值从未被应用），改动后 = 文件值 80.0**，判定行为逐位不变。

纪律与两道防线：

- **判据是"值真的在生效"，不是"文件能解析"**。`TestLabKernelConfigDecisionKeysAreInEffect`
  （`internal/config/configs_templates_test.go`）用**等值探针**：把文件里该键的取值原地改掉，
  解析结果必须跟着变 —— 键被挪回解析器不读的段时它立刻红（并有"必须声明在 `[acceptability]`"
  的位置断言）。改 lab 配置的键位前先跑 `go test ./internal/config/`。
- **同类现状（未修，且挪段救不活）**：`[heartbeat]` 的 `timeout_sec`/`enabled` 在 `Parse` 的
  **任何**段都不被读（`cfg.HeartbeatTimeoutSec` 全程为零值，唯一消费者 `internal/heartbeat`
  只在字段 > 0 时才覆盖内置 60s）—— 那是"解析层没实现"，不是"位置写错"，挪到哪都一样无效。
  测试里把它钉成断言：哪天接上解析就会红，提醒复核实验配置里那两行的去留。

#### 5.4.12 基质抽象（Task 4D Step 1）的等价性**范围**与判据（Fix round 1 收窄）

"clab 分支逐位等价"这句话必须带范围，否则就是一句过强的话：

| 范围 | 结论 | 证据 |
|---|---|---|
| `edge_reset.sh`（clab 基质） | **脚本级逐行等价**：五个场景（正常 / I9 拒绝 / agent 超时 / **deploy 失败** / 拓扑缺失）下"假 CLI 调用序列 + stdout + stderr + 退出码 + 产物"逐行相同 | `build/lab-diff.sh`：`git archive 97581d8` 取**真基线**整棵树、两侧跑**真脚本**、同一份假 CLI、私有 `/tmp` 命名空间 |
| `edge_matrix.sh` 干跑 | 除新增基质行与一处已声明措辞外**逐字等价** | **另行的手工干跑差分产出**（`EDGEEXP_DRY_RUN=1`，正常化运行标识后逐行 diff；评审独立复现过）。**`lab-diff.sh` 不跑干跑** —— 它只跑 `edge_reset.sh` 的五个场景，这一格以前错指向了它（复审 §6 已点出） |
| `edge_probe.sh` | **不是**"逐位不变"：它的假 CLI 注入方式由 `EDGEEXP_LAB_BIN` 改为 `EDGEEXP_DOCKER_BIN`（I-1 的修复），且三处错误串措辞随基质改写、`probe_host_ready` 的预检对象从 `lab_bin` 改为真正执行的 `lab_target_bin` | 20 项既有夹具无回归 + 新增判据（覆盖生效、不泄漏） |
| Go 侧 `-target` | 命令与观测主体**逐字不变**；错误串在 Step 2 一度变过，Fix round 1 已**逐字恢复**并加钉子（含 `os.Executable()` 失败那条 —— 复审 Minor-新-1） | `TestDockerErrorStringsMatchTask4CBytes`（四条子用例，期望值抄自 97581d8） |

为什么范围必须写清（评审 §1.1/§6.3 的教训）：**"既有夹具全绿"与"某个路径逐位不变"是两件事** ——
旧的等价性夹具是**手抄**基准（没有 git），且只跑成功路径；新夹具从 `git archive` 取基准、跑真脚本、
覆盖失败处置（含 `deploy` 失败这条"关键路径不做任何容错"的钉子），那条教训才算被吸收。

#### 5.4.13 Step 3 / Step 3B 的真机落地（A-1：硬化目标容器 + 真实 AppArmor 目标 TTP）

**Step 3（硬化目标容器）**：A-1 上新建 `asc-tgt-1`（`lxc launch ubuntu:24.04`，**不要**用控制侧的
`probe-ot005`），按下表装六个控制（**这一份是实测通过的配方，不是照抄文档**）：

> ⛔ **失效（仅存档）**：本条"在 **A-1** 上建 `asc-tgt-1`"已**不可复现** —— 该宿主 2026-10-19 退为备份端、
> 即将重置（数据归档 `/RAID-Mirror/from-a1/`）。**下面那份"装六个控制"的配方本身仍可用**（`apt-get install`
> 那一套与宿主无关）：`qemu` 基质的现行落点是 `edge_vm_provision.sh` / `edge_target_prepare.sh`（台账 B.5）。

| 控制 | 装法 | 实测注意事项 |
|---|---|---|
| IDS | `apt-get install -y suricata` + `systemctl enable --now suricata` | `systemctl is-active suricata` 必须是 `active`（RS-006 的 systemctl 分支） |
| SIEM 代理判据 | `aide` 的 `/etc/aide/aide.conf` 里要有能命中 `email|alert|notification` 的**真实告警配置** | **实测坑**：只追加 `report_level`/`report_url` 两行**不命中**该正则（控制侧的容器里恰好有一行含 `alert` 的注释才通过）。本步补的是 `mail_command`/`report_email`/`alert_notification=email` 三行 —— 那是真正的告警通知配置，不是为过门禁塞的词 |
| 2FA / 3FA | `apt-get install -y libpam-google-authenticator libpam-u2f libpam-fprintd` + 往 `/etc/pam.d/sshd` 追加三类模块各一行 | EF-001（任一子串）与 EF-002（**三类各≥1**，按文件累加）判据不同，见 §5.4.7 |
| AppArmor 已加载（OT-005）与 `tcp_syncookies=1`（RS-005） | A-1 上**天然满足** | —— |

实测结果：`-emit-checks` 给出**注册 80 条 / 失败 42 条**，**六个触发检查全部 `passed=True`**；
不注入任何失败采一条基线记录 ⇒ **六个因子全不激活**（链 0 条、`factors` 为 null、总分 68.78/阈值 80）。
⇒ **观测主体 `node:asc-tgt-1 (substrate=lxd, hostname=asc-tgt-1)`**。

> **"48 → 42"这个数字的留痕与更正（Task 4D Step 4-D 补，Minor ①）**：`48` 是**控制侧一次性容器
> `probe-ot005`** 上的一次探针数字，照本表配方实测其实是 **43 → 42**（43 那一次 `RS-007` **仍然失败**）。
> 也就是说：`48 → 42` 里 `RS-007` 那一格是**偶然**过的 —— 控制侧那份 `aide.conf` 恰好有一行含
> `alert` 的注释命中了正则，而那一行**从来没进过配方**。⇒ 两个数字都不得当作"配方正确"的证据：
> 能当证据的只有"**按配方补 `mail_command`/`report_email`/`alert_notification` 之后 `RS-007` 才过**"
> 这一条实测（43 → 42 的方向），以及"控制侧手跑成功 ≠ 配方可复现"这条教训。

**Step 3B（真实 AppArmor 限制策略 + 撞它的目标 TTP）**：

- **策略**：`lxc config set asc-tgt-1 raw.apparmor 'audit deny /etc/shadow r,'`（选它是因为判据链条最短：
  一条 `head -1 /etc/shadow` 就能把一个真实的安全属性映射成一个可观测的退出码）。
  `raw.apparmor` 需要**重启容器**才生效。
  > ⛔ **失效（仅存档）**：`raw.apparmor` 是 **LXD/LXC 侧**的实现语法，本条绑定的宿主已退场（2026-10-19）。
  > `qemu` 基质的等价实现是 **`aa-exec -p <profile>`** 把攻击进程挂进 profile（台账 B.5 末条），
  > **不是** `raw.apparmor`。本条的**判据结构**（策略在 ⇒ 目标 TTP 失败；策略不在 ⇒ 成功）**仍现行有效**。
- **两侧判据（都是实测）**：

  | 条件 | 容器内命令 | 宿主侧 AppArmor | 目标 TTP 的 link status |
  |---|---|---|---|
  | 策略在 | `head -1 /etc/shadow` ⇒ **rc=1 + `Permission denied`** | `apparmor="DENIED" … name="/etc/shadow" … denied_mask="r"`（profile 处于 `(enforce)`） | **`status=1`（ERROR）** |
  | 策略不在（`lxc config unset` + 重启） | 同一条命令 ⇒ **rc=0** 并打出第一行 | 无新 DENIED | **`status=0`（SUCCESS）** |

  ⇒ **这就是 L2 的标签方差来源**：同一条 TTP、同一台目标，只改"策略在/不在"，link 的 status 在
  `!=0` 与 `==0` 之间翻转。
- **宿主侧拒绝痕迹的一个实测坑**（不写成"看不到"就够诚实）：A-1 **没有 auditd**（`no auditd binary`），
  内核 audit 队列无人排空 ⇒ `kauditd_printk_skb: N callbacks suppressed`，`dmesg`/`journalctl -k`/
  `/var/log/kern.log` 里**默认查不到** DENIED。临时放宽 `kernel.printk_ratelimit`（跑完还原 5/10）
  之后即可查到完整记录。这一条限制了"事后从内核日志取证"的可用性，写进 §5.4.10 的未跑/已知限制。
- **口径（不许含糊）**：
  1. `compromised` = **该场景的目标 TTP 是否成功**（L2），**不是**"主机被攻陷"；
  2. 按 harness 今天的口径，`compromised = (成功 link 数 > 0)` —— 所以**对照 ability 的成功也会被算进去**。
     实测：策略在时"对照 status=0 + 目标 status=1"⇒ harness 口径给 `compromised=true`，
     而 **L2 口径是 `false`**。两者在 Step 4 落地 harness 时必须分开（`ground_truth.basis` 就是为这件事加的）；
  3. 分数侧的 `OT-005` 在 A-1 上**不会**翻成失败（容器共享宿主 AppArmor，`aa-status` 恒报 profiles loaded）
     ⇒ 场景"该防护缺失"仍是**合成注入**，**不得**写成"真机上那条检查真的失败了"；
  4. **陈旧 agent 的判据（Minor ②，从报告的"坑 2"提升到本节的口径列表）**：Caldera **保留已死 agent
     的条目**（`trusted=true` 但 `last_seen` 停在容器消失那一刻），而打到死 agent 上的 link 会得到
     `status=-3`（EXECUTE）—— **`-3` 不是"被拦住"**。harness 挑人/判定一律按三层判据
     「① `host` == 攻击目标 ② agent 的 `pid` **出现在目标内当前进程表里**（`lab_node_pids`）
     ③ `last_seen ≤ EDGEEXP_AGENT_FRESH_S`」；目标 link 全为 `-3` 且零成功 ⇒ **整轮失败**
     （不得写 `block_effective=true`）。实测：`asc-tgt-1` 上有过 8 条条目、只有 1 条与容器内活 pid 一致。
     采集/复位侧同一判据也各有一份实现（`edge_target_prepare.sh` 的 agent 就绪判定同源）；
     **Step 4-B2 实测到这条判据自己曾经是坏的**（python 同时用 stdin 读程序与 pid 列表 ⇒ 恒为空集，
     见 §5.4.14），修好之后"目标上有没有活着的 agent"才真的会拦住重拉。
  5. **策略在/不在会经"检查被跳过"影响分数侧（Step 5 试点实测，必须写进论文）**：策略在 ⇒ 检查
     `AS-012`（幽灵账户检测，`Delta=-6`）读不到 `/etc/shadow`，而框架把"**只因权限被拒而失败**"的检查
     转成 **skip（`passed=true`、`Delta=0`）**（`internal/model/model.go` 的 `IsPermissionDeniedDetail`
     分支，设计意图是非 root agent 不被扣分）⇒ 同一台机器上 **总分从 68.78 升到 69.72**，
     而 `compromised` 同时在翻转。⇒ **两个量在这次试点里是被同一条件用不同机制推动的**：
     标签靠目标 TTP 的 link status，分数靠"证据读不到 ⇒ 不扣分"。报告与论文里**不得**把这 0.94 分
     写成"硬化提升了安全分"，也不得用它当"标签与分数耦合"的证据。

**"策略在/不在"这个实验条件是怎么落到环境里的（Step 4-B2 实测口径）**

它不是注入、不是开关，而是**实例本身的一个属性**，因此由复位脚本落到环境上（脚本见 §5.4.14）：

1. 条件写进 `lxc config set asc-tgt-1 raw.apparmor '<规则>'`（卸下则 `config unset`）；
2. **只有重启实例才生效** ⇒ 复位脚本在"条件变了"时才重启，并在**节点内**自证两条方向都成立
   （策略在 ⇒ 读 `/etc/shadow` 必须 rc≠0；策略不在 ⇒ 必须 rc=0）——"我设了 config"不是证据；
3. 每个条件**一条记录**（`meta.env` 例如 `a1-lxd` / `a1-lxd-off`，各自成文件），场景名不变
   —— 试点里同一场景 `S0-baseline` 因此在两个环境标识下各有记录，比较按 `meta.env` 做。

**三个已知坑（都是实测，任何复现都要先读这三条）**：

| 坑 | 形态 | 处置 |
|---|---|---|
| ① 重启清空 `/tmp` | sandcat 载荷放 `/tmp` 时重启后消失，`nohup: failed to run command '/tmp/sandcat': No such file or directory` | 载荷固定放 **`/root/sandcat`**；重启后重新拉起（`setsid`，否则 exec 通道一断进程被带走） |
| ② Caldera 保留已死 agent | 8 条 `trusted=true` 条目只有 1 条与容器内活 pid 一致；打到死条目上的 link 是 **`status=-3`，看起来像"被拦住"** | 判据 = `(host, 容器内活 pid)` + 心跳新鲜（见上面口径 4）；`-3` 既不算成功也不算被拦 |
| ③ A-1 无 auditd（⛔ 仅存档：该宿主 2026-10-19 已退场，本条不可复现；`qemu` 上 `auditd` 是 `active`+`enabled`） | 内核 audit 队列无人排空 ⇒ `kauditd_printk_skb: N callbacks suppressed`，`dmesg` 默认查不到 AppArmor DENIED | 临时放宽 `kernel.printk_ratelimit`（跑完**还原 5/10**）；这一条限制了"事后从内核日志取证" |

另有一条**不是坑但极易读错**的事：策略在时 `compromised=false` 与"宿主更安全"是两回事 ——
分数侧同时被"检查被跳过"推高（见上面口径 5）。

> **【Fix round 2 的收口】** 口径 5 说的那件事**在记录里已经可见**：`meta.skipped_checks`
> （`[{id, reason}]`，additive）由采集器写出被跳过的检查；`cmd/edgescen` 侧有两条用例钉住
> "进 `meta`、不进 `checks[]`、对分数零影响、缺席时字段不出现、编解码往返不丢"。详见 §5.1。
> **仍未跑**：A-1 上**重新采一条**带该字段的记录（本轮 A-1 只读）；故"真实记录的字段长什么样"
> 目前只有离线证据（assembly 级 + 往返级），没有新的真机记录 —— 按"未跑"引用。

#### 5.4.14 Step 4-B2/B3 的 lxd 端到端落地（reset → attack → collect 在 A-1 上真跑通）

Step 4-B1 的脚本是**离线**写完的（`bash -n` + lab-diff 夹具全绿）；第一次在 A-1 上真跑时**一步都没走通**，
而且四处失败都**不是**报错形态，是"看起来正常"（超时、空日志、`trusted=false`、`status=-3`）。
这四条已修复并落进提交 `ccc36e0`，此处只记**判据与代价**（复现的人会踩同样的坑）：

| 缺陷 | 形态（为什么不像错） | 判据 |
|---|---|---|
| clab 拓扑文件被无条件判存在（`edge_reset.sh`/`edge_attack.sh`） | A-1 上没有 `asscor.clab.yml` ⇒ 复位/攻击 `rc=1` 死在**基质分支之前**，看起来像"环境问题" | 判据跟着基质走；**不能**下移到 lxd 早退之后（那会改 clab 的调用序列，lab-diff 实测变红） |
| C2 地址给错机器 | 默认 `http://127.0.0.1:8888` 是**宿主**地址 ⇒ 沙箱里 sandcat 一直连自己：进程活着、`/tmp/sandcat.log` **空文件**、Caldera 里条目**全 `trusted=false`**（与"agent 起不来"同形） | 取**容器内默认网关**（实测 `10.217.208.1`；容器内 `curl …/api/v2/abilities` → 200，`127.0.0.1:8888` → rc=7）+ 拉起**之前**的容器内可达性自证 + `EDGEEXP_C2_HOST` 覆盖。⛔ **仅存档**：`10.217.208.1` 是 **A-1/LXD `lxdbr0`** 的取值（该宿主 2026-10-19 已退场）；`qemu` 基质的等价口径是 **`EDGEEXP_CALDERA_URL` 必须给宿主地址**、`/32` 路由下一跳动态取（§10.4B 结论五、白皮书 §3.7），**不得**把这个网关值抄进 VM 批次 |
| "重启完成"等错对象 | `lab_node_running` 的判据打在 **stdout**（`true`/`false`），`until … >/dev/null` 把值丢掉 ⇒ STOPPED 也立刻通过；`lxc restart` 刚发起时容器还是 RUNNING ⇒ 后续 exec 落在停/起之间（`Error: Instance is not running`） | 先等 restart **子进程自己退出**，再等"节点内真能执行命令"；实例存在但 STOPPED ⇒ `lxc start` |
| agent 就绪判据**恒为否** | pid 列表走 **stdin**，而程序本体是 `python3 - <<'PY'` 也从 stdin 读 ⇒ 同一路 stdin 用两次，`sys.stdin.read()` 永远是空串 ⇒ 该判据**从来匹配不到任何 agent**（实测 `printf '886\n1096' \| live_agent_paws` 回空行） | pid 列表改走**第 5 个 argv**；这条判据是"别把 operation 打到死 agent 上"的唯一闸门（口径 4） |
| push 失败被咽下去 | 本脚本是 `set -uo pipefail`（**没有 `-e`**）；覆盖正在运行的 `/root/sandcat` 以 `sftp: … text file busy` 失败而脚本继续 ⇒ 最后以"agent 180s 没回连"收场 | 先 push 到 `.new` 再 `mv`（rename 对正在执行的旧文件合法）+ 每步显式判失败 + 超时打全三条自证证据 |

**B3：因子集相等断言的声明面改为「基线活跃集 ∪ 注入集」（用户 2026-09-12 裁定）**。链 = 宿主上
**自然活跃**的因子 ∪ 场景**注入**的因子，而旧声明面只写注入集 ⇒ 在未硬化宿主上 S0（声明空集）会被
**每一条**记录拒掉。扩展后三条牙**分开算**：注入集缺席 = **因子塌缩**（失败）｜基线集缺席 =
**声明与现实不符**（失败）｜链上多出 = 无人声明的自然失败（失败）。基线集由 `edge_attack.sh` 的
`EDGEEXP_BASELINE_FACTORS` 写进产物（`expected_baseline_factors` + `_source`），**空集也必须显式写出**；
旧产物缺该字段按"未提供（视为空基线集）"处理（行为与今天一致）。实测双向：声明一个不在链上的基线
因子（`EF-NO-IDS`）⇒ 精确报出"基线集缺少 `['EF-NO-IDS']`"并回滚；显式空基线集 ⇒ 通过。

**Step 4-B2 的验收实测（A-1，单场景端到端 ⛔ 仅存档：该宿主 2026-10-19 已退为备份端）**：复位幂等（策略已在 ⇒ 5s 不重启；条件变更 ⇒ 18s，
`重启过=1`）→ 攻击（`compromised=false` `block_effective=true`，`basis=targeted_ttp`，目标 link 1/0 成功、
对照 1/1）→ 采集（观测主体 `node:asc-tgt-1 (substrate=lxd, hostname=asc-tgt-1)`、门禁② 残差 **+0**、
记录落盘）。**Step 5 试点（3 个条件）的读数见报告**，本设计文档只钉住一条结论：`compromised` 在**同一
宿主状态**下取到过两个真值（策略在：目标=读 `/etc/shadow` ⇒ `false`；目标=写 marker ⇒ `true`）
⇒ 标签跟的是**目标 TTP**，不是"策略在不在"。

#### 5.4.15 决策层指标的**标签依据口径**（里程碑 B 计划的 Task 5 = 实际执行 **Task 21**，已完成；`cmd/edgecompare` 为准）

> 编号提示：标题原文是「**Task 5 开工必带** 的 durable 口径」—— 这里的 `Task 5` 指**计划里的**
> Task 5（重复性与方差），它**已执行完毕**（实际任务号 **Task 21**，台账 H.6）。两套编号并存不互相替换，
> 完整对照表见 `docs/superpowers/plans/2026-09-12-edge-factor-coupling-milestone-b.md` 顶部。

**这一节是"决策层能不能算"的唯一权威口径**（此前它只活在 CLI help、源码注释与 gitignored 的报告里
—— 复审 N-3 指出 `grep docs/ "allow-mixed-basis|assume-basis"` 零命中）。

**1. 参与决策层的唯一依据是 `ground_truth.basis = targeted_ttp`。** `compromised` 有两种口径：
`targeted_ttp`（该场景的**目标 TTP 是否成功**）与 `recon_playbook`（固定侦察剧本的结果，
**在任何姿态下都成功**，只是背景测量）。两者在数据上完全同形（都是一个 bool），
所以**不得**混进同一个漏判率/误阻断率：那两串数字的口径不同，混算出来的率**没有定义**。

**2. `recon_playbook` 的记录被自动丢出并记账。** `cmd/edgecompare` 的缺省口径下：

| 数据形态 | 缺省 | `--allow-mixed-basis`（逃生开关） |
|---|---|---|
| 全是 `targeted_ttp` | 全部进决策层 | 同左 |
| 全是 `recon_playbook` | **过滤后 N=0 ⇒ 报错、不给结论**（"决策层指标与选模都无从计算"） | 全部进（敏感性/历史对比用；stderr 明确标注不得当主结论） |
| 两类混装 | **过滤**：侦察口径的丢出（条数进 `basis_skipped`），用剩下的目标口径算 | **报错**（"两类都要进 = 混算，漏判率没有定义"） |
| 缺 `ground_truth.basis`（旧记录） | **报错**（三条出路见下） | 按旧口径 `recon_playbook` 理解并丢出（条数记进 `basis_skipped["(未声明)"]`） |

- **缺依据的三条出路**：用带 `basis` 的采集产物重采（Task 4D 起 `edge_attack.sh` 会写它）；
  `--assume-basis targeted_ttp|recon_playbook` 显式声明这批记录的口径（假设条数进
  `basis_assumed`，报告头写明"其中 N 条按 `--assume-basis` 归类"）；或 `--allow-mixed-basis`
  接受旧口径。**`--assume-basis` 只作用于"缺依据"的记录**，不改已有依据。
- **过滤后 `N == 0` ⇒ 不给结论**（两道独立闸门：`CompareWith` 报错 + 导出层 `RenderMarkdown`
  打印"未选模"）。**`-fit` 走同一套守卫**：拟合的标签向量就是 `compromised`，
  过滤后为空 ⇒ **不可算**（不产出参数段与 `-out` 文件）。
- **记账判据（可直接检查）**：`参与决策层 == 带目标 TTP 的场景数 × 重复数`；
  `basis_skipped(recon) == 其余场景数 × 重复数`；两者之和 `== 总记录数`。
  报告头逐条打印 `参与决策层 N 条（…）｜跳过 M 条（…）｜过滤前共 T 条`。
- **重复样本不是独立样本**：决策层 `N` 必须写成 `N=<条数>（<场景数> 场景 × <重复数> 次）`；
  拟合/自助法按**场景聚类**，或显式声明"按独立样本处理"的代价。
- **`--assume-basis` 与"无事可做"**：两类都在、没有缺依据的记录时，假设不生效
  （不静默改写任何记录），stderr 如实说明。

**3. 分数侧的读法（与决策层无关，但极易读错）**：任何"条件 ⇒ 分数上升"的结论都要**并排**给出
"失败集 + **跳过集**"（`meta.skipped_checks`，见 §5.1）。只有当跳过集在两组之间**不变**时，
"分数上升"才可以被读成安全姿态变化；跳过集有差异时，分数差里混着"评估器可观测性"这一项
（A-1 实测：AppArmor 拒读 `/etc/shadow` ⇒ `AS-012` 被跳过 ⇒ 失败 42→41、总分 68.78→69.72），
**不得**当作安全提升。

---

## 6. 形式化验证与测试策略

| 类别 | 内容 |
|---|---|
| 性质测试 | P1（有界）、P2（单调）、P5（极限）属性测试 + **因子全组合枚举 2⁶=64** 扫描 |
| 超模性 | P3：随机 `a`/`c` 下验证 `L(A) − L(∅) ≥ Σ_i [L({i}) − L(∅)]` |
| 兼容性 | 全默认配置 → 与历史评分**逐位一致**（硬门禁） |
| 参数校验 | 坏向量长度/`f` 越界/`c<0`/`λ≤0`/`Σ v>1` 全部 fail-fast |
| 拟合可信度 | 合成已知 `c_ij` 的数据 → 回归可恢复（含噪声容限） |
| 离线↔在线一致 | 总分与判定线共用同一份实现：离线直接调用内仓 `ssam.SSAMV20Formula`（域分加权、公式内钳位、`0.5·base+30·E+20·T` 聚合、两次取整全部由它完成），域级修正经 `RegisterDomainAdjust`、乘子经 `RegisterEdgeFactorStrategy` 注入，legacy 零注册；判定线同款 `总分 ≥ threshold`。**边界（勿过度承诺）**：因子激活项的**装配**（`ActivationFromResult` 的置信度换算）在线/离线仍是两份实现，只是算术口径相同。**`c_trigger` 不是一致性的前提**：对**同一个模型**，离线在任意 `c` 下都与在线同值 —— legacy 侧离线乘的就是记录里那个 `effective_factor`，而它的来源正是在线引擎的 `EdgeFactorResult.Factor`（同一个数，故不是"两条不同的算法碰巧相等"；有 `c=0.9` 的实测用例断言离线 == 在线观测 `final_score`）；V/G/C 侧在线经 `ActivationFromResult → EffectiveFactor(r.Factor, r.TriggerConfidence)`，离线的 `activationsFromResults` 是**同一次调用**的副本、同样跳过 `!Active`、同样归一 ID，故给定 schema 前提即逐位同值（该分支今天只有算术论证 —— 一致性门禁用的记录是 `c=1.0`）。§10.2 的 `c=1` 讲的是**另一件事**：同一套可信度策略下 legacy（衰减一次，`c`）与 V/G/C（装配层再衰减一次，`c²`）之间的口径差；它只在"选 V/G/C 还是选 legacy"这个跨模型选择上体现，与离线↔在线一致性无关（详见该节）。另：该行对 chain 不适用 —— chain 在线必失败（离线专用模型） |
| 内仓回归 | `ssam-lib` 钩子默认路径不改变既有测试结果（内仓 `go test ./...`） |
| 常规门禁 | 全 tag 构建、CI 全量线（新 tag 纳入）、LF 归一 gofmt |

---

## 7. 工程约束与交付物

### 7.1 归置（方案 A）

| 位置 | 职责 |
|---|---|
| `ssam-lib`（内嵌独立仓库） | **仅一处钩子**：`evalProductChain` 改为"可注入合成策略"（接口 + 默认连乘），默认路径逐位一致 |
| `internal/edgefactor`（主仓，**无 build tag**，默认编译） | 统一框架、四候选、参数校验、性质测试（纯函数、无内部依赖；随默认构建与 CI 无 tag 线一起受测） |
| `config.ini [edge_factors.model]` + `configs/edgeexp/` | 参数注入与实验模板 |
| `cmd/edgecompare`（tag 门控） | 离线重算、指标、拟合、报告（与在线共用同一实现） |
| `internal/engine/ssam/adapter.go` | 触发映射改由配置表提供（默认等价） |

### 7.2 纪律与风险

- **内仓纪律**：`ssam-lib` 改动须提交内仓 master **并**同步外层快照；禁止内仓 `git checkout -- .`（会覆盖外层新快照）。
- **tag**：`edgefactor` 与离线工具 tag 纳入全量测试线；默认内核不含新模型。
- **风险**：① 交互项可辨识性（§3.5 已给出降级策略与如实报告要求）；② 容器内 SELinux/AppArmor 不可真关（代理关系须标注）；③ **~~A-1 agent 上限~~**（⛔ 失效（仅存档）：A-1 已于 2026-10-19 退为备份端；VM 批次上的对应约束是"投送组必须本机独占"与 `REPEAT=1` 的记录条数门禁，见操作手册 §6.17/§6.18）；④ 论文数字——若 E1–E9 涉及因子行为，需在论文说明升级路径，**不得回退已有数字**。

### 7.3 交付物

① 统一框架与四候选（`internal/edgefactor`）；② `ssam-lib` 合成策略钩子（内仓 + 外层）；③ 配置段与实验模板；④ `cmd/edgecompare`（重算 + 拟合 + 报告）；⑤ 实验脚本与数据集（**`pve` CT 11 条 + `qemu` VM 全量 33 条 + 重复轴 99 条**；原文写"WSL + A-1"，那两套基质已不再是数据来源）；⑥ 设计文档 + 实验/选模报告（含参数文件与不确定度）。

---

## 8. 阶段划分与验收

| 阶段 | 交付 | 验收 |
|---|---|---|
| P1 | 统一框架 + 四候选 + 性质测试（纯函数，无 IO） | P1/P2/P3/P5 性质全绿 + P4 逐位一致（硬门禁） |
| P2 | 配置注入 + 参数校验 + 溯源字段 + 触发映射可配 | 坏参数 fail-fast；默认行为不变 |
| P3 | `ssam-lib` 钩子（内仓提交）+ 外层接入 | 内仓测试全绿；外层全量测试；默认逐位一致 |
| P4 | `cmd/edgecompare`（重算 + 指标 + 报告 + 拟合） | 离线↔在线逐位一致；合成数据可恢复 |
| P5 | 实验执行（**`pve` CT 批次 11 条 + `qemu` VM 全量批次 33 实例 + 重复轴 99 条**；原文写"WSL 22+3；A-1 重复 3 次"，见本表后的存档标记） | 数据集完整、脚本可复现、代理关系已标注 |
| P6 | 拟合与选模（logistic + 交叉验证 + 自助法） | 选定模型 + 参数文件 + 对比报告（含不确定度） |
| P7 | 文档 + 论文影响处理（原文的「+ 双分支同步」**已撤销**，见本表后的存档标记） | 文档归档、CI 绿；**分支策略按台账 A.1**（`main` 与 ARC 正式分叉、**永不整体同步**，只有被点名的关键模块单独移植） |

> ⛔ **失效（仅存档）**：P5 原文的「实验执行（**WSL 22+3；A-1 重复 3 次**）」是 2026-09-08 的基质排法。
> 实际产出：`pve` CT targeted 小批 **11 条** → `qemu` VM **22 场景 / 33 实例** → 重复轴 **99 条**
> （台账 C.2 与 H.6；数据集 `records-dl360-pve-20261013.jsonl` 11 条 / `records-dl360-qemu-20261016.jsonl` 33 条）。
> P5 是"怎么算通过"的条目，**基质写错等于换了考点** ⇒ 本表 P5 行已按实际基质改写，**验收条件不变**
> （数据集完整、脚本可复现、代理关系已标注）。

> ⛔ **失效（仅存档）**：P7 原本写的是「文档 + 论文影响处理 + **双分支同步**」/ 验收「文档归档、CI 绿、**main/ARC 同点**」。
> 该判据已被 **2026-09-13 的分支策略裁定撤销**（台账 A.1 四条规则：正式分叉、永不整体同步、
> 点名移植、历史债务/漏洞修复/审计修复三类**必须第一时间进 main**）。
> **"main/ARC 同点"照做就是一次被禁的全量快进**（`git push . ARC:main` 之类）。
> 现行口径以本行与台账 A.1 为准；"同点"这个判据**不得**再当作验收条件。

---

## 9. 决策记录（作者逐项确认）

| # | 决策点 | 结论 |
|---|---|---|
| D1 | "向量图"语义 | 三种解读**全部实现**（逐域向量 V / 耦合图 G / 时序链 C），并在共存场景下实测比较 |
| D2 | 主判据 | **决策层为主**（漏判率 + 误阻断率），排序层与数值层辅助 |
| D3 | 对比范式 | **离线重算为主**：实验只采原始观测 + 客观结果，四候选离线重算比较 |
| D4 | 因子注入 | **注入检查失败为主** + 少量真实缺失对照 |
| D5 | 理论边界 | **形式化界 + 证明 + 性质测试**（P1–P5） |
| D6 | RC-M4 范围 | **只参数化**（配置/实验注入），标定后置 |
| D7 | 总体方案 | **方案 A**：`ssam-lib` 单钩子 + 主仓实现（离线/在线同一份实现） |
| D8 | 向后兼容 | 默认 `legacy`，历史评分逐位一致；新模型仅实验启用 |
| D9 | **选模的结论口径** | **决策层为主**（漏判率 → 误阻断率 → AUC → 字典序）；排序层/数值层只作辅助、**不作为独立证据**（M2：排序层与标签同源）。实测**无区分力时不选模**，如实写 NULL（Task 24） |
| D10 | **重抽样单位** | k 折与自助法**必须按实例重抽**（`-group-by scenario`）：同一实例的两臂读数与分数逐项相同、只差标签，按行切折会把泛化误差系统性估低。逐行口径保留为历史口径（缺省），并在拟合报告头上**写明单位** |
| D11 | **拟合路径的输入校验** | 与对比路径**同口径**：逐条输入校验（生效权重表可用 + 域覆盖）提到依据守卫**之前**、对全部输入记录跑；拟合另有"特征域集合（`DefaultDomains ∩ λ`）必须有观测域分"一条（拟合没有 `-weights` 回退表）。数据坏 ⇒ `exit=1`，不再被记成"没有可用的标签" |

### 9.1 Task 6（拟合与选模）的实测结论（2026-10-21）：**NULL 结果**

> 一句话：**四候选在决策层无法区分，拟合无法辨识任何系数**。这不是失败，是**验证出来的 NULL**——
> 原因不是"模型太像"，而是**数据集的设计矩阵秩亏**（22 条记录只给出 5 个逐位不同的设计行，
> 而每个行都同时带着 `compromised=1` 与 `0`）。证据与原始输出：
> `lunwen/clab-lab/data/edgefactors/{compare-20261021.md,compare-20261021-rpt-targeted.md,fit-20261021.md,fit-20261021-rowlevel.md,fit-20261021-diagnostics.md,params-20261021.ini,params-20261021-factors.ini}`。

**1) 四候选对比（主判据 = 决策层）**

| 数据集 | N（决策层） | 决策一致率 | 漏判率 | 误阻断率 | AUC | 结论 |
|---|---|---|---|---|---|---|
| 主批 `records-dl360-qemu-20261016.jsonl` | 22（11 实例 × 2 臂；跳过 11 条 recon） | 0.500（四候选全等） | 0.000 | 0.500 | 0.500 | **未选模** |
| 重复批 `records-t21-qemu-rpt-targeted.jsonl`（稳定性复核，**不进主结论**） | 66（11 × 2 臂 × 3 次） | 0.500 | 0.000 | 0.500 | 0.500 | 同上（2026-10-19 那次独立运行逐位一致） |
| 重复批非 targeted 段 | — | — | — | — | — | `exit=3` **不适用**（没有 `targeted_ttp` 标签） |

- 四个候选的**决策层四项**（一致率 / 漏判率 / 误阻断率 / AUC）逐位相同；**排序层不是逐位相同**：
  `legacy` 的 Spearman/Kendall 是 **−0.036 / −0.062**，其余候选是 **−0.011 / −0.031**（工具原样输出见
  `compare-20261021.md`）。按 M2 排序层与标签同源、**不得当独立证据**，故这不影响"不选模"；
  但也不得写成"三层判据逐位相同"（第二次审计 Minor-1 订正）。
- **为什么必然 0.500**（结构性的，不是测量噪声）：同一实例两臂的 observed 除 `ts` 外逐字段相同
  ⇒ 任何"只看读数"的模型给两臂**同一个分数** ⇒ 判定线要么一起放行、要么一起阻断 ⇒ 一对里必有
  一条判错 ⇒ 一致率上限 0.5。实测 22 条**全部**被判定为 not acceptable（漏判 0、误阻断 0.5）。

**2) 拟合（`-fit`，graph 基准 + 5 条先验边、seed = 20261021）**

| 口径 | CVErr | 点估计 |
|---|---|---|
| 按实例（`-group-by scenario`，**权威产物**） | **0.693147 = ln 2** | β 全 0；5 条先验边全部按 `β ≤ 0 ⇒ 不写` 移除 |
| 留一实例（`-folds 11`，按实例） | 0.693147 | 同上 |
| 逐行（历史口径，仅作对照） | 3.491897 | 同上 |

`ln 2` 正是**常数预测器**的对数损失 ⇒ 按实例的交叉验证说明"对没见过的实例零预测信息"；
逐行的 3.49 **不是**"泛化很差"而是**病态**（训练集里有同一实例的同胞，验证时被自信地判错），
**不得**引作泛化误差。

**3) 可辨识性诊断（回答"够不够估 5 边 + 7 主效应"）**

- 主批 22 条 targeted 记录 → **5 个逐位不同的设计行**（11 个实例两臂各一行、同实例两臂同一行）；
  参数 **13 个**（截距 + 7 主效应 + 5 边）⇒ `rank(X) = 5 < 13`，条件数 **∞**。
  **VIF：11 / 12 个非截距列 = ∞；`EF-3FA` 是有限值 `12/11 ≈ 1.0909`**（它只在 2 条记录非零，
  `min=0, max=0.117`，仍不足以支撑可用的主效应估计）。**秩亏 ≠ 每列都 ∞**：VIF 的定义是
  `1/(1−R²)`，秩亏时 LS 投影仍唯一、R² 可算（第二次审计 Important-1；复算见
  `fit-20261021-diagnostics.md` §2）。
- 每个设计行**同时**带着两类标签 ⇒ 梯度方程被 `β = 0` 满足，L2 让 0 成为**唯一**最优点。
  故"系数为 0"是**不可辨识**的读数，**不是**"耦合强度为 0"的证据。
- 5 条先验边本身**不是数据选的**（`graph.ini`/`chain.ini` 里的 0.10/0.15/0.30/0.35/0.40 是手工先验，
  `λ` 全 1.0、`chain.window_seconds = 300` 也没有数据依据）⇒ 本任务的拟合只能估系数，
  边集在先验里就定死了。
- **重复样本不是独立样本**：重复批 66 条同样是 5 个不同设计行（重数 30/12/12/6/6，每行双标签），
  3 次重复**不增加**任何独立信息 ⇒ 有效样本量是 **11 个实例 / 5 个不同协变量行**。
  ⇒ **再加重复救不了可辨识性**；要估出耦合，必须设计**新的、每实例独立的协变量变化**（不是同一
  姿势的重复）。依据：`fit-20261021-diagnostics.md` §4（66 条仍是 5 行）。
- `EF-002FA|EF-3FA` 这一列在主批里**恒为 0**（级联边对应的两个因子从未在同一记录里同时激活到可观测），
  故 C 候选唯一的设计内"级联边"在本数据上**连列都没有变化**。
- 诚实边界：以上都是**对当前 22 行设计**的诊断，换边集/换主效应集合都会变；不可外推成
  "这些边永远不可辨识"。

**4) 结论口径逐条落实**（计划 Task 6 Step 3 的每一条）

- 选模依据只有**决策层**；本次三层判据全等 ⇒ **不选模**。
- **M2**：未攻陷样本 `severity ≡ 0`，而 `compromised` 又是 AUC 的标签 ⇒ Spearman/Kendall 与 AUC
  同源，**不得**当独立证据（本次两者都≈0，正好说明没有信息，而不是"负相关"）。
- **M3**：`ttc` 由采集器保证必填（数据侧已消除"未知=瞬时"）。
- 单类别数据集时 `AUC=0` 是**哨兵**不是"完全反向"（本数据两类都在，不适用）。
- **可信度双衰减（`c²`）**：本次全部候选都在**离线**评估（V/G/C 不在线装载），双衰减不进入
  本次任何数字；一旦在线启用 V/G/C，惩罚强度显著强于历史路径这一事实**仍需在标定报告里标注**。
- **`c_trigger = 0` 的因子不产生惩罚**（S5 读法）：主批有 2 条 `EF-002FA` 条目 `c_trigger = 0`
  ⇒ V/G/C 下该因子的 `a = 0`（而 legacy 真的乘它的值）；S5 的对照必须按这个口径写。
- **C 与 V**：本次 chain 与 vector 的三层判据逐位相同 ⇒ **本数据集无法区分 C 与 V**
  （不得因为某一项略好就宣称 C 更优）。
- **拟合优化的是分数的线性化代理**（`design()` 用标量汇总 `a_i = (1−eff_i)·Σ_d v_i[d]`）：故拟合出的
  `c_ij` 只是候选参数的**生成器**，本任务**没有**声称"拟合更优 ⇒ 决策层更好"；权威判据仍是
  "用该参数跑离线重算后比决策层指标"，而这一步在本次数据上**无区分力**。

**5) 降级选择原则（若工程上必须交付"一个默认候选"）**

本数据**没有**给出选模依据，故**默认候选只能是工程决定**，按下列顺序降级选择，并**必须**这样写进
报告，而不是反过来编一个数据理由：

1. **解析简单性**：`legacy`（`model = legacy`）—— 无向量、无耦合、无时间窗，且是**历史默认**，
   与既有评分逐位一致（P4 硬门禁）；它不引入任何**不可辨识**的参数。
2. **可解释性**：`vector` —— 每个因子只声明"主要打击哪些域"，参数含义可逐项核对，同样**不含**
   交互项 ⇒ 不引入无法估计的 `c_ij`。
3. **参数可辨识性**：`graph`/`chain` 的 `c_ij` 在本次设计上**不可辨识**（见上），故在数据补足之前
   **不作为默认**；若要用，只能作"待标定参数"处理，且报告中必须标注"不可辨识"。

> **不许做的事**：不得因为某一候选的某个辅助指标好一点就宣布"选定它"；不得把本节的 NULL 写成
> "耦合很弱"；不得用 `-l1` 的取值来解释边强度（`L1 > 0 ⇒ 耦合更小` 在本设计上是**假命题**：
> 实测点估计已是 0、罚项无从再推高任何系数；Task 10 的共线夹具上更是中等 L1 反而把 c 推高）。

**6) 论文影响判定（Task 7 Step 2）—— 原判定「无需改动论文」；2026-10-22 按用户裁定改为「按实际写」**

> ⚠️ **本条的结论已被用户裁定取代（2026-10-22）**；下面「改前」那段保留，因为它是**改前的事实**，
> 不是现行结论。用户原话：「**论文正文按实际的来写**」+「**拟合的 NULL 需要进论文并且说明**」。

**改前（第二次审计 Important-3 落字时）**：三份论文源文件里
`edge factor` / `coupling` / `边缘因子` / `耦合` / `Spearman` / `Kendall` / `AUC`
**全部 0 命中**（大小写不敏感）：

```bash
git grep -in -e 'edge factor' -e 'coupling' -e '边缘因子' -e '耦合' \
  -e 'Spearman' -e 'Kendall' -e 'AUC' -- \
  lunwen/paper/attacker-cognitive-loop-paper.tex \
  lunwen/paper/attacker-cognitive-loop.md \
  lunwen/paper/preprints-template/preprints_template_latex/attacker-cognitive-loop-preprints.tex
# 改前：rc=1（无输出 = 0 命中）；改后这三份文件必然命中，属预期
```

改前的理由当时成立：论文正文不涉及边缘因子/评分耦合，也未把排序层指标（Spearman/Kendall）或 AUC
当作证据 ⇒ 当时判「本方向的 NULL / 不可辨识结论不触达论文正文」。

**改后（2026-10-22，用户裁定「按实际写」+「NULL 进论文」）**：

- **σ 的取值表述按实现订正**：由 `σ ∈ [0,100]` 改为 **`σ ≥ 0`，名义 0–100 但上界不设**。
  依据 `ssam-lib/formulas_v2.go` 的 `SSAMV20Formula`：`Total` **无 100 钳位**；
  `exposure`/`threat` 系数只有 0.60 下界、**无上界**；`clamp95` 只夹 95% 置信区间端点。
  `threat_coeff=1.4`、其余为 1.0 时 `(1.0·50 + 1.0·30 + 1.4·20)/100 = 1.08 ⇒ σ = 108`。
  论文在该处加**脚注**（代码位置 + 算式），并在 `v_t=(100−σ)/100+ρ` 处补限定
  （σ > 100 时首项为负，实现按原式求值、无额外保护）。
  ⚠️ **这不关闭台账 F.1 的 `PP-01`**：论文按实际写 ≠ 代码要不要加钳位 —— 后者是**产品侧决定**，仍开放。
- **新增小节 `§7.5 Edge-Factor Coupling: An Identifiability Bound`**（三份论文文件同步），数字全部取自
  入库产物：22 条 → **5 个设计行**、`rank(X)=5 < p=13`、VIF **11/12 = ∞** 且 `EF-3FA = 12/11`、β 全 0、
  重复批 66 条**仍 5 行**（重数 30/12/12/6/6）、CV **0.693147 = ln 2**（按实例）vs **3.491897**（逐行）、
  四候选决策层 `.500/.000/.500/.500` ⇒ **未选模**；并写明「**不可辨识 ≠ 无耦合**」「**加重复救不了**」。
- **编译**：MDPI 版两遍 `rc=0`（23 页、**未定义引用 0**、overfull 4 与干净基线同值）；
  article 版 `rc=0`（22 页、0/0）。产物在 `build/`（gitignored）。
- **提交**：`02fbccb`（`docs(paper): σ 上界按实现改写并补脚注，拟合 NULL 进正文`）。

证据见本节第 1–5 条、`fit-20261021-diagnostics.md`、台账 H.8（NULL 判词）与 H.9（本轮裁定台账）。

---

## 10. 未决与风险

### 10.1 在线可用性与口径（Task 7 评审裁定，实现为准）

- **`chain` 为离线专用模型**：引擎结果类型（`ssam-lib` 的 `EdgeFactorResult`）不含时间戳字段，而 `Synthesize` 对 chain 要求每个激活因子带非零 `TS`（fail-fast，刻意不退化）。因此**在线装配期对 chain 直接失败**（不装载、不盖戳、评分回落到与未启用逐位一致的路径）；chain 的时间戳只存在于离线 JSONL（§5.1 的 `edge_factor_chain[].ts`），故 chain 的评估在 `cmd/edgecompare` 离线进行 —— 与 §2.2「离线重算为主」一致。
- **溯源（`Model`/`ParamsHash`）口径**：填写的判据是「**engine 已装载同一套参数**」，而不是「配置里写了模型段」。「未配置」时两个键不出现在 JSON；「显式 `model=legacy`」时输出 `legacy` + 指纹（用于区分"未配置"与"显式选 legacy"）。
- **显式 `model=legacy` 与「未配置」在评分上逐位一致**（评审裁定，`-U` 边界夹具 50.31）：两者都**不注册任何钩子**，走内仓默认的顺序乘法；差别只在**溯源输出**（显式 legacy 输出 `legacy` + 指纹，未配置不输出）。不得用"注册恒等乘子"来实现 legacy —— 那会把默认顺序乘法切成单次相乘，在取整半格上产生 1 ulp 差异。
- **域分口径**：域级修正 `P_d` **只作用于域分聚合**（`Score_d' = Base_d · P_d` 参与聚合）；对外输出的 `DomainScores` 仍是修正前的观测值。若后续需要"修正后域分"的证据链，需在输出层补字段。
- **运行时只修正 `λ` 覆盖到的域**：实际被修正的域 = `DefaultDomains ∩ λ`；未配 `λ` 的域不修正（运行时不额外提示）。

### 10.2 已知口径问题（标定前必须处理）

- **可信度被衰减两次**:`ssam-lib` 的 `ApplyEdgeFactorsToChecksPolicy` 已把因子值按可信度衰减一次（`factor = 1-(1-factor)·c`），而装配层 `ActivationFromResult` 又对同一个 `Factor` 再乘一次 `EffectiveFactor(·, c)`，合计为 `1-(1-f)·c²`。**这里说的是 legacy 与 V/G/C 之间的口径差**：同一个部署只能选一个模型，故它体现为"选 V/G/C 比选 legacy 多衰减一次"（`c²` vs `c`），**不是**"离线↔在线不一致" —— 后者对**同一个模型**在任意 `c` 下都成立（详见 §6 表）。可信度策略关闭（`c=1`）时两者恒等，故不影响"默认逐位一致"；但**一旦开启可信度策略，启用模型的惩罚强度会显著强于历史路径**。Task 8–10 的离线重算必须**复用同一口径**（`Task 8–10` 是**里程碑 A** 的编号；本里程碑语境下的对应物
（重复/链重复修复/拟合）是 Task 21 / 18 / 24，编号对照见计划文件顶部），并在标定报告中明确标注。引用时注意这是**衰减次数**的差，不是"同一个 `c` 数值"：两条路径的置信度归一化并不相同（legacy：`c<=0 或 c>1 ⇒ 1.0`；V/G/C 走 `NormalizeConfidence`：`<=0 ⇒ 默认值`、低于下限 `0.05` 抬到 `0.05`），故极端置信度下两侧的 `c` 数值本身也可能不同。是否修正（去掉重复衰减）属独立决策（会改评分）。
- **级联因子在 V/G/C 下不产生惩罚（`c_trigger = 0`）**：`EF-3FA → EF-002FA` 这类级联把 `EF-002FA` 压到 `0.82`，但该因子是"仅由级联激活"，`c_trigger = 0` ⇒ `EffectiveFactor(0.82, 0) = 1` ⇒ V/G/C 下 `a = (1−1)·v = 0`；而 legacy 路径**真的乘 0.82**。这是里程碑 A 的既有在线行为（本方向只如实记录、不改评分）。**后果**：spec §5 的 S5 组（级联 vs 独立）会表现为"V/G/C 忽略级联"，而准确表述是"**`c = 0` 的因子在可信度模型下不产生惩罚**"——标定报告必须这样写，否则 S5 的结论会被读错。
- **同名双条目在 V/G/C 下曾把 `a_i` 计入两次（Task 18 已定因并修复；`L_d` 口径变更，标定前必读）**：
  出厂/实验配置的 `[edge_factors.custom]` **刻意**复制了内置六因子的同名条目（§5.4.3 第 2 条，门禁⓪ 要观测的正是这个现象），`ConfigToEdgeFactors` 也**刻意不去重**（P4）；解析层把配置键**小写化**，而 `ssam-lib` 的 `ApplyEdgeFactorsToChecksPolicy` 用 **`efMap[f.ID]`（原始大小写）** 建键 ⇒ **同一个逻辑因子产出两条 `EdgeFactorResult`**（`EF-APPARMOR` 与 `ef-apparmor`），并因 `sort.Slice(by ID)` 的 ASCII 序（大写 0x45 < 小写 0x65）在输出与链上呈现为**两块各自的字典序**。`observeEdgeFactorChain` 随后把 ID 归一 ⇒ 链上"每个因子恰好两条"。**真机实测**（33 条 VM 记录 + 11 条 CT 记录**同形态**，故与基质无关）：24/33 条的两条目**逐字段相同**，9/33 条的 `EF-002FA` 一条 0.70（内置 `level4_override`）、一条 0.85（custom）；`n_i` **不是常数 2**（3 条记录含 `n_i = 1` ⇒ 如 `S3-3fa-selinux-apparmor` 的 `EF-002FA×1`/`EF-3FA×1`、`S5-cascade-3fa` 的 `EF-3FA×1`）。
  ⚠️ **论文措辞禁令**：**"每个因子恰好出现两次"只是这批矩阵上的观测，不是不变量**
  —— `n_i` 取决于该因子的**两个配置条目各自的触发检查是否都失败**，故它**逐记录可变**（本批已出现 1）。
  任何把它写成不变量的表述都是错的（**门禁⓪ 只观测、不断言**，正是因为这个量不是恒定的）。
  **后果（修复前）**：`edgefactor.Params` 的参数空间**是因子级的**（`Factors`（`factorWeights` 按归一 ID 建 map、同名时内置胜出）、`Vectors[id]`、`Coupling[i][j]`、离线 `-factors` 全部只认因子 ID），而合成层吃的是**条目级**列表 ⇒ 主效应项 `Σ a_i[d]` 计 **n_i** 次（S1-apparmor 实测 `L[attack_surface]` **0.162 vs 每因子一次 0.081 = 恰好 2 倍**）、耦合项按**条目对**计 **n_i·n_j** 次（实测 0.00113400 vs 单次 0.00028350 = **恰好 4 倍**；`Synthesize` 的耦合循环只跳过 `from.id == to.id`）。**2 : 4 的比例畸变无法被 λ 重新标定吸收**（λ 只在 `exp(−λ_d·L_d)` 里，只能吸收统一倍数），而 `Σc_ij a_i a_j / Σa_i` 恰恰是 G/C 候选要估计的对象；又因 `n_i` 逐记录不同（S3-3fa-selinux-apparmor 里 `EF-002FA×1`、`EF-3FA×1`），跨场景的 `L` **不可比**。另有一处分叉：离线 `fit.go:design()` 用 `eff[a.FactorID] = …` 建 map 是一次**未文档化的 last-wins 折叠**，而评分侧（`Synthesize`）**完全不折叠** —— 同一份记录两条路径口径不同。
  **处置（已修，Task 18 落地）**：折叠发生在**「条目 → 因子」的换算层**（唯一实现 `edgefactor.CollapseToFactors`，被 `internal/engine/ssam/activationsFromResults`、`cmd/edgecompare/activationsFromResults`、`cmd/edgecompare/activationsOf` 三处调用）。规则：**每因子保留一项，取最强观测惩罚（`EffectiveFactor` 最小）的那一项，并列取先出现者，输出按规范 ID 升序**。理由：① 对 24/33 条"两条逐字段相同"的记录，`effective_f_i` 只有一个值，折叠**不是选择而是 §3.1 的唯一读法** ⇒ 排除一切"跨条目再做一次算术"的规则（如取乘积 `f²`，那会在毫无争议的记录上改分）；② 冲突情形取最强惩罚与**模型自己的因子级裁定同值**（`factorWeights`：同名自定义项**不覆盖**内置权重 ⇒ `Factors["EF-002FA"] = 0.70`）；③ 单调（更强证据只会加重惩罚，P2 的方向）；④ 单条目输入**逐位不变**。
  **边界（不得误修）**：链、配置、`ConfigToEdgeFactors` 与 **legacy（M0）** 一律**不动** —— 链的重复是**如实观测**（`internal/edgeexp` 与里程碑 B 计划书**明文禁止**任何消费方按因子 ID 去重），而 **M0 的在线/离线评分正是逐条目相乘**（P4；`engineEdgeFactors` 产出的列表**不得**折叠）。两条反向钉子：`TestLegacyCandidateConsumesEveryChainEntry`、`TestChainDuplicateEntriesDoNotChangeCandidateScore`。
  **影响面与重跑**：**记录本体与在线评分未被污染**（本批在线用 `m0-baseline.ini` = `model = legacy`，从不调用被修复的换算函数）⇒ **不需要重采**；受影响的只有**离线 V/G/C 候选分数**，对既有 JSONL 重跑 `edgecompare`（分钟级）即可。实测（仓内 11 条 CT 记录，vector 候选）：67.52 → 67.93、65.90 → 66.94，逐条 `+0.04 … +1.04` 分。
  **残留裁定项（作者裁定前不得静默改动）**：冲突条目（`EF-002FA` 0.70 / 0.85）的**取值规则**取"最强惩罚"；备选是"净乘子"（`effective_f_i = ∏ 条目 eff`）。后者**不是**文档里的语义（会在 24/33 条无争议记录上把 `a_i` 由 `1−f` 改成 `1−f²`），故本任务不取；若裁定改用净乘子，只需改 `collapse.go` 的取值比较一处 + 更新两处期望值。

- **代理真实性**：SELinux/AppArmor 场景为检查失败代理，R 组仅能覆盖 IDS/SIEM/2FA；结论须标注。
- **ACL 标定**：RC-M4 的参数化完成后，其标定需要独立的实验设计（E1–E9 意图跟踪/策略效果），排在本方向 P7 之后。
- **论文影响**：因子相关论述若被更新，需与已提交的 Preprints 版本口径一致（保留 upper bound 限定，不回退数字）。

### 10.3 里程碑 B 实测（2026-09-12，实现与真机冒烟为准）

来源：Task 1–4/3B 的实现 + 多轮独立评审 + 一次真实 WSL2 Containerlab + Caldera 冒烟（3 场景 / 1322s）。**下表只写实测确证的；静态推断已标注。**

- **观察对象必须是"被注入/被攻击的那台机器"（实验设计级阻塞）**：当前采集器评估的是它**自己所在的宿主**，而该宿主上六个因子的触发检查本就全部失败（55 项失败、总分 52.21）⇒ "注入检查失败"是 no-op，冒烟的 `S0-baseline`/`S5-cascade-3fa`/`R-no-ids` 三条记录**除场景名与时间戳外逐字段相同**；按该宿主的自然失败集推算，**25 场景只买到 2 个不同数据点**。更关键的是**标签侧**：注入只发生在采集器**本地**的检查集里，矩阵脚本从不改动被攻击节点的防护 ⇒ `compromised/block_effective/nodes_affected` 恒定 ⇒ **单类别标签**，§2.1 的漏判率/误阻断率/AUC 与 §3.5 的拟合全部退化。处置选项（硬化基线 / 反转设计 / 缩小矩阵）见 `docs/audits/TECHNICAL_DEBT_BACKLOG_2026-09-08.md` §七 C1，**待作者裁定后方可跑全量扫描**。
- **门禁⓪（重复因子条目）实测确证**：出厂 `configs/*.ini` 的 `[edge_factors.custom]` 与内置因子同名 ⇒ 引擎**确实把同一因子乘两次**，链上出现重复 ID（三条冒烟记录均 11 条链 / 6 个 ID，重复对分别带 0.70（内置）与 0.85（custom））。**边界**：`EF-SYNCOOKIE` 的重复**未观测到**（宿主 `tcp_syncookies=1`，该因子未激活）；该结论不适用于**不带** `[edge_factors.custom]` 重复段的配置。
- **`C` 与 `V` 在无时间结构的场景上数值等价**：单条链只有一个 `ts` ⇒ `from.ts.Before(to.ts)` 恒假 ⇒ 耦合项消失、`L_d = Σ a_i[d]`。故 **C 的全部信号只来自顺序注入场景**（本矩阵 7 个 × 重复），其余 18 条是**对照**而非信号；这不是缺陷，但决定了 C 候选的可辨识性。
- **`ts` 基准按记录"全有或全无"**：非顺序场景一律取评估时刻（不混用 harness 注入时刻 —— 混用会造出"没人设计、也没人报告"的顺序），顺序场景才用注入阶段时刻；该基准逐条写进 `meta.ts_source`。顺序记录里"取评估时刻"的条目**不是设计顺序**（注入在前、自然失败在后由环境造成），**不得**当作级联时序证据。
- **离线复算的权重以记录为准**：`observed.effective_weights`（引擎**归一后**的生效权重，键集 = 参与聚合的域）是权威输入；`-weights` 只在记录**未带**该字段时生效（历史数据集/手写夹具），此路径与引入该字段之前逐位一致。§5.1 前提 2 至此从"期望"变为**实现事实**。
- **`-factors` 必须覆盖链上出现的每一个因子，包括 `EF-3FA`**：四份实验模板都声明了 `vector.EF-3FA`，故把它当**普通因子**处理（`EF-3FA=0.82`）即可；**省略**它会让离线工具**静默丢弃**该因子的惩罚（正是覆盖校验存在的意义），并砍掉 C 候选唯一的级联边 `EF-3FA→EF-002FA`。
- **报告与论文的措辞禁令**：n=3 时 `pearson` 对常量输入返回 0、`kendall` 跳过并列对、`AUC=0` 属单类别退化 ⇒ **不得**把排序层/数值层指标当作"某候选更好"的证据；诚实表述是"`chain ≠ vector` 恰好出现在有时间结构的地方"。另：`time_to_compromise_s` 缺失曾让 `severityOf` 给出**最大**加成（`1000/(0+1)`），采集器现已要求该字段必填。
- **总分可 >100**：`threat_coeff` 无上界（与引擎一致），`round2(0.5·base + 30·E + 20·T)` 在 `T=1.4, base=100, E=1.0` 时得 108，而 `ssam-lib/ir.go` 的 `final_score ∈ [0,100]` 是另一层约束 ⇒ 论文表格出现 >100 的分数**必须加脚注**。
- **阈值敏感性（含一处实测纠正）**：记录里的 `threshold` 来自部署配置（冒烟为 80.0，全部记录判"不可接受"）。**实测纠正**：该退化并**不**表现为"误阻断率 → 100 %" —— 冒烟三条记录**全部** `compromised=true`（**没有负类** ⇒ `fp` 计数恒为 0），故漏判率与误阻断率**都**是 0.000，退化表现为**"本次比较无区分力：未选模"**。**措辞精确化（配置清理评审 Q6/M6，已核 `cmd/edgecompare/metrics.go:281-283`）**：不得写成"误阻断率分母为零" —— 两个率都是 `计数 / N`（`N` = 记录数，恒不为零），0.000 是**良定义**值；真正的问题是**该指标在这份数据上没有信息量**（无负类样本 ⇒ `fp` 恒为 0）。更值得注意的是：在该数据集上按漏判率排序会**奖励"全都阻断"**的策略（`-threshold 60` 的敏感性行给出 legacy 漏判率 0、其余候选 1.000 ⇒ 工具"选定 legacy"）—— 这正是**缺少负类样本**时的退化最优，也是"标签必须有方差"的又一实证理由。`cmd/edgecompare -threshold` 提供**显式**敏感性覆盖（`0` = 用记录自带；>0 覆盖并在报告头/stderr 标注为敏感性值），**不得**把它当默认路径。


### 10.4 基质口径：基线活跃集的「**按基质如实声明**」（Task 7，用户 2026-10-10 裁定）

**一句话**：链上的因子集 = **这台基质上自然活跃的因子** ∪ **场景注入的因子**。前一半**按基质**声明，
后一半来自场景。相等断言的右边因此是

> **声明面 = 基线活跃集 ∪ 注入集**

#### 结论一：dl360gen9 的 **PVE CT** 基质的基线活跃集 = `{EF-SELINUX, EF-APPARMOR}`

**为什么（结构性的，不是这一台机器的偶然）**：

- `OT-005`（强制执行的可见性）在 PVE CT 里**不可观测** —— LXC 的 apparmor 命名空间不向容器
  暴露 profile：`aa-status` 报 `Failed to get profiles: 2`、可见策略数 0。**装包解决不了**。
- 而附录 B 的触发表里 `trigger.EF-SELINUX` 与 `trigger.EF-APPARMOR` **都指向 `OT-005`**
  ⇒ 只要 `OT-005` 在这台基质上必然失败，这两个因子就**恒在链上**，**与场景无关**。

**处置（用户裁定）**：**如实声明**，而不是去改 `internal/checks` 让 `OT-005` 在 CT 里"可测"
—— 那条路要动**底座文件**，会影响 main/ARC 的一致性审计，用户已明确否决。

**机制的落点**：`lunwen/clab-lab/scripts/edge_lab.sh` 的**基质层**在 `pve` 下自动设好并**导出**
`EDGEEXP_BASELINE_FACTORS=EF-SELINUX,EF-APPARMOR` 与
`EDGEEXP_BASELINE_FACTORS_SOURCE=<为什么>`；`clab` / `lxd` **不设、不导出**（一个字节不动）。
放在基质层的理由：一条"基线活跃集"说的是"**这个基质**能不能观测到某条检查"，而
"当前是哪一种基质"只有基质层知道 —— 放别处就会出现第二份真源。
**声明本身零新增机制**（`edge_attack.sh` 的 `EDGEEXP_BASELINE_FACTORS*` 是 Task 4D Step 4-B3 就做好的）。

> ⚠️ **适用范围**：本条只在 **PVE CT（LXC）基质**上成立（成因：`OT-005` 在 LXC 里结构性不可观测）。
> 它**不是全局结论**：VM（`qemu`）基质上**没有可推导的默认值**，实测终值是 `B = {EF-NO-IDS}`
> （§10.4B 结论二与现行「结论四」后的补注）。两套基线活跃集**不可混用** —— 记录侧的判据是
> `meta.observation_target` 里的 `substrate=`。

#### 结论二：`OT-005` / `KS-012` 记为「**此基质不可观测**」

> ⚠️ **适用范围**：本节能且仅能说明 **PVE CT（LXC）基质**。−30 的现行完整口径是「**取数权限 × 基质**」
> 耦合（见 §10.4B 现行「结论四」）：**−30 由取数权限产生，在 CT 上被基质形态掩盖**；VM 上的"不可观测"
> 只由**非 root 取数**造成（权限对齐后 `OT-005`/`KS-012` 都通过）。缺这个限定就会把本节读成 −30 的完整解释。

- 它们是**测量伪影**的来源：分数侧那个固定 **−30** 在**所有**记录上是**常量** ⇒
  它**不产生方差**（不影响耦合分析的可辨识性），但**污染绝对分数**。
  **拿该基质的绝对分与其他基质/历史数据直接比较是错的。**
- **措辞禁令**（论文、报告、图注、结论一律适用）：
  **不得**写成"该机器真的没有 AppArmor / SELinux"，**不得**写成"硬化提升了安全分"
  （或任何方向相反的暗示）。正确表述是
  「**该控制在此基质上不可观测，其判据的惩罚是测量伪影**」。
- **待办的机制（不阻塞扫描）**：把它们也记进 `meta.skipped_checks`。现状是
  `meta.skipped_checks` **只由采集器按真实的 skip 产生**（实测：`AS-012` 走的就是它，
  原因是"读不了 `/etc/shadow`"），而 `OT-005` 是 **fail 不是 skip** ——
  要让它以"不可观测"的身份进那一栏，需要新机制，**不在 Task 7 范围内**。

#### 结论三：R 组三个场景在此基质上**结构性不可达**

> ⚠️ **适用范围**：本结论的**适用基质 = CT**。VM（`qemu`）基质上的**根因不同**：`prepare` 装齐六控制
> 而 R 组语义要求"目标机上真的缺该防护"，且 `R-no-ids` 实测可跑（单独跑通、不占批次）
> ⇒ VM 上的根因与逐条实测见 §10.4B 结论六第 4 条。**不得**把本节的根因照搬到 VM 上。

`R-no-2fa` / `R-no-ids` / `R-no-siem` 的语义是"目标机上**真的**缺该控制"，而
`edge_target_prepare.sh`（复位的一部分）**幂等地**把六个控制装齐
（`suricata` / `aide` / 三个 PAM 包），`edge_attack.sh` 的 `real_missing` 探针会因此**响亮失败**。
实测原文：

```
edge_attack: R 组的真实缺失**不成立**：ids 的防护在节点 asc-tgt-c2 上仍然在位
  （探针对应 EF-NO-IDS 的触发检查条件）—— 真实缺失对照不可得，整轮失败；
  不得用注入失败顶上（那就是伪造 ground truth 的对照面）。
```

⇒ **记为不可达，不得伪造**。要让它可达必须**改实验定义**（换一种对照形态），
那是设计决策，不是本口径能定的。

#### 结论三·补：**取数用户是测量前提**（Task 16 注册，用户 2026-10-15 已裁定）

`pct exec` 在容器里**天生以 root 执行**，qemu 基质 `ssh` 登录的是 cloud-init 建的 `asc`
⇒ 「这条记录采自哪种基质」这句话**只说了半件事**，另一半是「**谁在读**」。
实测（`task-16-measure-semantics-report.md` §2 端到端复跑）：**同一份二进制、同一台 VM**，
把取数用户从 `asc` 换成 root 等价，80 条检查里 **10 条翻转**，两条决定 `B` 的
（`OT-005` / `KS-012`）**恰好在内** ⇒ 同样的机器会给出**不同的 `B`**。

⇒ **硬口径**：qemu 基质的取数**必须**与 `pct exec` 等价（root 等价，经客人侧 NOPASSWD sudo）；
`nodescen`/qemu 侧拿不到 root 等价权限时**响亮失败**，**不降级**成 `asc` 去取数。

#### 结论四：四条可检验的口径

1. **声明面 = 基线活跃集 ∪ 注入集**（**相等**，不是包含）—— 由 `edge_collect.sh` 的
   **因子集相等断言**执行；三条子判据分开报：注入集缺席 = **因子塌缩**；
   基线集缺席 = **声明与现实不符**；多出来的因子 = **还有别的检查在自然失败而无人声明**。
2. 基线集**按基质声明**，**来源必须与它一起写出来**（`expected_baseline_factors_source`）。
   非空声明却缺来源时，基质层**响亮警告** —— 否则产物里的来源会退化成
   `未声明（默认空基线集）`，与**真的**空基线集在数据上无法区分
   （"声明了但没写为什么"与"没声明"必须能分开读）。
3. 断言失败时**整轮失败并回滚该条记录**（`rejected-<场景>.jsonl` 留档）——
   **不是**安静地写一条脏记录。故"忘记声明"的形态本来就是**响亮**的。
4. 跑批**前**先编出 `build/edgescen`；否则矩阵只打一行警告就把 25 个场景
   **全规划成 `recon_playbook policy=1`**（连 S2 也是）—— 那是**安静的错误**，必须先堵。

**场景 × 可达性普查表（25 行，独立复核）见 附录 D。**

#### 结论五：**已登记的「既有口径缺陷」清单**（Task 16 登记；**本任务不改**）

这一节登记的是**已知会失真、但改动属于「判据语义变更」**的口径问题。登记它们的目的：
让"这条口径是**有意**保留的、不是没人发现"在数据与文档里都能读出来。
**任何一条要改，都要重跑所有既有数据（CT 数据集与 VM 数据集各自重跑），另开任务。**

| # | 口径 | 失真形态（**双向**，不是"少算"） | 为什么不在这里改 |
|---|---|---|---|
| 1 | **「跳过（skipped）的检查算通过」** | 非 root 取数下实测 **6 条假通过**（`detail = "skipped — requires root privileges"` 而 `passed=true`：`AC-002`/`AS-012`/`BC-006`/`OT-004`/`OT-008`/`OT-020`）+ **4 条假失败**（`KS-010`/`KS-012`/`OT-005`/`AS-004`）⇒ **两个方向同时失真** | 改它 = 改 `internal/checks/**` 的**判据语义**（红线：Task 16 只对齐**权限**，不动**判据**）。且改完既有 CT/VM 记录全部不可比 |
| 2 | **`meta.skipped_checks` 只由采集器按真实 skip 产生** | `OT-005` 在这台基质上恒失败**且**是 fail 而非 skip ⇒ 它**不会**出现在 `skipped_checks` 里；"不可观测"与"真的没有"在数据上**不可区分** | 同上（要新机制） |

> **对 #1 的实际缓解**（Task 16 已落地）：把 qemu 基质的取数用户对齐成 root 等价 ⇒
> 「跳过算通过」这条口径在 qemu 基质上**不再被触发**（根因被移走了），
> 但**口径本身仍在**（别的非 root 取数路径照样会踩），故保留登记。

### 10.4B `qemu` 基质：VM 成为方向② 的**生产**基质（Task 13，用户 2026-10-15 两条裁定）

#### 结论零（基质选择判据，用户原话的直接落地）

| 基质 | 定位 | 用途 |
|---|---|---|
| **PVE CT（LXC）** | **快速验证 / 轻量模拟 / 临时短期任务** | 探路、单点验证、看协议通不通、试脚本能不能跑 |
| **QEMU/KVM VM（`qemu`）** | **完整环境 ⇒ 数据准确性 + 环境可靠性** | **长线任务（全量批次、重复轴）、中重型拓扑模拟、要进论文的重要任务** |

> 用户原话：「CT 的作用本来就是快速验证和轻量模拟，应该作为临时短期任务的选择。
> 长线和中重型拓扑模拟和重要任务本来就应该交给拥有完整环境的 VM 来保证数据的准确性
> 和环境可靠性。」以及「如果 CT 用起来难受或者受限太多直接用 VM，不然我为啥会选择
> PVE 作为系统」。

⇒ **全量批次在 VM 上跑，不在 CT 上跑**；`CT 904`（`asc-tgt-c2`）**保留不动** ——
它是"快速验证"那一格的现成靶机。

#### 结论一：`qemu` 的原语（与前三套基质的**结构性**差别）

| 原语 | docker / lxd / pve | **qemu（VM）** |
|---|---|---|
| 送文件 | `docker cp` / `lxc file push` / `pct push --perms 755` | **`scp -O <本地> <主机>:<路径>` + `ssh … chmod 0755 <路径>`** |
| 目标内执行 | `docker exec -e` / `lxc exec --env` / `pct exec -- env` | **`ssh <连接参数> -- <主机> env EDGESCEN_NODE_NONCE=<nonce> <二进制> -emit-checks`** |
| 实例视图 | `docker inspect` / `lxc info` / `pct status`·`pct config` | **`qm status` / `qm config`**（`qm` 与 `ssh` 是**两个不同的二进制**） |
| 节点标识 | 容器名 / 实例名 / **vmid（只认数字）** | **vmid 或名字**（`qm` 两种标识都收） |
| 建/毁 | `lab_up`/`lab_down` 对 lxd/pve 响亮失败 | **同样响亮失败，但理由不同**：建机/清机有**单一来源** `edge_vm_provision.sh` |

**VM 为什么不能塞进 `pve:` 前缀**：VM 是**另一种基质**而不是"pve 的一个变体"——
两者的**定位**不同（结论零），且**基线活跃集随基质变**（结论二）。
把 VM 塞进 `pve:` 就等于让"这条记录采自哪种基质"在数据上消失，而那正是后面所有结论的前提。
⇒ 记录里必须印出 `substrate=qemu`（与 `substrate=pve` / `substrate=lxd` 同一形状）。

**唯一一处"不能逐项对应"的地方（结构性，不是实现选择）**：前三者都有一个"把 argv
原样交给客人"的 CLI，而 **`ssh` 没有** —— 它把 `-- <主机>` 之后的**所有格**拼成一个
字符串，交给**客人侧的登录 shell** 再分词。故 `lab_target_exec` 在 qemu 下把 argv
**显式**重建成一条命令串（`"$*"`）交给客人侧 `bash -c` 当一整段脚本执行；
需要"格边界精确保真"的调用点在 qemu 基质上要自己保证引号。

**硬不变量逐条不破例**：nonce **只经环境变量**下发、**绝不进 argv**（客人侧二进制的
argv 恰好是 `[-emit-checks]`）；SSH 目标与私钥走环境变量（私钥给的是**路径**而不是
内容）；**不接受**任何"SSH 选项串"环境变量（否则 `-o ProxyCommand=…` 能把取数目标
悄悄改到别处）；私钥路径不可读 ⇒ 响亮失败，**不退回** ssh 自己的默认钥匙。

#### 结论二：**基线活跃集随基质变化**（本任务最硬的一条口径）

- **pve（LXC）**：`B = {EF-SELINUX, EF-APPARMOR}` 是**推导**出来的 ——
  LXC 的 apparmor 命名空间不向容器暴露 profile ⇒ `OT-005` 结构性不可观测 ⇒
  那两个因子恒在链上。该推导只依赖"这是 LXC"这一件事，**故在基质层写死是对的**。
- **qemu（VM）**：**没有**可推导的默认值。LSM 是否真的 enforcing、`OT-005` 过不过、
  有几个 profile 可见，**全都取决于这一批 VM 的实际配置**（镜像、cloud-init 装的包、
  有没有加载自定义 profile）。把它写死成 `∅` 或 `{EF-APPARMOR}` 等于**把一次实测结果
  当成前提**；而实测结果会随镜像与配置变 —— 那时脚本仍然"有个基线集"，只是它已与
  事实不符，且**不会有任何症状**（链只是安静地多算/少算一个因子）。
  ⇒ `edge_lab.sh` 的 qemu 分支**不设默认值**，并要求跑批前**显式**给
  `EDGEEXP_BASELINE_FACTORS` + `EDGEEXP_BASELINE_FACTORS_SOURCE`（空集就写空串）。

#### 结论三：**两套基质的数据不可混用**（硬口径）

- 既有 CT 数据集（Task 9 的 `records-dl360-pve-20261013.jsonl` 等）是**另一种基质上的
  数据**：**只标"CT 基质"、单独陈述**；**禁止与 VM 数据混算、互相解释、或合并进同一个拟合**。
- 判据是机器可读的：`meta.observation_target` 里的 `substrate=` 是**唯一**凭据。
  任何 `substrate=pve` / `substrate=lxd` / 裸名字的记录都**不是** VM 基质的数据。
- **VM 基质的数据集（已入库）**：`lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl`
  （**33 条**，sha256 `82d37eade414327ba3bdaee8d96d419e84eba64eba80264947f1807531f5b468`）+
  `run-20261015-3482605.json` + `run.d-qemu-20261016/**`；
  **CT 基质的数据集**：`records-dl360-pve-20261013.jsonl`（11 条）。**两者不得合并**。
- ⚠️ **"两套基质"之外还有第二维**：**取数权限**（结论四）。同一台 VM、同一份二进制，
  `asc` 与 root 两种取数下的**失败检查条数**与**基线活跃集**都可能不同
  ⇒ 比较"失败条数"这类量之前，先确认两边的取数权限相同。

#### 结论四·已被推翻（仅存档）：−30 是 **LXC 基质上的测量伪影；VM 基质上不存在**（Task 13 实测，Task 15 推翻）

> ⛔ **本节标题里的那条结论已被推翻，原文保留仅为留痕** —— **不要引用它**。（标题原名就是「结论四」，
> 与紧随其后的**现行**「结论四」同名 ⇒ 2026-10-19 的文档整理给这一节加了「·已被推翻（仅存档）」后缀，
> 消除"见 §10.4B 结论四"这个引用的歧义。**两节结论相反，引用时必须写清是哪一个**。）
> 它依据的是下面这张表里 VM 侧的**手工 root 探针**（即"谁在跑 = root"），而 Task 15 的真机端到端取数
> 证明**只有 root 才成立**。正确的结论在**紧随其后的那一节**（标题也以「结论四」开头，但带「**取数权限**」）。
> 这条留痕本身就是一条教训：**"某台机器上的读数"必须与"谁在读"一起写，否则它会被当成设备的属性。**

此前所有 targeted 场景的链上都挂着一个**常量 −30** 惩罚（`OT-005` −15 + `KS-012` −15），
当时的定性是"测量伪影"。**Task 13 在真 VM 上把它证完了**（原始输出见
`task-13-vm-substrate-report.md` §2）：

| 项 | CT 904（`asc-tgt-c2`，LXC） | **VM `asc-vm910`（QEMU/KVM，Ubuntu 24.04 noble cloud image）** |
|---|---|---|
| `aa-status` | **不存在/不可用**（`ls /sys/kernel/security/apparmor/` → `No such file or directory`；根因就是 `Failed to get profiles: 2`） | **`rc=0`，`117 profiles are loaded`，`23 profiles are in enforce mode`** |
| `/sys/kernel/security/lsm` | 容器内不可见 | **`lockdown,capability,landlock,yama,apparmor`** |
| 自定义 LSM 策略能 enforce 吗 | 只有宿主层的 `lxc.apparmor.raw` | **能**：`apparmor_parser -r` 加载自写 profile，`aa-exec -p … -- cat /etc/shadow` **被拦住**（`Permission denied`，rc=1），而允许的 `/etc/passwd` rc=0 |
| `OT-005` 判据（`getenforce` 失败 ⇒ 看 `aa-status` 含 `profiles are loaded`） | **恒失败** | **满足（通过）** |
| `KS-012` 判据（至少一个 LSM enforcing） | **取不到** | **满足** → `AppArmor(23 profiles)` |
| 工具链（`suricata`/`aide`/三个 PAM 包） | 要"宿主下载闭包 + 送进去 + `dpkg --configure -a`"的绕法 | **`apt-get install` 直接 rc=0 装成**（VM 有真外网 + 真 dpkg） |
| `systemd` | 残缺 | **`systemctl is-system-running` = `running`**；`auditd` `active` + `enabled` |
| SELinux | 不可用 | **同样不可用**（Ubuntu 默认不装；`EF-SELINUX` 的 trigger 指向 `OT-005`，已由 AppArmor 判过） |

**⚠️ 这张表的测量条件必须与结论一起读**（Task 16 勘误）：
VM 侧那两行（`OT-005` 判据满足 / `KS-012` 判据满足）**依据的是「手工以 root 跑判据谓词」**
（`sudo aa-status` / `sudo` 下的等价动作）—— **不是**真机采集器产出的记录。
即：**谁在跑 = root，权限 = root 等价，手段 = 手工探针**。
下一条（结论四）就是这条测量条件的**直接后果**。

#### 结论四：−30 是「**取数权限**」与「**基质**」耦合出来的伪影（Task 15 推翻 + Task 16 定稿）

> **这是本小节内**两个**同名「结论四」中的第二个（现行的那个）**：前一个已改名为
> 「**结论四·已被推翻（仅存档）**」，两节结论相反 ⇒ 任何"见 §10.4B 结论四"的引用**必须写清是哪一个**。

此前所有 targeted 场景的链上都挂着一个**常量 −30** 惩罚（`OT-005` −15 + `KS-012` −15）。
Task 13 把它写成「**在 LXC 基质上是测量伪影；VM 基质上不存在**」，依据是上表那两行
**手工 root 探针**。**Task 15 的真机端到端取数（`edgescen -target qemu:910`）把这条措辞推翻了**：

| 条件（**同一份二进制**） | `OT-005` | `KS-012` | 由 `trigger` 推出的 `B` | 取数用户 / 权限 | 测量手段 |
|---|---|---|---|---|---|
| CT 904（`asc-tgt-c2`，LXC） | false（−15） | false（−15） | `{EF-SELINUX, EF-APPARMOR}` | **root**（`pct exec` 天生 root） | 真机采集器 |
| VM 910（qemu 基质**原样**：登录 `asc`） | **false（−15）** | **false（−15）** | `{EF-SELINUX, EF-APPARMOR}`（与 CT **逐项相同**） | **`asc`（非 root）** | 真机采集器 |
| VM 910（手工 root 探针） | true | true | **未按 `trigger` 推导**（探针只测了 `OT-005`/`KS-012`，`B` 根本没算） | **root** | **手工探针**（非记录） |
| VM 910（**权限对齐后**，Task 16 端到端，**未跑 `prepare`** 的裸 VM） | **true** | **true** | **`{EF-NO-IDS, EF-NO-SIEM}`** | **root 等价**（客人侧 NOPASSWD sudo） | 真机采集器 |
| VM 910（**权限对齐 + `prepare` 装齐六控制**，Task 17 全量批次） | **true** | **true** | **`{EF-NO-IDS}`** | **root 等价** | 真机采集器 |

> ⚠️ **最后两行的差别必须说清（Task 19 补齐；数值由 Task 25 按一手证据订正 —— 原先两处都写作 `{}`）**：
> Task 16 那台是**没跑 `edge_target_prepare.sh` 的裸 VM** ⇒ `B = {EF-NO-IDS, EF-NO-SIEM}`
> （`RS-006`/`RS-007` 都失败；依据是 Task 16 报告的对齐后推导段 —— 46 条自然失败里能推出因子的只有
> `RS-006`→`EF-NO-IDS`、`RS-007`→`EF-NO-SIEM`）。**一次真实跑批会先跑 `prepare`**
> （装齐六个控制 + 写 `aide` 告警面）⇒ `RS-007` 从失败变**通过**（`EF-NO-SIEM` 退出链），
> 而 `RS-006` 仍**失败**（`suricata.service=failed`、无 IDS 进程）
> ⇒ **VM 上 `B` 的实测终值是 `{EF-NO-IDS}`**（详见 §10.4B 结论四之后的补注与审计归档 B.3）。
> **两行都对**，但引用时必须带上"靶机是不是装齐控制的"这个条件。

**⇒ 口径订正（Task 16 定稿，措辞按此）**：

> **−30 是「取数权限」与「基质」耦合出来的伪影。**
> 它在 CT 上因 `pct exec` **天生以 root 执行**而"看不见"，
> 在 VM 上因基质默认登录用户**不是 root**而**原样复现**。
> **对齐取数权限之后，VM 上那一对 `OT-005`/`KS-012` 都通过、那个 −30 消失**——
> 但那**不是基质的功劳，是权限的功劳**。
>
> ⚠️ **"−30 消失" ≠ "`B` 是空集"**（**这一句很容易被读反，Task 17 实测钉死**）：
> `B` 是**链上事实活跃的因子集**，它由**装了什么控制**决定，与 −30 无关。
> 对齐权限后 VM 上的实测值是 **`B = {EF-NO-IDS}`**（`RS-006` 失败）。
> **"空集 `{}`"在任何真机记录里从未出现过**：未跑 `prepare` 的裸 VM 上是 `{EF-NO-IDS, EF-NO-SIEM}`
> （Task 16，权限已对齐、真机采集器），跑过 `prepare` 的真实跑批是 `{EF-NO-IDS}`（Task 17，33 条）。

**同一条二进制、同一台 VM、只换取数用户** ⇒ 80 条检查里 **10 条翻转，且双向**：

* **6 条在 `asc` 下 `skipped — requires root privileges` 却被算作通过**
  （`AC-002`/`AS-012`/`BC-006`/`OT-004`/`OT-008`/`OT-020`）—— root 下才真正被判失败；
* **4 条（含 `OT-005`/`KS-012`/`KS-010`）在 `asc` 下假失败**、root 下通过。

⇒ 记录里 `detail` 写的是「SELinux和AppArmor均未检测到」——**听起来像 VM 真的没装**
（实测 VM 里 `aa-status` rc=0、117 profiles、23 enforce，自写 profile 真能 enforce 并拦住
`/etc/shadow` 的读）。**故`B` 的两个口径必须分开写，且每条记录都要能读出"谁在读"。**

**口径的落点（Task 16 代码）**：

* qemu 基质的取数命令变成
  `ssh <连接参数> -- <主机> sudo -n env EDGESCEN_NODE_NONCE=<nonce> /tmp/asscor-edgescen -emit-checks`
  —— **客人侧二进制的 argv 仍然恰好是 `[-emit-checks]`**（nonce 只经环境变量），
  硬不变量不破例；
* 拿不到 root 等价权限（客人侧没有 `sudo -n`、或 sudoers 要口令、或配置文件是只读的）
  ⇒ **响亮失败并给出修法**，**绝不**降级成 `asc` 去取数；
* 建机侧（`edge_vm_provision.sh`）在每次建机后**实测** `id -u` 与 `sudo -n id -u`
  并把结果打印出来 —— 那就是"权限等价"的证据。

**保留 Task 13 仍然成立的部分**（这些是 VM 相对 LXC 的**真实优势**，**与权限无关**）：

* **AppArmor 在 VM 上真能 enforce**：自写 profile 能 `apparmor_parser -r` 加载、
  `aa-exec -p <profile> -- cat /etc/shadow` **被拦住**（rc=1 + `Permission denied`），
  而允许的 `/etc/passwd` rc=0 ⇒ 排除"什么都读不到"这种假阳性；该 profile 在 `aa-status` 里可见；
* **装包不需要 CT 那套绕法**：`suricata`/`aide`/三个 PAM 包**直接 `apt-get install` rc=0**
  （VM 有真外网 + 真 dpkg；CT 上要"宿主下载闭包 + 送进去 + `dpkg --configure -a`"）；
* **`systemctl` 正常**（`is-system-running` = `running`）、**`auditd` active + enabled**
  （CT 里 systemd 残缺，auditd 基本起不来）；
* **SELinux 不可用与基质无关**（Ubuntu 默认不装；`EF-SELINUX` 的 trigger 指向 `OT-005`）。

**「基质选择判据」那一节（结论零）逐字保留**，不受本勘误影响：
CT = 快速验证 / 轻量 / 临时；VM = 长线 / 中重型 / 重要任务。

**跨基质的措辞禁令（Task 16 追加）**：**不得**再用「VM 基质上不存在 −30」这种把
权限与基质混在一起的写法；正确表述是「**−30 由取数权限产生，在 CT 上被基质形态掩盖**」。
两套数据仍**禁止混算**（结论三），且现在多了一条理由：**它们的取数权限也未必相同**。

#### 结论五：网络拓扑是 VM 基质的**已知约束**（Task 13 实测，Task 15 已定案）

实测（三个视角同一时刻，见 Task 13 报告 §2.6）：

- **VM 挂 `vmbr1`**：外网**通**（`cloud-images` rc=200）、宿主 `vmbr1` 侧**通**、
  **到 C2（`192.168.30.2`）不通**（逐个端口试过 8888/80/443/8000/8080/5000/8443，全部不可连）。
- **CT 904（本就在 `vmbr0` 同网段 `192.168.30.65/24`）到 C2:8888 也**不通****；
  而**宿主自己**在两个端口上都能连（`ss` 实测 Caldera 监听 `192.168.30.2` 的 8022/7010/7012/8888）。
- 宿主在 `vmbr0` 上**没有**任何防火墙规则（`iptables -S` 只有三条 ACCEPT 默认策略、
  `nft list ruleset` 为空）⇒ 最可能是 **bridge 同段回程 / hairpin** 或**上游 S5720 的转发策略**。

⇒ **跑批前必须定案**：VM 基质若要和 Caldera 通信，要么把 VM 挂到 C2 所在的桥并解决这一格，
要么把 C2 挪到 `vmbr1`。**两套基质的这一格都要重测**（不能假设"CT 能通 VM 就能通"）。

**✅ Task 15 已定案（结论已收口，两句话）**：

1. Task 13 报的「VM 到 C2 不通」**结论本身是真的**，但**根因不是"探了错的端点"** ——
   是真的**缺一条到 `192.168.30.0/24` 的路**。**默认网关有两行、且两个值本来就不是同一个**
   （Task 25 订正：这里原先把它们压成一句并判「任务书里写的 `192.168.1.2` 要订正」，
   **那个结论不成立** —— `.2` 是宿主的网关，不是笔误）：
   **客人** `default via 192.168.1.1 dev ens18`（`proto dhcp`，`src` 在客人网段内）、
   **宿主** `default via 192.168.1.2 dev vmbr1`（`proto dhcp`）；宿主在 `vmbr1` 上是
   **`192.168.1.242`**。⇒ **纪律：任何脚本不得写死默认网关**（两个值都来自 DHCP、会变）；
   `/32` 主机路由的下一跳取"**宿主在客人网段内的地址**"并**动态取**。详见白皮书 §3.7（乙）。
   两条修法都实测可用：
   * **VM 挂 `vmbr0`** ⇒ 与 C2 同网段**直连可达**，不需要任何静态路由（`ping` 0% 丢包、
     `TCP+HTTP` 拿到 `HTTP/1.0 401 Unauthorized`）；
   * **VM 挂 `vmbr1` + 一条静态路由** `ip route add 192.168.30.0/24 via 192.168.1.242` ⇒
     立刻打通（删掉后又变回不通 ⇒ 差异确实由那条路由造成）。
2. ⚠️ 任务书说「宿主已开 `ip_forward`」——**实测 `net.ipv4.ip_forward = 0`**。
   上面那条路由之所以仍然成立，是因为 `192.168.30.2` **就是宿主自己在 `vmbr0` 上的地址**
   ⇒ 报文到宿主是**本机投递**，不需要转发。若将来要经宿主去到**别的** `192.168.30.x` 主机，
   `ip_forward=0` 就会成为真问题（见 Task 15 报告 concern 4）。

⇒ **全量批次的口径（v1.1 按实际实现订正）**：**实际采用的是「VM 挂 `vmbr1` + 一条 `/32` 主机路由」**，
而不是"挂 `vmbr0` 直连"。理由（写进 `edge_target_prepare.sh` 的代码注释里）：
**`/32` 恰好覆盖"我们要去的那台机器"，不替操作者做"`192.168.30.0/24` 整段该怎么走"的决定**
（那是网络侧的事，而本项目的纪律是不碰任何网络设备）。
落地细节：路由由 `edge_target_prepare.sh` 在**客人侧**用 `ip route replace <C2_HOST>/32 via <宿主在客人网段的地址> dev <iface>` **幂等**添加
（必须 `replace` 而不是 `add`：后者第二次报 `File exists`，而那条错会以**"复位失败"**的形态出现），
并且随后**自证**——在客人内问到 `http://<pve-host-ip>:8888/api/v2/abilities` 得 **200** 才继续。
⚠️ 这条路由是**客人侧的一次性实验状态**，随 VM 销毁而消失（**不在宿主上留任何网络改动**）。
⇒ 白皮书的 §3.7 记录的就是这条通路的实测形态。

#### 结论六：依赖 **CT 数据** 的既有结论 —— **VM 基质上已复核（Task 17 全量批次，33 条）**

> **本节在 Task 19 从"待复核"更新为"已复核"**：Task 13 当时**没跑**端到端 targeted 批次，
> 故下面四条都被标成"待复核"。**Task 17 已在 VM 基质上跑完全量批次**（22 场景 / 33 实例，
> 数据集 `records-dl360-qemu-20261016.jsonl`）⇒ 逐条给出复核结果。
> **判据**：`lunwen/clab-lab/data/edgefactors/records-dl360-qemu-20261016.jsonl`（33 条）。

1. **"零标签方差 ⇒ 只能加策略臂"**（Task 9：11/11 记录 `basis=targeted_ttp` 且全部 `compromised=True`）
   ⇒ ✅ **在 VM 上已被策略臂解决**：11 个 targeted 场景 × 2 条臂 = **22 条记录**，
   `meta.policy_on="0"` 的 **11/11 全部 `compromised=True`**、`="1"` 的 **11/11 全部 `False`**，
   **零例外**。⇒ 决策层指标在 VM 批次上**有正负两类标签**（这也是"零方差"问题的收口）。
   ⚠️ 但注意下面第 2 条：**两类标签只存在于 `ground_truth` 里，分数侧与链侧都区分不开两条臂。**
2. **"两臂链读数相同"**（Task 10 的 `POLICY_ON=0/1` 两臂）⇒ ✅ **在 VM 上逐项复核成立，并且更强**：
   33 条记录的实测（忽略 `ts`）——**11/11 个 targeted 场景**的两臂在
   `edge_factor_chain`（因子/触发检查/c_trigger/effective_factor）、`checks[]`、`domain_scores`、
   `final_score` 上**逐项相同**，**唯一不同的是 ground truth 标签**（`compromised`/`block_effective`
   互为反面）。⇒ **这条 limitation 换基质后依然成立，论文里不许撤**（见 §10.4B 结论四与本条）。
   **机器判据（Task 20 Step 3）**：`lunwen/clab-lab/tests/test-arm-limitation.sh` —— 9 条断言直接读已入库的
   33 条数据集（标签随臂翻转 / 去重后链序列相同 / `final_score` 相同 + 3 条加固），已接进 `run-all.sh`。
   **它变红 = 提示去更新文档**（limitation 不再成立 ⇒ 论点要重写），不是叫你把断言放松。
3. **附录 D 的"场景 × 可达因子普查表"** —— 表的**基质标注是 PVE CT**；`OT-005`/`KS-012` 两行的可达性
   在 VM 基质上**按结论四已变**（**前提是取数权限已对齐**）⇒ ✅ **已测出 VM 的实际取值**：
   `OT-005`/`KS-012` **通过**、`RS-006` **失败**、`RS-007` **通过** ⇒ **VM 上的 `B = {EF-NO-IDS}`**。
   该表**仍然不得**直接搬到 VM 基质上使用（`B` 不同 ⇒ 声明面不同 ⇒ 可达性判定的输入不同）。
4. **`R` 组三个场景"结构性不可达"**（Task 7）—— ✅ **复核后要改根因，不能照抄**：
   Task 13 当时把根因写成"`EF-SELINUX`/`EF-APPARMOR` 恒在链上"，**在 VM 上这个根因不成立**
   （取数权限对齐后两者都不在链上）。**VM 上的真实根因是另一件事**：`edge_target_prepare.sh`
   **装齐六个控制**并写告警面 ⇒ 而 R 组的语义是"目标机上**真的没有**这个防护"，硬闸门要求
   **真实缺失必须成立**。逐条实测：
   - `R-no-ids`：`RS-006` 谓词（IDS/NIDS 不运行）**确实成立**（suricata `failed`、无 IDS 进程）⇒ **可跑**（已单独跑通，不占批次）；
   - `R-no-siem`：`RS-007` 谓词（无告警面）**不成立**（`prepare` 写了 `alert_notification=email`）⇒ 闸门在**建 operation 之前**整轮失败；
   - `R-no-2fa`：`EF-001` 谓词（PAM 无第二因素）**不成立**（`prepare` 装了包并写了 `pam.d/sshd`）⇒ 同上。
   ⇒ **全量批次按 33 实例放（不含 R 组那 2 条不可能产出记录的场景）**，
   理由是"把它们塞进去会让 `REPEAT=1` 的**记录条数门禁必然为红**，连门禁①/② 都拿不到"。
   **这是如实收口，不是跳过**（1 条跑通 + 2 条闸门原文均已留档）。

**场景 × 可达性普查表（25 行，独立复核）见 附录 D。**

### 10.5 Task 6 复审 Important-1 登记：`${Status}` 的修复**落在 lxd 分支内**
**背景**：Task 6（`pve` 基质驱动）独立复审判 Approved（Critical 0 / **Important 1** / Minor 1）。
Important-1 指出一处**字面违反硬不变式**的改动，复审判**可接受**但**必须登记到可跟踪处**
（此前只写在**未跟踪**的过程报告里 ⇒ 等于没有披露）。此处即为登记（另见
`docs/experiments/EDGE_FACTOR_EXPERIMENT_AUDIT_LEDGER.md` 的有意差异登记）。

| 项 | 内容 |
|---|---|
| **改的是什么** | `lunwen/clab-lab/scripts/edge_target_prepare.sh` 的"六控制装完了吗"两处轮询判据：`lab_target_exec "$TARGET" sh -c 'dpkg-query -W -f="${Status}" <包> …'` → `lab_target_exec "$TARGET" dpkg-query -W -f='${Status}' <包> …`（判据串抽成常量 `PKG_INSTALLED_STATUS`）。<br>**只有"怎么把 `-f` 交给 `dpkg-query`"这一件事变了**；循环的时序、超时、退出码、错误串**逐字未变**。 |
| **为什么必须改** | 这是**既有缺陷**，不是 Task 6 引入的：那段字符串由宿主用**单引号**交给容器内的 `sh -c`，而**容器里的 sh 会展开** `${Status}` —— 那里没有这个变量 ⇒ 展开成空串 ⇒ `dpkg-query: error in show format: may not be empty string`（rc=1）⇒ `grep -q "install ok installed"` **永远不匹配** ⇒ 轮询循环**永远不会 break**，只会一路跑到 `APT_TIMEOUT_S` 再报"apt 没装完"。**失败形态与"包装得很慢"完全同形**。<br>基线 `0a05b7d` 的 **160-162 行（lxd 路径）** 就是这个写法；它在 A-1 上从未暴露，因为那里的控制包**早就装好了**（`MISSING` 为空 ⇒ 那段根本不进来）。 |
| **对 lxd 路径的实际影响范围** | **两处**轮询（lxd 的 apt 路径 + pve 的本地镜像路径）都改了，净效果是把**"永远超时失败"变成"装完即通过"**；A-1 上因控制包早已到位而观测不到差别。lxd 的**其余**路径（`lxc launch/start/config`、`raw.apparmor`、agent 落地）**一字未动**。 |
| **机器证据** | Task 7 复核时重跑：`lab-diff`（`git archive 97581d8` 的**真基线差分**，`edge_target_prepare.sh` 不在它的场景里但 `edge_lab.sh`/`edge_reset.sh` 在）仍是 **31**；`test-edge-lab` 的 B/F/G 段全绿。两处改动都不在 clab 路径上。 |
| **登记的意义** | "lxd 分支不变"是硬不变式；这处修复**字面**动了 lxd 分支内的代码。判可接受的理由是"改的是**既有缺陷**、且行为是**修复**方向"，但它必须**在册** —— 以后审计"ARC 到底动了 lxd 路径哪些地方"时要能一眼查到。 |

---


## 附录 A：域顺序（`v_i[d]` 向量顺序）

`attack_surface, business_continuity, operation_trust, resilience, kernel_security`（与 `config.ini` 域定义及 `WeightConfig` 一致）。

## 附录 B：因子与触发检查（默认表）

以 `internal/engine/ssam/adapter.go:ConfigToEdgeFactors` 与 `config.ini [edge_factors]` 现状为准：

| 因子 ID | 名称 | 默认权重（config.ini） | 触发检查 | 备注 |
|---|---|---|---|---|
| `EF-002FA` | 2FA Missing | 0.85（`[edge_factors.level4_override]` 下 0.70） | `EF-001` | 等保四级覆盖存在 |
| `EF-SYNCOOKIE` | SYN Cookie Disabled | 0.75 | `RS-005` | |
| `EF-SELINUX` | SELinux Disabled | 0.80 | **`OT-005`** | 与 AppArmor **共用触发检查** → 耦合先验有实证 |
| `EF-APPARMOR` | AppArmor Disabled | 0.82 | **`OT-005`** | 同上 |
| `EF-NO-SIEM` | SIEM Integration Missing | 0.90 | `RS-007` | 与 NO-IDS 同域（监测缺失） |
| `EF-NO-IDS` | IDS/IPS Missing | 0.88 | `RS-006` | 同上 |
| `EF-3FA` | 3FA Not Met | 0.82（硬编码） | `EF-002` | **`CascadeTo=EF-002FA`、`CascadeValue=0.82`、`CascadeOnly=true`** —— 既有硬编码级联 |
| 自定义 | `[edge_factors.custom]`（如 `EF-002FA` 覆盖项） | 配置 | 配置 | 可扩展因子 |

**P2 阶段任务**：把这张表（含触发检查与级联关系）从 `adapter.go` 的硬编码改为配置表，默认值保持与现状等价。

## 附录 C：参数默认值

| 参数 | 默认 | 说明 |
|---|---|---|
| `model` | `legacy` | 不配置即现状 |
| `p_floor` | 0.50 | 惩罚上限 = 1 − p_floor |
| `λ_d` | 1.0 | 每域饱和速率 |
| `v_i[d]` | 未配置 = 代码 fallback（全 1，不写配置）；配置时必须 `Σ_d v_i[d] ≤ 1` | 归一化写典型值 0.2/域 |
| `c_ij` | 0 | 仅 `graph`/`chain` 且必须显式给出 |
| `chain.window_seconds` | 300 | 级联时序窗口 |

## 附录 D：场景 × 可达因子普查表（dl360gen9 的 **PVE CT** 基质）

> **证据等级图例（Task 25 补）**：逐行标证据等级，**不是**整表判定 ——
> - ✅ **真跑（11 行）**：`targeted_ttp` 那 11 个场景已由 **targeted 小批（Task 9，2026-10-13）**逐行对账
>   （11/11 一致，走的是 `POLICY_ON=0` 的**旧臂**；两条臂都跑过的收口见 D.4 与 §10.4B 结论六第 2 条）。
> - ◐ **离线复算（其余 14 行 = 11 个 `recon_playbook` + 3 个 R 组）**：判定来自离线推演
>   （`edgescen -list` + `edge_attack.sh` 的相位表 sed 抽出），**在 CT 基质上未逐行真跑**。
>   ⚠️ 限定词是「**在 CT 上**」：这 11 个 `recon_playbook` 场景在 **qemu 全量批次（33 实例 = 22 targeted + 11 recon）**
>   里**已经真跑过**，但那不是本表的基质（`B` 与声明面都不同），故那批数据不能把本表的证据等级提升为 ✅。
>   ⇒ 本表里**凡是没写"已真跑确认"的行，证据等级都是 ◐**。
> - ⚠️ **「不设基线声明时（反证）」整列未测**：仅 Task 7 对 `S0-baseline` / `S1-no-ids` 两条做过真跑旁证
>   （D.3 边界第 1 条）。
> - ⚠️ **本表不得搬到 VM（`qemu`）基质上使用**：`B` 不同（CT `{EF-SELINUX, EF-APPARMOR}` / VM `{EF-NO-IDS}`）
>   ⇒ **声明面不同** ⇒ 可达性判定的输入就不同。VM 上的实际取值见 §10.4B 结论六第 3/4 条。
> - ⛔ **整表标"失效"是错的**：本表的判定（**22 可达 / 0 需改机器状态 / 3 结构性不可达**，`4 / 18 / 3` 复核）
>   在 CT 基质上**仍然成立**，且它是仓里唯一一份"场景 × 可达因子"普查。缺的只是证据等级与基质限定。

> **Task 10 起**：`targeted_ttp` 场景在矩阵里跑**两条臂**（`POLICY_ON=0` = 本表的"卸策略"口径 /
> `POLICY_ON=1` = 新增的"策略在"口径），两臂**只差策略**，且**声明面与链都不随策略变**
> （`OT-005` 恒假 ⇒ `B` 不变；两臂的因子集相等断言都必须过）⇒ **本表的可达性判定对两条臂同等适用**。
> 详见 **D.4**。

**口径**（见 §10.4）：`声明面 = 基线活跃集 B ∪ 注入集`，其中本基质 **B = {EF-SELINUX, EF-APPARMOR}**；
本基质上的**链** = `B ∪ 实际注入的因子集 I`（自然失败里只有 `OT-005` 能点亮因子 —— 实测：
CT 904 上 `observed.checks[]` 的 **44 条全部是失败项**（该数组只落失败项 —— 这是
**采集器**的约定：`cmd/edgescen/observe.go` 的 `checkObservations` 里 `if c.Passed { continue }`；
`internal/edgeexp` 的读取层**不校验**它，`record.go` 明写"采集器的额外约定，读取层不校验"。
Task 8 收尾更正了本节原先"是 `internal/edgeexp` 的硬门禁"的说法），
而其中**属于因子触发检查的只有 `OT-005` 一条**
（`EF-001`/`EF-002`/`RS-005`/`RS-006`/`RS-007` 在这台 CT 上**通过** ⇒ 它们的因子不上链）。

**判定三选一**：
- **可达** = 本基质上链与声明面相等（声明后能写出合法记录）；
- **需改机器状态** = 要靠改机器状态才成立；
- **结构性不可达** = 改机器状态也不成立。

**复算方法**（全部离线，可复现）：读 `edgescen -list` 拿场景声明因子集；
对每个场景跑 `EDGEEXP_PRINT_EXPECTED=1 bash edge_attack.sh <场景> /tmp/x.json` 拿产物里的
`expected_chain_factors`；注入集 I 从 `edge_attack.sh` 的**相位表用 sed 抽**（不手抄）。

| # | 场景 | 注入方式 | 声明面 B∪E | 不设基线声明时（反证） | 判定 |
|---|---|---|---|---|---|
| 1 | `R-no-2fa` | real_missing | EF-002FA,EF-APPARMOR,EF-SELINUX | 先被 `real_missing` 探针拦下 | **结构性不可达** |
| 2 | `R-no-ids` | real_missing | EF-APPARMOR,EF-NO-IDS,EF-SELINUX | 先被 `real_missing` 探针拦下 | **结构性不可达** |
| 3 | `R-no-siem` | real_missing | EF-APPARMOR,EF-NO-SIEM,EF-SELINUX | 先被 `real_missing` 探针拦下 | **结构性不可达** |
| 4 | `S0-baseline` | none | EF-APPARMOR,EF-SELINUX | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 5 | `S1-2fa` | check_fail | EF-002FA,EF-APPARMOR,EF-SELINUX | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 6 | `S1-apparmor` | check_fail | EF-APPARMOR,EF-SELINUX | **被打回**（多出 EF-SELINUX） | 可达（**已真跑确认**，2026-10-13） |
| 7 | `S1-no-ids` | check_fail | EF-APPARMOR,EF-NO-IDS,EF-SELINUX | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 8 | `S1-no-siem` | check_fail | EF-APPARMOR,EF-NO-SIEM,EF-SELINUX | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 9 | `S1-selinux` | check_fail | EF-APPARMOR,EF-SELINUX | **被打回**（多出 EF-APPARMOR） | 可达（**已真跑确认**，2026-10-13） |
| 10 | `S1-syn-cookie` | check_fail | EF-APPARMOR,EF-SELINUX,EF-SYNCOOKIE | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 11 | `S2-2fa-selinux` | check_fail | EF-002FA,EF-APPARMOR,EF-SELINUX | **被打回**（多出 EF-APPARMOR） | 可达（**已真跑确认**，2026-10-13） |
| 12 | `S2-apparmor-no-ids` | check_fail | EF-APPARMOR,EF-NO-IDS,EF-SELINUX | **被打回**（多出 EF-SELINUX） | 可达（**已真跑确认**，2026-10-13） |
| 13 | `S2-no-siem-no-ids` | check_fail | EF-APPARMOR,EF-NO-IDS,EF-NO-SIEM,EF-SELINUX | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 14 | `S2-selinux-apparmor` | check_fail | EF-APPARMOR,EF-SELINUX | 仍通过（本来就声明了那两个因子） | 可达（**已真跑确认**，2026-10-13） |
| 15 | `S2-selinux-no-ids` | check_fail | EF-APPARMOR,EF-NO-IDS,EF-SELINUX | **被打回**（多出 EF-APPARMOR） | 可达（**已真跑确认**，2026-10-13） |
| 16 | `S2-selinux-no-siem` | check_fail | EF-APPARMOR,EF-NO-SIEM,EF-SELINUX | **被打回**（多出 EF-APPARMOR） | 可达（**已真跑确认**，2026-10-13） |
| 17 | `S2-syn-cookie-no-ids` | check_fail | EF-APPARMOR,EF-NO-IDS,EF-SELINUX,EF-SYNCOOKIE | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 18 | `S2-syn-cookie-no-siem` | check_fail | EF-APPARMOR,EF-NO-SIEM,EF-SELINUX,EF-SYNCOOKIE | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 19 | `S3-3fa-selinux-apparmor` | check_fail | EF-002FA,EF-3FA,EF-APPARMOR,EF-SELINUX | 仍通过（本来就声明了那两个因子） | 可达（**已真跑确认**：2026-10-13 targeted 小批再跑一致；Task 7 首次实测见 D.1） |
| 20 | `S3-selinux-apparmor-2fa` | check_fail | EF-002FA,EF-APPARMOR,EF-SELINUX | 仍通过（本来就声明了那两个因子） | 可达（**已真跑确认**，2026-10-13） |
| 21 | `S3-selinux-no-siem-no-ids` | check_fail | EF-APPARMOR,EF-NO-IDS,EF-NO-SIEM,EF-SELINUX | **被打回**（多出 EF-APPARMOR） | 可达（**已真跑确认**，2026-10-13） |
| 22 | `S3-syn-cookie-no-siem-no-ids` | check_fail | EF-APPARMOR,EF-NO-IDS,EF-NO-SIEM,EF-SELINUX,EF-SYNCOOKIE | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 23 | `S4-all` | check_fail | EF-002FA,EF-APPARMOR,EF-NO-IDS,EF-NO-SIEM,EF-SELINUX,EF-SYNCOOKIE | 仍通过（本来就声明了那两个因子） | 可达（**已真跑确认**，2026-10-13） |
| 24 | `S5-2fa-only` | check_fail | EF-002FA,EF-APPARMOR,EF-SELINUX | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |
| 25 | `S5-cascade-3fa` | check_fail | EF-002FA,EF-3FA,EF-APPARMOR,EF-SELINUX | **被打回**（多出 EF-APPARMOR,EF-SELINUX） | 可达 |

**统计**：**可达 22 ｜ 需改机器状态 0 ｜ 结构性不可达 3**（＝ 25）。

**复算口径（修正过一次，务必按这条算）**：链 = `B ∪ 注入集 ∪ 级联闭包(注入集)` ——
注入 `EF-3FA` 时，**级联目标 `EF-002FA` 也会上链**（见 D.1）。

### D.1 与控制侧给的 `4 / 18 / 3` 的复核结论

控制侧的划分口径是"**声明面是否天然吻合**"，本表独立复算的结果是：

| 划分 | 控制侧 | 本次独立复算 | 一致？ |
|---|---|---|---|
| 声明面天然吻合（场景本身就声明了 B 的两个因子） | **4** | **4**：`S2-selinux-apparmor` / `S3-3fa-selinux-apparmor` / `S3-selinux-apparmor-2fa` / `S4-all` | ✅ 完全一致 |
| 声明面漏了那两个天然因子（**需基线声明**才不被相等断言打回） | **18** | **18**（22 个 S 场景 − 上述 4） | ✅ 完全一致 |
| 结构性不可达（R 组） | **3** | **3**：`R-no-2fa` / `R-no-ids` / `R-no-siem` | ✅ 完全一致 |

⇒ **`4 / 18 / 3` 复核通过**（同一口径、独立算的，逐场景名字也对得上）。
可达性轴上的结论是 **22 可达 / 0 需改机器状态 / 3 结构性不可达**。

### D.1.1 一处**我自己的推演被实测推翻**（如实登记，不要删）

初版普查表把第 19 行 `S3-3fa-selinux-apparmor` 判成"**预期失败**"，依据是离线推演
「链 = B ∪ 注入集」：该场景的产物期望集含级联目标 `EF-002FA`（`edge_attack.sh` 的
`EF-3FA → EF-002FA` 展开），而注入相位只注入 `EF-3FA` 与 `EF-SELINUX,EF-APPARMOR`
⇒ 推得 `EF-002FA` **不可能上链**。

**真跑把这个推演推翻了**：该场景 `collect-rc=0`、因子集相等断言**通过**
（`链 4 个 ID = 声明面：注入 4 个 ∪ 基线 2 个`）。记录原文：

```
链条数 = 6
  factor=EF-002FA    trigger=EF-001  c_trigger=0  eff=0.7000    ← 注入集里没有它，链上却有
  factor=EF-APPARMOR trigger=OT-005  c_trigger=1  eff=0.8200
  factor=EF-SELINUX  trigger=OT-005  c_trigger=1  eff=0.8000
  factor=EF-3FA      trigger=EF-002  c_trigger=1  eff=0.8200
  …（OT-005 的两个因子各再出现一次；共 6 条 / 去重 4 个 ID）
```

**机制**：引擎的**级联**会把级联目标带上链，且以 `c_trigger = 0`（"**仅由级联激活**"）出现 ——
这与 §10.2 已登记的"级联因子在 V/G/C 下不产生惩罚（`c_trigger = 0`）"是**同一条行为**。

**为什么 `EF-002FA` 的 `trigger_check = EF-001` 不在 `checks[]` 里却仍然合法**（Task 8 勘误：
初版把依据写成"`EF-001` 不在 checks 里 ⇒ 级联不需要它被观测"，**结论对、理由不严谨**）：
真正的依据是 `internal/edgeexp/record.go` 里 **`func (r Record) CheckTriggerCrossReference()` 的注释块**与
**`func MarshalRecord` 的注释**（**请按符号名定位** —— 这个方法名就是权威锚点；
"legacy 的 identity/级联路径**请勿调用本检查**"这句在它的**错误串**里）。
⚠️ **行号会随提交漂移，不要用来定位**：本节初版引的是 `c0fe19a` 上的 598–612 / 675–677 / 628，
而在 `5eaedec` 上这三个方法分别在 **644 / 709** 行、该错误串也在方法体内 —— 典型的一次漂移。
`grep -n 'func (r Record) CheckTriggerCrossReference\|func MarshalRecord' internal/edgeexp/record.go` 一跑就能拿到当前行号。
—— legacy 的
**identity 分支 / 级联路径**产出的链条目，其 `trigger_check` 是"该因子**登记的**触发检查"，
**未必**是真正失败的那个检查；那条"`trigger_check` 必须以 `passed=false` 出现在 `checks[]` 里"
的交叉核对**仅插件路径（V/G/C）适用**，源码里就写着"legacy 的 identity/级联路径**请勿调用本检查**"。
⇒ `EF-002FA` 以 `c_trigger=0` 上链、其登记触发检查未失败，是**制度允许的既有行为**，不是异常。
（另注：`EF-001` "不在 `checks[]` 里"这件事本身只是**该数组只落失败项**的后果 —— 它恰恰也是
Minor-1 那条勘误的同一个点。）

**修正后的口径**：链 = `B ∪ 注入集 ∪ 级联闭包(注入集)`（注入 `EF-3FA` ⇒ 同时带上 `EF-002FA`）。
本表的复算脚本按此修正并重跑，结论 **22 / 0 / 3**。

**教训（写在这里以防再犯）**：离线推演可以做**预测**，但**不能替代真跑**。
第 19 行就是"推演看起来无懈可击、实测一句话推翻"的例子；凡是对**链上会出现什么**
下判断的地方，都要用真跑收口。

### D.2 "需改机器状态"为什么是 0

逐个排除：
- 22 个 S 场景的触发检查（`EF-001`/`EF-002`/`RS-005`/`RS-006`/`RS-007`/`OT-005`）**都在** CT 的
  检查登记表里（登记表 = **`checks.GetAll()`**，即平台闸门按 `runtime.GOOS` 过滤后的注册表 =
  `internal/checks/linux/checks.go` 的 `All()` **68 项** + `kernel_security.go` 的 `ksAll()` **12 项**
  = **80 项**；实测 `-emit-checks` 信封里就是 80 条，按域 attack_surface 19 / operation_trust 22 /
  resilience 24 / business_continuity 3 / kernel_security 12，六个触发检查**逐条都在**。
  Task 8 勘误前这里写的"实测：44 项检查含全部 6 个触发检查"**不实**：44 是
  `observed.checks[]` 里的**失败项数**（该数组只落失败项 —— 那是**采集器**的约定，
  见 `cmd/edgescen/observe.go` 的 `checkObservations`，读取层不校验），
  而其中属于因子触发检查的**只有 `OT-005`** —— 本批两条记录实测：`checks[]` 各 45 条、
  `passed=true` 的 0 条，命中的触发检查只有 `OT-005`（`S1-apparmor`）与
  `OT-005,RS-006`（`S1-no-ids`，后者是本场景自己注入的）），
  而 `check_fail` 注入是**强制翻转** `Passed`（`edgescen` 的 `resolveInjections` + `collectChecks`），
  **不依赖机器本来是什么状态** ⇒ 不需要改机器状态；
- 3 个 R 场景**要**"机器真的缺该控制"，但复位的**契约**就是"把六个控制装齐"（幂等）⇒
  改机器状态也没用（下一次复位又装回去）⇒ 归入**结构性不可达**而不是"需改机器状态"。

### D.3 这 11 行已由 **targeted 小批（Task 9）真跑确认**（2026-10-13）

附录 D 的 25 行里 **11 行是 `targeted_ttp` 场景**（注入因子含 `EF-SELINUX`/`EF-APPARMOR`）。
Task 9 把这 11 个各跑了 **1 次**（走矩阵层 `edge_matrix.sh`、默认 **1800s** 攻击观察窗、
`2026-10-13T05:51:06Z → 06:17:41Z`、`run_id=20261013-2286810`），并把这 11 行**逐行对账**。

**方法（机械、不是通读）**：本表这一列的「声明面 B∪E」是一个**可检验断言** —— 真跑记录的
`observed.edge_factor_chain` **去重后必须逐元素相等**（这正是采集侧那条"链上因子集 == 声明面"
的相等断言：不通过就整轮失败并回滚，压根写不出记录）。对账脚本读
`lunwen/clab-lab/data/edgefactors/records-dl360-pve-20261013.jsonl` 的 11 条记录与本文档的 11 行，
逐行比集合（脚本与原始输出见 Task 9 报告 §6）。

**结果：11 / 11 行一致，0 行被推翻**（每行都 `reset`/`attack`/`collect` 全 rc=0、
`ground_truth.basis=targeted_ttp`、记录 11/11、门禁① `exit_code=0`、门禁② 最大偏差 0）：

| 行 | 场景 | 文档「声明面 B∪E」 | 真跑：链去重因子 | 一致 |
|---|---|---|---|---|
| 6 | `S1-apparmor` | EF-APPARMOR,EF-SELINUX | 同 | ✅ |
| 9 | `S1-selinux` | EF-APPARMOR,EF-SELINUX | 同 | ✅ |
| 11 | `S2-2fa-selinux` | EF-002FA,EF-APPARMOR,EF-SELINUX | 同 | ✅ |
| 12 | `S2-apparmor-no-ids` | EF-APPARMOR,EF-NO-IDS,EF-SELINUX | 同 | ✅ |
| 14 | `S2-selinux-apparmor` | EF-APPARMOR,EF-SELINUX | 同 | ✅ |
| 15 | `S2-selinux-no-ids` | EF-APPARMOR,EF-NO-IDS,EF-SELINUX | 同 | ✅ |
| 16 | `S2-selinux-no-siem` | EF-APPARMOR,EF-NO-SIEM,EF-SELINUX | 同 | ✅ |
| 19 | `S3-3fa-selinux-apparmor` | EF-002FA,EF-3FA,EF-APPARMOR,EF-SELINUX | 同（链 6 条 / 去重 4 个 ID） | ✅ |
| 20 | `S3-selinux-apparmor-2fa` | EF-002FA,EF-APPARMOR,EF-SELINUX | 同 | ✅ |
| 21 | `S3-selinux-no-siem-no-ids` | EF-APPARMOR,EF-NO-IDS,EF-NO-SIEM,EF-SELINUX | 同 | ✅ |
| 23 | `S4-all` | EF-002FA,EF-APPARMOR,EF-NO-IDS,EF-NO-SIEM,EF-SELINUX,EF-SYNCOOKIE | 同 | ✅ |

**这次没有被推翻的行** —— 与 D.1.1 那次（第 19 行）刚好互补：那次是"离线推演**错**、
真跑纠正"，这次是"离线推演**对**、真跑确认"。两者都留档，因为第 2 种情况同样重要：
**推演对的时候也要真跑收口**，否则"对"与"恰好没被测到"在文档里同形。

**边界（本轮没有测到的）**：

1. 「**不设基线声明时（反证）**」那一列**不在本次确认范围**：本轮 11 个场景**始终声明了**
   基线活跃集（`pve` 基质下 `edge_lab.sh` 自动声明 `EDGEEXP_BASELINE_FACTORS=EF-SELINUX,EF-APPARMOR`）；
   要测反证必须**显式置空**再跑（Task 7 用 `EDGEEXP_BASELINE_FACTORS=` 对
   `S0-baseline`/`S1-no-ids` 做过一次：多出基线因子 ⇒ 相等断言不通过 ⇒ 记录回滚）。
   ⇒ 这 11 行的反证列仍是**离线推演 + Task 7 两条真跑旁证**。
2. **另外 14 行**（`recon_playbook` 的 11 行 + R 组 3 行）**本轮没跑**（Task 9 只跑 targeted）——
   它们的可达性仍来自离线复算，**待全量扫描收口**。


### D.4 `targeted_ttp` 场景的**两条臂**（Task 10，用户 2026-10-13 裁定「甲」）

**为什么加**：本表的 11 个 `targeted_ttp` 场景在 `POLICY_ON=0` 下策略是卸掉的 ⇒ 目标 TTP
（`head -1 /etc/shadow`）**必然成功** ⇒ 它们的 `compromised` **全是 `true`**（Task 9 的 11 条实测如此），
决策层指标拿不到两类标签。故矩阵对每个 targeted 场景**再加一条"策略在"（`POLICY_ON=1`）的臂**：
同一个场景、同一个目标 TTP、同一个 pair 剧本、同一个攻击组、同一份采集配置、默认 1800s 观察窗 ——
**只差策略**。

**它对本表的判定有什么影响：没有。** 三条理由（都是可检验的）：

1. **声明面不随策略变**：`B = {EF-SELINUX, EF-APPARMOR}` 的结构性理由（`OT-005` 在 PVE CT 里恒假）
   与策略无关 ⇒ 两臂的**因子集相等断言都必须过**（`S1-apparmor` 的两臂已实测：都过）。
2. **可达性的分母仍是"场景"**：可达 = "本基质上链与声明面相等（声明后能写出合法记录）"，
   两条臂**都能写出记录**（一条 `compromised=true`、一条 `false`）⇒ 本表 22 可达 / 3 结构性不可达
   **不受影响**。
3. **臂的身份写在记录里**（`meta.policy_on`，additive）：读者只靠数据集就能把两臂分开，
   不需要靠文件名或运行顺序 —— 这是"两臂只差策略"这句话可被检验的前提。

**实例记账**：`targeted_ttp` 场景 → **2 条实例**，其余 → 1 条 ⇒ 全量一轮的实例数是
**11×2 + 14 = 36**（干跑实测：`targeted_ttp(policy=0)=11 ｜ targeted_ttp(policy=1)=11 ｜
recon_playbook=14 ｜ 合计 36`）；`EDGEEXP_POLICY_ON_ARM=0` 可关掉新臂（此时与 Task 9 的矩阵逐字节相同）。
⚠️ **这是「矩阵口径」的实例数，不等于实际跑过的条数**：本里程碑**实际放的是 33 实例** = 22 targeted + 11 recon
—— R 组那 2 条结构性不满足（会撞 `REPEAT=1` 的记录条数门禁）、`R-no-ids` 单独跑通但不占批次
（和解文本见台账 B.5 与 §10.4B 结论六第 4 条）。**不要**把 36 读成"实际跑过 36 条"。

**边界（截至 2026-10-14）**：**只有一个场景（`S1-apparmor`）真跑过"策略在"的臂**（一对记录的
`compromised` 一真一假）；其余 10 个 targeted 场景的"策略在"臂**尚未真跑** ——
本表那 11 行的"已真跑确认"标记说的是**旧臂**（`POLICY_ON=0`）已经跑过，**不等于**两条臂都跑过。

> ✅ **该边界已收口（2026-10-16，Task 17 全量批次，VM 基质）**：**11 个 targeted 场景 × 2 条臂
> = 22 条记录全部真跑**（数据集 `records-dl360-qemu-20261016.jsonl` 的前 22 条）。
> ⇒ 上表那 11 行现在**两条臂都跑过**；"策略在"的臂不再是单场景的试点。
> ⚠️ 并且补上一条这个批次**新测得**的 limitation：**两臂的链与分数逐项相同，只有标签不同**
> （11/11）⇒ 本表"两臂只差策略"这句话在**记录里可检验**，但**分数侧区分不开两条臂**（见 §10.4B 结论六第 2 条）。

**更新（2026-10-15，重复轴落地后）**：`S1-apparmor` 已以 **2 条臂 × 3 个重复 = 6 条记录**真跑，
并且**由两个人各自独立跑出一份数据集**（两套数据目录、各自的记录文件），结论一致：

| 重复 `meta.repeat` | 臂 `meta.policy_on` | 实例号 | `compromised` | `block_effective` |
|---|---|---|---|---|
| 1（字段**缺席** = 第 1 遍） | `0`（策略卸掉） | 01 | `true` | `false` |
| 1 | `1`（策略在） | 02 | `false` | `true` |
| 2 | `0` | 03 | `true` | `false` |
| 2 | `1` | 04 | `false` | `true` |
| 3 | `0` | 05 | `true` | `false` |
| 3 | `1` | 06 | `false` | `true` |

- **因子集相等断言**：6 条记录的链去重集 **全部** == 声明面 `{EF-APPARMOR, EF-SELINUX}`（链均 4 条）✅
- **门禁①/② 当轮退出码**：每个重复的 `run-*.json` 都是 `exit_code=0`（**不是 `null`/`skipped`**）✅
- **记录条数门禁**：`record_counts_ok=True`（`2/2`、`4/4`、`6/6`）✅
- **两份独立数据集的前 10 行逐字相同** ⇒ 这两条臂的**标签与因子集是可重复的**（ttc 仍有抖动，
  但**标签口径**没有抖）。
- ⚠️ **当时只覆盖 1 个场景**：另外 10 个 targeted 场景的"策略在"臂**仍未真跑**，
  须由**全量批次**收口。
  > ✅ **已由全量批次收口（2026-10-16，Task 17，VM 基质）**：11 个 targeted 场景全部跑了两条臂
  > （22 条记录），`S1-apparmor` 的两臂在这里只是**第一个**样本，不再是唯一的一个。

## 附录 E：`targeted_ttp` 口径的三件 Caldera 实体（建法 + ID 记档）

**为什么需要这一节**（Task 8 Step ①）：`edge_matrix.sh` 把"注入因子含 `EF-SELINUX`/`EF-APPARMOR`"的
**11 个** S 场景判成 `basis=targeted_ttp`，并要求给出目标/对照 ability 与 pair 剧本。
这套实体在 A-1 上**有**，但**是手工建的、仓里没有创建脚本** ⇒ 换一台 C2（dl360gen9 上的
这个 Caldera）就**没有它们**，于是 **25 个场景一齐跑会在门禁处整批被拒（rc=2）**。
把"怎么建"变成可跟踪、可重跑的东西，本身就是记档。

### E.1 建法（唯一入口，幂等）

```
EDGEEXP_CALDERA_URL=http://<pve-host-ip>:8888 EDGEEXP_CALDERA_KEY=<c2-key> \
  bash lunwen/clab-lab/scripts/edge_ttp_provision.sh
```

> 上例中的两个值必须来自**未跟踪的本地配置**：`<pve-host-ip>` 是本机在管理 VLAN 上的地址，
> `<c2-key>` 是 C2 的 API 口令（**不得**写进仓库）。占位符口径见
> `docs/experiments/EDGE_FACTOR_EXPERIMENT_ENVIRONMENT_WHITEPAPER.md` §0。

脚本做三件事：**已存在则不重建，而是核对关键字段**（ability 的 `command`、adversary 的
`atomic_ordering`）—— 不一致就**响亮失败**，因为那意味着"C2 上的实体与夹具/文档引用的不是
同一个东西"，比"缺实体"更难发现。

**不得拿别的 ability 冒充**：Caldera 自带的 `Access /etc/shadow (Local)`
（`af30d8506a8aba7a022b687261d22541`）执行的是 `sudo cat /etc/shadow > /tmp/T1003.008.txt; cat …`，
与 A-1 上被判据引用的那一条**命令不同**；换掉它，链上看到的 `command` 就与已落盘的历史数据不可比。
本脚本只借用现成 Linux ability 的 **executor 字段形状**（`sh` / `platform: linux` / `timeout: 60`）。

### E.2 三件实体（ID 与 A-1 **逐字相同**）

> ⚠️ **适用范围**：「与 A-1 逐字相同」是 **2026-09 的溯源**（这三个实体当初建在 A-1 上、ID 逐字照抄）。
> A-1 已于 **2026-10-19** 退为备份端、即将重置 ⇒ 这句话只说明**出处**，不再说明"还能去哪台机器上核对"。
> **三个 ID 本身是常量、仍然现行有效**（后续批次照用，见 E.3 的跑批变量）。

| 角色 | ID | 名字 | 命令 / ordering |
|---|---|---|---|
| **目标 TTP** ability | `a5c0ffee-0000-4000-8000-0000000003b1` | `T4D Step 3B: read /etc/shadow (AppArmor target TTP)` | `head -1 /etc/shadow`（**撞 AppArmor 策略**） |
| **对照** ability | `a5c0ffee-0000-4000-8000-0000000003c1` | `T4D Step 3B control: write marker (no policy collision)` | `echo t4d-control-ok > /tmp/t4d-control-marker && cat /tmp/t4d-control-marker` |
| **pair 剧本** adversary | `a5c0ffee-0000-4000-8000-0000000003c2` | `T4D Step 3B pair (control + target TTP)` | `atomic_ordering = [ …3c1, …3b1 ]`（**先对照、后目标**）；`objective = 495a9828-cab1-44dd-a0ca-66e58177d8cc`（Caldera 自带 `default`） |

语义（照 A-1 的原始 chain 与 `experiments-final/pilot-step5-2026-09-13/README.md`）：
**目标**撞策略 —— 策略在 ⇒ 被拒（`compromised=false`）；策略不在 ⇒ 成功（`true`）。
**对照**不撞策略 —— 它回答"通道与执行器健不健康"：对照失败 ⇒ 目标失败**不能**归因于策略。

### E.3 跑批要给的**五个**变量（不是三个；其中**必需 3 个、可选 2 个**）

```bash
# —— 必需 3 个（选中 targeted 场景时缺任一，矩阵层**干跑就 rc=2**）——
export EDGEEXP_TTP_TARGET_ABILITY=a5c0ffee-0000-4000-8000-0000000003b1
export EDGEEXP_TTP_PLAYBOOK_ID=a5c0ffee-0000-4000-8000-0000000003c2
export EDGEEXP_TTP_PLAYBOOK_NAME='T4D Step 3B pair (control + target TTP)'

# —— 可选 2 个（给了更好，缺了不会被拒）——
export EDGEEXP_TTP_CONTROL_ABILITY=a5c0ffee-0000-4000-8000-0000000003c1
export EDGEEXP_TTP_TARGET_ABILITY_NAME='T4D Step 3B: read /etc/shadow (AppArmor target TTP)'
```

| 变量 | 必需性 | 判据（源码） |
|---|---|---|
| `…_TTP_TARGET_ABILITY` | **必需** | `edge_matrix.sh` 门禁（缺 ⇒ `exit 2`）；`edge_attack.sh` 里 "链里**没有**目标 ability … 的 link" 即 `fail`（函数 `target/control 分开计` 那段） |
| `…_TTP_PLAYBOOK_ID` | **必需** | `edge_matrix.sh` 门禁（缺 ⇒ `exit 2`） |
| `…_TTP_PLAYBOOK_NAME` | **必需** | `edge_attack.sh` 的**剧本漂移守卫**（`if playbook.get('name') != PLAYBOOK_NAME:` 那段；缺省 `Discovery` 在文件头的 `PLAYBOOK_NAME=` 赋值处）—— 缺了会在**攻击步**被拒；**2026-10-13 起矩阵层也拦它**（缺了在干跑就 `exit 2`，见下） |
| `…_TTP_CONTROL_ABILITY` | *可选* | `edge_attack.sh` 文件头的环境变量说明自述"（可选，只用于归类与报告）"；判据在 `control_links = […]` 的 `not CONTROL_ABILITY or …` 处 |
| `…_TTP_TARGET_ABILITY_NAME` | *可选* | 同上，自述"（可选，仅用于核对 ID 没被换掉）"；判据是 `if TARGET_ABILITY_NAME:` 那段 |

> ⚠️ **本表按符号/代码片段引用，不写行号** —— 本节的三个行号引用里已有一处漂移，
> 行号引用在本项目**被证明不可靠**。需要当前行号时用
> `grep -n '<片段>' lunwen/clab-lab/scripts/edge_attack.sh` 现取。

（这是**矩阵层**的变量名：`edge_matrix.sh` 的 `apply_scenario_conditions` 会按场景把它们
**导出成子脚本那一套** —— `EDGEEXP_TARGET_ABILITY` / `EDGEEXP_TARGET_ABILITY_NAME` /
`EDGEEXP_CONTROL_ABILITY` / `EDGEEXP_PLAYBOOK_ID` / `EDGEEXP_PLAYBOOK_NAME`；
直接手跑 `edge_attack.sh` 时要用后者，而它的名字缺省值就是 `Discovery`（见文件头的 `PLAYBOOK_NAME=` 赋值处）。）

**`..._PLAYBOOK_NAME` 是必须的**（Task 8 实测踩到）：`edge_attack.sh` 的剧本名默认值是
`Discovery`，而它有一条**剧本漂移守卫**；只给 `PLAYBOOK_ID` 不给名字 ⇒ **每一个
`targeted_ttp` 场景都会在攻击步被拒**：

```
edge_attack: 剧本 ID a5c0ffee-0000-4000-8000-0000000003c2 现在的名字是
  'T4D Step 3B pair (control + target TTP)'，与固定的 'Discovery' 不符 —— 剧本漂移，拒绝在这种状态下采集
```

**它同时意味着"干跑绿 ≠ 能跑"**（Task 8 复审实测的缺口）：缺名字时 25 场景干跑**照样 rc=0**、
规划表完全正常，直到第一个 targeted 场景的攻击步才 rc=1 —— 而前面的 reset 已经白跑。
故 2026-10-13（Task 8 复审修复轮）在矩阵层与 `TARGET_ABILITY`/`PLAYBOOK_ID` **同一处**加了
第三条门禁：缺 `…_TTP_PLAYBOOK_NAME` 且选中了 targeted 场景 ⇒ **干跑前就 `exit 2`**。
判据只看**选中的**场景 ⇒ 只跑侦察场景时不受影响。

`..._TARGET_ABILITY_NAME` 只用于"ID 没被换掉"的**可选**核对（`edge_attack.sh` 里同一条守卫），
建议一起给。`EDGEEXP_TTP_GROUP` 默认 `t4d-ttp`，与 `edge_target_prepare.sh` 拉起 agent 时用的
`--group` 同源 —— 投送范围因此可证明只到目标机。


