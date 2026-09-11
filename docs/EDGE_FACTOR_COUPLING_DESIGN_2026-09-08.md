# ASSCOR 边缘因子耦合与变量化设计（方向②）

- **日期**：2026-09-08
- **分支**：ASSCOR-Research-Core（实现需同步 main）
- **状态**：设计定稿（所有取舍经作者逐项确认），等待实现计划
- **关联**：债务清单 §四 ②（边缘因子耦合放大缺理论边界）+ RC-M4（ACL 硬编码权重参数化，本轮只参数化、标定后置）；方向① 设计 `docs/CONFIDENCE_MODEL_DESIGN_2026-09-08.md`（本方向不改其语义）
- **实验环境**：WSL2 Containerlab（14 节点真实拓扑，主战场）+ 远程 A-1（≤14 agent 多进程模拟，重复性验证）

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
  4. A-1 每场景重复 3 次提供重复样本，提高可辨识性；场景矩阵可后续扩充（S2 全 15 组）。

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
- 固定攻击剧本（Caldera），拓扑与剧本哈希入档；清除环境依赖的顺序（clab `destroy+deploy`，不用 `--reconfigure`）。

### 5.1 采集 schema（每场景一条 JSONL）

> 下面这条记录为可读性做了缩进；**JSONL 里必须压成单行**（一行一条记录，读取层按行切分）。
> 本节 schema 与读取层、以及示例自身的数值自洽性，由 `cmd/edgecompare/docs_schema_test.go`
> 直接对照本示例强制执行：**文档漏字段、示例数值自相矛盾、或读取层单方面收紧**，该测试即红。
> 读取层对**其它**必填项的"放宽"方向由 `cmd/edgecompare/load_test.go` 的逐字段定向用例覆盖
> （`scenario_id`/`threshold`/`domain_scores`/`c_trigger`/`effective_factor`/`ts`/`compromised`
> 各有独立的"缺失必拒"用例）。

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
                "delta": -6.0, "confidence": 0.9, "ts": "2026-09-08T10:00:03Z"}],
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

> **示例里的每个值都必须自洽**：`factors` / `edge_factor_chain[].factor` 用**规范因子 ID**（`EF-SELINUX`，不是展示名 `selinux_disabled` —— 写错会让离线重算查不到 `Vectors` 而静默走"全 1"fallback，改变 V/G/C 的惩罚强度）；`trigger_check` 与该因子的默认触发检查一致（`EF-SELINUX`/`EF-APPARMOR` 共用 `OT-005`，这正是 S2 组要建模的同源耦合）；`effective_factor` 是策略层衰减后的观测值（默认配置 `f_selinux=0.80`、`f_apparmor=0.82`，`1−(1−f)·c` 取 `c=0.9` ⇒ 0.82 / 0.838）；`final_score` 必须能被 `cmd/edgecompare` 用记录自身的输入复算出来（`docs_schema_test.go` 会对本示例做这条 round-trip 断言，数值自相矛盾即红）。

**必填字段（缺失即整条记录 fail-fast，读取层 `cmd/edgecompare/load.go:validateRecord`）**

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

`spc_score` / `threat_coeff` 的来源是引擎 `AssessmentOutput.SPCScore` 与 `[threat] coefficient`（引擎总分 = `round2(0.5·base + 30·E + 20·T)`）。**注意**：仓内 `internal/attck/attck.go` 中存在同名字段但写的是 `predictedRisk.EnhancedThreat`（**另一个量**），采集器取错会让离线分数整体偏移而门禁全绿 —— 故本节的示例记录带一条 round-trip 钉桩（`observed.final_score` 必须能被 `cmd/edgecompare` 用记录自身输入复算出来，已验证），采集器落地时必须对自采数据做同样的事。

**round-trip 的前提是"候选声明的因子集 == 记录里出现的因子集"**：离线重算只惩罚候选（`params.Factors`）声明的因子，记录里有而候选没声明的会被**静默丢掉**（实测：同一条示例记录，只声明 `EF-SELINUX` 算出 84.68，声明两个才是 80.02）。这正是 CLI 的 `-factors` 覆盖校验存在的原因，也是采集器必须把每个场景实际激活的因子完整写进 `factors` / `edge_factor_chain` 的原因。

### 5.2 离线重算流程（`cmd/edgecompare`）

1. 读 JSONL → 装配离线评估所需的输入（域分与权重、因子激活与触发链、`spc_score`/`threat_coeff`、链上时间戳）；
2. 对每个候选模型 × 参数组重算域分、总分与接受性判定；
3. 计算三层指标（决策一致率/漏判率/误阻断率；Spearman/Kendall；AUC）；
4. 交叉验证选模型，输出报告（Markdown + JSON）与**可直接粘贴的 config 参数段**；
5. `--fit` 模式：拟合主效应与先验交互边，输出参数 + 自助法不确定度。

### 5.3 环境分工

| 环境 | 角色 | 注意 |
|---|---|---|
| WSL2 Containerlab（14 节点真实拓扑） | 主战场，22+3 场景 | `clab destroy+deploy`；`.wslconfig` 限内存 8GB |
| A-1（Ubuntu，2c/3.4GB） | 重复性（每场景 3 次）+ 稳定性 | **agent ≤14**；曾因 24 进程压垮 sshd |

---

## 6. 形式化验证与测试策略

| 类别 | 内容 |
|---|---|
| 性质测试 | P1（有界）、P2（单调）、P5（极限）属性测试 + **因子全组合枚举 2⁶=64** 扫描 |
| 超模性 | P3：随机 `a`/`c` 下验证 `L(A) − L(∅) ≥ Σ_i [L({i}) − L(∅)]` |
| 兼容性 | 全默认配置 → 与历史评分**逐位一致**（硬门禁） |
| 参数校验 | 坏向量长度/`f` 越界/`c<0`/`λ≤0`/`Σ v>1` 全部 fail-fast |
| 拟合可信度 | 合成已知 `c_ij` 的数据 → 回归可恢复（含噪声容限） |
| 离线↔在线一致 | 总分与判定线共用同一份实现：离线直接调用内仓 `ssam.SSAMV20Formula`（域分加权、公式内钳位、`0.5·base+30·E+20·T` 聚合、两次取整全部由它完成），域级修正经 `RegisterDomainAdjust`、乘子经 `RegisterEdgeFactorStrategy` 注入，legacy 零注册；判定线同款 `总分 ≥ threshold`。**边界（勿过度承诺）**：因子激活项的**装配**（`ActivationFromResult` 的置信度换算）在线/离线仍是两份实现，只是算术口径相同；"逐位一致"在 `c=1` 时成立（spec §10.2 的双重衰减口径见该节），且对 chain 无定义 —— chain 在线必失败（离线专用），故该行对 chain 不适用 |
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
- **风险**：① 交互项可辨识性（§3.5 已给出降级策略与如实报告要求）；② 容器内 SELinux/AppArmor 不可真关（代理关系须标注）；③ A-1 agent 上限；④ 论文数字——若 E1–E9 涉及因子行为，需在论文说明升级路径，**不得回退已有数字**。

### 7.3 交付物

① 统一框架与四候选（`internal/edgefactor`）；② `ssam-lib` 合成策略钩子（内仓 + 外层）；③ 配置段与实验模板；④ `cmd/edgecompare`（重算 + 拟合 + 报告）；⑤ 实验脚本与数据集（WSL + A-1）；⑥ 设计文档 + 实验/选模报告（含参数文件与不确定度）。

---

## 8. 阶段划分与验收

| 阶段 | 交付 | 验收 |
|---|---|---|
| P1 | 统一框架 + 四候选 + 性质测试（纯函数，无 IO） | P1/P2/P3/P5 性质全绿 + P4 逐位一致（硬门禁） |
| P2 | 配置注入 + 参数校验 + 溯源字段 + 触发映射可配 | 坏参数 fail-fast；默认行为不变 |
| P3 | `ssam-lib` 钩子（内仓提交）+ 外层接入 | 内仓测试全绿；外层全量测试；默认逐位一致 |
| P4 | `cmd/edgecompare`（重算 + 指标 + 报告 + 拟合） | 离线↔在线逐位一致；合成数据可恢复 |
| P5 | 实验执行（WSL 22+3；A-1 重复 3 次） | 数据集完整、脚本可复现、代理关系已标注 |
| P6 | 拟合与选模（logistic + 交叉验证 + 自助法） | 选定模型 + 参数文件 + 对比报告（含不确定度） |
| P7 | 文档 + 论文影响处理 + 双分支同步 | 文档归档、CI 绿、main/ARC 同点 |

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

---

## 10. 未决与风险

### 10.1 在线可用性与口径（Task 7 评审裁定，实现为准）

- **`chain` 为离线专用模型**：引擎结果类型（`ssam-lib` 的 `EdgeFactorResult`）不含时间戳字段，而 `Synthesize` 对 chain 要求每个激活因子带非零 `TS`（fail-fast，刻意不退化）。因此**在线装配期对 chain 直接失败**（不装载、不盖戳、评分回落到与未启用逐位一致的路径）；chain 的时间戳只存在于离线 JSONL（§5.1 的 `edge_factor_chain[].ts`），故 chain 的评估在 `cmd/edgecompare` 离线进行 —— 与 §2.2「离线重算为主」一致。
- **溯源（`Model`/`ParamsHash`）口径**：填写的判据是「**engine 已装载同一套参数**」，而不是「配置里写了模型段」。「未配置」时两个键不出现在 JSON；「显式 `model=legacy`」时输出 `legacy` + 指纹（用于区分"未配置"与"显式选 legacy"）。
- **显式 `model=legacy` 与「未配置」在评分上逐位一致**（评审裁定，`-U` 边界夹具 50.31）：两者都**不注册任何钩子**，走内仓默认的顺序乘法；差别只在**溯源输出**（显式 legacy 输出 `legacy` + 指纹，未配置不输出）。不得用"注册恒等乘子"来实现 legacy —— 那会把默认顺序乘法切成单次相乘，在取整半格上产生 1 ulp 差异。
- **域分口径**：域级修正 `P_d` **只作用于域分聚合**（`Score_d' = Base_d · P_d` 参与聚合）；对外输出的 `DomainScores` 仍是修正前的观测值。若后续需要"修正后域分"的证据链，需在输出层补字段。
- **运行时只修正 `λ` 覆盖到的域**：实际被修正的域 = `DefaultDomains ∩ λ`；未配 `λ` 的域不修正（运行时不额外提示）。

### 10.2 已知口径问题（标定前必须处理）

- **可信度被衰减两次**:`ssam-lib` 的 `ApplyEdgeFactorsToChecksPolicy` 已把因子值按可信度衰减一次（`factor = 1-(1-factor)·c`），而装配层 `ActivationFromResult` 又对同一个 `Factor` 再乘一次 `EffectiveFactor(·, c)`，合计为 `1-(1-f)·c²`。默认可信度策略关闭（c=1）时两者恒等，故不影响"默认逐位一致"；但**一旦开启可信度策略，启用模型的惩罚强度会显著强于历史路径**。Task 8–10 的离线重算必须**复用同一口径**，并在标定报告中明确标注；是否修正（去掉重复衰减）属独立决策（会改评分）。



- **交互项可辨识性**：样本量限制下只用先验边集 + 正则；若结论不足，扩充 S2 至全 15 组 / 增加重复次数（A-1）。
- **代理真实性**：SELinux/AppArmor 场景为检查失败代理，R 组仅能覆盖 IDS/SIEM/2FA；结论须标注。
- **ACL 标定**：RC-M4 的参数化完成后，其标定需要独立的实验设计（E1–E9 意图跟踪/策略效果），排在本方向 P7 之后。
- **论文影响**：因子相关论述若被更新，需与已提交的 Preprints 版本口径一致（保留 upper bound 限定，不回退数字）。

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
