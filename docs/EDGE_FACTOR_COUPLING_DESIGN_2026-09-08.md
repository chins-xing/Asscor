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
> `meta` 的三个可选溯源字段（`omitempty`，读取层不要求，Task 3B 起）：`weight_source` 只讲**权重口径**（`observed.effective_weights` 从哪来，以 `config_hash` 为锚点）；`ts_source` 只讲**链条目 `ts` 的基准**（新增独立字段 —— 此前 ts 基准被续写在 `weight_source` 末段，一个字段讲两件事；混用基准会造出"没人设计、也没人报告"的顺序，而数据看起来完全正常，故它必须有自己的槽位）；`assembly_error` 记装配期的非致命异常。

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

| 环境 | 角色 | 注意 |
|---|---|---|
| WSL2 Containerlab（14 节点真实拓扑） | 主战场，22+3 场景 | `clab destroy+deploy`；`.wslconfig` 限内存 8GB |
| A-1（Ubuntu，2c/3.4GB） | 重复性（每场景 3 次）+ 稳定性 | **agent ≤14**；曾因 24 进程压垮 sshd |

### 5.4 实验执行手册（Task 4 交付）

本节是**照着做就能复现**的执行面：脚本、参数、命令、门禁与失败语义。任何一条与脚本实现不一致，
以脚本为准并回头改本节 —— 手册与实现漂移过一次就会让"这份记录是怎么采的"永远说不清。

#### 5.4.1 交付物与落盘位置

| 交付物 | 路径 | 说明 |
|---|---|---|
| 实验模板 ×4 | `configs/edgeexp/{m0-baseline,vector,graph,chain}.ini` | 四份**只差** `[edge_factors.model]` 段；采集恒用 `m0-baseline.ini` |
| 复位脚本 | `lunwen/clab-lab/scripts/edge_reset.sh` | Caldera 就绪 + `clab destroy --cleanup` + `clab deploy` + sandcat agent 回连 |
| 攻击脚本 | `lunwen/clab-lab/scripts/edge_attack.sh <scenario> <out.json>` | 相位推进 + 固定剧本 + 客观结果（ground truth 的唯一来源） |
| 采集脚本 | `lunwen/clab-lab/scripts/edge_collect.sh <scenario> <config.ini> <attack.json> <run>` | 一条记录 + **因子集相等断言** + 门禁⓪ + 时钟核对 + 门禁② 残差 |
| 矩阵驱动 | `lunwen/clab-lab/scripts/edge_matrix.sh [场景…]` | 25 场景全量（无参数）或冒烟子集（给了场景名）；名单与 `edgescen -list` 逐项核对 |
| 阈值敏感性驱动 | `lunwen/clab-lab/scripts/edge_threshold_sensitivity.sh` | §5.4.6 的强制行；**只读**记录 + 配置 + 离线工具（不碰 clab/Caldera），故随时可补跑；**默认不跑**（`EDGEEXP_SENSITIVITY_THRESHOLDS` 显式开启） |
| `-factors`/`-weights` 推导 | `lunwen/clab-lab/scripts/edge_spec_lib.sh` | 被矩阵与敏感性驱动**共用**的函数库（单一来源：不在两个脚本里各抄一份 Python，否则两份报告可能用了不同的因子权重而看不出来） |
| 记录 | `lunwen/clab-lab/data/edgefactors/records-<env>-<date>.jsonl` | 每场景**一条**；门禁①/② 直接跑这份**全量**文件 |
| 被拒记录留档 | `.../data/edgefactors/run.d/rejected-<scenario>.jsonl` | 断言失败时该条记录**从数据集回滚**、但必须留痕的那一行 |
| 运行级证据 | `.../data/edgefactors/run.json`（+ `run-<run-id>.json` 副本） | 拓扑/剧本/配置哈希（两种精度）、权重口径、逐场景耗时、因子集相等断言、门禁⓪①②、时钟核对、记录条数（**含文件总行数**）、`threshold_sensitivity`（未跑时为 `null`） |
| 阈值敏感性产物 | `.../data/edgefactors/sensitivity/{report-threshold-<T>.md, .raw.md, .log, sensitivity.json}` | **显式 opt-in**（`EDGEEXP_SENSITIVITY_THRESHOLDS=60`）才产生；覆盖部署判定线，**不是**主对比报告，见 §5.4.6 |

#### 5.4.2 前置条件

1. **WSL2 `Containerlab` 发行版**：Docker + `clab`，拓扑 `lunwen/clab-lab/asscor.clab.yml`
   —— 实测 **18 个节点容器**（`asc-asscor-{edge0,host1..host12,r1..r5}`，拓扑里 `prefix: asc`）。
   **攻击侧只部署一个 sandcat agent（默认 `host1`）**，这直接决定了客观结果的口径：
   `nodes_affected ≡ 1`（多节点横向不在本手册的范围内）。
2. **Caldera v5** 在 `/opt/caldera`。`edge_reset.sh` 会自己**确保它在跑**：
   `./venv/bin/python server.py --fresh -P sandcat,stockpile,atomic`。
   `-P sandcat,stockpile,atomic` 必须显式给出 —— 缺插件列表时 `sandcat.go-linux` payload 不会被生成，
   而"没有 payload"会在第 4 步以一个看起来像网络问题的错误出现。
3. **两个 Linux 工具**（交叉编译，脚本默认读 `build/`）：
   ```bash
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags 'expr,engine,checks' -o build/edgescen  ./cmd/edgescen
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags edgeexp                -o build/edgecompare ./cmd/edgecompare
   ```
   `edgescen` 的最小 tag 集是 **`expr,engine,checks`**（三个都不可省：`engine` 给评分链、`checks` 给真实
   检查登记表、`expr` 是实验工具的构建约束）。
4. **模板纳入回归门禁**：`go test ./internal/config/ -run TestEdgeExpConfigTemplatesLoad` 必须绿 ——
   模板装不上要在 `go test` 阶段就红，而不是在 WSL 上跑完一轮采集之后。

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
`EDGEEXP_PHASE_GAP_S`（相位间隔，默认 3，**不得小于 1**）、`EDGEEXP_TARGET_HOST`（攻击目标节点，默认 `host1`）、
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
解析器只在 `[acceptability]` 里读它，写错段位是静默 no-op，见 §5.4.8）。
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
5. **采集器评的是"跑 `edgescen` 的那台主机"**：真实检查结果来自 `internal/checks` 在本机的执行，
   攻击侧（clab 节点上的 sandcat agent）只提供客观结果。故 R 组的"真实缺失"是在**采集主机**上核实的。
6. **A-1 的 3 次重复**是排序层方差用的（§5.3），不属于本手册的四脚本管线。重复运行时**必须同时**换
   `EDGEEXP_RUN_INDEX`（`run` 号）、`EDGEEXP_ENV`（例如 `EDGEEXP_ENV=a1-ubuntu`）与
   `EDGEEXP_RECORDS`（让每轮的记录各自成文件）。**`run>1` 而不给 `EDGEEXP_ENV` 会被直接拒绝** ——
   否则重复样本会被打上 `wsl-clab-14` 的标签混进主战场数据集，而那正是"重复性实验"最容易被读错的地方。
7. **先验边集里只有两条有直接证据，其余是假设**（措辞必须区分）：`EF-SELINUX ↔ EF-APPARMOR` 有实证
   （两者**共用触发检查 `OT-005`** → 同一次检查失败会同时激活），`EF-002FA ↔ EF-3FA` 有实证
   （既有的硬编码级联 `EF-3FA → EF-002FA`）。其余三条（`EF-NO-SIEM ↔ EF-NO-IDS`、
   `EF-SELINUX ↔ EF-002FA`、`EF-SYNCOOKIE ↔ EF-NO-IDS`）**是同域/同类的先验假设，尚无直接证据** ——
   报告与论文里必须这样标注，不得把它们写成"已证实存在的耦合"。

#### 5.4.8 lab 配置的键位纪律（每个键都要写在解析器**会读**的段里）

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

- **可信度被衰减两次**:`ssam-lib` 的 `ApplyEdgeFactorsToChecksPolicy` 已把因子值按可信度衰减一次（`factor = 1-(1-factor)·c`），而装配层 `ActivationFromResult` 又对同一个 `Factor` 再乘一次 `EffectiveFactor(·, c)`，合计为 `1-(1-f)·c²`。**这里说的是 legacy 与 V/G/C 之间的口径差**：同一个部署只能选一个模型，故它体现为"选 V/G/C 比选 legacy 多衰减一次"（`c²` vs `c`），**不是**"离线↔在线不一致" —— 后者对**同一个模型**在任意 `c` 下都成立（详见 §6 表）。可信度策略关闭（`c=1`）时两者恒等，故不影响"默认逐位一致"；但**一旦开启可信度策略，启用模型的惩罚强度会显著强于历史路径**。Task 8–10 的离线重算必须**复用同一口径**，并在标定报告中明确标注。引用时注意这是**衰减次数**的差，不是"同一个 `c` 数值"：两条路径的置信度归一化并不相同（legacy：`c<=0 或 c>1 ⇒ 1.0`；V/G/C 走 `NormalizeConfidence`：`<=0 ⇒ 默认值`、低于下限 `0.05` 抬到 `0.05`），故极端置信度下两侧的 `c` 数值本身也可能不同。是否修正（去掉重复衰减）属独立决策（会改评分）。
- **级联因子在 V/G/C 下不产生惩罚（`c_trigger = 0`）**：`EF-3FA → EF-002FA` 这类级联把 `EF-002FA` 压到 `0.82`，但该因子是"仅由级联激活"，`c_trigger = 0` ⇒ `EffectiveFactor(0.82, 0) = 1` ⇒ V/G/C 下 `a = (1−1)·v = 0`；而 legacy 路径**真的乘 0.82**。这是里程碑 A 的既有在线行为（本方向只如实记录、不改评分）。**后果**：spec §5 的 S5 组（级联 vs 独立）会表现为"V/G/C 忽略级联"，而准确表述是"**`c = 0` 的因子在可信度模型下不产生惩罚**"——标定报告必须这样写，否则 S5 的结论会被读错。

- **交互项可辨识性**：样本量限制下只用先验边集 + 正则；若结论不足，扩充 S2 至全 15 组 / 增加重复次数（A-1）。
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
- **阈值敏感性**：记录里的 `threshold` 来自部署配置（冒烟为 80.0，全部记录判"不可接受"⇒ 决策层指标退化）；`cmd/edgecompare -threshold` 提供**显式**敏感性覆盖（`0` = 用记录自带；>0 覆盖并在报告头/stderr 标注为敏感性值），**不得**把它当默认路径。


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
