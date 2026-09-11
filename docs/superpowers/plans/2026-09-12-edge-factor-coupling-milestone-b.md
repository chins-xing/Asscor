# 边缘因子耦合与变量化实现计划 — 里程碑 B（场景矩阵执行 + 拟合选模 + 文档口径）

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把方向② 的四候选（M0 legacy / V 逐域向量 / G 耦合图 / C 时序链）从"离线工具能算"推进到"用真实攻防实验数据选出部署模型"：先补齐**观测链的输出层承载**与**生产者/消费者共用的 JSONL 契约**，再实现采集器与 S0–S5(22)+R(3) 场景矩阵，最后用 `cmd/edgecompare` 拟合选模并把结论写进文档与论文口径。

**Architecture:** 生产侧只做三件事 —— ① `model.AssessmentResult` 增加"本次评分实际观测到的边缘因子链"（`omitempty`，默认路径输出逐位不变）；② 新增**无 build tag** 的 `internal/edgeexp` 承载 spec §5.1 的记录 schema 与存在性/值域校验（消费者 `cmd/edgecompare` 与生产者 `cmd/edgescen` 共用同一份，杜绝契约漂移）；③ `cmd/edgescen`（tag `expr`）在实验环境里按场景注入检查失败、跑真实攻击、把引擎评估与客观结果 join 成一条 JSONL。实验执行侧是脚本化的场景矩阵（WSL2 Containerlab 主战场、A-1 做 3 次重复），产出物是数据集 + 拟合报告 + 参数文件（**必须三件一起给**：`[edge_factors.model]` 段 + `[edge_factors]` 段 + JSONL，见 spec §5.2）。

**Tech Stack:** Go 1.26、build-tag 模块模式（`expr` / `edgeexp` / `engine`）、`internal/edgefactor`（无 tag 合成层）、`internal/engine`（tag engine 的真实评分入口）、Containerlab + Docker + Caldera（真实攻击剧本）、既有 `cmd/edgecompare`（离线重算/指标/拟合/报告）。

**Spec:** `docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md`（§5.1 记录 schema 与记录构造要求、§5.2 流程与可复现性、§5.3 环境分工、§6 验证策略、§8 P5–P7、§10.1/§10.2 已知口径）

**前置计划（已完成）:** `docs/superpowers/plans/2026-09-08-edge-factor-coupling.md`（里程碑 A：Task 1–10 + 2 独立任务，全部收口并推送）

## Global Constraints

- 分支 `ASSCOR-Research-Core`；提交说明必须**中文**（`feat(edgeexp): …` 前缀可保留英文分类词）；完成后同步 `main`（本地快进）并**两分支一起推送**。
- **默认行为不变（硬门禁）**：未配置 `[edge_factors.model]` 时评分与历史**逐位一致**；未启用必须零注册（不得注册"等价默认策略"）；显式 `model=legacy` 与"未配置"逐位一致（差别只在溯源输出）。新增输出字段一律 `omitempty`，不得改变任何既有 JSON 键的取值。
- **契约单一来源**：JSONL 的字段名/存在性/值域只允许有一份实现（本计划落在 `internal/edgeexp`），`cmd/edgecompare` 改为消费它；此前"文档 §5.1 与读取层各写一份"已经漂移过一次（示例被自己的解析器拒绝）。
- **记录构造要求**（spec §5.1，生产者必须满足，读取层不校验）：因子 ID 用**规范 ID**（`EF-SELINUX`，不是展示名）；`trigger_check` 与该因子在**当前部署解析出的**触发检查一致（内置因子 = `ResolveEdgeFactorTriggerMap`；`[edge_factors.custom]` 条目 = `[edge_factors.custom_triggers]` + `trigger.<ID>` 覆盖）；`c_trigger > 0` 时该检查必须以 `passed=false` 出现在 `checks[]`（**仅插件路径成立**：`c_trigger = 0` 的级联形态豁免，且 `model=legacy` 的 identity 分支激活时链上的 `trigger_check` 是登记值、未必是失败的那个检查 —— 详见 Task 2 Step 3）；`checks[].delta` **逐字**取自引擎检查登记表；`checks[]` 必须落盘引擎的**全部失败检查**；**引擎实际生效的逐域权重**写进记录（`observed.effective_weights`，键集 = 参与聚合的域），`meta.weight_source`/`config_hash` 说明其来源。
- **`c_trigger` 下界取 0**（不是 `(0,1]`）：`c_trigger = 0` 是"仅由级联激活、自身触发检查未失败"的既有形态（S5 组会产出）；被拒的是**缺失**。
- **`chain` 只能离线评估**：在线装配期对 `model=chain` fail-fast（引擎结果类型无时间字段）。C 模型的离线时间来源是记录里的 `edge_factor_chain[].ts`。
- **离线与在线共用同一评分公式**：`cmd/edgecompare` 直接调用内仓 `ssam.SSAMV20Formula`；参数在评分前按 `DefaultDomains ∩ λ` 一致裁剪；非默认域的 λ/向量键一律拒绝（在线装配期口径）。
- **可信度双衰减（spec §10.2，标定前必须处理）**：开启可信度策略时 V/G/C 的惩罚口径为 `1-(1-f)·c²`（legacy 为 `c`）；离线必须复用同一口径，并在报告里明确标注；**是否修正属独立决策（会改评分）**。
- **论文数字不可回退**：E1–E9 的意图跟踪准确率必须保留"理想测试环境上限（upper bound）"限定；本方向若触碰论文既有数字，只允许标注升级路径。
- **`ssam-lib` 是内嵌独立仓库**：改动必须提交内仓 `master` **并**同步外层快照；禁止内仓 `git checkout -- .`。
- **门禁命令**（每条任务的验收都要跑）：
  - 无 tag：`go build ./...`、`go vet ./internal/...`
  - 无 tag 测试：`go test ./internal/edgefactor/... ./internal/edgeexp/... ./internal/model/...`
  - 引擎线：`go test -tags "engine,assessor" ./internal/engine/... ./cmd/kernel/...`
  - 离线工具：`go test -tags edgeexp ./cmd/edgecompare/`（Windows 若被 Application Control 拦，用 `go test -c -o build/x.test.exe` 后**在包目录内**运行；`../../docs/` 是 cwd 相对路径）
  - 采集器：`go test -tags expr ./cmd/edgescen/`
  - gofmt：对**改动文件**做 LF 归一后 `gofmt -l`（Windows 下未归一会假阳性）

---

## 用户裁定门禁（开工前必须确认；未确认的项按"暂缓该分支"处理）

这 6 项会改变评分、启动语义或产出物内容，**不得由执行者自行决定**。它们与里程碑 B 的耦合点已写明，只有标 ✅ 的项真正阻塞开工。

| # | 待裁定 | 阻塞与否 |
|---|---|---|
| ① | legacy 覆盖分支权重来源是否统一到 `[edge_factors]`（字面量 0.88） | ❌ 不阻塞：M0 基线**不写模型段**，走的就是既有路径 |
| ② | "模型段存在但装配失败"是否升级为内核启动失败（现状只 WARN） | ⚠️ 半阻塞：S5/G/C 候选在实验环境出现装配失败时，WARN 会让场景被静默跳过 —— 采集器必须**显式记录装配失败**（Task 3 的 `meta.assembly_error`），否则实验会"少场景而人不知" |
| ③ | `chain` 在线不可用是否扩内仓时间戳字段（改内仓 `EdgeFactorResult`） | ❌ 不阻塞：本计划按"chain 离线专用"执行 |
| ④ | `EF-3FA`（纯级联、无 `[edge_factors]` 权重）是否加 `-factors` 放行开关 | ✅ **阻塞 S5**：不加开关，S5 的 `EF-3FA` 记录会被离线工具的覆盖校验拒掉，C 模型失去唯一现实依据 |
| ⑤ | 是否加 `.gitattributes`（`*.go text eol=lf`） | ❌ 不阻塞：仅影响本地 gofmt 假阳性频度 |
| ⑥ | `deploy/Makefile` 第三份 `MODULE_TAGS` 漂移（缺 `oscal,expr`）是否补齐 | ❌ 不阻塞：实验用 `scripts/build.sh` 的 tag 线 |
| ⑦ | 拟合器 IRLS 的 40 轮上限是否改为"未收敛即报错"（Task 10 遗留疑虑 3） | ❌ 不阻塞：本问题实测 6–12 轮收敛；Task 6 必须**报告每轮拟合的实际迭代数**，若出现触顶的边，该边结论一律标为"不可辨识" |

**M2/M3 口径**（Task 6/7 必须写进报告，否则会把辅助证据当成独立证据）：
- **M2**：`severityOf` 对未攻陷样本一律 0，而 `compromised` 又是 AUC 的标签 ⇒ Spearman/Kendall 很大程度在重测同一个二分类；真正含信息的是 **compromised 子集内**的序。报告必须写明。
- **M3**：`time_to_compromise_s` 缺失（=0）时 `severityOf` 给的是**最大**加成（`1000/(0+1)`），等于把"未知"当"瞬时攻陷"。**本计划的处理**：采集器把 `time_to_compromise_s` 列为**必填**（Task 3 的写出期断言），从而在数据侧消除该形态；排序层公式本身不动（改它会改既有报告数字）。

---

## File Structure

| 位置 | 动作 | 职责 |
|---|---|---|
| `internal/model/model.go` | 修改 | 新增 `EdgeFactorObservation` 类型 + `AssessmentResult.EdgeFactorChain []EdgeFactorObservation \`json:"edge_factor_chain,omitempty"\``（观测链落到输出层） |
| `internal/engine/ssam/engine.go` | 修改（tag engine） | `ComputeScore` 内把本次实际使用的 `edgeFactors`（含 ID / 触发检查 / `TriggerConfidence` / 观测值）与装载参数指纹一起写入输出 |
| `internal/engine/assessor.go` | 修改（tag engine/assessor） | legacy 路径 `evaluateEdgeFactorChain` 同样写出观测链（M0 基线的记录需要它） |
| `internal/kernel/persistence_types.go` | 修改（tag persistence） | `AssessmentRecord` 透出观测链（实验数据落盘） |
| `internal/edgeexp/record.go` | 新建（**无 tag**） | spec §5.1 记录的**唯一** schema：类型、`Validate()`、`MarshalRecord()`、字段路径化错误 |
| `internal/edgeexp/record_test.go` | 新建 | 契约用例（缺失/越界/规范化/round-trip），从 `cmd/edgecompare/load_test.go` 迁移 |
| `cmd/edgecompare/load.go` | 修改（tag edgeexp） | 改为消费 `internal/edgeexp`（删除本地重复 schema 与校验） |
| `cmd/edgecompare/docs_schema_test.go` | 修改 | 文档示例门禁指向 `internal/edgeexp` 的校验（口径不变、目标换源） |
| `cmd/edgescen/main.go` | 新建（tag `expr`） | 场景执行与采集：注入检查失败 → 跑真实攻击 → 取引擎评估 → join 客观结果 → 写 spec §5.1 JSONL |
| `cmd/edgescen/scenario.go` | 新建（tag `expr`） | 场景定义（S0–S5/R 的因子集与注入规格）与 `--scenario` 解析 |
| `cmd/edgescen/observe.go` | 新建（tag `expr`） | 通过 `internal/engine.Assessor` 取得评估（含观测链），并断言记录构造要求 |
| `cmd/edgescen/groundtruth.go` | 新建（tag `expr`） | 从攻击harness产物解析客观结果（`compromised`/`ttc`/`ttps`/`nodes`/`block_effective`） |
| `docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md` | 修改 | §5.1 指向 `internal/edgeexp`；§5.4 新增"实验执行手册"小节（场景脚本、复位流程、失败处理） |
| `configs/edgeexp/*.ini` | 新建 | 实验模板：M0 基线（**无** `[edge_factors.model]` 段）、V/G/C 候选模板（含 `lambda`/`vector`/`coupling`/`chain`） |
| `lunwen/clab-lab/scripts/` | 新建脚本 | `edge_*.sh`：场景矩阵驱动（clab 复位、注入、攻击、采集、落盘、日志） |
| `lunwen/clab-lab/data/edgefactors/` | 新建目录 | 数据集与报告归档（JSONL、拟合报告、参数文件） |

---

### Task 1: 观测链落到输出层（默认路径逐位不变）

**Files:**
- Modify: `internal/model/model.go:261-320`（`EdgeFactors` 旁新增类型与字段）
- Modify: `internal/engine/ssam/adapter_engine.go`（**填充点**：与溯源戳同一处、同一判据）
- Modify: `internal/engine/assessor.go:606-726`（legacy `evaluateEdgeFactorChain`）
- Modify: `internal/kernel/persistence_types.go:62-104`
- Test: `internal/model/edgefactor_chain_test.go`（新建）、`internal/engine/ssam/edgefactor_chain_test.go`（新建）、`internal/engine/assessor_chain_test.go`（新建）

**Interfaces:**
- Produces:
  - `model.EdgeFactorObservation{Factor string; TriggerCheck string; CTrigger float64; EffectiveFactor float64; TS string}` —— JSON 键依次为 `factor` / `trigger_check` / `c_trigger` / `effective_factor` / `ts`，与 spec §5.1 逐字一致。
  - `model.AssessmentResult.EdgeFactorChain []EdgeFactorObservation`（`omitempty`）。
  - `kernel.AssessmentRecord.EdgeFactorChain []model.EdgeFactorObservation`（`omitempty`）。
- Consumes（**不需要改内仓**）：
  - `ssam.AssessmentOutput.EdgeFactors []ssam.EdgeFactorResult` —— 内仓输出**已经**带着本次评分的逐因子结果（`ID` / `Name` / `Factor` / `Active` / `TriggerConfidence`），只是外层此前没把它写进 `model.AssessmentResult`。`EdgeFactorResult` **没有** `TriggerCheck` 字段，触发检查必须由外层用 `config.ResolveEdgeFactorTriggerMap(cfg)` 解析后补（这正是不该改内仓的理由：内仓不该知道配置层的触发映射）。
  - 现成测试辅助：`scoreAdapter(t, cfg, checks)`、`graphTestConfig()`、`factoryChecks()`、`provenanceChecks()`、`defaultTestEdgeFactors()`（都在 `internal/engine/ssam/*_test.go`）。

- [ ] **Step 1: 写失败测试（模型层）**

```go
// internal/model/edgefactor_chain_test.go
package model_test

func TestEdgeFactorChainIsOmittedWhenEmpty(t *testing.T) {
	var r model.AssessmentResult
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "edge_factor_chain") {
		t.Fatalf("零值必须不输出（默认路径的历史 JSON 一个字节都不能变）: %s", raw)
	}
}

func TestEdgeFactorChainSerializesSpec51Keys(t *testing.T) {
	r := model.AssessmentResult{EdgeFactorChain: []model.EdgeFactorObservation{{
		Factor: "EF-SELINUX", TriggerCheck: "OT-005",
		CTrigger: 0.9, EffectiveFactor: 0.82, TS: "2026-09-12T10:00:03Z",
	}}}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"factor":"EF-SELINUX"`, `"trigger_check":"OT-005"`, `"c_trigger":0.9`, `"effective_factor":0.82`, `"ts":"2026-09-12T10:00:03Z"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("输出缺少 spec §5.1 的键 %s：%s", key, raw)
		}
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/model/ -run TestEdgeFactorChain -v`
Expected: FAIL —— `undefined: model.EdgeFactorObservation`

- [ ] **Step 3: 实现模型层**

```go
// internal/model/model.go（紧接 EdgeFactors 之后）

// EdgeFactorObservation 是一次评分中**实际观测到**的边缘因子链条目
// （spec §5.1 的 observed.edge_factor_chain[]）。
//
// 为什么必须在输出层承载它：实验记录要把"引擎这次到底用了哪些因子、各自被哪个检查
// 触发、可信度多少、观测值多少"写进 JSONL，而离线重算（尤其 chain 模型）与审计复现
// 都以此为唯一输入。此前这些信息只存在于评分过程的输出结构里
// （ssam.AssessmentOutput.EdgeFactors），外层只把它折算成六个数值权重，采集器无从取得。
//
// 口径：EffectiveFactor 是**在线观测值**（内仓策略层已按可信度衰减一次的值，即
// edgeFactorResult.Factor）；CTrigger 是触发检查的可信度；TS 是该条观测的时间戳
// （空串合法，见 spec §5.1 必填表 —— chain 模型要求非零）。
type EdgeFactorObservation struct {
	Factor          string  `json:"factor"`
	TriggerCheck    string  `json:"trigger_check"`
	CTrigger        float64 `json:"c_trigger"`
	EffectiveFactor float64 `json:"effective_factor"`
	TS              string  `json:"ts"`
}
```

并在 `AssessmentResult` 里加：

```go
	// EdgeFactorChain 是本次评分实际观测到的因子链（omitempty：默认路径不输出，
	// 既有 JSON 逐位不变）。见 EdgeFactorObservation 的注释。
	EdgeFactorChain []EdgeFactorObservation `json:"edge_factor_chain,omitempty"`
```

- [ ] **Step 4: 跑模型层测试**

Run: `go test ./internal/model/ -run TestEdgeFactorChain -v`
Expected: PASS

- [ ] **Step 5: 写引擎侧失败测试（关键：链必须与"实际用到的因子"同源）**

```go
// internal/engine/ssam/edgefactor_chain_test.go
//go:build engine

// 断言：配置了模型时输出链非空、每条都命中出厂触发表、值域合法。
func TestComputeScoreEmitsObservedFactorChain(t *testing.T) {
	cfg := graphTestConfig()                              // 既有夹具
	got := scoreAdapter(t, cfg, graphWiringChecks())      // 让 graph 的耦合边真的参与
	if len(got.EdgeFactorChain) == 0 {
		t.Fatal("配置了模型却没有输出观测链 —— 采集器将无法写 spec §5.1 的记录")
	}
	triggers := config.DefaultEdgeFactorTriggerMap()
	for i, ob := range got.EdgeFactorChain {
		if edgefactor.NormalizeFactorID(ob.Factor) != ob.Factor {
			t.Errorf("链上因子 %q 不是规范 ID", ob.Factor)
		}
		if want := triggers[ob.Factor]; ob.TriggerCheck != want {
			t.Errorf("链[%d] %s 的 trigger_check = %q，出厂表是 %q", i, ob.Factor, ob.TriggerCheck, want)
		}
		if ob.CTrigger < 0 || ob.CTrigger > 1 {
			t.Errorf("链[%d] c_trigger = %v 越界", i, ob.CTrigger)
		}
		if ob.EffectiveFactor <= 0 || ob.EffectiveFactor > 1 {
			t.Errorf("链[%d] effective_factor = %v 越界", i, ob.EffectiveFactor)
		}
		if ob.TS == "" {
			t.Errorf("链[%d] 缺时间戳 —— chain 模型离线评估要求非零 ts", i)
		}
		if _, err := time.Parse(time.RFC3339, ob.TS); err != nil {
			t.Errorf("链[%d] 的 ts 不是 RFC3339: %q", i, ob.TS)
		}
	}
}

// 反向对照一：未配置模型段时不得输出链（"零值不输出"这条硬门禁）。
func TestComputeScoreEmitsNoChainWhenUnconfigured(t *testing.T) {
	cfg := &config.Config{EdgeFactors: defaultTestEdgeFactors()} // 与 provenance_test 情形 A 同款
	if got := scoreAdapter(t, cfg, provenanceChecks()); len(got.EdgeFactorChain) != 0 {
		t.Fatalf("未配置模型段却输出了观测链: %+v", got.EdgeFactorChain)
	}
}

// 反向对照二：链上的观测值必须**就是**评分乘上去的那个值 —— 用链自己重算总分，
// 必须与 final_score 逐位相同（这比"字段非空"强得多：它钉住链与评分同源）。
func TestChainReproducesTheScoreItDescribes(t *testing.T) { /* 见 Step 7 的口径说明 */ }
```

- [ ] **Step 6: 跑测试确认失败**

Run: `go test -tags "engine,assessor" ./internal/engine/ssam/ -run TestComputeScoreEmits -v`
Expected: FAIL —— `got.EdgeFactorChain undefined`

- [ ] **Step 7: 在适配层回填（与溯源戳同一处、同一判据）**

填充点=**已经在做"引擎是否真的装载了模型"判断的那一处**（`internal/engine/ssam/adapter_engine.go`，`LoadedEdgeFactorParams()` 的分支，紧邻现有 `result.EdgeFactors.Model/ParamsHash` 盖戳），因为两者是同一个判据的两种落地：没装载就既不该盖戳、也不该输出链。伪码（实现者按该文件既有风格写，参数名以实际签名为准）：

```go
if p, loaded := a.engine.LoadedEdgeFactorParams(); loaded {
	result.EdgeFactors.Model = string(p.Model)
	result.EdgeFactors.ParamsHash = p.Hash()

	// 观测链：来源是本次评分**自己的输出**（ssam.AssessmentOutput.EdgeFactors），
	// 触发检查来自配置层解析结果 —— 两者都不是"再看一眼配置"推出来的。
	triggers := config.ResolveEdgeFactorTriggerMap(a.confCfgPtr())
	now := time.Now().UTC().Format(time.RFC3339)
	chain := make([]model.EdgeFactorObservation, 0, len(output.EdgeFactors))
	for _, f := range output.EdgeFactors {
		if !f.Active {
			continue
		}
		id := NormalizeFactorID(f.ID)
		chain = append(chain, model.EdgeFactorObservation{
			Factor:          id,
			TriggerCheck:    triggers[id],
			CTrigger:        f.TriggerConfidence,
			EffectiveFactor: f.Factor,
			TS:              now,
		})
	}
	result.EdgeFactorChain = chain
}
```

**三条必须在实现时确认的口径**（写进代码注释）：
1. `EffectiveFactor` 写的是**在线观测值**（内仓策略层已衰减一次的值 = `f.Factor`）。对 V/G/C 而言装配层会再衰减一次（`c²`）—— 这是 spec §10.2 的已知问题，**记录仍写观测值**，理由：记录描述"引擎看到了什么"，口径差由离线重算与报告负责标注。
2. `TS` 取**评分时刻**（本进程时间），不是检查的采集时刻 —— `model.CheckResult` 没有时间字段。它满足 chain 模型"要求非零时间戳"的前提；同一场景内的相对顺序由写出顺序保证，**报告必须写明该口径**。
3. `output.EdgeFactors` 里 `Active == false` 的项**不写进链**（它们没有产生任何惩罚，写进去会让离线重算凭空产生惩罚 —— 与 Task 8 的"丢弃未建模因子"是同一类纪律）。`TriggerCheck` 用解析后的触发表查得；查不到（自定义因子）留空并在报告里计入"无法追溯来源的因子"计数。

- [ ] **Step 8: legacy 路径同样写出链**

在 `internal/engine/assessor.go` 的 `evaluateEdgeFactorChain` 内，因子映射完成后回填 `result.EdgeFactorChain`（用同一份 `ResolveEdgeFactorTriggerMap(a.cfg)` 解析触发检查、`EffectiveFactor` 写 legacy 实际乘上去的那个值），并加用例：

```go
// internal/engine/assessor_chain_test.go
//go:build engine

func TestLegacyAssessmentEmitsObservedFactorChain(t *testing.T) {
	res := evalTriggers(t, /* 既有辅助：真实调用 evaluateEdgeFactorChain */)
	if len(res.EdgeFactorChain) == 0 {
		t.Fatal("legacy 路径也要输出观测链（M0 基线记录需要它）")
	}
	for _, ob := range res.EdgeFactorChain {
		if ob.EffectiveFactor <= 0 || ob.EffectiveFactor > 1 {
			t.Errorf("legacy 链的 effective_factor = %v 越界（应当是 legacy 实际乘上去的那个值）", ob.EffectiveFactor)
		}
	}
}
```

- [ ] **Step 9: 持久化透出**

在 `internal/kernel/persistence_types.go` 的 `AssessmentRecord` 增加同名字段并在构造处赋值（`json:"edge_factor_chain,omitempty"`），补一条持久化往返用例（`internal/kernel/` 下既有 store/持久化测试文件）。

- [ ] **Step 10: 全门禁 + 提交**

Run:
```
go build ./... && go vet ./internal/...
go test ./internal/model/...
go test -tags "engine,assessor" ./internal/engine/... ./cmd/kernel/...
```
Expected: 全绿；**并且**里程碑 A 的两条硬门禁仍绿（出厂夹具冻结值 `73.9`、取整半格 `50.31` vs "等价默认策略" `50.32`）。

```bash
git add internal/model internal/engine internal/kernel
git commit -F build/commit-msg.txt   # 中文说明：feat(edgefactor): 观测链落到输出层（默认路径逐位不变）
```

---

### Task 2: 共享 JSONL 契约包 `internal/edgeexp`（生产者/消费者单一来源）

**Files:**
- Create: `internal/edgeexp/record.go`、`internal/edgeexp/record_test.go`
- Modify: `cmd/edgecompare/load.go`（改为消费新包）、`cmd/edgecompare/load_test.go`（迁出契约用例）
- Modify: `cmd/edgecompare/docs_schema_test.go`（门禁目标换源）

**Interfaces:**
- Produces（`package edgeexp`，**无 build tag**）:
  - `type Record struct{ ScenarioID string; Factors []string; Injection string; Observed Observed; GroundTruth GroundTruth; Meta Meta }`
  - `type Observed struct{ DomainScores map[string]float64; EffectiveWeights map[string]float64; FinalScore float64; Acceptable bool; Threshold float64; SPCScore float64; ThreatCoeff float64; Checks []CheckObs; EdgeFactorChain []ChainObs }` —— `effective_weights`（JSON 键 `effective_weights`）是 Task 1 实现者实测出来的**必需补充**：①legacy 的内在层加权用 `DynamicScoringEngine` 的**动态权重**（0 权重域会填默认值并 `Normalize(100)`），故"配置权重 ≠ 生效权重"，只凭配置复算会有系统偏差；②`DomainScores` 的核心域字段恒存在，记录无法区分"该域参与聚合但值为 0"与"该域不在聚合里"。故键集 = "参与聚合的域"，值 = 引擎实际使用的权重。**在 `Validate` 里是可选**（否则既有 `cmd/edgecompare` 夹具会红，破坏 Task 2 的"既有用例一条不改仍全绿"验收），但 **Task 3 的采集器必须写它**（生产者自检断言），Task 4 的 round-trip 门禁以它为准。
  - `type CheckObs struct{ ID, Domain string; Passed bool; Delta, Confidence float64; TS string }`
  - `type ChainObs struct{ Factor, TriggerCheck string; CTrigger, EffectiveFactor float64; TS string }`
  - `type GroundTruth struct{ Compromised bool; TimeToCompromiseS int; TTPsAchieved, NodesAffected int; BlockEffective bool }`
  - `type Meta struct{ Env, PlaybookHash, ConfigHash string; WeightSource string; Run int; Timestamp string; AssemblyError string }`
  - `func (r Record) Validate() error` —— 存在性 + 值域 + **记录构造要求**（见 Global Constraints）；错误一律带字段路径。
  - `func LoadFile(path string) ([]Record, error)`、`func MarshalRecord(r Record) ([]byte, error)`（单行 JSONL、无 BOM、`\n` 结尾）。
- Consumes: 无（纯类型 + 标准库）。

- [ ] **Step 1: 迁移契约用例（先红）**

把 `cmd/edgecompare/load_test.go` 里的**校验类**用例（`TestLoadRecordsRejectsMissingSPCScore`、`…RejectsMissingThreshold`、`…RejectsMissingCTrigger`、`…RejectsEmptyDomainScores`、`…RejectsMissingCompromised`、`…AcceptsBoundaryChainValues`、`…RejectsOutOfRangeChainValues`、`…RejectsUnparsableTimestamp`、`…ReportsBadLine` 等）逐个改写成 `internal/edgeexp/record_test.go` 里的 `TestValidate*`，断言口径逐条不变：

```go
// internal/edgeexp/record_test.go
func TestValidateRejectsMissingSPCScore(t *testing.T) {
	r := validRecord()
	r.Observed.spcScoreSet = false // 同包内部测试：直接操作存在性标记
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "spc_score") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("缺失必须被拒且理由指向『缺失』（只报字段名的写法抓不到存在性校验被放宽）: %v", err)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/edgeexp/ -v`
Expected: FAIL —— 包与类型都不存在

- [ ] **Step 3: 实现 `record.go`**

从 `cmd/edgecompare/load.go` **逐字搬迁**现有语义（不要重写：那些注释记录了每一处判据的失败后果），仅做两处必要改动：
- 类型与函数改为导出（`Validate`/`LoadFile`/`MarshalRecord`），字段名与 JSON tag 不变；
- 新增 `Meta.WeightSource` 与 `Meta.AssemblyError` 两个可选字段（Task 3 需要；`omitempty`），以及 `Validate` 里的**记录构造要求**检查：
  - `Observed.EdgeFactorChain[i].Factor` 必须满足 `edgefactor.NormalizeFactorID(id) == id`（规范 ID）；
  - 因子 ID 不得只有大小写不同（折叠冲突会静默合并）；
  - `checks[]` 必须包含所有 `c_trigger > 0` 的链条目对应的 `trigger_check` 且 `passed == false` —— **但这条只能对插件路径（V/G/C）成立，不得对 `model=legacy`（无模型段）记录硬失败**（Task 1 实现者实测）：legacy 保留 *identity 分支*（检查 ID 恰等于因子 ID 时直接激活该因子）与级联写值，此时链上的 `trigger_check` 是"该因子**登记的**触发检查"，**未必**是真正失败的那个检查（例：identity 检查 `EF-002FA` 失败时链上写的是登记值 `EF-001`）。故实现上把它做成"插件路径记录"的构造要求，并在注释里写明"**任何消费者都不得用 `trigger_check` 反推 `checks[]`**"；`checks[]` 的穷尽性（落盘引擎的**全部失败检查**）是它的前提，不是读取层的校验项。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/edgeexp/ -v`
Expected: PASS

- [ ] **Step 5: 让 `cmd/edgecompare` 消费新包**

`cmd/edgecompare/load.go` 缩减为薄封装（保留 `Record = edgeexp.Record` 之类的类型别名与 `LoadRecords(path)` 转发，保证 `main.go`/`metrics.go`/`fit.go` 零改动），删除本地重复的 schema 与 `validateRecord`。既有 33+ 用例必须**一条不改**地全绿 —— 那是"搬迁未改变行为"的证据。

Run: `go test -tags edgeexp ./cmd/edgecompare/`
Expected: PASS（含 `docs_schema_test.go` 的文档示例门禁）

- [ ] **Step 6: 补一条"生产者-消费者同源"门禁**

```go
// internal/edgeexp/record_test.go
// 同一份记录，MarshalRecord → LoadFile 必须逐位往返（生产者的写出与消费者的读入
// 不是两份实现，而是同一个 Validate 的两端）。
func TestMarshalLoadRoundTrip(t *testing.T) { /* 用 spec §5.1 示例记录构造 Record，断言往返 DeepEqual */ }
```

- [ ] **Step 7: 提交**

```bash
git add internal/edgeexp cmd/edgecompare
git commit -F build/commit-msg.txt   # refactor(edgeexp): JSONL 契约下沉为共享包（生产者/消费者单一来源）
```

---

### Task 3: 采集器 `cmd/edgescen`（组装记录 + 严格写出）

**Files:**
- Create: `cmd/edgescen/main.go`、`cmd/edgescen/scenario.go`、`cmd/edgescen/observe.go`、`cmd/edgescen/groundtruth.go`、`cmd/edgescen/main_test.go`
- Modify: `.github/workflows/ci.yml`、`scripts/build.sh`（把 `cmd/edgescen` 纳入构建/测试行，与 `cmd/edgecompare` 同款两行）

**Interfaces:**
- CLI：`edgescen --scenario S2-selinux-apparmor --config configs/edgeexp/vector.ini --out data/edgefactors/records.jsonl --run 1 --attack-out <攻击harness的JSON> --env wsl-clab-14`
- Produces: 一行一条 spec §5.1 JSONL（经 `edgeexp.MarshalRecord`），并打印自检摘要（场景数/因子数/权重来源/装配错误）。
- Consumes: `internal/engine.Assessor`（`NewAssessor(cfg)` / `AssessFromResults(host, hostname, []model.CheckResult)`）、`edgeexp.Record`、`config.Load`。

- [ ] **Step 1: 场景定义先落表（TDD 的第一块）**

```go
// cmd/edgescen/scenario.go
var scenarios = map[string]scenarioSpec{
	"S0-baseline":            {Factors: nil},
	"S1-selinux":             {Factors: []string{"EF-SELINUX"}},
	"S1-apparmor":            {Factors: []string{"EF-APPARMOR"}},
	"S1-syn-cookie":          {Factors: []string{"EF-SYNCOOKIE"}},
	"S1-no-siem":             {Factors: []string{"EF-NO-SIEM"}},
	"S1-no-ids":              {Factors: []string{"EF-NO-IDS"}},
	"S1-2fa":                 {Factors: []string{"EF-002FA"}},
	"S2-selinux-apparmor":    {Factors: []string{"EF-SELINUX", "EF-APPARMOR"}},   // 同源耦合（共用 OT-005）
	"S2-selinux-no-ids":      {Factors: []string{"EF-SELINUX", "EF-NO-IDS"}},
	"S2-no-siem-no-ids":      {Factors: []string{"EF-NO-SIEM", "EF-NO-IDS"}},
	"S2-syn-cookie-no-siem":  {Factors: []string{"EF-SYNCOOKIE", "EF-NO-SIEM"}},
	"S3-selinux-apparmor-2fa":{Factors: []string{"EF-SELINUX", "EF-APPARMOR", "EF-002FA"}},
	"S4-all":                 {Factors: []string{"EF-002FA", "EF-SYNCOOKIE", "EF-SELINUX", "EF-APPARMOR", "EF-NO-SIEM", "EF-NO-IDS"}},
	"S5-cascade-3fa":         {Factors: []string{"EF-3FA"}, CascadeTo: "EF-002FA"},
	"S5-2fa-only":            {Factors: []string{"EF-002FA"}},
	"R-no-ids":               {RealMissing: []string{"ids"}},
	"R-no-siem":              {RealMissing: []string{"siem"}},
	"R-no-2fa":               {RealMissing: []string{"2fa"}},
}
```

**必须补齐到 spec §5 的 22 组**：S1 六组（六个因子各一）、S2 优先同源/可疑耦合共 8 组（上表 4 组之外再补 4 组，从 15 组里按"同域/共触发/级联相关"挑）、S3 四组（含 `EF-3FA` 三方组）、S4 一组、S5 两组（级联 vs 单独）+ R 三组。**表里的每一项都必须有 `--scenario` 名对应的可执行注入规格**，不留占位。

- [ ] **Step 2: 注入与观测（先写失败用例）**

```go
// cmd/edgescen/main_test.go
//go:build expr

// mustLoadConfig 走生产解析层装载实验模板（cmd/edgescen 的 cwd 是包目录，
// 故路径相对 `../../configs/`）；装载失败即 Fatal —— 模板本身是 Task 4 的产物，
// 这里只断言"它能被真实解析器读懂"。
func mustLoadConfig(t *testing.T, rel string) *config.Config {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("装载 %s: %v", rel, err)
	}
	if cfg.EdgeFactorModel.Model == "" {
		t.Fatalf("%s 缺 [edge_factors.model] 段（除 M0 基线外，实验模板都必须有）", rel)
	}
	return cfg
}

// 注入规格必须产出"指定的检查失败 + 其余取真实结果"的检查集，且写出的记录能通过 edgeexp.Validate。
func TestScenarioInjectionProducesValidRecord(t *testing.T) {
	cfg := mustLoadConfig(t, "configs/edgeexp/vector.ini")
	gt := groundTruth{Compromised: true, TimeToCompromiseS: 213, TTPsAchieved: 4, NodesAffected: 3}
	rec, err := buildRecord(context.Background(), "S2-selinux-apparmor", cfg, gt, 1)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	if err := rec.Validate(); err != nil {
		t.Fatalf("写出的记录必须自检通过（生产者与消费者共用同一份契约）: %v", err)
	}
	if got := len(rec.Observed.EdgeFactorChain); got < 2 {
		t.Fatalf("S2 两个因子必须都有链条目，得到 %d", got)
	}
	for _, ob := range rec.Observed.EdgeFactorChain {
		if ob.TriggerCheck == "" || ob.CTrigger < 0 || ob.EffectiveFactor <= 0 || ob.TS == "" {
			t.Errorf("链条目字段不完整: %+v", ob)
		}
	}
	// 记录构造要求：**插件路径**（V/G/C）下，链上每个 c_trigger>0 因子的触发检查必须以
	// failed 出现在 checks[] 里。**这条只适用于插件路径** —— legacy（无模型段）保留 identity
	// 分支（检查 ID 恰等于因子 ID 时直接激活）与级联写值，此时链上的 trigger_check 是"登记的
	// 触发检查"、未必是失败的那个检查（Task 1 实现者实测）。故断言必须按产生该记录的模型分支
	// 分开写，且**绝不可用 trigger_check 反推 checks[]**（checks[] 是独立落盘的引擎失败检查全集）。
	failed := map[string]bool{}
	for _, ck := range rec.Observed.Checks {
		if !ck.Passed {
			failed[ck.ID] = true
		}
	}
	pluginPath := rec.Observed.EdgeFactorChain  // 采集器的插件路径记录
	for _, ob := range pluginPath {
		if ob.CTrigger > 0 && !failed[ob.TriggerCheck] {
			t.Errorf("链上 %s 的 c_trigger = %v > 0，但 %s 不在失败检查里 —— 记录自相矛盾", ob.Factor, ob.CTrigger, ob.TriggerCheck)
		}
	}
	// 另：`checks[]` 必须落盘引擎的**全部失败检查**（穷尽性），而不是"链上提到的那几条"。
	if len(rec.Observed.Checks) == 0 {
		t.Error("checks[] 为空 —— 记录构造要求是落盘引擎的全部失败检查")
	}
	// effective_weights 必须写出且与域分键集一致（Task 1 实测的动态权重/聚合域歧义）。
	if len(rec.Observed.EffectiveWeights) == 0 {
		t.Error("缺 observed.effective_weights —— 离线复算的权重口径无法还原（动态权重 ≠ 配置权重）")
	}
}

// 反向对照：装配失败（如 chain 在线、或 λ 未覆盖任何默认域）必须**显式记录**在
// meta.assembly_error 里并拒绝写出记录，而不是静默产出一条"未启用"的记录
// （否则实验会"少场景而人不知" —— 这也是用户裁定项②在数据侧的兜底）。
func TestAssemblyFailureIsRecordedNotSilentlyDropped(t *testing.T) { /* ... */ }
```

- [ ] **Step 3: 跑测试确认失败**

Run: `go test -tags expr ./cmd/edgescen/ -v`
Expected: FAIL —— `undefined: buildRecord`

- [ ] **Step 4: 实现三块逻辑**

- `observe.go`：`runChecks()` 取该主机真实检查结果（复用 `internal/checks` + `internal/engine.Assessor.Assess`），再按场景规格**强制指定检查失败**（`Passed=false`、`Delta` 取自引擎登记表、`Confidence` 取自可信度解析结果），然后调用 `AssessFromResults` 取得 `*model.AssessmentResult`；从 `result.EdgeFactorChain`（Task 1 交付）读观测链。
  **`ts` 必须由采集器按"该因子的注入/采集时刻"重写**（Task 1 评审实测发现的硬要求）：引擎侧链上所有条目的 `ts` 是**同一个评分时刻**（`adapter_engine.go:128`），而 chain 模型要求相邻观测严格递增（`synthesize.go:161-171` 用 `from.ts.Before(to.ts)`）⇒ 全部同值会让**所有有向耦合被跳过、C 候选退化成 V**。harness 知道每个检查的注入时刻 ⇒ 采集器把 `ts` 写成"该因子触发检查的注入时刻"（逐条不同、且反映真实先后）；**不得**为了"让 C 有东西可用"而编造递增时间。
  **`spc_score` / `threat_coeff` 的取值有唯一正确来源**（评审的越界观察，必须钉住）：**只允许**取 `result.SPCScore` 与 `result.ThreatCoeff` —— 它们就是引擎传给评分公式的 `RiskContext.Exposure` / `.Threat`（`internal/engine/ssam/engine.go` 的 `RiskContext{Exposure: output.SPCScore, Threat: output.ThreatCoeff}`）。**禁止**从 `internal/attck` 的 `predictedRisk.EnhancedThreat`（`internal/attck/attck.go:526` 恰好也叫 `threat_coeff`，但那是**另一个量**）取，也禁止自己算 —— 取错会让离线分数整体偏移而**所有门禁全绿**。为此实现一条**round-trip 钉桩**（见 Step 5 的门禁②）。
- `groundtruth.go`：解析攻击 harness 产物得到 `compromised`/`ttc`/`ttps`/`nodes`/`block_effective`；**`ttc` 缺失即报错**（M3 的数据侧处理）。
- `main.go`：装配 `edgeexp.Record`，调用链**必须**是 `Validate()`（读取层口径）→ `ValidateConstruction()`（记录构造：规范 ID、大小写折叠、触发关系）→ `CheckTriggerCrossReference()`（**仅插件路径记录**）→ `CheckEffectiveWeightsRecorded()` → `MarshalRecord()` 追加写出；任何一步失败都**不写半条记录**并返回非零退出码。**四条 Task 1 实测出来的硬要求**：
  - **必须写 `observed.effective_weights`**（引擎**实际生效**的逐域权重 —— legacy 内在层用 `DynamicScoringEngine` 的动态权重，0 权重域会被填默认值并 `Normalize(100)`），键集 = 参与聚合的域；否则离线复算的权重口径无法还原（Task 4 门禁②依赖它）。**存在性判据是 `len(...) > 0`**：空 map 会序列化成 `"effective_weights":null`。
  - **不得用 `trigger_check` 反推 `checks[]`**：`checks[]` 必须独立落盘引擎的**全部失败检查**。legacy（无模型段）的 identity 分支激活时，链上的 `trigger_check` 是**登记的**触发检查而未必是失败的那个（例：identity 检查 `EF-002FA` 失败、链上写登记值 `EF-001`）；`c_trigger = 0` 的级联写值同理。
  - **区分"未配置模型"与"有模型但本次无因子激活"**：两者在 JSON 上因 `omitempty` 同形（链为空），**必须读溯源戳**（`edge_factors.model` / `params_hash`），不得据链是否为空判断。
  - **每条记录都必须同时有溯源戳与非空观测链，否则拒绝写出**（Task 1 评审实测的 Important-2）：链只在**引擎真的装载了模型**时才回填（与盖戳同一判据），而**未装载**时（无模型段 / `model=chain` / 参数不可用）内仓默认路径**仍然用六因子乘分** ⇒ 会产出"**有惩罚、但链为空**"的记录；这种记录让离线复算（门禁②）**必然失败**，而且看起来像"这个场景没有因子生效"。故采集器必须断言"戳记存在 且 链非空"，不满足即报错退出（不允许"少一条链、静默继续"）。**这也是 M0 基线模板必须显式写 `model = legacy` 的原因**（见 Task 4 Step 1）：显式 legacy 与"未配置"评分逐位一致，但只有前者会装载并输出链。
  - **观测链是"列表不是映射"**：出厂 `configs/*.ini` 把同样的六个 ID 又写进 `[edge_factors.custom]`，解析层小写化后它们会成为**额外的**因子条目，归一化到同一个规范 ID ⇒ **同一条链里会出现两条 `EF-SELINUX`**（引擎确实乘了两次）。任何消费方都**不得**按因子 ID 去重或建 map（离线 `engineEdgeFactors` 已按列表处理；链时间戳建 map 的那处是 C 模型的既有退化输入，已在代码注释里说明）。

- [ ] **Step 5: 跑测试确认通过 + CI 接线**

Run: `go test -tags expr ./cmd/edgescen/ -v`
Expected: PASS

在 `.github/workflows/ci.yml` 与 `scripts/build.sh` 加两行（与 `cmd/edgecompare` 同款）：
```
go build -tags "$MODULE_TAGS" ./cmd/edgescen/
go test  -tags "$MODULE_TAGS" ./cmd/edgescen/
```

**场景设计必须给 C 候选留出可分辨的时间结构**（Task 1 评审实测）：若某场景的所有因子在同一时刻注入，则链上 `ts` 全同 ⇒ chain 的严格时间窗（`from.ts.Before(to.ts)`）全部被跳过 ⇒ **C 与 V 在这条数据上不可区分**。故：
- S5（级联 vs 独立）**天然是顺序注入**（先 `EF-002` 触发 3FA，再级联把 `EF-002FA` 压到 0.82），必须采集到两条不同时刻的观测；
- 另需**至少 2 组"分先后注入"的 S2/S3 子场景**（例如先 `EF-SELINUX` 再 `EF-APPARMOR`，或先 `EF-NO-IDS` 再 `EF-NO-SIEM`），并把注入时刻逐个写进 `run.json` 供采集器回填 `ts`；
- 其余场景仍可同时注入（C 应与 V 同分，这正是"无时间结构时 C 不该凭空变好"的**反向证据**）。

- [ ] **Step 6: 提交**

```bash
git add cmd/edgescen .github/workflows/ci.yml scripts/build.sh
git commit -F build/commit-msg.txt   # feat(edgescen): 场景采集器（注入检查失败 + 真实攻击结果 join 成 spec §5.1 记录）
```

---

### Task 4: 实验模板与场景矩阵脚本（WSL2 Containerlab，22+3 场景）

**Files:**
- Create: `configs/edgeexp/m0-baseline.ini`（**无** `[edge_factors.model]` 段）、`configs/edgeexp/vector.ini`、`configs/edgeexp/graph.ini`、`configs/edgeexp/chain.ini`
- Create: `lunwen/clab-lab/scripts/edge_reset.sh`、`edge_attack.sh`、`edge_collect.sh`、`edge_matrix.sh`
- Modify: `docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md`（新增 §5.4 实验执行手册）

**Interfaces:**
- Consumes: Task 3 的 `edgescen` 二进制（交叉编译 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 -tags expr`）。
- Produces: `lunwen/clab-lab/data/edgefactors/records-<env>-<date>.jsonl` + 每次运行的 `run.json`（拓扑哈希/剧本哈希/配置哈希/时间戳/退出码）。

- [ ] **Step 1: 模板配置先自我校验（含实验模板纳入既有回归门禁）**

**M0 基线模板必须显式写 `[edge_factors.model]` + `model = legacy`**（Task 1 评审实测）：显式 legacy 与"未配置"在**评分上逐位一致**（里程碑 A 裁定），但只有**装载了模型**的路径才会输出观测链 —— 若 M0 用"不写段"，记录会变成"有惩罚、链为空"，离线复算（门禁②）必然失败。故本计划的 M0 = **显式 legacy**，并把"不写段"留给"未启用部署"这一类，不作为实验基线。

实验模板不能只靠"实验跑起来才发现装不上"。把既有回归用例扩到 `configs/edgeexp/`（**一个包的改动**，不新造工具）：

```go
// internal/config/configs_templates_test.go 追加
// TestEdgeExpConfigTemplatesLoad 与 TestShippedConfigTemplatesLoad 同款：
// configs/edgeexp/*.ini 必须全部能被 Load 解析。
//
// 例外必须显式断言：m0-baseline.ini **必须**含 [edge_factors.model] 且 model = legacy
// （Task 1 评审实测：不写段 ⇒ 引擎不装载 ⇒ 记录"有惩罚、链为空" ⇒ 离线复算必然失败），
// 其余模板必须含该段且模型为四项之一。
func TestEdgeExpConfigTemplatesLoad(t *testing.T) {
	pattern := filepath.Join("..", "..", "configs", "edgeexp", "*.ini")
	paths, err := filepath.Glob(pattern)
	if err != nil || len(paths) == 0 {
		t.Fatalf("no edge experiment templates at %s (err=%v)", pattern, err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("实验模板必须能加载: %v", err)
			}
			if cfg.EdgeFactorModel.Model == "" {
				t.Error("实验模板必须声明 [edge_factors.model]（含 M0 基线的显式 legacy）—— 否则引擎不装载、记录没有观测链")
			}
			if filepath.Base(path) == "m0-baseline.ini" && cfg.EdgeFactorModel.Model != "legacy" {
				t.Errorf("M0 基线必须是显式 model = legacy，实际 %q", cfg.EdgeFactorModel.Model)
			}
		})
	}
}
```

Run: `go test ./internal/config/ -run TestEdgeExpConfigTemplatesLoad -v`
Expected: 先 FAIL（模板还没建）→ 建好模板后 PASS。

**同一提交还要修一处出厂模板的"静默 no-op"陷阱**（Task 1 复审顺带发现，已核代码）：7 份 `configs/*.ini` 把 `scoring_engine` 的说明与键写在 **`[extension_weights]`** 段（如 `configs/config.enterprise.ini:184-185`），而解析器**只在 `[weights]` 段**读它（`internal/config/config.go:221-226`；`[extension_weights]` 的循环只取数值，`config.go:365-370` 对非数值静默跳过）⇒ 运营者按出厂骨架取消注释并填 `legacy` 会得到一个**静默无效**的配置。修法：把该键（连同其注释）移到 `[weights]` 段，并加回归断言 —— ①`[weights] scoring_engine = legacy` 必须解析为 `cfg.ScoringEngine == "legacy"`；②**任何出厂模板都不得在解析器不读的段里声明该键**（用 `parseSections` 或直接断言各段内容）。这条与"出厂模板 check_deltas 符号写错"是同一类缺陷（模板说的位置/取值与实际解析不符），也是 Task 4 之后选择 M0 评分路径的前提。

**关键**：V/G/C 模板的 `lambda` 必须覆盖到默认域的子集且声明的向量覆盖全部 5 域（否则离线导出会被 `validateRenderable` 拒），`chain` 模板必须带 `chain.window_seconds > 0`。

- [ ] **Step 2: 复位脚本（每次场景从干净环境开始）**

```bash
# lunwen/clab-lab/scripts/edge_reset.sh
set -euo pipefail
cd "$(dirname "$0")/.."
clab destroy -t asscor.clab.yml --cleanup 2>/dev/null || true
clab deploy -t asscor.clab.yml          # 必须 destroy+deploy，不用 --reconfigure（不重建 veth）
./scripts/agent_deploy.sh               # 起 agent ≤14 个（A-1 上限）
```

- [ ] **Step 3: 攻击脚本（客观结果来源）**

固定攻击剧本（Caldera ability / Atomic Red Team），拓扑与剧本哈希入 `run.json`：
```bash
# lunwen/clab-lab/scripts/edge_attack.sh <scenario> <out.json>
# 1) 记录剧本哈希与拓扑哈希；2) 触发剧本；3) 轮询 agent 心跳判定 compromised；
# 4) 记录 time_to_compromise_s / ttps_achieved / nodes_affected / block_effective
```

- [ ] **Step 4: 采集脚本（join 成一条记录）**

```bash
# lunwen/clab-lab/scripts/edge_collect.sh <scenario> <config.ini> <attack.json> <run>
./build/edgescen --scenario "$scenario" --config "$config" \
  --attack-out "$attack" --out data/edgefactors/records-wsl-clab-14.jsonl \
  --run "$run" --env wsl-clab-14
```

- [ ] **Step 5: 矩阵驱动（22+3 场景，逐场景可中断续跑）**

```bash
# lunwen/clab-lab/scripts/edge_matrix.sh
set -euo pipefail
SCENARIOS=(S0-baseline S1-2fa S1-selinux ... R-no-2fa)   # 22+3 全列出，不留占位
for s in "${SCENARIOS[@]}"; do
  for cfg in m0-baseline vector graph chain; do
    ./scripts/edge_reset.sh
    ./scripts/edge_attack.sh "$s" "data/edgefactors/attack-$s.json"
    ./scripts/edge_collect.sh "$s" "configs/edgeexp/$cfg.ini" "data/edgefactors/attack-$s.json" 1
  done
done
```

**每次场景结束必须断言**：记录条数 == 4（四个候选各一条）× 场景数；任何 `edgescen` 非零退出即整轮失败（不"跳过继续"）。

- [ ] **Step 6: 数据完整性门禁（写入 spec §5.4）**

**门禁①** 工具能读全量记录、无 fail-fast：
```bash
./build/edgecompare -records data/edgefactors/records-wsl-clab-14.jsonl \
  -candidate m0=configs/edgeexp/m0-baseline.ini ... -weights attack_surface=35,business_continuity=25,operation_trust=25,resilience=15,kernel_security=10
```
Expected: 读出全部记录、无 fail-fast。

**门禁② round-trip 钉桩（`spc_score`/`threat_coeff` 取值来源的唯一保障）**：对**每一条**采集记录，用**记录自身的输入**（域分 + `spc_score` + `threat_coeff` + 链上 `effective_factor`）离线复算 `final_score`，必须与记录里的值相等。这条就是"E/T 取错则门禁会红"的那道闸门 —— 评审实测过：字段取错时所有其它门禁都是绿的。
```bash
# 实现方式：edgescen 写完后立刻自检（同一进程内用同一公式重算），
# 或在 edgecompare 的报告里输出逐条 |复算 − 记录| 的对比表并要求全零。
```
Expected: 逐条相等（浮点逐位或两位小数内相等，取整口径与引擎一致）。

- [ ] **Step 7: 提交（脚本 + 模板 + spec §5.4）**

```bash
git add configs/edgeexp lunwen/clab-lab/scripts docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md
git commit -F build/commit-msg.txt   # feat(edgeexp): 场景矩阵脚本与实验模板（S0–S5 + R 共 22+3 组）
```

---

### Task 5: A-1 重复性与方差（每场景 3 次）

**Files:**
- Create: `lunwen/clab-lab/scripts/edge_repeat.sh`、`lunwen/clab-lab/scripts/edge_variance.py`
- Produce: `lunwen/clab-lab/data/edgefactors/records-a1-<date>.jsonl`、`variance-report.md`

- [ ] **Step 1: 重复执行**（A-1：Ubuntu 2c/3.4GB，**agent ≤14**；历史教训：24 进程压垮 sshd）
```bash
# 每场景 3 次：run=1,2,3，其余参数与 WSL 完全一致（同一 config、同一剧本哈希）
```
- [ ] **Step 2: 方差报告**：对同一场景的 3 次重复，输出域分/final_score/因子观测值的极差与标准差，以及决策层判定是否翻转。
- [ ] **Step 3: 门禁**：**判定翻转的场景必须单独列出**并作为"环境敏感"标注进报告（不隐去、不取平均掩盖）。
- [ ] **Step 4: 提交**（脚本 + 方差报告）。

---

### Task 6: 拟合与选模（`cmd/edgecompare --fit`）

**Files:**
- Produce: `lunwen/clab-lab/data/edgefactors/fit-<date>.md`、`params-<date>.ini`（`[edge_factors.model]` 段）、`params-<date>-factors.ini`（`[edge_factors]` 段）
- Modify: `docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md`（§9 决策记录追加实测结论）

- [ ] **Step 1: 四候选对比（决策层主判据：漏判率 → 误阻断率 → AUC → 字典序）**
```bash
./build/edgecompare -records <全量数据集> \
  -candidate m0=... -candidate vector=... -candidate graph=... -candidate chain=... \
  -weights ... -report md -out fit-report.md
```
- [ ] **Step 2: 拟合**（先验边集 ≤5、L1/L2、交叉验证、自助法）
```bash
./build/edgecompare -records <全量> -fit -prior-edges data/edgefactors/prior-edges.txt ... 
```

**两条必须遵守的拟合纪律**（都来自 Task 10 的实测，违反会把结论变成假命题）：
- **`-l1` 默认关闭，且不得用它来"解释边强度"**：Task 10 Fix round 1 在共线夹具上实测到一个反直觉现象 —— **中等强度 L1 反而把耦合系数推高**（`n=20000`、真值 `c=0.4`：`l1=0 → 0.453`；`0.01 → 0.664`；`0.05 → 0.918`，同时主效应被压到 0）。机理是 L1 先罚掉主效应，交互列随即成为它们的代理。故"`L1 > 0 ⇒ 耦合更小`"在该设计上是**假命题**。若 Task 6 要在真实数据上启用 `-l1`，报告必须同时说明**共线性与罚项都对边系数有影响**，不得把系数大小直接读作"边强度"；`-l1` 的收缩语义只有在正交设计上才可精确断言（那是单测的范围）。
- **不得为了迁就实现而放宽偏置阈值**：`TestFitCouplingIsUnbiasedAcrossSeeds` 的 `0.08` 阈值是按"相对罚项下偏置 3.9σ 余量"选的（绝对罚项 4.4σ 超阈值）。相对罚项下把 `l2` 从 `0.01` 提到 `0.05` 会带来约 `+0.15` 的偏置 ⇒ 该用例会变红。**正确处置是复核默认值本身**（或重新论证阈值），而不是放宽阈值让绿灯回来。
- [ ] **Step 3: 结论口径**（**必须逐条写进报告**，否则结论不可引用）：
  - 选定模型的依据是**决策层**（漏判率/误阻断率），排序层与数值层只作辅助；
  - **M2**：排序层与标签同源（未攻陷样本 severity 恒 0，而 compromised 又是 AUC 标签）⇒ Spearman/Kendall 与 AUC 高度相关，不得当作独立证据；
  - **M3**：`ttc` 由采集器保证必填（数据侧已消除"未知=瞬时"）；
  - 单类别数据集（全是 compromised 或全不是）时 `AUC=0` 是**哨兵**，不是"完全反向"；
  - **可信度双衰减**（`c²`）若在实验中开启，必须在报告里标注"启用模型的惩罚强度显著强于历史路径"，并说明是否修正属独立决策；
  - **S5 级的读法**（Task 1 实测）：`EF-3FA` 的级联把 `EF-002FA` 压到 `0.82`，但该因子"仅由级联激活"⇒ `c_trigger = 0` ⇒ `EffectiveFactor(0.82, 0) = 1` ⇒ **V/G/C 下 `a = 0`（无惩罚），而 legacy 真的乘 0.82**。故 S5 的对照必须写成"**`c = 0` 的因子在可信度模型下不产生惩罚**"，**不得**写成"V/G/C 忽略了级联"——后者是错误结论（spec §10.2 已记）。
  - **C 与 V 不可区分时必须如实说**（Task 1 评审实测的时间结构问题）：若某场景的观测在时间上无先后（所有 `ts` 相同或先后不反映真实注入顺序），chain 的时间窗全部被跳过 ⇒ **C ≡ V**。此时报告必须写"**本数据集无法区分 C 与 V**"，**不得**因为 C 的某项指标略好就宣称 C 更优（那是浮点噪声或定序差异）。反向亦然：若 C 在**顺序注入**的场景上明显更差（时间窗把该有的耦合砍掉），那才是有信息量的结论。
  - **拟合优化的是分数的线性化代理，不是分数本身**（里程碑 A 最终修复报告遗留疑虑 2，已核代码）：`design()` 用的是**标量汇总**特征 `a_i = (1−eff_i)·Σ_d v_i[d]`（`fit.go` 的 `vectorMass`），而真实评分是**逐域** `L_d`/`P_d` 再乘各域分 —— 两者不同源。故拟合出的 `c_ij` 只是候选参数的**生成器**，报告**不得**声称"拟合更优 ⇒ 决策层更好"；唯一权威判据是用该参数跑**离线重算**后比决策层指标，且必须写明这层近似。
  - **`RenderConfigSection` 不含 `f_i`**（另一已知边界）："贴回配置段 + 同一 JSONL"**不是**完整复现包，必须再给 `[edge_factors]` 表（就是下面这条三件套）。
  - **共线性与罚项都会影响边系数**（Task 10 Fix round 1 实测）：22 个真实场景下特征列高度相关，`c_ij` 的点估计不能直接读作"耦合强度"；报告必须同时给出**点估计、自助法区间、以及"该边是否可辨识"的判断**（不可辨识要明说），并注明 `-l1`/`l2` 的取值对系数的影响方向不保证单调。
  - **合成数据的可恢复性 ≠ 真实场景的可辨识性**（Task 10 报告的遗留疑虑 4）：拟合器在合成数据上的无偏/一致只证明**估计量本身**没问题，22 个真实场景（含 A-1 重复）未必能辨识出耦合边；报告**不得**把 Task 10 的 `±0.25` 容差当作真实数据上的精度承诺，必须给出真实数据上的自助法区间与"哪些边可辨识"的明确结论（含"不可辨识"这一结论本身）；
  - **候选参数的 `f_i` 必须显式给出**：离线工具**不读** `[edge_factors]`（唯一来源是带 `engine` tag 的适配层，离线工具不能 import）⇒ 不传 `-factors` 时 CLI 只在 stderr 告警，而离线重算会退化为"不修正域分"。故 Task 6 的每一条对比命令都必须带 `-factors`，并把该段一并归档（就是下面这条三件套）。
  - 参数可复现性 = **`[edge_factors.model]` 段 + `[edge_factors]` 段 + JSONL** 三件齐出（spec §5.2）。
- [ ] **Step 4: 提交**（报告 + 两份参数文件 + spec §9 追加）。

---

### Task 7: 文档、论文口径与双分支同步

**Files:**
- Modify: `docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md`（P5–P7 结论、§5.4 实测记录、§10 已知问题更新）
- Modify: `docs/audits/TECHNICAL_DEBT_BACKLOG_2026-09-08.md`（债务状态更新）
- Modify（若论文涉及）: `lunwen/paper/*.tex`（**只允许**加标注与升级路径，**不得回退**既有数字；E1–E9 的 upper bound 限定必须保留）

- [ ] **Step 1: 债务与已知问题对账**：把本里程碑新发现的问题（含被评审记下但本轮未处理的项）逐条落到债务清单，标 Status/Decision。
- [ ] **Step 2: 论文影响判定**：若结论触达论文中"边缘因子/评分"相关表述，写一段"升级路径"说明；否则在报告里明确"无需改动论文"。**并处理两条必须在论文口径里说明的边界**（评审的越界观察，核过代码）：
  - **`threat_coeff` 无上界 ⇒ 总分可能 >100**：引擎公式是 `round2(0.5·base + 30·E + 20·T)`，`T = 1.4` 且 `base = 100`、`E = 1.0` 时得 `108`，而 `ssam-lib/ir.go:96` 的 `final_score ∈ [0,100]` 是**另一层**的约束。离线工具忠实复现引擎口径（这是 C1 裁定要求的），但**论文表格里出现 >100 的分数必须加脚注说明**，否则会被读成计算错误。
  - **排序层与标签同源（M2）**：与 Task 6 的口径一致，论文若引用 Spearman/Kendall 必须写明它测的是什么。
- [ ] **Step 3: 双分支同步与推送**
```bash
git push . ASSCOR-Research-Core:main      # 本地快进 main（不切分支）
git push origin ASSCOR-Research-Core && git push origin main
git fetch origin && git for-each-ref --format="%(refname) %(objectname:short)" refs/remotes/origin/
```
Expected: 两个远端 ref 与本地同点；工作树干净。

---

## Self-Review（写完后自查，已跑）

1. **Spec 覆盖**：§5.1 schema/记录构造要求 → Task 2（唯一来源）+ Task 3（生产者自检）；§5.2 流程与可复现性 → Task 6 Step 3；§5.3 环境分工 → Task 4/5；§6 验证策略（离线↔在线一致、性质测试、2⁶ 扫描）→ 里程碑 A 已交付，本计划在 Task 1/2 的回归门禁里继续跑；§8 P5–P7 → Task 4/5、Task 6、Task 7；§10.1/§10.2 → Global Constraints（chain 离线专用、双衰减标注）。
2. **占位符扫描**：无 "TBD/TODO/类似上文"；Task 4 Step 1/5 明确"22 组必须逐一列出、不留占位"，并把"补齐到 22 组"写成执行者的硬要求（S2 的 8 组需按同源/共触发/级联相关挑选，选择依据必须写进 §5.4）。
3. **类型一致性**：`model.EdgeFactorObservation`（Task 1）↔ `edgeexp.ChainObs`（Task 2）↔ `edgescen` 写出的 JSON 键（Task 3）三处的字段名/JSON 键逐字一致（`factor`/`trigger_check`/`c_trigger`/`effective_factor`/`ts`）；`edgeexp.Record` 与 `cmd/edgecompare` 的消费点通过类型别名衔接，避免二次 schema。
4. **用户裁定门禁**：仅 ④ 阻塞 S5，② 需要 Task 3 的 `meta.assembly_error` 兜底（已写进 Task 3 Step 2 的反向对照用例），其余四项不阻塞。
