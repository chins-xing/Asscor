//go:build expr && engine && checks

package main

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/checks"
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgeexp"
	"github.com/chins-xing/asscor/internal/model"
)

// ============================================================================
// 夹具：实验模板形状的配置 + 目标机检查登记表
// ============================================================================

// fixtureConfigINI 是**实验模板形状**的配置夹具。
//
// 为什么不直接读 `configs/edgeexp/vector.ini`：那几份模板是 **Task 4** 的交付物，本任务不创建
// 它们（任务书明确"不污染生产配置"、模板归 Task 4）。采集器的单元测试因此自带一份同形状的
// 夹具；`TestEdgeExpTemplatesAreConsumableWhenPresent` 会在模板真的落地后**立刻**把它们也拉进
// 门禁 —— 那时这条夹具与模板的一致性由 `internal/config` 的模板用例守住。
//
// 夹具刻意保留出厂部署的**真实形状**：`[edge_factors.custom]` 把同样六个 ID 又写了一遍
// （小写键），`[edge_factors.custom_triggers]` 给它们配触发检查 —— 这正是"链上会出现两条
// EF-SELINUX"的来源（见 TestChainIsAListNotAMap）。
const fixtureConfigINI = `[weights]
attack_surface = 35
business_continuity = 25
operation_trust = 25
resilience = 15

[extension_weights]
kernel_security = 10

[acceptability]
threshold = 60.0

[edge_factors]
two_factor_failure = 0.85
syn_cookie_disabled = 0.75
selinux_disabled = 0.80
apparmor_disabled = 0.82
no_siem = 0.90
no_ids = 0.88

[edge_factors.model]
model = legacy
p_floor = 0.50

[edge_factors.custom]
EF-002FA = 0.85
EF-SYNCOOKIE = 0.75
EF-SELINUX = 0.80
EF-APPARMOR = 0.82
EF-NO-SIEM = 0.90
EF-NO-IDS = 0.88
EF-3FA = 0.82

[edge_factors.custom_triggers]
EF-002FA = EF-001
EF-SYNCOOKIE = RS-005
EF-SELINUX = OT-005
EF-APPARMOR = OT-005
EF-NO-SIEM = RS-007
EF-NO-IDS = RS-006
EF-3FA = EF-002
`

// vectorModelSection 是 vector 候选的模型段（替换夹具里的 `[edge_factors.model]`）。
// 约束来自 `Params.Validate`：已声明的向量必须覆盖全部 5 个默认域且 Σ ≤ 1；
// `lambda.<domain>` 至少覆盖一个默认域（否则装配期 fail-fast）。
const vectorModelSection = `[edge_factors.model]
model = vector
p_floor = 0.50
lambda.attack_surface = 1.0
lambda.operation_trust = 1.0
lambda.resilience = 1.0
vector.EF-002FA = 0.2,0.2,0.2,0.2,0.2
vector.EF-SYNCOOKIE = 0.2,0.2,0.2,0.2,0.2
vector.EF-SELINUX = 0.2,0.2,0.2,0.2,0.2
vector.EF-APPARMOR = 0.2,0.2,0.2,0.2,0.2
vector.EF-NO-SIEM = 0.2,0.2,0.2,0.2,0.2
vector.EF-NO-IDS = 0.2,0.2,0.2,0.2,0.2
`

// writeFile 写一份夹具文件并返回路径。
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写夹具 %s: %v", name, err)
	}
	return path
}

// mustLoadConfig 走生产解析层装载实验模板。
//
// 装载失败即 Fatal —— 夹具本身不是 Task 4 的产物，但它必须能被**真实解析器**读懂：
// 采集器跑不起来的第一种形态就是"模板解析不过"。
func mustLoadConfig(t *testing.T, name, content string) *config.Config {
	t.Helper()
	cfg, err := config.Load(writeFile(t, name, content))
	if err != nil {
		t.Fatalf("装载 %s: %v", name, err)
	}
	return cfg
}

// fixtureConfig 返回带 `model = legacy` 模型段（M0 基线的显式形态）的夹具配置。
func fixtureConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := mustLoadConfig(t, "fixture-legacy.ini", fixtureConfigINI)
	if cfg.EdgeFactorModel.Model != "legacy" {
		t.Fatalf("夹具必须含 [edge_factors.model] 段（否则引擎不装载 ⇒ 没有溯源戳与观测链）")
	}
	return cfg
}

// fixtureWithoutModel 返回**没有** [edge_factors.model] 段的配置（"未启用部署"）。
func fixtureWithoutModel(t *testing.T) *config.Config {
	t.Helper()
	cut := strings.Index(fixtureConfigINI, "[edge_factors.model]")
	if cut < 0 {
		t.Fatal("夹具里找不到模型段，测试夹具已失效")
	}
	return mustLoadConfig(t, "fixture-nomodel.ini", fixtureConfigINI[:cut]+fixtureConfigINI[strings.Index(fixtureConfigINI, "[edge_factors.custom]"):])
}

// fixtureChainModel 返回 `model = chain` 的配置：chain 是**离线专用**模型（在线结果类型没有
// 时间字段，装配期即 fail-fast），引擎因此不会装载它 —— 采集器必须据此拒绝写出。
func fixtureChainModel(t *testing.T) *config.Config {
	t.Helper()
	return mustLoadConfig(t, "fixture-chain.ini", strings.Replace(fixtureConfigINI,
		"model = legacy\np_floor = 0.50", "model = chain\np_floor = 0.50\nchain.window_seconds = 300", 1))
}

// fixtureHostChecks 是"目标机真实检查结果"的夹具：登记表里六个触发检查 + 一个内核安全检查
// + 一个业务连续性检查，全部**通过**（只看注入出来的失败）。ID/域/delta 逐字取自
// `internal/checks/linux`：
//
//	EF-001 attack_surface 0｜EF-002 attack_surface 0｜OT-005 operation_trust -15
//	RS-005 resilience -5｜RS-006 resilience -10｜RS-007 resilience -6｜KS-001 kernel_security
//	BC-005 business_continuity
//
// 与真实登记表的**唯一**差异是 Platform 留空（真实条目写 "linux"）：部署目标机是 Linux，
// 而单元测试要在开发机（Windows）上跑，`Register` 会按 Platform 过滤掉 linux 条目。
func fixtureHostChecks() []model.CheckResult {
	items := fixtureCheckItems()
	out := make([]model.CheckResult, 0, len(items))
	for _, it := range items {
		out = append(out, it.Run())
	}
	return out
}

// hostChecksWithFailures 返回"目标机真实结果"，其中 ids 列出的检查**真实失败**
// （R 组的真实缺失对照就靠它：服务真的被停掉，检查自然失败，采集器不做注入）。
func hostChecksWithFailures(ids ...string) []model.CheckResult {
	host := fixtureHostChecks()
	bad := map[string]bool{}
	for _, id := range ids {
		bad[id] = true
	}
	for i := range host {
		if bad[host[i].CheckID] {
			host[i].Passed = false
		}
	}
	return host
}

// registerFixtureChecks 把夹具登记表装进引擎的**真实**注册表（`checks.Register`）——
// 采集器取宿主检查结果走的就是这张表，不在注册表里的检查无法被注入，采集器会明确报错。
//
// 这是"模拟目标机"的合法手段：用的是引擎自己的注册 API，与 `internal/checks/linux` 的 init
// 完全同一条路径。重复注册会被 `Register` 跳过（同名 ID 保留先到者），故夹具与真机并存时
// 以先到者为准 —— 用例只断言"必须出现"的因子，不依赖具体的先到者是谁。
func registerFixtureChecks() {
	fixtureOnce.Do(func() {
		checks.Register(fixtureCheckItems()...)
	})
}

var fixtureOnce sync.Once

func fixtureCheckItems() []model.CheckItem {
	return []model.CheckItem{
		{ID: "EF-001", Domain: model.DomainAttackSurface, Name: "双因素认证", Delta: 0, Check: alwaysPass},
		{ID: "EF-002", Domain: model.DomainAttackSurface, Name: "三因素认证", Delta: 0, Check: alwaysPass},
		{ID: "OT-005", Domain: model.DomainOperationTrust, Name: "SELinux/AppArmor", Delta: -15, Check: alwaysPass},
		{ID: "RS-005", Domain: model.DomainResilience, Name: "SYN Cookie防护", Delta: -5, Check: alwaysPass},
		{ID: "RS-006", Domain: model.DomainResilience, Name: "HIDS/NIDS部署", Delta: -10, Check: alwaysPass},
		{ID: "RS-007", Domain: model.DomainResilience, Name: "入侵告警配置", Delta: -6, Check: alwaysPass},
		{ID: "KS-001", Domain: model.DomainKernelSecurity, Name: "内核加固", Delta: -10, Check: alwaysPass},
		{ID: "BC-005", Domain: model.DomainBusinessContinuity, Name: "异地备份", Delta: -8, Check: alwaysPass},
	}
}

func alwaysPass() (bool, string) { return true, "fixture: pass" }

// newGroundTruth 构造一条客观结果。
//
// **必须**走这个构造器而不是写结构体字面量吗？—— 不是：`groundTruth` 是本工具自己的类型，
// 字面量完全合法。真正的约束在进记录的那一步：`edgeexp.GroundTruth` 的 `compromised`
// 存在性标记只由 `UnmarshalJSON` 设置（见 recordGroundTruth 的说明），故这里只是给用例一个
// 顺手的入口，避免每条用例都写全五个字段。
func newGroundTruth(compromised bool, ttc float64, ttps, nodes int, blockEffective bool) groundTruth {
	return groundTruth{
		Compromised:       compromised,
		TimeToCompromiseS: ttc,
		TTPsAchieved:      ttps,
		NodesAffected:     nodes,
		BlockEffective:    blockEffective,
		Injections:        map[string]time.Time{},
	}
}

// ============================================================================
// 场景表（spec §5 的 22 + 3 组）
// ============================================================================

// specGroupCounts 是 spec §5 的场景矩阵计数（S0–S5 = 22 组 + R = 3 组真实缺失对照）。
var specGroupCounts = map[string]int{
	"S0": 1, "S1": 6, "S2": 8, "S3": 4, "S4": 1, "S5": 2, "R": 3,
}

// TestScenarioTableMatchesSpecMatrix 钉住场景表的分组计数与可执行性。
//
// 为什么这条必须先红：场景表是采集器的**输入规格**，表里少一组、或某一组没有可执行的注入
// 计划，整轮实验就会"少场景而人不知"（报告照常打印、样本量与实验规模对不上）。
func TestScenarioTableMatchesSpecMatrix(t *testing.T) {
	got := map[string]int{}
	for name := range scenarios {
		group, _, ok := strings.Cut(name, "-")
		if !ok {
			t.Fatalf("场景名 %q 不是 <组>-<描述> 形式", name)
		}
		got[group]++
	}
	for group, want := range specGroupCounts {
		if got[group] != want {
			t.Errorf("%s 组场景数 = %d, want %d", group, got[group], want)
		}
	}
	for group := range got {
		if _, ok := specGroupCounts[group]; !ok {
			t.Errorf("表里出现了 spec §5 之外的组 %q", group)
		}
	}

	known := map[string]bool{}
	for _, id := range canonicalFactorIDs() {
		known[id] = true
	}
	for name, spec := range scenarios {
		for _, factors := range spec.Inject {
			for _, f := range factors {
				if !known[f] {
					t.Errorf("%s: 注入因子 %q 不是规范因子 ID", name, f)
				}
			}
		}
		for _, f := range spec.Factors {
			if !known[f] {
				t.Errorf("%s: 声明因子 %q 不是规范因子 ID", name, f)
			}
		}
		if len(spec.Inject) == 0 && len(spec.RealMissing) == 0 && name != "S0-baseline" {
			t.Errorf("%s: 既没有注入计划也没有真实缺失声明 —— 表里的每一项都必须对应可执行的注入规格，不留占位", name)
		}
		// 顺序注入的场景必须给 C 候选留出**可分辨的时间结构**（brief Step 5）：每个阶段
		// 至少要落到一个"别的阶段没用过"的检查上，否则拿不到 N 个不同时刻。
		// （阶段内部两个因子共用一个触发检查是正常的：EF-SELINUX 与 EF-APPARMOR 共用 OT-005
		//   正是 S2/S3 组要建模的同源耦合。）
		if len(spec.Inject) > 1 {
			distinct := map[string]bool{}
			for _, phase := range spec.Inject {
				for _, id := range resolvePhaseChecks(factorsOf(phase)) {
					distinct[id] = true
				}
			}
			if len(distinct) < len(spec.Inject) {
				t.Errorf("%s: %d 个注入阶段只落在 %d 个不同的触发检查上 —— 拿不到 %d 个不同时刻，C 会退化成 V",
					name, len(spec.Inject), len(distinct), len(spec.Inject))
			}
		}
	}
}

// factorsOf 把注入阶段原样返回（让上面那段读起来是"阶段 → 检查"的两步）。
func factorsOf(phase []string) []string { return phase }

// canonicalFactorIDs 是 spec §5 因子集：六个直接触发因子 + 级联因子 EF-3FA。
func canonicalFactorIDs() []string {
	return []string{"EF-002FA", "EF-SYNCOOKIE", "EF-SELINUX", "EF-APPARMOR", "EF-NO-SIEM", "EF-NO-IDS", "EF-3FA"}
}

// resolvePhaseChecks 用**出厂触发表**把一组因子解析成检查 ID（只用于场景表自检）。
func resolvePhaseChecks(factors []string) []string {
	triggers := config.ResolveEdgeFactorTriggerMap(nil)
	out := make([]string, 0, len(factors))
	for _, f := range factors {
		if tc := triggers[f]; tc != "" {
			out = append(out, tc)
		}
	}
	return out
}

// TestSequentialScenariosExistForTheChainModel 钉住"给 C 候选留时间结构"这条硬要求：
// S5 级联组必须是顺序注入，另有 ≥2 组 S2/S3 子场景分先后注入。
func TestSequentialScenariosExistForTheChainModel(t *testing.T) {
	var sequential []string
	for name, spec := range scenarios {
		if len(spec.Inject) > 1 {
			sequential = append(sequential, name)
		}
	}
	s2s3 := 0
	for _, name := range sequential {
		if strings.HasPrefix(name, "S2-") || strings.HasPrefix(name, "S3-") {
			s2s3++
		}
	}
	if !hasSequential(sequential, "S5-cascade-3fa") {
		t.Errorf("S5 级联组必须是顺序注入（先 EF-002 触发 3FA，再级联到 EF-002FA），实际顺序注入场景: %v", sequential)
	}
	if s2s3 < 2 {
		t.Errorf("至少需要 2 组分先后注入的 S2/S3 子场景，实际 %d 组（全部顺序注入场景: %v）", s2s3, sequential)
	}
}

func hasSequential(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// ============================================================================
// 注入与观测
// ============================================================================

// TestScenarioInjectionProducesValidRecord：注入规格必须产出"指定的检查失败 + 其余取真实结果"
// 的检查集，且写出的记录能通过 edgeexp.Validate。
func TestScenarioInjectionProducesValidRecord(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	gt := newGroundTruth(true, 213, 4, 3, false)
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
	pluginPath := rec.Observed.EdgeFactorChain // 采集器的插件路径记录
	for _, ob := range pluginPath {
		if ob.CTrigger > 0 && !failed[ob.TriggerCheck] {
			t.Errorf("链上 %s 的 c_trigger = %v > 0，但 %s 不在失败检查里 —— 记录自相矛盾", ob.Factor, ob.CTrigger, ob.TriggerCheck)
		}
	}
	// 另：`checks[]` 必须落盘引擎的**全部失败检查**（穷尽性），而不是"链上提到的那几条"。
	if len(rec.Observed.Checks) == 0 {
		t.Error("checks[] 为空 —— 记录构造要求是落盘引擎的全部失败检查")
	}
	// 链上至少要能分辨出"同源耦合"的两个因子（SELinux 与 AppArmor 共用 OT-005）。
	if !chainHasFactor(rec, "EF-SELINUX") || !chainHasFactor(rec, "EF-APPARMOR") {
		t.Errorf("S2-selinux-apparmor 的链上必须同时有 EF-SELINUX 与 EF-APPARMOR: %+v", rec.Observed.EdgeFactorChain)
	}
	// effective_weights 必须写出且与域分键集一致（Task 1 实测的动态权重/聚合域歧义）。
	if len(rec.Observed.EffectiveWeights) == 0 {
		t.Error("缺 observed.effective_weights —— 离线复算的权重口径无法还原（动态权重 ≠ 配置权重）")
	}
}

func chainHasFactor(rec edgeexp.Record, id string) bool {
	for _, ob := range rec.Observed.EdgeFactorChain {
		if ob.Factor == id {
			return true
		}
	}
	return false
}

// TestChainIsAListNotAMap（裁定 2）：链是**列表**，同一条链允许出现多条同一个因子 ID。
//
// 出厂 `configs/*.ini` 把同样六个 ID 又写进 `[edge_factors.custom]`（小写键），解析层不去重、
// ssam 按 ID 各留一份 ⇒ 引擎**确实乘了两次** ⇒ 链上两条 `EF-SELINUX`。任何按因子 ID 去重或
// 建 map 的消费方都会把这份真实观测压扁成一条（惩罚少算一次）。
func TestChainIsAListNotAMap(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	rec, err := buildRecord(context.Background(), "S1-selinux", cfg, newGroundTruth(true, 120, 3, 2, false), 1)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	count := 0
	for _, ob := range rec.Observed.EdgeFactorChain {
		if ob.Factor == "EF-SELINUX" {
			count++
		}
	}
	if count < 2 {
		t.Fatalf("出厂形状的配置下链上必须出现两条 EF-SELINUX（内置项 + [edge_factors.custom] 的同名项各自乘了一次），实际 %d 条: %+v",
			count, rec.Observed.EdgeFactorChain)
	}
	// factors 是**声明集合**（去重合法），链是列表 —— 两者口径不同，不得互相推导。
	if n := countFactor(rec.Factors, "EF-SELINUX"); n != 1 {
		t.Errorf("factors 是声明集合，同一个 ID 只该出现一次，实际 %d 次: %v", n, rec.Factors)
	}
	if len(rec.Factors) != countDistinct(rec.Observed.EdgeFactorChain) {
		t.Errorf("factors 必须与链上出现的因子集合一致（离线重算按 factors 建模）: factors=%v 链上集合=%v",
			rec.Factors, factorIDsOf(rec.Observed.EdgeFactorChain))
	}
}

func countFactor(ids []string, want string) int {
	n := 0
	for _, id := range ids {
		if id == want {
			n++
		}
	}
	return n
}

func countDistinct(chain []edgeexp.ChainObs) int {
	seen := map[string]bool{}
	for _, ob := range chain {
		seen[ob.Factor] = true
	}
	return len(seen)
}

func factorIDsOf(chain []edgeexp.ChainObs) []string {
	seen := map[string]bool{}
	var out []string
	for _, ob := range chain {
		if !seen[ob.Factor] {
			seen[ob.Factor] = true
			out = append(out, ob.Factor)
		}
	}
	return out
}

// TestChainCanLegitimatelyContainEF3FA（裁定 2 的第二半）：小写的 `[edge_factors.custom]`
// 重复条目**不是** CascadeOnly，故它们会以 `EF-3FA` 出现在真实链上；里程碑 A 的
// `edgefactor_chain_test.go` 断言的是"**内置** EF-3FA 不以 Active 出现"，两者不矛盾 ——
// 采集器不得因此认为链有问题（更不得把它过滤掉）。
func TestChainCanLegitimatelyContainEF3FA(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	// S5 是顺序注入场景：注入时刻是硬要求（裁定 3），故这里的 harness 必须报出两个阶段。
	gt := newGroundTruth(true, 300, 5, 3, true)
	gt.Injections = map[string]time.Time{
		"EF-002": time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC),
		"EF-001": time.Date(2026, 9, 8, 10, 0, 20, 0, time.UTC),
	}
	rec, err := assembleRecord(context.Background(), cfg, "S5-cascade-3fa", gt, 1, fixtureHostChecks())
	if err != nil {
		t.Fatalf("assembleRecord: %v", err)
	}
	if !chainHasFactor(rec, "EF-3FA") {
		t.Errorf("出厂形状配置下 EF-3FA 的 custom 条目会激活并上链（它不是 CascadeOnly），实际链: %+v", rec.Observed.EdgeFactorChain)
	}
	if !chainHasFactor(rec, "EF-002FA") {
		t.Errorf("级联目标 EF-002FA 必须在链上: %+v", rec.Observed.EdgeFactorChain)
	}
	// S5 的时间结构必须真的存在：EF-3FA 的观测（EF-002 注入）早于 EF-002FA 的直接触发（EF-001）。
	var ts3FA, ts2FA string
	for _, ob := range rec.Observed.EdgeFactorChain {
		switch ob.Factor {
		case "EF-3FA":
			ts3FA = ob.TS
		case "EF-002FA":
			ts2FA = ob.TS
		}
	}
	if ts3FA == "" || ts2FA == "" || ts3FA == ts2FA {
		t.Errorf("S5 级联组必须有两条不同时刻的观测（EF-3FA @ %q, EF-002FA @ %q）—— 否则 C 与 V 不可分辨", ts3FA, ts2FA)
	}
}

// TestChainTriggerConfidenceMatchesChecks：链上 `c_trigger`（因子被多大可信度的检查触发）
// 必须与该检查在 `checks[]` 里的 `confidence` 逐位相等 —— 两者是**同一个量**
// （`ApplyEdgeFactorsToChecksPolicy` 用 `NormalizeConfidence(check.Confidence, policy)` 做触发衰减）。
//
// 为什么要钉：`CheckResult.Confidence` 的原始值在 `[confidence]` 未启用时恒为 0（解析器是
// no-op），直接落盘会让 `checks[]` 看起来像"这次观测毫无可信度"，而引擎实际用的是 1.0 ——
// 记录与引擎口径不一致，且这种不一致在报告里完全看不出来。
func TestChainTriggerConfidenceMatchesChecks(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	rec, err := buildRecord(context.Background(), "S2-selinux-apparmor", cfg, newGroundTruth(true, 213, 4, 3, false), 1)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	byID := map[string]float64{}
	for _, ck := range rec.Observed.Checks {
		byID[ck.ID] = ck.Confidence
	}
	for _, ob := range rec.Observed.EdgeFactorChain {
		if ob.CTrigger <= 0 {
			continue
		}
		want, ok := byID[ob.TriggerCheck]
		if !ok {
			t.Fatalf("链上 %s 的触发检查 %s 不在 checks[] 里", ob.Factor, ob.TriggerCheck)
		}
		if ob.CTrigger != want {
			t.Errorf("%s 的 c_trigger = %v，而 checks[%s].confidence = %v —— 同一个量必须同值", ob.Factor, ob.CTrigger, ob.TriggerCheck, want)
		}
	}
}

// ============================================================================
// 时间戳（裁定 3）
// ============================================================================

// TestChainTimestampsComeFromHarnessInjections：链上 `ts` 必须是**该因子触发检查的注入时刻**，
// 由 harness 提供、逐条回填，而不是引擎的评分时刻。
//
// 为什么是硬要求：引擎侧链上所有条目的 `ts` 是同一个评分时刻（adapter_engine.go），而 chain
// 模型用 `from.ts.Before(to.ts)` 做严格时间窗 ⇒ 全部同值会让**所有有向耦合被跳过**、C 候选
// 退化成 V。harness 知道每个检查的注入时刻，采集器逐条回填即可；**不得**为了"让 C 有东西可用"
// 而编造递增时间（故这里同时断言回填值与 harness 逐位一致）。
func TestChainTimestampsComeFromHarnessInjections(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)

	t1 := time.Date(2026, 9, 8, 10, 0, 3, 0, time.UTC)
	t2 := time.Date(2026, 9, 8, 10, 0, 11, 0, time.UTC)
	gt := newGroundTruth(true, 213, 4, 3, false)
	gt.Injections = map[string]time.Time{"RS-007": t1, "RS-006": t2}

	rec, err := assembleRecord(context.Background(), cfg, mustScenario(t, "S2-no-siem-no-ids"), gt, 1, fixtureHostChecks())
	if err != nil {
		t.Fatalf("assembleRecord: %v", err)
	}
	want := map[string]string{
		"RS-007": t1.Format(time.RFC3339),
		"RS-006": t2.Format(time.RFC3339),
	}
	distinct := map[string]bool{}
	for _, ob := range rec.Observed.EdgeFactorChain {
		got, ok := want[ob.TriggerCheck]
		if !ok {
			continue
		}
		if ob.TS != got {
			t.Errorf("%s 的 ts = %q, want %q（该因子触发检查 %s 的注入时刻）", ob.Factor, ob.TS, got, ob.TriggerCheck)
		}
		distinct[ob.TS] = true
	}
	if len(distinct) != 2 {
		t.Fatalf("顺序注入场景必须采到两个不同时刻的观测（C 候选的可分辨输入），实际时刻集: %v\n链: %+v",
			distinct, rec.Observed.EdgeFactorChain)
	}
}

// TestSimultaneousInjectionKeepsOneTimestamp 是**反向证据**：同时注入（没有任何时间结构）的
// 场景，链上时刻就必须是同一个 —— C 与 V 在这条数据上不可区分是**如实结果**，不是缺陷。
// 若采集器"为了让 C 有东西可用"而自己造递增时间，本条立刻变红。
func TestSimultaneousInjectionKeepsOneTimestamp(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)

	at := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	gt := newGroundTruth(true, 213, 4, 3, false)
	gt.Injections = map[string]time.Time{"OT-005": at}

	rec, err := assembleRecord(context.Background(), cfg, mustScenario(t, "S2-selinux-apparmor"), gt, 1, fixtureHostChecks())
	if err != nil {
		t.Fatalf("assembleRecord: %v", err)
	}
	if len(rec.Observed.EdgeFactorChain) == 0 {
		t.Fatal("链为空")
	}
	for _, ob := range rec.Observed.EdgeFactorChain {
		if ob.TS != at.Format(time.RFC3339) {
			t.Errorf("同时注入的检查（%s）必须全部取同一个注入时刻，得到 %q", ob.TriggerCheck, ob.TS)
		}
	}
}

// TestMissingInjectionTimeIsAnAssemblyError：harness 没有报出某个注入检查的注入时刻时，
// 采集器**不得**悄悄回落到评分时刻（那会让该场景的时间结构与"同时注入"同形），
// 而是显式拒绝写出。
func TestMissingInjectionTimeIsAnAssemblyError(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	gt := newGroundTruth(true, 213, 4, 3, false)
	gt.Injections = map[string]time.Time{} // harness 什么都没报

	rec, err := assembleRecord(context.Background(), cfg, mustScenario(t, "S2-no-siem-no-ids"), gt, 1, fixtureHostChecks())
	if err == nil {
		t.Fatal("缺注入时刻时必须拒绝写出（否则顺序注入场景会静默退化成同时注入）")
	}
	if rec.Meta.AssemblyError == "" {
		t.Error("装配失败必须显式记进 meta.assembly_error")
	}
	if !strings.Contains(err.Error(), "注入时刻") {
		t.Errorf("拒绝理由必须指向缺失的注入时刻: %v", err)
	}
}

// TestSequentialScenarioNeedsDistinctInstants：harness 报的时刻若全同，顺序注入场景就
// **没有**时间结构 —— C 会退化成 V，而这在数据上不可见。采集器必须响亮地拒绝。
func TestSequentialScenarioNeedsDistinctInstants(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	at := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	gt := newGroundTruth(true, 213, 4, 3, false)
	gt.Injections = map[string]time.Time{"RS-007": at, "RS-006": at}

	rec, err := assembleRecord(context.Background(), cfg, mustScenario(t, "S2-no-siem-no-ids"), gt, 1, fixtureHostChecks())
	if err == nil {
		t.Fatal("顺序注入场景的注入时刻必须有两个不同值，全同时应拒绝写出")
	}
	if rec.Meta.AssemblyError == "" {
		t.Error("装配失败必须显式记进 meta.assembly_error")
	}
}

// mustScenario 取场景名并断言它在表里（组装只为用例留一个顺手的入口）。
func mustScenario(t *testing.T, name string) string {
	t.Helper()
	if _, ok := scenarios[name]; !ok {
		t.Fatalf("场景表里没有 %q", name)
	}
	return name
}

// ============================================================================
// 生效权重（裁定 4）
// ============================================================================

// TestEffectiveWeightsAreWhatTheEngineActuallyUsed：`observed.effective_weights` 必须是引擎
// **实际生效**的逐域权重，键集 = 参与聚合的域。
//
// 两个坑（Task 1 评审实测）：①legacy 内在层的 `DynamicScoringEngine` 会给 0 权重域填默认值并
// `Normalize(100)`，故"配置权重 ≠ 生效权重"；②`DomainScores` 的四个核心域字段恒存在，记录
// **无法**从域分本身区分"该域参与聚合但值为 0"与"该域不在聚合里"。故采集器必须写出参与聚合
// 的域与它们的权重，且判存在性一律用 `len(...) > 0`（nil map 会序列化成 null）。
func TestEffectiveWeightsAreWhatTheEngineActuallyUsed(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	rec, err := buildRecord(context.Background(), "S4-all", cfg, newGroundTruth(true, 400, 6, 5, false), 1)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	if len(rec.Observed.EffectiveWeights) == 0 {
		t.Fatal("effective_weights 为空 —— 存在性判据是 len(...) > 0")
	}
	if err := rec.CheckEffectiveWeightsRecorded(); err != nil {
		t.Fatalf("生效权重自检必须通过: %v", err)
	}
	// 夹具的检查覆盖 5 个域（含 kernel_security），故生效权重 = [weights] 的四项 + [extension_weights] 的 kernel_security。
	want := map[string]float64{
		"attack_surface": 35, "business_continuity": 25, "operation_trust": 25,
		"resilience": 15, "kernel_security": 10,
	}
	if len(rec.Observed.EffectiveWeights) != len(want) {
		t.Fatalf("生效权重键集 = %v, want %v（键集即『参与聚合的域』）", rec.Observed.EffectiveWeights, want)
	}
	for d, w := range want {
		if got := rec.Observed.EffectiveWeights[d]; got != w {
			t.Errorf("effective_weights[%s] = %v, want %v", d, got, w)
		}
	}
	// 权重来源必须留痕（config_hash 是锚点），否则这份权重从哪来无从归因。
	if rec.Meta.WeightSource == "" {
		t.Error("meta.weight_source 必须写出（说明这份权重是从哪来的）")
	}
}

// TestEffectiveWeightsExcludeDomainsThatDidNotTakePart：没有检查的域**不参与聚合**，
// 而 `DomainScores` 的四个核心域字段恒存在 ⇒ 只能靠"该域有没有检查"判定参与者。
// 把它算进去会让离线复算按一个 0 分的域加权（系统性压低总分），而门禁全绿。
func TestEffectiveWeightsExcludeDomainsThatDidNotTakePart(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	// 目标机只有 operation_trust 的检查（其余域在这次评估里没有任何观测）
	host := []model.CheckResult{}
	for _, c := range fixtureHostChecks() {
		if c.Domain == model.DomainOperationTrust {
			host = append(host, c)
		}
	}
	rec, err := assembleRecord(context.Background(), cfg, mustScenario(t, "S1-selinux"), newGroundTruth(true, 100, 2, 1, false), 1, host)
	if err != nil {
		t.Fatalf("assembleRecord: %v", err)
	}
	if len(rec.Observed.EffectiveWeights) != 1 || rec.Observed.EffectiveWeights["operation_trust"] != 25 {
		t.Fatalf("生效权重 = %v, want 只有 operation_trust=25（只有它参与了聚合）", rec.Observed.EffectiveWeights)
	}
}

// ============================================================================
// 拒绝写出（裁定 5）
// ============================================================================

// TestAssemblyFailureIsRecordedNotSilentlyDropped：装配失败（无模型段 / 模型在线不可执行 /
// 触发检查未注册）必须**显式记录**在 `meta.assembly_error` 里并拒绝写出记录，而不是静默
// 产出一条"未启用"的记录（否则实验会"少场景而人不知"）。
func TestAssemblyFailureIsRecordedNotSilentlyDropped(t *testing.T) {
	registerFixtureChecks()

	t.Run("无模型段", func(t *testing.T) {
		cfg := fixtureWithoutModel(t)
		rec, err := buildRecord(context.Background(), "S1-selinux", cfg, newGroundTruth(true, 100, 2, 1, false), 1)
		if err == nil {
			t.Fatal("没装载合成模型时必须拒绝写出 —— 那会产出『有惩罚、但链为空』的记录，离线复算必然失败")
		}
		if rec.Meta.AssemblyError == "" {
			t.Error("装配失败必须显式记进 meta.assembly_error")
		}
		// 主要保证在写出层：`runCLI` 只在 buildRecord 返回 nil error 时才碰输出文件
		// （见 TestCLIRefusesToWriteOnAssemblyFailure）；这里只确认它确实没能自检通过。
		if err := rec.Validate(); err == nil {
			t.Error("被拒的记录不得通过读取层契约")
		}
	})

	t.Run("chain 模型在线不可执行", func(t *testing.T) {
		cfg := fixtureChainModel(t)
		rec, err := buildRecord(context.Background(), "S1-selinux", cfg, newGroundTruth(true, 100, 2, 1, false), 1)
		if err == nil {
			t.Fatal("chain 是离线专用模型（在线结果类型没有时间字段），引擎不会装载它 —— 必须拒绝写出")
		}
		if rec.Meta.AssemblyError == "" {
			t.Error("装配失败必须显式记进 meta.assembly_error")
		}
	})

	t.Run("legacy 评分模式", func(t *testing.T) {
		// `[weights] scoring_engine = legacy` 与 `[edge_factors.model] model = legacy` 是两回事：
		// 前者按生产装配**不**接插件引擎，走内置 DynamicScoringEngine —— 那条路径永远不盖溯源戳
		// （Task 7 评审 I1 的裁定），故这类配置产不出可用的实验记录，必须拒绝并说清该改哪一行。
		cfg := mustLoadConfig(t, "fixture-scoring-legacy.ini",
			strings.Replace(fixtureConfigINI, "[weights]\n", "[weights]\nscoring_engine = legacy\n", 1))
		if cfg.ScoringEngine != "legacy" {
			t.Fatalf("夹具未能让解析层读到 scoring_engine = legacy（实际 %q）", cfg.ScoringEngine)
		}
		rec, err := buildRecord(context.Background(), "S1-selinux", cfg, newGroundTruth(true, 100, 2, 1, false), 1)
		if err == nil {
			t.Fatal("legacy 评分模式不盖溯源戳，必须拒绝写出")
		}
		if !strings.Contains(rec.Meta.AssemblyError, "scoring_engine = legacy") {
			t.Errorf("拒绝理由必须指出该配置的 legacy 评分模式（并说明 M0 应改用 [edge_factors.model] model = legacy）: %q", rec.Meta.AssemblyError)
		}
	})

	t.Run("触发检查未注册", func(t *testing.T) {
		// 把 EF-SELINUX 的触发检查指向一个登记表里不存在的检查：注入无从执行，
		// 而"照常评一条没有任何失败的记录"正是要禁止的静默路径。
		cfg := mustLoadConfig(t, "fixture-bogus-trigger.ini",
			strings.Replace(fixtureConfigINI, "[edge_factors.model]\nmodel = legacy\np_floor = 0.50",
				"[edge_factors.model]\nmodel = legacy\np_floor = 0.50\ntrigger.EF-SELINUX = ZZ-999", 1))
		rec, err := buildRecord(context.Background(), "S1-selinux", cfg, newGroundTruth(true, 100, 2, 1, false), 1)
		if err == nil {
			t.Fatal("触发检查不在登记表里时无法执行注入，必须拒绝写出")
		}
		if rec.Meta.AssemblyError == "" {
			t.Error("装配失败必须显式记进 meta.assembly_error")
		}
	})

	t.Run("R 组真实缺失没发生时拒绝", func(t *testing.T) {
		// R 组不注入：靠目标机上真实失败的检查。检查没失败 ⇒ 声明的因子没出现 ⇒ 场景没跑对。
		registerFixtureChecks()
		cfg := fixtureConfig(t)
		rec, err := assembleRecord(context.Background(), cfg, mustScenario(t, "R-no-ids"),
			newGroundTruth(true, 100, 2, 1, false), 1, fixtureHostChecks()) // 全部通过
		if err == nil {
			t.Fatal("R 组声明真实缺失的因子没有出现在链上时必须拒绝写出")
		}
		if rec.Meta.AssemblyError == "" {
			t.Error("装配失败必须显式记进 meta.assembly_error")
		}
	})
}

// TestRealMissingScenarioRecordsTheNaturalFailure：R 组的对照是"服务真的被停掉"，
// 采集器不注入、只如实采集真实失败的检查。
func TestRealMissingScenarioRecordsTheNaturalFailure(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	rec, err := assembleRecord(context.Background(), cfg, mustScenario(t, "R-no-ids"),
		newGroundTruth(true, 100, 2, 1, false), 1, hostChecksWithFailures("RS-006"))
	if err != nil {
		t.Fatalf("assembleRecord: %v", err)
	}
	if !chainHasFactor(rec, "EF-NO-IDS") {
		t.Fatalf("真实缺失的 RS-006 失败必须激活 EF-NO-IDS: %+v", rec.Observed.EdgeFactorChain)
	}
	if rec.Injection != "real_missing" {
		t.Errorf("R 组的 injection 口径 = %q, want real_missing", rec.Injection)
	}
}

// TestRefusesPenaltiesWithoutChain（裁定 5 的核心）：链只在引擎真的装载了模型时回填，
// 而"未装载时内仓默认路径仍然用六因子乘分"⇒ 会产出"有惩罚、但链为空"的记录 ——
// 这种记录让离线复算必然失败，且看起来像"这个场景没有因子生效"。采集器必须断言
// "戳记存在 且（有惩罚时）链非空"，不满足即报错退出。判据只能读**溯源戳**，不得据链是否为空判断。
func TestRefusesPenaltiesWithoutChain(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureWithoutModel(t)
	rec, err := buildRecord(context.Background(), "S4-all", cfg, newGroundTruth(true, 400, 6, 5, false), 1)
	if err == nil {
		t.Fatal("有惩罚但链为空（引擎未装载模型）的记录必须被拒绝")
	}
	if rec.Meta.AssemblyError == "" {
		t.Fatal("装配失败必须显式记进 meta.assembly_error")
	}
	if !strings.Contains(rec.Meta.AssemblyError, "溯源戳") && !strings.Contains(rec.Meta.AssemblyError, "装载") {
		t.Errorf("拒绝理由必须指向『引擎没有装载合成模型』（而不是据链是否为空判断）: %q", rec.Meta.AssemblyError)
	}
	if len(rec.Observed.EdgeFactorChain) != 0 {
		t.Errorf("未装载模型时链本就为空，不得凭空补齐: %+v", rec.Observed.EdgeFactorChain)
	}
}

// TestBaselineScenarioWithNoActivationIsWritable：S0 基线**没有因子**，链为空是合法观测；
// "有惩罚但链为空"才是要拒绝的形态。若把判据写成"链必须非空"，S0 这类真实场景会被判死。
func TestBaselineScenarioWithNoActivationIsWritable(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	rec, err := assembleRecord(context.Background(), cfg, mustScenario(t, "S0-baseline"),
		newGroundTruth(false, 0, 0, 0, true), 1, fixtureHostChecks())
	if err != nil {
		t.Fatalf("S0 基线（没有任何因子激活）必须能写出: %v", err)
	}
	if len(rec.Observed.EdgeFactorChain) != 0 {
		t.Errorf("S0 基线不该有链条目: %+v", rec.Observed.EdgeFactorChain)
	}
	if len(rec.Factors) != 0 {
		t.Errorf("S0 基线的 factors 必须为空: %v", rec.Factors)
	}
}

// ============================================================================
// round-trip 钉桩（spec §5.1："采集器落地时必须对自采数据做同样的事"）
// ============================================================================

// TestRoundTripPinHoldsForEveryCandidate：用**记录自身的输入**复算总分必须等于记录里的
// `final_score`（容差半个取整格）。这条是"spc/threat 取错来源"、"生效权重写错"、"链上漏了
// 惩罚"这类**所有其它门禁全绿**的错误的唯一闸门。
//
// 两个候选各跑一次：legacy（无钩子，内仓默认逐次相乘）与 vector（域级修正 P_d 由装配期装好的
// 钩子表达）。vector 那次同时证明"复算复用的是本次评分装配的那套钩子"，而不是另算一套。
func TestRoundTripPinHoldsForEveryCandidate(t *testing.T) {
	registerFixtureChecks()
	cases := []struct {
		name    string
		content string
	}{
		{"legacy", fixtureConfigINI},
		{"vector", strings.Replace(fixtureConfigINI,
			"[edge_factors.model]\nmodel = legacy\np_floor = 0.50", strings.TrimRight(vectorModelSection, "\n"), 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustLoadConfig(t, "fixture-"+tc.name+".ini", tc.content)
			if want := tc.name; cfg.EdgeFactorModel.Model != want {
				t.Fatalf("夹具模型段 = %q, want %q", cfg.EdgeFactorModel.Model, want)
			}
			gt := newGroundTruth(true, 213, 4, 3, false)
			gt.Injections = map[string]time.Time{
				"OT-005": time.Date(2026, 9, 8, 10, 0, 3, 0, time.UTC),
			}
			rec, err := assembleRecord(context.Background(), cfg, "S2-selinux-apparmor", gt, 1, fixtureHostChecks())
			if err != nil {
				t.Fatalf("assembleRecord: %v", err)
			}
			if got := recomputeFinalScore(rec); math.Abs(got-rec.Observed.FinalScore) > roundTripTolerance {
				t.Fatalf("复算总分 %.4f != 记录里的 %.4f（记录内部不自洽）", got, rec.Observed.FinalScore)
			}
		})
	}
}

// TestRoundTripPinHasTeeth：钉桩必须真的能红 —— 把记录里的 `spc_score` 改成"引擎没用的那个值"
// （这正是 spec §5.1 警告的取错来源形态），复算就必须对不上。
func TestRoundTripPinHasTeeth(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)
	gt := newGroundTruth(true, 213, 4, 3, false)
	rec, err := assembleRecord(context.Background(), cfg, "S2-selinux-apparmor", gt, 1, fixtureHostChecks())
	if err != nil {
		t.Fatalf("assembleRecord: %v", err)
	}
	if err := roundTripCheck(rec); err != nil {
		t.Fatalf("未篡改的记录必须通过钉桩: %v", err)
	}
	tampered := rec
	tampered.Observed.SPCScore = 0.60 // 引擎实际用的是 1.0（无 SPC 提供方）
	if err := roundTripCheck(tampered); err == nil {
		t.Fatal("把 spc_score 换成引擎没用的值时钉桩必须红 —— 否则这道闸门形同虚设")
	}
	// 生效权重同样受钉桩保护：换掉权重表会让复算的加权基数变化。
	tampered = rec
	tampered.Observed.EffectiveWeights = map[string]float64{"attack_surface": 100}
	if err := roundTripCheck(tampered); err == nil {
		t.Fatal("改掉 effective_weights 后钉桩必须红（离线复算的权重口径不会被静默换掉）")
	}
}

// ============================================================================
// ground truth 解析（M3：ttc 缺失即报错）
// ============================================================================

func TestLoadGroundTruthParsesHarnessReport(t *testing.T) {
	path := writeFile(t, "attack.json", `{
  "scenario": "S2-selinux-apparmor",
  "compromised": true,
  "time_to_compromise_s": 213,
  "ttps_achieved": 4,
  "nodes_affected": 3,
  "block_effective": false,
  "playbook_hash": "sha256:deadbeef",
  "topology_hash": "sha256:cafe",
  "injections": [
    {"check": "RS-007", "at": "2026-09-08T10:00:03Z"},
    {"check": "RS-006", "at": "2026-09-08T10:00:11Z"}
  ]
}`)
	gt, err := loadGroundTruth(path, "S2-selinux-apparmor")
	if err != nil {
		t.Fatalf("loadGroundTruth: %v", err)
	}
	if !gt.Compromised || gt.TimeToCompromiseS != 213 || gt.TTPsAchieved != 4 || gt.NodesAffected != 3 || gt.BlockEffective {
		t.Errorf("客观结果解析错: %+v", gt)
	}
	if gt.PlaybookHash != "sha256:deadbeef" {
		t.Errorf("剧本哈希 = %q", gt.PlaybookHash)
	}
	if len(gt.Injections) != 2 || gt.Injections["RS-006"].UTC().Format(time.RFC3339) != "2026-09-08T10:00:11Z" {
		t.Errorf("注入时刻解析错: %+v", gt.Injections)
	}
}

// TestLoadGroundTruthRequiresTimeToCompromise（M3 的数据侧处理）：`ttc` 缺失即报错。
func TestLoadGroundTruthRequiresTimeToCompromise(t *testing.T) {
	path := writeFile(t, "attack.json", `{"compromised": true, "ttps_achieved": 4, "nodes_affected": 3}`)
	if _, err := loadGroundTruth(path, "S1-selinux"); err == nil {
		t.Fatal("缺 time_to_compromise_s 必须报错（M3 的数据侧处理）")
	}
}

// TestLoadGroundTruthRequiresCompromised：`compromised` 缺失必须报错，不能静默当成 false
// （那会把该场景标成"未攻陷"，直接扭曲漏判率）。契约类型的"存在性标记"只由 UnmarshalJSON 设置，
// 故这条必须在**解析处**拦住，不能指望写出口兜住。
func TestLoadGroundTruthRequiresCompromised(t *testing.T) {
	path := writeFile(t, "attack.json", `{"time_to_compromise_s": 213, "ttps_achieved": 4}`)
	if _, err := loadGroundTruth(path, "S1-selinux"); err == nil {
		t.Fatal("缺 compromised 必须报错（缺失会被当成 false ⇒ 静默标成未攻陷）")
	}
}

// TestLoadGroundTruthRejectsWrongScenario：把 A 场景的 harness 产物 join 到 B 场景上是最容易
// 发生也最难发现的错误（记录照常写出、只是标签全错），故 harness 报了场景名时必须核对。
func TestLoadGroundTruthRejectsWrongScenario(t *testing.T) {
	path := writeFile(t, "attack.json", `{"scenario":"S1-selinux","compromised":true,"time_to_compromise_s":10}`)
	if _, err := loadGroundTruth(path, "S2-no-siem-no-ids"); err == nil {
		t.Fatal("harness 报的场景名与 --scenario 不一致时必须报错")
	}
}

// TestLoadGroundTruthRejectsDuplicateInjectionTimes：同一次运行里同一个检查被报了两个注入
// 时刻是歧义输入（它会让"哪个才是 ts"变成任意选择），必须报错。
func TestLoadGroundTruthRejectsDuplicateInjectionTimes(t *testing.T) {
	path := writeFile(t, "attack.json", `{"compromised":true,"time_to_compromise_s":10,
	  "injections":[{"check":"RS-006","at":"2026-09-08T10:00:03Z"},{"check":"RS-006","at":"2026-09-08T10:00:11Z"}]}`)
	if _, err := loadGroundTruth(path, "S1-selinux"); err == nil {
		t.Fatal("同一个检查报了两个注入时刻必须报错")
	}
}

// TestGroundTruthRecordFieldCarriesExplicitPresence：客观结果进记录时必须**显式**带上
// `compromised`（契约的 Validate 要求它"在场"，而该标记只由 UnmarshalJSON 设置）。
func TestGroundTruthRecordFieldCarriesExplicitPresence(t *testing.T) {
	gt := groundTruth{Compromised: false, TimeToCompromiseS: 0, TTPsAchieved: 0, NodesAffected: 0, BlockEffective: true}
	contract, err := gt.recordGroundTruth()
	if err != nil {
		t.Fatalf("recordGroundTruth: %v", err)
	}
	if !contract.CompromisedSet() {
		t.Fatal("写进记录的 ground_truth 必须显式带 compromised（存在性标记只由 UnmarshalJSON 设置）")
	}
	rec := edgeexp.Record{ScenarioID: "S0-baseline", GroundTruth: contract}
	if err := rec.Validate(); err == nil {
		t.Fatal("夹具本身不完整（缺 threshold 等）—— 本条只验证存在性标记，不应通过完整契约")
	} else if strings.Contains(err.Error(), "ground_truth.compromised") {
		t.Fatalf("compromised 已被标记为在场，不该报它缺失: %v", err)
	}
}

// ============================================================================
// CLI
// ============================================================================

// TestCLIWritesOneRecordLine：CLI 端到端 —— 一次运行写且只写一行 spec §5.1 JSONL，
// 并能被**消费者**（edgeexp.LoadFile）读回。
func TestCLIWritesOneRecordLine(t *testing.T) {
	registerFixtureChecks()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vector.ini")
	if err := os.WriteFile(cfgPath, []byte(fixtureConfigINI), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	attackPath := filepath.Join(dir, "attack.json")
	if err := os.WriteFile(attackPath, []byte(`{"scenario":"S2-selinux-apparmor","compromised":true,
	  "time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false,
	  "playbook_hash":"sha256:deadbeef","injections":[{"check":"OT-005","at":"2026-09-08T10:00:03Z"}]}`), 0o600); err != nil {
		t.Fatalf("写 harness 产物: %v", err)
	}
	outPath := filepath.Join(dir, "records.jsonl")

	var stdout, stderr strings.Builder
	code := runCLI([]string{
		"--scenario", "S2-selinux-apparmor", "--config", cfgPath, "--attack-out", attackPath,
		"--out", outPath, "--run", "1", "--env", "wsl-clab-14",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("退出码 = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	recs, err := edgeexp.LoadFileAs("test", outPath)
	if err != nil {
		t.Fatalf("写出的记录必须能被消费者读回: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("一次运行必须写且只写一行，得到 %d 行", len(recs))
	}
	rec := recs[0]
	if rec.ScenarioID != "S2-selinux-apparmor-01" {
		t.Errorf("scenario_id = %q, want S2-selinux-apparmor-01（spec §5.1 的示例带运行号）", rec.ScenarioID)
	}
	if rec.Meta.Env != "wsl-clab-14" || rec.Meta.Run != 1 || rec.Meta.ConfigHash == "" {
		t.Errorf("meta 未写全: %+v", rec.Meta)
	}
	if rec.Meta.PlaybookHash != "sha256:deadbeef" {
		t.Errorf("playbook_hash 必须从 harness 产物带过来: %q", rec.Meta.PlaybookHash)
	}
	for _, want := range []string{"场景", "因子", "权重来源", "装配错误"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("自检摘要必须包含 %q:\n%s", want, stdout.String())
		}
	}
}

// TestCLIRefusesToWriteOnAssemblyFailure：装配失败时**不写半条记录**、退出码非零。
func TestCLIRefusesToWriteOnAssemblyFailure(t *testing.T) {
	registerFixtureChecks()
	dir := t.TempDir()
	cut := strings.Index(fixtureConfigINI, "[edge_factors.model]")
	noModel := fixtureConfigINI[:cut] + fixtureConfigINI[strings.Index(fixtureConfigINI, "[edge_factors.custom]"):]
	cfgPath := filepath.Join(dir, "nomodel.ini")
	if err := os.WriteFile(cfgPath, []byte(noModel), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	attackPath := filepath.Join(dir, "attack.json")
	if err := os.WriteFile(attackPath, []byte(`{"compromised":true,"time_to_compromise_s":10,
	  "ttps_achieved":1,"nodes_affected":1,"block_effective":false,
	  "injections":[{"check":"OT-005","at":"2026-09-08T10:00:03Z"}]}`), 0o600); err != nil {
		t.Fatalf("写 harness 产物: %v", err)
	}
	outPath := filepath.Join(dir, "records.jsonl")

	var stdout, stderr strings.Builder
	code := runCLI([]string{
		"--scenario", "S1-selinux", "--config", cfgPath, "--attack-out", attackPath, "--out", outPath,
	}, &stdout, &stderr)
	if code == exitOK {
		t.Fatalf("装配失败必须返回非零退出码\nstdout:\n%s", stdout.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Errorf("装配失败时不得留下产物文件（半条记录最容易被误读）: err=%v", err)
	}
	if !strings.Contains(stderr.String(), "装配") {
		t.Errorf("stderr 必须转述装配失败的原因: %s", stderr.String())
	}
}

// TestCLIUsageErrors：缺必填开关、未知场景都属**用法错误**（退出码 2），且不产生任何产物。
func TestCLIUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"缺场景", []string{"--config", "x.ini", "--attack-out", "a.json", "--out", "o.jsonl"}},
		{"缺配置", []string{"--scenario", "S0-baseline", "--attack-out", "a.json", "--out", "o.jsonl"}},
		{"缺 harness 产物", []string{"--scenario", "S0-baseline", "--config", "x.ini", "--out", "o.jsonl"}},
		{"缺输出路径", []string{"--scenario", "S0-baseline", "--config", "x.ini", "--attack-out", "a.json"}},
		{"未知场景", []string{"--scenario", "S9-nope", "--config", "x.ini", "--attack-out", "a.json", "--out", "o.jsonl"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if code := runCLI(tc.args, &stdout, &stderr); code != exitUsage {
				t.Errorf("退出码 = %d, want %d（用法错误）", code, exitUsage)
			}
		})
	}
}

// TestCLIListScenarios 让矩阵脚本能迭代场景表（Task 4 的 edge_matrix.sh 需要它）。
func TestCLIListScenarios(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := runCLI([]string{"--list"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("--list 退出码 = %d, want 0\n%s", code, stderr.String())
	}
	for name := range scenarios {
		if !strings.Contains(stdout.String(), name) {
			t.Errorf("--list 必须列出场景 %s", name)
		}
	}
}

// ============================================================================
// 与 Task 4 的交接：模板落地后立刻纳入门禁
// ============================================================================

// TestEdgeExpTemplatesAreConsumableWhenPresent：`configs/edgeexp/*.ini` 是 **Task 4** 的
// 交付物。模板落地前本条跳过；落地后它立刻把"模板能被采集器真正消费"纳入门禁 ——
// 这比"模板能被 config.Load 读懂"强一层（后者是 Task 4 自己的用例）。
func TestEdgeExpTemplatesAreConsumableWhenPresent(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "configs", "edgeexp", "*.ini"))
	if err != nil || len(paths) == 0 {
		t.Skipf("configs/edgeexp/*.ini 尚未落地（Task 4 的交付物）: paths=%v err=%v", paths, err)
	}
	registerFixtureChecks()
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("实验模板必须能被生产解析层装载: %v", err)
			}
			if cfg.EdgeFactorModel.Model == "" {
				t.Fatalf("%s 缺 [edge_factors.model] 段 —— 引擎不会装载 ⇒ 记录没有溯源戳与观测链", filepath.Base(path))
			}
			// 模板声明的候选若在线不可执行（chain），采集器必须明确拒绝而不是照常评分。
			rec, err := buildRecord(context.Background(), "S1-selinux", cfg, newGroundTruth(true, 120, 2, 1, false), 1)
			if cfg.EdgeFactorModel.Model == "chain" {
				if err == nil {
					t.Fatalf("chain 模板在线不可执行，必须拒绝写出")
				}
				if rec.Meta.AssemblyError == "" {
					t.Error("装配失败必须显式记进 meta.assembly_error")
				}
				return
			}
			if err != nil {
				t.Fatalf("模板 %s 必须能被采集器消费: %v", filepath.Base(path), err)
			}
		})
	}
}

// TestRecordGroundTruthMatchesHarnessBytes：记录里的 ground_truth 必须与 harness 产物逐字段一致
// （join 的两个来源之间不得有第三种口径）。
func TestRecordGroundTruthMatchesHarnessBytes(t *testing.T) {
	path := writeFile(t, "attack.json", `{"compromised":true,"time_to_compromise_s":213,
	  "ttps_achieved":4,"nodes_affected":3,"block_effective":false,"playbook_hash":"sha256:deadbeef",
	  "injections":[{"check":"RS-006","at":"2026-09-08T10:00:11Z"}]}`)
	gt, err := loadGroundTruth(path, "R-no-ids")
	if err != nil {
		t.Fatalf("loadGroundTruth: %v", err)
	}
	raw, err := json.Marshal(gt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["compromised"] != true || back["time_to_compromise_s"] != float64(213) {
		t.Errorf("客观结果字段漂移: %v", back)
	}
}
