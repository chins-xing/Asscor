//go:build expr && engine && checks

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
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
// + 一个业务连续性检查，全部**通过**（只看注入出来的失败）。ID/域/delta/名称逐字取自
// `internal/checks/linux`：
//
//	EF-001 attack_surface 0｜EF-002 attack_surface 0｜OT-005 operation_trust -15
//	RS-005 resilience -5｜RS-006 resilience -10｜RS-007 resilience -6
//	KS-001 kernel_security -15｜BC-005 business_continuity -10
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
		// 末两项的 ID/域/**delta/名称**同样逐字取自 internal/checks/linux：
		//   kernel_security.go 的 KS-001 "Kernel Version CVE Check" = -15
		//   checks.go 的 BC-005 "备份机制" = -10
		// （Fix round 1 / 评审 M5：此前写的 -10/-8 与登记表不符，而注释声称"逐字取自"。）
		{ID: "KS-001", Domain: model.DomainKernelSecurity, Name: "Kernel Version CVE Check", Delta: -15, Check: alwaysPass},
		{ID: "BC-005", Domain: model.DomainBusinessContinuity, Name: "备份机制", Delta: -10, Check: alwaysPass},
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
				for _, id := range resolvePhaseChecks(phase) {
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
	// 本采集器写出的记录都出自插件路径（未装载模型的记录在上游已被拒），故对这些条目逐条做交叉校验。
	// 变量名不用 `pluginPath`：链不是"路径"（评审 M13 指出该名字会让读者以为它承载路径信息）。
	pluginChainEntries := rec.Observed.EdgeFactorChain
	for _, ob := range pluginChainEntries {
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

// TestSimultaneousScenarioNeverMixesChainTimestamps（Fix round 1 / 评审 Important 2 的钉子）
//
// 真机实测过的坏形态：非顺序场景里，"命中 harness 的条目拿注入时刻、其余沿用评分时刻"
// 会产出**混用基准**的链（评审实测 11 条里 4 条带注入时刻、7 条带更晚的评分时刻）——
// 那个"注入先、自然失败后"的顺序既不是实验设计的，也没有任何地方报告它。
//
// 本用例同时制造两类条目：`OT-005` 是**注入**的（harness 报了它的时刻），`RS-006` 是目标机
// **自然失败**的（harness 不知道它）。断言：
//   - 链上**没有任何**条目取 harness 的注入时刻；
//   - 全部条目共用同一个时刻（= 评估时刻 ⇒ 无时间结构 ⇒ C 与 V 在这条数据上同分）；
//   - harness 的注入时刻仍然照常进 `checks[]`（信息没丢，只是不当模型的入参）。
//
// 旧的"混用"实现会在这里红：EF-SELINUX 会带注入时刻、EF-NO-IDS 带评分时刻。
func TestSimultaneousScenarioNeverMixesChainTimestamps(t *testing.T) {
	registerFixtureChecks()
	cfg := fixtureConfig(t)

	at := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	gt := newGroundTruth(true, 213, 4, 3, false)
	gt.Injections = map[string]time.Time{"OT-005": at}

	// RS-006 在目标机上自然失败（服务真的缺失）—— 它不在 harness 的注入清单里。
	rec, err := assembleRecord(context.Background(), cfg, mustScenario(t, "S1-selinux"), gt, 1,
		hostChecksWithFailures("RS-006"))
	if err != nil {
		t.Fatalf("assembleRecord: %v", err)
	}
	if !chainHasFactor(rec, "EF-SELINUX") || !chainHasFactor(rec, "EF-NO-IDS") {
		t.Fatalf("夹具必须同时造出『注入激活』与『自然失败激活』两条链: %+v", rec.Observed.EdgeFactorChain)
	}
	harnessTS := at.Format(time.RFC3339)
	distinct := map[string]bool{}
	for _, ob := range rec.Observed.EdgeFactorChain {
		if ob.TS == harnessTS {
			t.Errorf("链上 %s（触发检查 %s）取了 harness 的注入时刻 —— 同时注入场景**一条都不该**取，"+
				"混用会造出一个没人设计、也没人报告的顺序", ob.Factor, ob.TriggerCheck)
		}
		distinct[ob.TS] = true
	}
	if len(distinct) != 1 {
		t.Fatalf("同时注入场景的链条目必须共用同一个时刻（无时间结构），实际: %v\n链: %+v",
			distinct, rec.Observed.EdgeFactorChain)
	}
	// 注入时刻没有丢：它属于 checks[]（逐检查的观测时刻，不是模型入参）。
	seen := false
	for _, ck := range rec.Observed.Checks {
		if ck.ID == "OT-005" && ck.TS == harnessTS {
			seen = true
		}
	}
	if !seen {
		t.Errorf("harness 的注入时刻必须仍然落在 checks[] 上（它是该检查的观测时刻），实际: %+v", rec.Observed.Checks)
	}
	// 来源必须留痕（记录里那句溯源注记要说明"注入时刻不用于链条目"）—— Task 3B Step 3 起
	// 它有自己的字段 `meta.ts_source`，而 `meta.weight_source` 回到只讲权重口径。
	if !strings.Contains(rec.Meta.TSSource, "链条目 ts") || !strings.Contains(rec.Meta.TSSource, "同时注入") {
		t.Errorf("链条目 ts 的来源必须写进记录（meta.ts_source），实际: %q", rec.Meta.TSSource)
	}
	if strings.Contains(rec.Meta.WeightSource, "链条目 ts") {
		t.Errorf("meta.weight_source 必须只讲权重口径（ts 基准已迁到 meta.ts_source），实际: %q", rec.Meta.WeightSource)
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
		// 拒绝理由必须**指名道姓**：这条记录从未密封（`sealRecord` 在自检链里、失败即返回），
		// 直接在它上面跑 Validate 只会报"observed.threshold 缺失"这种密封前的假象 ——
		// 那既不是失败原因，也永远为真（评审 M1）。真正的保证在写出层：`runCLI` 只在
		// buildRecord 返回 nil error 时才碰输出文件（见 TestCLIRefusesToWriteOnAssemblyFailure）。
		// 这里改为断言错误的**内容**：必须指向"引擎未装载合成模型"这条真正的拒绝理由。
		if !strings.Contains(err.Error(), "没有装载") && !strings.Contains(err.Error(), "溯源戳") {
			t.Errorf("拒绝理由必须指向『引擎没有装载合成模型』: %v", err)
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
		// 拒绝理由必须**针对 chain 本身**（Task 4 的 chain.ini 会撞上这一条）：笼统地说
		// "必须声明 [edge_factors.model]" 会让操作者去改一行本来就写对了的配置。
		if !strings.Contains(rec.Meta.AssemblyError, "chain") || !strings.Contains(rec.Meta.AssemblyError, "离线") {
			t.Errorf("chain 模板的拒绝理由必须说明『chain 在线不可执行、由 edgecompare 离线评估』: %q", rec.Meta.AssemblyError)
		}
	})

	t.Run("vector 没有声明任何 lambda", func(t *testing.T) {
		// 另一个"引擎装了却没装载"的形态：V/G 没有 λ 就一个域都不会被修正 ⇒ 装配期拒绝装载
		// （否则会出现『戳记写着 vector、评分却分毫未变』的假溯源）。提示必须指向 λ。
		cfg := mustLoadConfig(t, "fixture-nolambda.ini",
			strings.Replace(fixtureConfigINI, "[edge_factors.model]\nmodel = legacy\np_floor = 0.50",
				"[edge_factors.model]\nmodel = vector\np_floor = 0.50", 1))
		rec, err := buildRecord(context.Background(), "S1-selinux", cfg, newGroundTruth(true, 100, 2, 1, false), 1)
		if err == nil {
			t.Fatal("没有任何 lambda.<domain> 的 vector 模型不会被装载，必须拒绝写出")
		}
		if !strings.Contains(rec.Meta.AssemblyError, "lambda") {
			t.Errorf("拒绝理由必须指向缺失的 lambda.<domain>: %q", rec.Meta.AssemblyError)
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
	for _, want := range []string{"场景", "因子", "权重来源", "链条目 ts", "装配错误"} {
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

// TestCLIUsageErrors：缺必填开关、未知场景都属**用法错误**（退出码 2）。
//
// 本条只断言退出码（评审 M10：原文案声称"不产生任何产物"，而这里并没有断言产物不存在 ——
// 那句"产物不存在"的保证由 `TestCLIRefusesToWriteOnAssemblyFailure` 用真实的输出路径断言）。
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

// TestCLIListEmitsCascadeTarget pin Fix round 3 的第 4 项：`--list` 必须把 `CascadeTo` 输出给
// harness，让"哪个场景级联到哪个因子"只有**一份**真源（此前 harness 自己维护了一张表，
// 只在一边加场景时会把一条合法的链判成多余项）。
//
// 判据双向：设了 `CascadeTo` 的场景必须带 `级联目标=`，没设的必须**不带** ——
// 只查前者的话，"给所有场景都印一个级联目标"这种错会溜过去。
func TestCLIListEmitsCascadeTarget(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := runCLI([]string{"--list"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("--list 退出码 = %d, want 0\n%s", code, stderr.String())
	}
	lines := map[string]string{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasPrefix(line, "  ") {
			lines[fields[0]] = line
		}
	}
	if len(lines) != len(scenarios) {
		t.Fatalf("--list 输出的场景行数 = %d, want %d", len(lines), len(scenarios))
	}
	withCascade := 0
	for name, spec := range scenarios {
		line := lines[name]
		if spec.CascadeTo == "" {
			if strings.Contains(line, "级联目标=") {
				t.Errorf("场景 %s 没有 CascadeTo，却打印了级联目标：%s", name, line)
			}
			continue
		}
		withCascade++
		if want := "级联目标=" + spec.CascadeTo; !strings.Contains(line, want) {
			t.Errorf("场景 %s 必须打印 %q，实际：%s", name, want, line)
		}
	}
	if withCascade == 0 {
		t.Fatal("场景表里一个带 CascadeTo 的场景都没有 —— 这条用例失去了意义（级联是 C 模型的现实依据）")
	}
}

// TestCLIPlaybookHashOverride：`--playbook-hash` 覆盖 harness 产物里的剧本哈希，并落进
// `meta.playbook_hash`。两种用途：harness 没写哈希时由脚本补，以及同一段剧本换哈希重跑
// （评审 M12：这个开关此前没有任何用例碰过）。
func TestCLIPlaybookHashOverride(t *testing.T) {
	registerFixtureChecks()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "legacy.ini")
	if err := os.WriteFile(cfgPath, []byte(fixtureConfigINI), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	// harness 产物**故意不带** playbook_hash。
	attackPath := filepath.Join(dir, "attack.json")
	if err := os.WriteFile(attackPath, []byte(`{"scenario":"S2-selinux-apparmor","compromised":true,
	  "time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false,
	  "injections":[{"check":"OT-005","at":"2026-09-08T10:00:03Z"}]}`), 0o600); err != nil {
		t.Fatalf("写 harness 产物: %v", err)
	}
	outPath := filepath.Join(dir, "records.jsonl")

	var stdout, stderr strings.Builder
	code := runCLI([]string{
		"--scenario", "S2-selinux-apparmor", "--config", cfgPath, "--attack-out", attackPath,
		"--out", outPath, "--run", "1", "--env", "wsl-clab-14", "--playbook-hash", "sha256:override",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("退出码 = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	recs, err := edgeexp.LoadFileAs("test", outPath)
	if err != nil {
		t.Fatalf("读回: %v", err)
	}
	if recs[0].Meta.PlaybookHash != "sha256:override" {
		t.Errorf("--playbook-hash 必须覆盖 harness 产物里的值（harness 没写时更必须落上），实际 %q", recs[0].Meta.PlaybookHash)
	}
}

// TestSealingIsLosslessForEveryPopulatedField：把契约类型的**每个导出字段**都填成非零再密封，
// 断言这次编解码逐字节无损。
//
// 为什么需要它（Fix round 1 / 评审的加固项）：`Observed` / `ChainObs` / `GroundTruth` 各自的
// `UnmarshalJSON` 里有一份 aux **字段清单**，将来给这些类型加字段却忘了同步它，字段就会在密封处
// 被吃掉 —— 而密封后的记录才是被自检、被写出的那一份 ⇒ "字段加了却永远到不了磁盘"这件事
// 在其它所有门禁上都看不见（round-trip 钉桩也只看总分）。这里用反射把每个导出字段填满，
// 于是任何漏字段都会让 `json.Marshal(sealed)` 与密封前的字节不同而立刻暴露。
func TestSealingIsLosslessForEveryPopulatedField(t *testing.T) {
	var full edgeexp.Record
	report := fillExported(reflect.ValueOf(&full).Elem())
	if report.filled == 0 {
		t.Fatal("填充器一个节点都没写 —— 本用例会退化成恒真（没有字段被真的填过）")
	}
	if len(report.missing) > 0 {
		t.Fatalf("填充器遇到 %v 种未支持的字段类型 %v —— 这些字段在密封前后都是零值，本用例对它们**静默恒真**；"+
			"新增字段类型时必须先扩展 fillExported（或在此显式声明豁免）", len(report.missing), report.missing)
	}
	// 独立对照组（Fix round 1 / Minor 2）：自己数一遍"填过之后还剩几个零值可写节点"。
	// 与填充器的自述互补 —— 填充器说"我写过"，这里查"结果确实非零"，两者都覆盖不到时才叫盲区。
	if n := zeroSettableNodes(reflect.ValueOf(&full).Elem()); n != 0 {
		t.Fatalf("填过之后仍有 %d 个零值可写节点 —— 无损断言对这些字段恒真（先扩展 fillExported 或显式豁免）", n)
	}

	before, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sealed, err := sealRecord(full)
	if err != nil {
		t.Fatalf("密封必须无损（漏字段会在长度/字节断言处暴露）: %v", err)
	}
	after, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("marshal sealed: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("密封前后记录字节不同 —— 契约类型的解码漏了字段：\n前: %s\n后: %s", before, after)
	}
	if len(sealed.Observed.EdgeFactorChain) != len(full.Observed.EdgeFactorChain) ||
		len(sealed.Observed.Checks) != len(full.Observed.Checks) {
		t.Fatalf("密封前后切片长度不一致: chain %d→%d, checks %d→%d",
			len(full.Observed.EdgeFactorChain), len(sealed.Observed.EdgeFactorChain),
			len(full.Observed.Checks), len(sealed.Observed.Checks))
	}
}

// fillReport 是填充器的自检结果（Task 3B Step 4）：
//   - filled  —— 真的被写成非零值的节点数（0 说明这次填充什么都没做 ⇒ 依赖它的断言恒真）；
//   - missing —— 访问到却**没能**填充的 kind → 出现次数。调用方据此**硬失败**：
//     静默跳过正是"新增字段类型 ⇒ 无损断言对该字段恒真"的成因。
type fillReport struct {
	filled  int
	missing map[reflect.Kind]int
}

func (r *fillReport) note(kind reflect.Kind) {
	if r.missing == nil {
		r.missing = map[reflect.Kind]int{}
	}
	r.missing[kind]++
}

// fillExported 把结构体里每个**可写**字段填成该类型的非零值（递归，含切片/映射/数组/指针/
// 空接口的元素），并报告"访问到却没填成非零"的 kind。
//
// 覆盖的 kind：String / Bool / Int* / Uint* / Float* / Complex* / Slice / Map / Array / Ptr /
// Struct / 空 Interface（`interface{ ...方法 }` 无法凭空造出实现，如实记进 missing）。
// 通道/函数等无法填充的 kind 同样记进 missing —— 覆盖不了的字段必须是**可观测的**，
// 否则它就是"永远零值"的静默盲区。
// 非导出字段（契约的字段存在性标记）不可写，自动跳过 —— 它们不参与序列化，也不需要填。
func fillExported(v reflect.Value) fillReport {
	var rep fillReport
	fillValue(v, &rep)
	return rep
}

// fillValue 是 fillExported 的递归体（把自检结果带到底层）。
func fillValue(v reflect.Value, rep *fillReport) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	case reflect.Complex64, reflect.Complex128:
		v.SetComplex(1)
	case reflect.Slice:
		elem := reflect.New(v.Type().Elem()).Elem()
		fillValue(elem, rep)
		v.Set(reflect.Append(reflect.MakeSlice(v.Type(), 0, 1), elem))
	case reflect.Array:
		elem := reflect.New(v.Type().Elem()).Elem()
		fillValue(elem, rep)
		for i := 0; i < v.Len(); i++ {
			v.Index(i).Set(elem)
		}
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		key := reflect.New(v.Type().Key()).Elem()
		fillValue(key, rep)
		val := reflect.New(v.Type().Elem()).Elem()
		fillValue(val, rep)
		m.SetMapIndex(key, val)
		v.Set(m)
	case reflect.Ptr:
		p := reflect.New(v.Type().Elem())
		fillValue(p.Elem(), rep)
		v.Set(p)
	case reflect.Interface:
		if v.NumMethod() > 0 {
			// 非空接口：没有可实例化的具体类型，只能如实上报（调用方会硬失败）。
			rep.note(v.Kind())
			return
		}
		v.Set(reflect.ValueOf("x"))
	case reflect.Struct:
		visited := 0
		for i := 0; i < v.NumField(); i++ {
			if !v.Field(i).CanSet() {
				continue
			}
			visited++
			fillValue(v.Field(i), rep)
		}
		if visited == 0 {
			// **一个可写字段都没有**（例如 `time.Time`：字段全非导出）：这次填充对这个字段
			// 什么也没写。若照样记一笔"填过"，密封前后的字节比较对它**恒真** ——
			// 而"字段加了却永远到不了磁盘"正是本填充器要堵的那类盲区。如实上报。
			rep.note(v.Kind())
			return
		}
	default:
		// 通道 / 函数 / 不安全指针等：无法填充，如实上报而不是静默跳过。
		rep.note(v.Kind())
		return
	}
	rep.filled++
}

// zeroSettableNodes 递归统计**仍然为零值**的可写节点（填充器的对照组：
// 填充器声称"每个访问到的字段都被写成非零"，这里独立地数一遍，出现 >0 即说明两者的覆盖对不上）。
//
// 无可写字段的结构体计 1（而不是 0）：那个节点**无法被核实** —— 填充器写不进去、字节比较也
// 看不出差别，把它算成"没问题"正是 Fix round 1 / Minor 2 指出的那个恒真盲区。
func zeroSettableNodes(v reflect.Value) int {
	switch v.Kind() {
	case reflect.Struct:
		n, visited := 0, 0
		for i := 0; i < v.NumField(); i++ {
			if !v.Field(i).CanSet() {
				continue
			}
			visited++
			n += zeroSettableNodes(v.Field(i))
		}
		if visited == 0 {
			// 无可写字段 ⇒ 这个节点**无法被核实**（填充器写不进去，字节比较也看不出差别）。
			// 计 1 而不是 0：对照组必须能把这类盲区报出来（Fix round 1 / Minor 2）。
			return 1
		}
		return n
	case reflect.Ptr:
		if v.IsNil() {
			return 1
		}
		return zeroSettableNodes(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return 1
		}
		return 0
	default:
		if v.IsZero() {
			return 1
		}
		return 0
	}
}

// TestFillExportedCoversEveryKindAndReportsTheRest（Task 3B Step 4）：填充器的覆盖必须**有牙齿**。
//
// 为什么需要它（Task 3 复审建议 2）：`TestSealingIsLosslessForEveryPopulatedField` 的力气全部
// 来自"每个字段都被填成非零"。填充器此前遇到未支持的 kind 时**静默跳过** —— 将来给契约加一个
// `uint` / 指针 / 数组 / 接口字段时，那条无损断言对该字段**恒真**（密封前后都是零值，字节当然
// 相同），而"字段加了却永远到不了磁盘"在其它所有门禁上都看不见。
//
// 两个方向都钉住：①Uint/Ptr/Array/Interface 等必须**真的**被填成非零（而不是被跳过）；
// ②覆盖不了的 kind 必须被**报告**，让调用方硬失败，而不是让它静默通过。
func TestFillExportedCoversEveryKindAndReportsTheRest(t *testing.T) {
	type inner struct{ S string }
	type sample struct {
		U  uint32
		P  *inner
		A  [2]int
		I  interface{}
		C  complex128
		M  map[string]inner
		Sl []inner
	}
	var s sample
	rep := fillExported(reflect.ValueOf(&s).Elem())
	if len(rep.missing) != 0 {
		t.Fatalf("Uint/Ptr/Array/Interface/Complex/Map/Slice 都应当被填充，missing = %v", rep.missing)
	}
	if rep.filled == 0 {
		t.Fatal("一个节点都没被填 —— 依赖填充器的断言会恒真")
	}
	if s.U == 0 || s.P == nil || s.P.S == "" || s.A[0] == 0 || s.A[1] == 0 ||
		s.I == nil || s.C == 0 || len(s.M) == 0 || len(s.Sl) == 0 {
		t.Fatalf("填过之后仍有零值叶子: %+v", s)
	}
	if n := zeroSettableNodes(reflect.ValueOf(&s).Elem()); n != 0 {
		t.Errorf("填充器漏了 %d 个可写节点（对照计数）: %+v", n, s)
	}

	// 反例方向：覆盖不了的 kind 必须被报告 —— 否则 `missing` 恒空，调用方的硬失败是摆设。
	type unfillable struct {
		Ch chan int
		Fn func()
		MI interface{ Close() error } // 非空接口：无法凭空造出实现
	}
	var u unfillable
	rep = fillExported(reflect.ValueOf(&u).Elem())
	for _, k := range []reflect.Kind{reflect.Chan, reflect.Func, reflect.Interface} {
		if rep.missing[k] == 0 {
			t.Errorf("kind %v 无法填充，必须被报告（实际 missing = %v）", k, rep.missing)
		}
	}

	// 反例方向 ②（Fix round 1 / Minor 2）：**一个可写字段都没有**的结构体 —— 例如 `time.Time`
	// （字段全非导出），或将来契约里任何"不透明"类型。填充器对它写不进任何东西；若只在 `Struct`
	// 分支里走一圈就算"填过"，密封前后的字节比较对这个字段**恒真**，而它正是 Step 4 要堵的那类
	// 盲区（例如将来给 `Meta` 加 `CollectedAt time.Time` 会被静默漏掉）。
	type opaque struct{ T time.Time }
	var o opaque
	rep = fillExported(reflect.ValueOf(&o).Elem())
	if rep.missing[reflect.Struct] == 0 {
		t.Errorf("无可写字段的结构体必须被报告（实际 missing = %v）—— 否则该字段永远是零值而断言恒真", rep.missing)
	}
	if n := zeroSettableNodes(reflect.ValueOf(&o).Elem()); n == 0 {
		t.Errorf("对照组必须把『无法核实的节点』计进来（实际 %d）—— 否则它对这类盲区同样恒真", n)
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

// TestGroundTruthMarshalsWithHarnessKeys：解析出来的客观结果**用 harness 产物的键名**序列化
// （`compromised` / `time_to_compromise_s` …），两处导出一致 —— 这份 JSON 会进测试日志、
// 也可能被后续工具再读一遍，键名漂了就会静默变成另一个形状。
//
// 本条不是"记录里的 ground_truth 与 harness 逐字段一致"的证明（那由 `recordGroundTruth` 的
// JSON 往返与 `TestGroundTruthRecordFieldCarriesExplicitPresence` 负责；评审 M6 指出原名
// `TestRecordGroundTruthMatchesHarnessBytes` 会误导读者以为它碰了 `edgeexp.Record`）。
func TestGroundTruthMarshalsWithHarnessKeys(t *testing.T) {
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
