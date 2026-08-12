# ASSCOR ��չ��ϵ��Ƥ��

**�汾**��v1.1
**����**��2026-08-12
**״̬**������
**�����ĵ�**��SSAM 2.0 ��Ƥ�飨��һƪ�£�������ʵ�ְ�Ƥ�飨����ƪ�£�

> ���������ˡ�ASSCOR ��չ�ӿڱ��桷�롶ASSCOR ���滻���������桷��ϵͳ���� ASSCOR ����չ�ܹ�������������������ڡ�DI �������¼����ߡ���չ��ϵͳ��ҵ��ģ��ӿڡ������ע�����Լ�ȫ������ģ��ͼ�����Ŀ��滻����ơ�

---

## ժҪ

ASSCOR ����"΢�ں� + ���"�ܹ���ͨ����׼���ӿڡ�����ע���������¼����ߺ���չ��ϵͳ��ʵ���˴ӵײ��������������������**ȫջ���滻��**�����ĵ�ϵͳ��¼ ASSCOR ����չ�ӿ���ϵ�����滻�Ի��ơ��Լ���չ�����淶��Ϊ�����������ߺ������������ṩ�����Ľ���ָ�ϡ�

---

## Ŀ¼

1. [����������ڽӿ�](#һ����������ڽӿ�)
2. [DI ����������ע��](#��di-����������ע��)
3. [�¼�����](#���¼�����)
4. [��չ��ϵͳ](#����չ��ϵͳ)
5. [ҵ��ģ��ӿ�](#��ҵ��ģ��ӿ�)
6. [�����ע�������滻��](#�������ע�������滻��)
7. [����ģ����滻��](#�ߺ���ģ����滻��)
8. [�ⲿ����������ί��](#���ⲿ����������ί��)
9. [��չ��������ָ��](#����չ��������ָ��)
10. [�滻���Ӷ���ȱ�ڷ���](#ʮ�滻���Ӷ���ȱ�ڷ���)

---

## һ������������ڽӿ�

### 1.1 Plugin�����Ľӿڣ�

���� ASSCOR ģ�����ʵ�� `Plugin` �ӿڣ����Ķ���λ�� [plugin.go](file:///f:/Argus/internal/kernel/plugin.go#L102-L114)��

```go
type Plugin interface {
    Info() PluginInfo
    Dependencies() []PluginDependency
    Init(ctx context.Context, kc KernelContext) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    State() PluginState
}
```

**��������״̬��**��

```
Unregistered �� Registered �� Initialized �� Started �� Stopping �� Stopped
                                                    �K Failed
```

| �׶� | ���� | Լ�� |
|------|------|------|
| Registered | `RegisterPlugin()` | ���ע�ᵽ Kernel |
| Initialized | `Init()` | ������ʼ�����������á�ע����չ�㡢�� DI������������������� |
| Started | `Start()` | ��� goroutine������ Bus�������ʱ�� |
| Stopping | `Stop()` | ���� goroutine���ر� channel��ȡ�� context |

### 1.2 PriorityPlugin�����ȼ������

```go
type PriorityPlugin interface {
    Plugin
    Priority() int
}
```

ʵ�ִ˽ӿڵĲ���� `Priority()` �������������ֹͣ��

**��ģ�����ȼ�����**��

| ���ȼ� | ��� | ˵�� |
|:------:|------|------|
| 1 | ConfigWatcherModule | �����ļ�������������ȼ� |
| 2 | ConcurrencyModule | �������ƻ�����ʩ |
| 3 | PersistenceModule | �־û��� |
| 5 | HeartbeatModule | Agent �������� |
| 10 | CTIModule | ������в�鱨 |
| 20 | SPCModule | ��ȫ̬�Ƽ��� |
| 21 | ATTACKModule | ATT&CK ֪ʶ������Ϊ���� |
| 35 | ScoringEngineModule | SSAM �������� |
| 40 | AssessorModule | ���������� |
| 45 | AdapterIntegrationModule | �ⲿ���������� |
| 50 | PolicyModule | �������� |
| 55 | SourceManagerModule | �ⲿԴ���� |
| 60 | CommanderModule | �����·� |
| 70 | LogCollectorModule | ��־�ռ� |

### 1.3 HealthCheckable��������飩

```go
type HealthCheckable interface {
    HealthCheck(ctx context.Context) error
}
```

ʵ���ߣ�SPCModule��ConcurrencyModule �ȡ�Kernel �� `HealthCheck()` ��������ʵ�ִ˽ӿڵĲ�����ռ�״̬��

### 1.4 ConfigurablePlugin���ȼ������ã�

```go
type ConfigurablePlugin interface {
    Plugin
    Configure(config map[string]string) error
}
```

�ȼ���ʱ Kernel ���� `Configure(k.config)` ע�������á�

### 1.5 ��������

```go
type PluginInfo struct {
    Name, Version, Description, Author string
}

type PluginDependency struct {
    Interface interface{}
    Name      string
}
```

---

## ����DI ����������ע��

DI ���������� [di.go](file:///f:/Argus/internal/kernel/di.go)���ṩ���Ͱ�ȫ������ע�롣

### 2.1 �����ӿ�

| ���� | ǩ�� | ˵�� |
|------|------|------|
| `Bind` | `(iface interface{}, impl interface{})` | �Խӿڵ� reflect.Type Ϊ key ע��ʵ�֣�**�ظ�����ֱ�Ӹ���** |
| `BindNamed` | `(name string, iface interface{}, impl interface{})` | ������ |
| `Resolve` | `(iface interface{}) (interface{}, bool)` | �����Ͳ���ʵ�� |
| `ResolveNamed` | `(name string) (interface{}, bool)` | �����Ʋ���ʵ�� |
| `Inject` | `(target interface{}) error` | ͨ�� `inject:"true"` �� `inject:"����"` ��ǩ�Զ�ע�� |
| `Remove` | `(iface interface{})` | �Ƴ��� |
| `Count` | `() int` | �����Ѱ����� |

### 2.2 ���� DI �󶨱�

| ��� | �󶨽ӿ� | ��ʵ�� | �ļ�λ�� |
|:---:|------|------|------|
| 1 | `(*engine.AssessorEngine)(nil)` | `ssam.NewEngineAdapter(cfg)` | `main.go` (ƽ̨��ע��) |
| 2 | `(*AssessorInterface)(nil)` | AssessorModule | [assessor.go:L99](file:///f:/Argus/internal/kernel/assessor.go#L99) |
| 3 | `(*PersistenceInterface)(nil)` | PersistenceModule | [persistence.go:L261](file:///f:/Argus/internal/kernel/persistence.go#L261) |
| 4 | `(*ConcurrencyInterface)(nil)` | ConcurrencyModule | [workerpool.go:L209](file:///f:/Argus/internal/kernel/workerpool.go#L209) |
| 5 | `(*WorkerPoolInterface)(nil)` | WorkerPool | [workerpool.go:L210](file:///f:/Argus/internal/kernel/workerpool.go#L210) |
| 6 | `(*SPCInterface)(nil)` | SPCModule | [spc.go:L447](file:///f:/Argus/internal/kernel/spc.go#L447) |
| 7 | `(*AdapterIntegrationInterface)(nil)` | AdapterIntegrationModule | [adapter_integration.go:L56](file:///f:/Argus/internal/kernel/adapter_integration.go#L56) |
| 8 | `(*CTIInterface)(nil)` | CTIModule | [cti.go:L47](file:///f:/Argus/internal/kernel/cti.go#L47) |
| 9 | `(*HeartbeatInterface)(nil)` | HeartbeatModule | [heartbeat.go:L55](file:///f:/Argus/internal/kernel/heartbeat.go#L55) |
| 10 | `(*ATTACKInterface)(nil)` | ATTACKModule | [attck.go:L292](file:///f:/Argus/internal/kernel/attck.go#L292) |
| 11 | `(*CommanderInterface)(nil)` | CommanderModule | [commander.go:L106](file:///f:/Argus/internal/kernel/commander.go#L106) |
| 12 | `(*PolicyInterface)(nil)` | PolicyModule | [policy.go:L86](file:///f:/Argus/internal/kernel/policy.go#L86) |
| 13 | `(*SourceManagerInterface)(nil)` | SourceManagerModule | [source_manager.go:L157](file:///f:/Argus/internal/kernel/source_manager.go#L157) |
| 14 | `(*LogCollectorInterface)(nil)` | LogCollectorModule | [collector.go:L74](file:///f:/Argus/internal/kernel/collector.go#L74) |
| 15 | `(*ScoringEngineProvider)(nil)` | ScoringEngineModule | [main.go:L131](file:///f:/Argus/cmd/kernel/main.go#L131) |

### 2.3 ��������ʱ��

����ģ�����������������**����ʱ**���� Init ʱ�̻�������ʹ�����滻��Ϊ���ܣ�

| ����ģ�� | �����ӿ� | ����ʱ�� |
|------|------|------|
| Assessor | `SPCInterface` | ÿ������ʱ |
| Assessor | `CTIInterface` | ÿ������ʱ |
| Assessor | `ATTACKInterface` | ÿ������ʱ |
| Assessor | `ScoringEngineProvider` | Init ʱ |

### 2.4 ����ע��ģʽ

```go
// ��ģ�� Init ��ͨ�� KernelContext ��ȡ����
var spc SPCInterface
if impl, ok := kc.Container().Resolve((*SPCInterface)(nil)); ok {
    spc = impl.(SPCInterface)
}
```

---

## �����¼�����

### 3.1 ���ⳣ��

������ [plugin.go](file:///f:/Argus/internal/kernel/plugin.go#L83-L100)��

| ���� | ֵ | ˵�� |
|------|-----|------|
| `TopicAssessorResult` | `"assessor.result"` | ������ɺ󷢲� |
| `TopicPolicyAction` | `"policy.action"` | �������津������ʱ���� |
| `TopicAgentRegistered` | `"agent.registered"` | Agent ע��ʱ���� |
| `TopicAgentTimeout` | `"agent.timeout"` | Agent ��ʱʱ���� |
| `TopicConfigChanged` | `"config.changed"` | ���ñ��ʱ���� |
| `TopicSPCUpdated` | `"spc.updated"` | SPC ���ݸ���ʱ���� |
| `TopicCTIUpdated` | `"cti.updated"` | CTI �鱨����ʱ���� |
| `TopicCommandEnqueued` | `"command.enqueued"` | �������ʱ���� |
| `TopicCommandResult` | `"command.result"` | ����ִ�н������ʱ���� |
| `TopicAgentHeartbeat` | `"agent.heartbeat"` | Agent ����ʱ���� |
| `TopicConfigReloaded` | `"config.reloaded"` | �����������ʱ���� |
| `TopicCTIThreatDetected` | `"cti.threat_detected"` | CTI ��в��⵽ʱ���� |
| `TopicAdapterFindings` | `"adapter.findings"` | Adapter ���ֽ��ʱ���� |
| `TopicSourceManagerDeployed` | `"source_manager.deployed"` | �ⲿԴ�������ʱ���� |

### 3.2 ���Ĺ�ϵ��

| ������ | ���� | Handler |
|--------|------|---------|
| **PersistenceModule** | `TopicAssessorResult` | `m.onAssessmentResult` |
| **PersistenceModule** | `TopicAgentRegistered` | `m.onAgentRegistered` |
| **PersistenceModule** | `TopicAgentTimeout` | `m.onAgentTimeout` |
| **ATTACKModule** | `TopicAssessorResult` | `m.onAssessmentResult` |
| **CommanderModule** | `TopicPolicyAction` | `m.onPolicyAction` |
| **PolicyModule** | `TopicAssessorResult` | `m.onAssessmentResult` |

### 3.3 �¼���ͼ

```
Agent �ϱ� �� HeartbeatModule
    ���� TopicAgentRegistered ������ PersistenceModule (�־û�ע���¼)
    ���� TopicAgentHeartbeat   ������ (ϵͳ�ڲ�)

�������� �� AssessorModule
    ���� TopicAssessorResult
        ������ PersistenceModule (д��������ʷ)
        ������ ATTACKModule     (ATT&CK �����ʷ��� / APT ����)
        ������ PolicyModule     (�����ж� �� ���ܴ�������)

�����ж� �� PolicyModule
    ���� TopicPolicyAction ������ CommanderModule (�·���� Agent)
```

---

## �ġ���չ��ϵͳ

��չ�㶨���� [extensions.go](file:///f:/Argus/internal/kernel/extensions.go)��

### 4.1 ��������

```go
type ExtensionPoint struct {
    Name        string
    Description string
    Version     string
}

type ExtensionHandler func(ctx context.Context, data interface{}) error
```

### 4.2 ExtensionRegistry ����

| ���� | ˵�� |
|------|------|
| `RegisterPoint(point ExtensionPoint)` | ע����չ�㣨��ƽ̨����ã�������ɵ��ã� |
| `RegisterExtension(pluginID, pointName string, handler ExtensionHandler, priority int) error` | ע����չ������ |
| `Execute(ctx, pointName string, data interface{}) []error` | ִ�����д����� |
| `ExecuteUntilFirst(ctx, pointName string, data interface{}) (string, interface{}, error)` | ִ�е���һ���� nil ��������ز��ID�ͷ���ֵ |
| `UnregisterPlugin(pluginID string)` | �Ƴ�ָ�������������չ |
| `ListPoints() []ExtensionPoint` | �г�������ע����չ�� |
| `ListExtensions(pointName string) []string` | �г�ָ����չ��Ĵ����� ID |

### 4.3 �ں˼���չ�㣨6 ����

| ��չ������ | ����ʱ�� |
|-----------|---------|
| `kernel.pre_init` | ���в�� Init ֮ǰ |
| `kernel.post_init` | ���в�� Init ֮�� |
| `kernel.pre_start` | ���в�� Start ֮ǰ |
| `kernel.post_start` | ���в�� Start ֮�� |
| `kernel.pre_stop` | �ر����п�ʼǰ |
| `kernel.post_stop` | ���в�� Stop ֮�� |

### 4.4 ҵ��ģ����չ�㣨70 ����v0.2.3+��

**AssessorModule��4 ����**��`assessor.pre_evaluate`��`assessor.pre_score`��`assessor.post_evaluate`��`assessor.report_generated`��`assessor.outbound`

**PolicyModule��3 ����**��`policy.action_decided`��`policy.notify`��`policy.status_changed`

**RemediationModule��3 ����**��`remediation.pre_apply`��`remediation.post_apply`��`remediation.action_resolved`

**VerifyModule��3 ����**��`verify.pre_check`��`verify.post_check`��`verify.status_changed`

**ArchiveModule��3 ����**��`archive.pre_write`��`archive.post_write`��`archive.rotation`

**CLI/WebUI ƽ̨��չ��2 ����**��`cli.command.register`��`webui.route.register`

**SPCModule��3 ����**��`spc.pre_calculate`��`spc.post_calculate`��`spc.cve_updated`

**ATTACKModule��13 ����**��

| ��չ�� | ����ʱ�� | ���� |
|------|------|------|
| `attck.coverage.complete` | �����ʷ������ | ������ |
| `attck.apt.matched` | APT ��֯ƥ���� | APT ���� |
| `attck.risk.predicted` | Ԥ���Է���������� | �������� |
| `attck.detection.alert` | ���澯���� | ���澯 |
| `attck.detection.anomaly` | �߷��쳣��⵽ | ���澯 |
| `attck.emulation.complete` | ���ַ������ | ���� |
| `attck.assessment.complete` | ������������� | ���� |
| `attck.apt.chain_detected` | APT �������ع���� | APT ���� |
| `attck.apt.attribution` | APT ����ִ�� | APT ���� |
| `attck.apt.hunt_confirmed` | ��в���Լ���ȷ�� | ��в���� |
| `attck.apt.report_generated` | APT ������������ | ���� |
| `attck.behavioral.alert` | ��Ϊ�澯���� | ��Ϊ���� |
| `attck.behavioral.beacon` | C2 Beaconing ��⵽ | ��Ϊ���� |

**HeartbeatModule��3 ����**��`heartbeat.agent_timeout`��`heartbeat.agent_reconnected`��`heartbeat.agent_pruned`

**ConfigWatcherModule��3 ����**��`config.pre_reload`��`config.post_reload`��`config.load_error`

**CTIModule��3 ����**��`cti.pre_update`��`cti.post_update`��`cti.coefficient_changed`

**AdapterIntegrationModule��2 ����**��`adapter.pre_fetch`��`adapter.post_fetch`

**SIEM Pusher��3 ����**��`siem.pre_push`��`siem.post_push`��`siem.push_failure`

**CommanderModule��2 ����**��`commander.command_expired`��`commander.key_rotated`

**SourceManagerModule��4 ����**��`source.pre_deploy`��`source.post_deploy`��`source.pre_enable`��`source.pre_disable`

**Log Collector��2 ����**��`log.entry_received`��`agent.log_uploaded`

**PersistenceModule��3 ����**��`persistence.pre_append`��`persistence.post_append`��`persistence.dashboard_written`

**�������ڽ׶�ӳ��**��

| �׶� | ��չ�� | ����ģ�� |
|------|--------|---------|
| **̽��** | 23 | Assessor + SPC + ATT&CK + Heartbeat + Adapter + CTI |
| **��Ӧ** | 5 | Policy + ConfigWatcher |
| **����** | 8 | Assessor + ATT&CK + SIEM + Log + Persistence |
| **�޸�** | 5 | Remediation + Commander |
| **��֤** | 3 | Verify |
| **�鵵** | 6 | Archive + Persistence |

### 4.5 ��չ��ע��ʾ����v0.2.3 ���л��ܹ���

��չ����ƽ̨�� `RegisterAllExtensionPoints()` ���ж����� `kernel/platform_extensions.go`��ģ�鲻��ע������չ�㣨`ModuleExtensions` �ӿڲ��� `RegisterPoint`����ֻ�ܶ���������չ�㣺

```go
// ƽ̨��: platform_extensions.go ����ע��
func RegisterAllExtensionPoints(r *ExtensionRegistry) {
    r.RegisterPoint(ExtensionPoint{
        Name: "spc.pre_calculate", Description: "Called before SPC calculation", Version: "1.0",
    })
}

// ģ��: ʹ�� RegisterExtension ���ģ����� RegisterPoint��
kc.Extensions().RegisterExtension("my_plugin", "spc.pre_calculate",
    func(ctx context.Context, data interface{}) error { return nil }, 10,
)
```

---

## �塢ҵ��ģ��ӿ�

### 5.1 ScoringEngineProvider

[assessor.go:L20-L27](file:///f:/Argus/internal/kernel/assessor.go#L20-L27) �� SSAM ���������ṩ��

```go
type ScoringEngineProvider interface {
    Assess(hostID string, hostname string) *model.AssessmentResult
    AssessFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult
    SSAMEngine() *ssam.Engine
    ReloadWeights(cfg *config.Config)
    ValidateEdgeFactors(registeredChecks []model.CheckItem) []string
    PrintReport(result *model.AssessmentResult) string
}
```

### 5.2 AssessorInterface

[assessor.go:L515-L520](file:///f:/Argus/internal/kernel/assessor.go#L515-L520) �� ����������

```go
type AssessorInterface interface {
    Evaluate(hostID string) *model.AssessmentResult
    EvaluateFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult
    GetResult(hostID string) *model.AssessmentResult
    ReloadConfig(cfg *config.Config)
}
```

### 5.3 PolicyInterface

[policy.go:L182-L185](file:///f:/Argus/internal/kernel/policy.go#L182-L185) �� ��������

```go
type PolicyInterface interface {
    EvaluateHost(hostID string, score float64) (HostStatus, []PolicyAction)
    GetHostStatus(hostID string) HostStatus
}
```

### 5.4 SPCInterface

[spc.go:L1194-L1213](file:///f:/Argus/internal/kernel/spc.go#L1194-L1213) �� ��ȫ̬�Ƽ���

```go
type SPCInterface interface {
    Calculate(hostID string, assetPackages []string) SPCCorrection
    AddCVE(score SPCCVEScore)
    AddCVEs(scores []SPCCVEScore)
    MergeCVEs(cves []SPCCVEScore) (added int, updated int)
    GetCVEs() []SPCCVEScore
    GetCVECount() int
    GetKEVCount() int
    ClearCache()
    UpsertAsset(asset LocalAsset)
    GetAsset(hostID string) *LocalAsset
    FetchFromAllSources() []SPCFetchResult
    FetchFromEPSS() SPCFetchResult
    FetchFromCISAKEV() SPCFetchResult
    ImportOSCAL(data []byte, format string) (int, error)
    ConfigureMISP(baseURL, apiKey string) error
    Enabled() bool
    SetEnabled(v bool)
    LastUpdate() time.Time
}
```

### 5.5 CTIInterface

[cti.go:L166-L170](file:///f:/Argus/internal/kernel/cti.go#L166-L170) �� ������в�鱨

```go
type CTIInterface interface {
    GetCoefficient() float64
    ReportThreat(severity string)
    ClearThreat()
}
```

### 5.6 ����ģ��ӿ�

| �ӿ� | �ļ�λ�� | ������ |
|------|------|:---:|
| `HeartbeatInterface` | [heartbeat.go:L223-L229](file:///f:/Argus/internal/kernel/heartbeat.go#L223-L229) | 5 |
| `CommanderInterface` | [commander.go:L324-L328](file:///f:/Argus/internal/kernel/commander.go#L324-L328) | 3 |
| `PersistenceInterface` | [persistence.go:L651-L661](file:///f:/Argus/internal/kernel/persistence.go#L651-L661) | 9 |
| `ConcurrencyInterface` | [workerpool.go:L304-L311](file:///f:/Argus/internal/kernel/workerpool.go#L304-L311) | 6 |
| `WorkerPoolInterface` | [workerpool.go:L313-L321](file:///f:/Argus/internal/kernel/workerpool.go#L313-L321) | 6 |
| `ATTACKInterface` | [attck.go:L1560-L1639](file:///f:/Argus/internal/kernel/attck.go#L1560-L1639) | 30+ |
| `AdapterIntegrationInterface` | [adapter_integration.go:L198-L201](file:///f:/Argus/internal/kernel/adapter_integration.go#L198-L201) | 2 |
| `LogCollectorInterface` | [collector.go:L177-L180](file:///f:/Argus/internal/kernel/collector.go#L177-L180) | 2 |
| `SourceManagerInterface` | [source_manager.go:L88-L103](file:///f:/Argus/internal/kernel/source_manager.go#L88-L103) | 14 |

---

## ���������ע�������滻��

### 6.1 ע������

�����ͨ�� [registry.go](file:///f:/Argus/internal/checks/registry.go) ��ȫ��ע�������

```go
var (
    mu       sync.RWMutex
    registry []model.CheckItem
)

func Register(items ...model.CheckItem)     // ע���¼����
func Unregister(checkIDs ...string)          // �� ID �Ƴ������
func GetAll() []model.CheckItem             // ��ȡȫ��ע����
func GetByID(checkID string) (model.CheckItem, bool)  // �� ID ����
func GetByDomain(domain model.ScoreDomain) []model.CheckItem  // ����ɸѡ
```

Ĭ�ϼ������ [init.go](file:///f:/Argus/internal/checks/init.go) ��ͨ�� `init()` �Զ�ע�᣺

```go
func init() {
    Register(linux.All()...)
}
```

### 6.2 �滻�����

**���� A���滻���������**

```go
checks.Unregister("AS-001")
checks.Register(model.CheckItem{
    ID: "AS-001", Domain: model.DomainAttackSurface, Function: myCustomAS001Checker,
})
```

**���� B���滻ȫ�������**

```go
checks.Unregister(/* ��ȡ�������� ID */...)
checks.Register(myCustomCheckSet...)
```

**���� C�����Ϲ�Ҫ��ü�**

```go
ids := checks.GetByComplianceLevel("�ȱ�����")
// ���˺�����ע��
checks.Unregister(getIDs(all)...)
checks.Register(keep...)
```

### 6.3 �滻ע������

| ע��� | ˵�� |
|------|------|
| ?? **��Ե���� TriggerCheck ����** | �滻�������ͬ������ `TriggerCheck` ӳ�� |
| ?? **ATT&CK ����ӳ��** | ���� ATTACKModule ��ͬ������ |
| ?? **�ȱ������ע** | �滻�����ע��ȷ�ĵȱ������� |
| ? **����ʱ��ȫ** | `sync.RWMutex` ������֧�ֲ�����д |

---

## �ߡ�����ģ����滻��

### 7.1 DI �����滻ԭ��

DI ������[di.go](file:///f:/Argus/internal/kernel/di.go#L23-L32)���� `Bind` ����**���ǲ���**�����ظ���ͬһ�ӿڻᾲĬ����֮ǰ��ʵ�֣�

```go
func (c *Container) Bind(iface interface{}, impl interface{}) {
    t := reflect.TypeOf(iface).Elem()
    c.bindings[t] = impl  // ֱ�Ӹ��ǣ��޼��
}
```

### 7.2 ���滻������

| ��� | ���滻�� | �滻���� | ���滻 |
|------|:---:|------|:---:|
| ԭ������� | ? | ע��� API��Register/Unregister�� | ? |
| SPC ��ȫ̬�Ƽ��� | ? | DI ���� Bind ���� SPCInterface | ? |
| CTI ������в�鱨 | ? | DI ���� Bind ���� CTIInterface | ? |
| SSAM �������� | ? | DI ���� Bind ���� ScoringEngineProvider | ? |
| ATT&CK ֪ʶ�� | ? | DI ���� Bind ���� ATTACKInterface | ? |
| Assessor �������� | ? | DI ���� Bind ���� AssessorInterface | ? |
| Policy �������� | ? | DI ���� Bind ���� PolicyInterface | ? |
| Commander �����·� | ? | DI ���� Bind ���� CommanderInterface | ? |
| Persistence �־û� | ? | DI ���� Bind ���� PersistenceInterface | ? |
| ���� 6 ������ģ�� | ? | DI ���� Bind ���Ƕ�Ӧ�ӿ� | ? |

### 7.3 �滻������

| �滻ģ�� | Ӱ������� |
|------|------|
| `SPCInterface` | Assessor �� SSAM ��ʽ��P_score ���ӣ� |
| `CTIInterface` | Assessor �� SSAM ��ʽ���� ��вϵ���� |
| `ScoringEngineProvider` | Assessor �� �������ֹܵ� |
| `ATTACKInterface` | Assessor �� ������/APT ���� |
| `PolicyInterface` | �����ж� �� Commander �����·� |
| `ConcurrencyInterface` | ����ʹ�� WorkerPool ��ģ�� |

### 7.4 �滻ʾ��

```go
// �滻 SPC Ϊ�Զ���ʵ��
type MySPC struct{}
func (m *MySPC) Calculate(hostID string, assetPackages []string) SPCCorrection {
    return SPCCorrection{Score: 1.0, Weight: 1.0}
}
// ʵ�� SPCInterface �����з���...

// �� main.go ���滻
k.Container().Bind((*kernel.SPCInterface)(nil), &MySPC{})
```

---

## �ˡ��ⲿ����������ί��

### 8.1 �ⲿ����������

[AdapterIntegrationModule](file:///f:/Argus/internal/kernel/adapter_integration.go) �ṩ�ⲿ��ȫ���ߵļ��ɣ�

```
�ⲿ��ȫ����            AdapterIntegration          Assessor
����������������������            ������������������������������������          ����������������
Wazuh / OpenSCAP / Lynis / Falco
    ������   RunAdapters() �� CollectFindings() �� EvaluateFromResults()
                                                  ��
                                         []model.CheckResult
```

### 8.2 �ⲿ���ע���

Assessor �ṩ����������ڣ�

| ��� | ǩ�� | �����Դ |
|------|------|------|
| `Evaluate` | `(hostID string)` | ԭ�������ע��� |
| `EvaluateFromResults` | `(hostID, hostname string, checkResults []model.CheckResult)` | �ⲿ����� CheckResult ��Ƭ |

**��ȫ���ԭ�������**��

```go
checks.Unregister(getAllIDs()...)           // ���ԭ�������
adapterResults := adapter.CollectFindings()  // �ռ��ⲿ�����
result := assessor.EvaluateFromResults(hostID, hostname, adapterResults)
```

### 8.3 ������������ģ�ͽṹ

```go
type CheckResult struct {
    CheckID           string       // ����� ID
    Domain            ScoreDomain  // ������AS/BC/OT/RS��
    Passed            bool         // �Ƿ�ͨ��
    Score             float64      // �÷�
    Detail            string       // ����
    Description       string       // ����
    ComplianceRef     string       // �Ϲ�����
    ATTACKTechniqueID string       // ATT&CK ���� ID
    EdgeFactors       []string     // �����ı�Ե���� ID
}
```

---

## �š���չ��������ָ��

### 9.1 ��������嵥

1. ʵ�� `Plugin` �ӿڣ�`Info/Dependencies/Init/Start/Stop/State`��
2. ����������˳��ʵ�� `PriorityPlugin` �ӿ�
3. ���轡����飬ʵ�� `HealthCheckable` �ӿ�
4. �����ȼ������ã�ʵ�� `ConfigurablePlugin` �ӿ�
5. �� `Init` �У�ͨ�� `kc.Container().Resolve()` ��ȡ������ͨ�� `kc.Container().Bind()` ע������ӿڡ�ͨ�� `kc.Extensions().RegisterExtension()` ������չ��
6. �� `Start` �У�ͨ�� `kc.Bus().Subscribe()` �����¼������ goroutine
7. �� `Stop` �У��ر� goroutine��������Դ
8. �� [main.go](file:///f:/Argus/cmd/kernel/main.go) ��ʵ������ע��

### 9.2 ������չ�㣨ƽ̨�������

��չ�㶨����� ASSCOR ƽ̨�㣨`kernel/platform_extensions.go`�����������ģ�顣������չ������ `RegisterAllExtensionPoints()` ��������ӣ�

```go
// platform_extensions.go: ����ע��
func RegisterAllExtensionPoints(r *ExtensionRegistry) {
    r.RegisterPoint(ExtensionPoint{
        Name: "module.phase", Description: "����˵��", Version: "1.0",
    })
}
// ģ�鴥��: ����λ�þ���
errs := kc.Extensions().Execute(ctx, "module.phase", data)
```

### 9.3 �����¼�����

1. �� [plugin.go](file:///f:/Argus/internal/kernel/plugin.go) ����� `Topic*` ����
2. ���������� `kc.Bus().Publish(ctx, TopicXxx, payload)`
3. ���ķ����� `kc.Bus().Subscribe(TopicXxx, "my_id", handler)`
4. Handler ǩ����`func(ctx context.Context, msg Message) error`

### 9.4 ����Լ��

- ��չ�����ƣ�`ģ����.�׶�`���� `spc.pre_calculate`��
- �¼����⣺`ģ����.�¼���`���� `assessor.result`��
- DI �� key��`(*InterfaceName)(nil)` �� reflect.Type

---

## ʮ���滻���Ӷ���ȱ�ڷ���

### 10.1 �滻�Ѷ�

| �Ѷ� | ��� |
|:---:|------|
| ? **��**�����д��룩 | �������CTI��Policy��Commander��LogCollector��Heartbeat |
| ?? **��**��< 50 �У� | SPC��Persistence��AdapterIntegration��SourceManager��Concurrency |
| ??? **��**������֤�� | SSAM ���桢ATTACK��Assessor |

### 10.2 ��֪ȱ��

| ȱ�� | ˵�� | Ӱ�� |
|------|------|:---:|
| ������� DI ������ͳһ | �������ȫ��ע��������ģ���� DI ���� | ���� API |
| `Evaluate` ��ڲ�͸�� | �ڲ����� `checks.GetAll()`���޷����Ǽ������Դ | ���������ֶ����� `EvaluateFromResults` |
| ��������ԭ��������ϲ�ȱʧ | ������������ֶ����� `EvaluateFromResults`�����Զ��ϲ�ͨ�� | �������� |

### 10.3 ͳ�ƻ���

| ��� | ���� |
|------|:---:|
| ���Ĳ���ӿ� | 4��Plugin / PriorityPlugin / HealthCheckable / ConfigurablePlugin�� |
| ��ע���� | 15 |
| ҵ��ģ��ӿ� | 13 |
| DI ������ | 15 |
| �¼����߻��� | 13 |
| ���߶��Ĺ�ϵ | 6 |
| ��չ������ | 76���ں� 6 + ҵ��ģ�� 70�� |
| ȫ�����滻 | ? |

---

## 11. �ⲿ��չģ������չ����v0.2.3+��

ASSCOR v0.2.3 ������**�ⲿ��չ��ϵ**�������ں˼��ɵ� ExtensionManager (extmgr) �����ġ����������ģ�黯��չϵͳ���������ԭ��**�ⲿ��չ���޸��ں˴��룬ͨ�� Go import �� Extension Point ϵͳ����**��

### 11.1 Ŀ¼�ṹ

```
optional/                          # �ⲿ��չ��Ŀ¼���������ںˣ�
������ README.md                      #   ʹ��ָ��
������ SCHEMA.md                      #   package.json ��ʽ�淶
������ pkgmgr/                        #   ��չ��������� (asscor-pkg CLI)
��   ������ main.go                    #     6 �� CLI ����
��   ������ manifest.go                #     package.json ���� + �������
��   ������ fetcher.go                 #     git �ⲿ�ֿ��¡ + ������У��
������ algorithms/                    #   ����;: �㷨��չ
��   ������ modules/                   #     ��ģ����չ
��   ��   ������ multi-algo-orchestrator/ #   ���㷨������ (���� Go module)
��   ������ packages/                  #     ��ģ����չ��
��       ������ example-pack/          #       ʾ����չ��
��           ������ package.json       #         �������� + �ⲿ�ֿ�����
������ adapters/                      #   ����;: ��������չ
��   ������ modules/
��   ������ packages/
������ checks/                        #   ����;: �������չ
��   ������ modules/
��   ������ packages/
������ platform/                      #   ����;: ƽ̨����չ
    ������ modules/
    ������ packages/
```

### 11.2 ��ģ�� vs ��չ��

ASSCOR �ⲿ��չ�ṩ������ʽ��

| ��ʽ | Ŀ¼·�� | ���뷽ʽ | ���ó��� |
|------|---------|---------|---------|
| **��ģ��** | `<category>/modules/<name>/` | �� `cmd/kernel/main.go` �� `import`��ͨ�� `Register()` ���ص� Extension Point | �����������ܣ�����㷨���ţ� |
| **��չ��** | `<category>/packages/<name>/` | ͨ�� `package.json` ����ģ�鼯�ϡ��ⲿ�����ͳ�ͻ��ʹ�� `asscor-pkg install` �Զ���ȡ�ⲿ�ֿ� | ��ģ��ۺϡ��������� git �ֿ������ĸ�����չ |

��ģ���ǲ�����Ķ���ģ�顣��չ��ͨ�� `package.json` ��������ģ�顢�ⲿ git �ֿ����á���������ͻ��֧�� `asscor-pkg` �Զ�������

### 11.3 ��չ�������� (asscor-pkg)

`asscor-pkg` ��ר�Ź��� `optional/` ����չ���������й��ߡ���������ں˶����ƣ������������

```bash
cd optional/pkgmgr && go build -o asscor-pkg .
```

| ���� | ���� |
|------|------|
| `asscor-pkg resolve` | �ݹ�ɨ�� `package.json`����������ͼ����⻷������δ����� |
| `asscor-pkg install` | ��¡ `external_sources` ���������ⲿ git �ֿ� + ������У�� |
| `asscor-pkg list` | �г������ѷ��ֵ���չ�� |
| `asscor-pkg info <name>` | �鿴��չ����ϸ��Ϣ��ģ�顢�������ⲿԴ�������ԣ� |
| `asscor-pkg graph` | ��� DOT ��ʽ����ͼ���ɹܵ��� `dot -Tpng`�� |
| `asscor-pkg validate` | У������ `package.json` ��ʽ���ֶκϷ��� |

#### 11.3.1 ���������

- **�汾Լ��**��֧�� `>=` `<=` `>` `<` `^x.y.z` `~x.y.z` `1.0.0 - 2.0.0` `1.x` ��ȷƥ��
- **�����������**��DFS �����㷨��ʶ�𲢱���ѭ������
- **��ͻ����**��ͨ�� `conflicts` �ֶ�������������չ��
- **��ѡ����**����� `optional: true` ������ȱʧ����Ϊ����
- **������У��**����� `asscor_version` / `go_version` / `ssam_version` / `platform` Լ��

### 11.4 package.json �嵥��ʽ

ÿ����չ����Ŀ¼����� `package.json`�����ں� ExtensionManager �� `extension.json` ��������`extension.json` ��������ʱ�����װ��`package.json` �������ʱ���������

```json
{
  "name": "example-security-pack",
  "version": "1.0.0",
  "description": "ʾ����չ��",
  "compatibility": { "asscor_version": ">=0.2.1", "go_version": ">=1.26", "platform": ["linux"] },
  "modules": [
    { "id": "multi-algo-orchestrator", "path": "../../modules/multi-algo-orchestrator" }
  ],
  "external_sources": [
    { "repo": "https://github.com/user/repo", "ref": "v1.0.0", "path": "subdir/", "target": "modules/custom-checks" }
  ],
  "dependencies": [
    { "package": "base-algorithms-pack", "version": ">=1.0.0" },
    { "package": "experimental-plugin", "version": ">=0.1.0", "optional": true }
  ],
  "conflicts": [
    { "package": "legacy-scoring-only", "versions": "<=0.5.0", "reason": "ʹ�������õ���������" }
  ]
}
```

�����淶�� `optional/SCHEMA.md`��

### 11.5 ���㷨������ (multi-algo-orchestrator)

λ�� `optional/algorithms/modules/multi-algo-orchestrator/`�����ⲿ��չ��ϵ���׸���ģ��ʵ�֡������һ�����㷨��"ľͰЧӦ"����ͨ�����Ŷ���㷨����/����/����ִ�У�ȡ��ͷ�������һ�㷨ƫ�

#### 11.5.1 ���뷽ʽ

���޸��ں˴��룬ͨ�� Extension Point ϵͳ���أ�

```go
import multialgo "github.com/asscor/asscor-optional-multi-algo"

cfg := multialgo.OrchestrationConfig{
    Mode:  multialgo.ModeCascade,
    Merge: multialgo.MergeWorstOf,
    Algorithms: []multialgo.AlgorithmProfile{
        {ID: "ssam_v2", Name: "SSAM 2.0", Role: multialgo.RolePrimary, ...},
        {ID: "baseline", Name: "��׼�㷨", Role: multialgo.RoleSecondary, ...},
    },
}
orch := multialgo.NewOrchestrator(cfg)
orch.Register(k.PlatformExtensionRegistry())  // ���� assessor.pre_score ��չ��
```

#### 11.5.2 ����ִ��ģʽ

| ģʽ | ��Ϊ | ���� |
|------|------|------|
| `sequential` | ������ִ�� | ������֤ |
| `parallel` | goroutine ����ִ�������㷨 | ������ |
| `cascade` | ���㷨���� (����ֵ) ���������㷨 | ������ʡ��Դ |

#### 11.5.3 ���ֺϲ�����

| ���� | ��Ϊ | ����ľͰЧӦ |
|------|------|:---:|
| `best_of` | ȡ��߷� | ? |
| `worst_of` | **ȡ��ͷ�** | ? |
| `weighted_average` | ���㷨���Ŷȼ�Ȩƽ�� | ?? |
| `consensus` | һ����ƽ��������ȡ��� | ? |
| `primary_only` | ��ʹ�����㷨 | ? |

#### 11.5.4 �����ģʽ

| ģʽ | ��Ϊ |
|------|------|
| `merge` | �ϲ������㷨������ CheckID ȥ�� |
| `independent` | ���㷨ӵ�ж���������б���������� |
| `tagged` | ������ע��Դ�㷨����������ɼ���Դ��ǩ |

#### 11.5.5 ľͰЧӦ����

������������ṩ�������㷨����������
- `AlgoSpread`����߷֡���ͷֲ���
- `AlgoVariance`��ͳ���㷨�䷽��
- `WorstAlgo` / `BestAlgo`��ʶ��̰�ͳ����㷨
- `EliminatedByCascade`������ģʽ���������㷨�б�

---

## ����

ASSCOR ����չ��ϵ�ṩ��**���ֻ�������չ����**���������ڲ�� (Plugin �ӿ�)������ʱ���� (Extension Point)���ں˰�װʽ��չ (ExtensionManager + extension.json)���ⲿ����ʱ��չ (optional/ + pkgmgr + package.json)���������˴ӵײ����߼��������������桢���ں���Ƕ����������ģ���ȫ������չ������14 ������ģ��ӿ�ȫ��ͨ�� DI ����ע�룬�����ͨ��ע��� API ������ⲿ��չͨ�� Extension Point ϵͳʵ�����������ʽ���أ���չ��ͨ�� `asscor-pkg` �����������������ⲿ�ֿ����á�������ϵΪ�������������ṩ�˴����������������㷨���ŵ�ȫά����չ������