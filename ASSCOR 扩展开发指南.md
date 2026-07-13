# ASSCOR 鎵╁睍寮€鍙戞寚鍗?
**鐗堟湰**锛歷1.1 | **閫傜敤**锛欰SSCOR v0.2.1 / SSAM 2.0 | **鏃ユ湡**锛?026-07-07

---

## 鎽樿

ASSCOR 閲囩敤寰唴鏍?+ 鎻掍欢鏋舵瀯锛屾彁渚?**10 绉嶆墿灞曟柟寮?*锛岃鐩栦粠闆堕棬妲涢厤缃埌涓撲笟 Go 寮€鍙戠殑瀹屾暣鎵╁睍闈€傛湰鎸囧崡闈㈠悜甯屾湜涓?ASSCOR 缂栧啓鑷畾涔夋墿灞曠殑寮€鍙戣€呫€?
---

## 1. 鎵╁睍浣撶郴鎬昏

### 1.1 鍗佺鎵╁睍鏂瑰紡

| 鏂瑰紡 | 闂ㄦ | 娉ㄥ唽鍏ュ彛 | 鎺ュ叆鏂瑰紡 |
|------|------|----------|----------|
| `user_check` | 馃煝 闆?| `config.ini [user_check.*]` | 缂栬緫閰嶇疆鏂囦欢 |
| `adapter_script` | 馃煝 鏋佷綆 | `config.ini [adapter_script.*]` | 鑴氭湰 + 閰嶇疆 |
| `check_module` | 馃煛 浣?| `checks.Register()` | 缂栬瘧鏈?init() / 鎵╁睍鍖?|
| `scoring_plugin` | 馃煛 浣?| `Engine.RegisterFormula()` | 杩愯鏃?|
| `adapter` | 馃煛 浣?| `adapter.Register()` | 缂栬瘧鏈?init() |
| `hook` | 馃煛 浣?| `Assessor.RegisterHook()` | 杩愯鏃?|
| `domain` | 馃煛 浣?| `model.RegisterDomain()` | 杩愯鏃?/ 閰嶇疆 |
| `edge_factor` | 馃煛 浣?| `model.RegisterEdgeFactor()` | 缂栬瘧鏈?init() / 閰嶇疆 |
| `cli_command` | 馃煛 浣?| `CLIModule.RegisterCommand()` | 鎵╁睍鐐?|
| `custom` | 馃敶 涓?| `kernel.Plugin` 鎺ュ彛 | 鎻掍欢娉ㄥ唽 |
| `web_panel` | 馃敶 涓?| `webui.route.register` 鎵╁睍鐐?| 杩愯鏃?|

### 1.2 閫夋嫨鎸囧崡

| 闇€姹?| 鎺ㄨ崘鏂瑰紡 | 闇€瑕佸啓浠ｇ爜 |
|------|----------|-----------|
| 娣诲姞涓€涓懡浠ゆ鏌?| `user_check` | 鉂?涓嶉渶瑕?|
| 杩愯鑷畾涔夎剼鏈?| `adapter_script` | 鉁?Bash/Python |
| 瀵规帴鏂版壂鎻忓伐鍏?| `adapter` | 鉁?Go |
| 鑷畾涔夎瘎鍒嗙畻娉?| `scoring_plugin` | 鉁?Go |
| 瀹屾暣瀛愮郴缁?| `Plugin SDK` | 鉁?Go锛堢嫭绔嬫ā鍧楋級 |

鎵╁睍浠ｇ爜浣滀负 Go 鍖呯紪鍏ヤ簩杩涘埗锛岄€氳繃 `init()` 鍑芥暟鍦ㄥ惎鍔ㄦ椂鑷姩娉ㄥ唽銆傞浂杩愯鏃朵緷璧栵紝淇濇寔鍗曚簩杩涘埗閮ㄧ讲浼樺娍銆?
**妯″紡 B 鈥?杩愯鏃舵墿灞曞寘锛圗xtensionManager锛?*

鎵╁睍浠ュ閮ㄥ寘褰㈠紡锛坓it/http/鏈湴锛夊垎鍙戯紝鐢?`ExtensionManager` 涓嬭浇銆佹牎楠屻€佽В鍘嬨€佹敞鍐岋紝鏀寔 `Install 鈫?Enable 鈫?Disable 鈫?Delete` 鐢熷懡鍛ㄦ湡銆傞€傜敤浜庣涓夋柟鍒嗗彂鐨勫彲鎻掓嫈鎵╁睍銆?
---

## 2. 鎵╁睍绫诲瀷璇﹁В

### 2.1 user_check 鈥?閰嶇疆鏂囦欢瀹氫箟妫€鏌ラ」锛堥浂闂ㄦ锛?
**涓嶉渶瑕佺紪鍐欎换浣曚唬鐮併€?* 鍦?`config.ini` 涓坊鍔?`[user_check.<鍚嶇О>]` 鑺傚嵆鍙垱寤烘鏌ラ」銆?
**缂栧啓绀轰緥**锛?
```ini
[user_check.nginx]
id = CU-001
domain = attack_surface
name = Nginx service status
command = systemctl is-active nginx
delta = -8
output_match = active
```

**宸ヤ綔鍘熺悊**锛氬唴鏍稿惎鍔ㄦ椂瑙ｆ瀽 `user_check.*` 閿紝涓烘瘡涓湁鏁堢殑鑺傚垱寤?`model.CheckItem` 骞舵敞鍐屽埌妫€鏌ラ」娉ㄥ唽琛ㄣ€傛敮鎸?`command`锛堝懡浠ゆ鏌ワ級鍜?`file_path + file_regex`锛堟枃浠跺唴瀹规鏌ワ級涓ょ妯″紡銆?
**瑕佺偣**锛?- 淇敼鍚庢墽琛?`systemctl reload asscor-kernel`锛圫IGHUP锛夊嵆鍙敓鏁堬紝鏃犻渶閲嶅惎
- `command` 妯″紡閫氳繃 shell 鎵ц锛宔xit 0 鎴栬緭鍑轰腑鍚?`output_match` 鍒欎负閫氳繃
- `file_path` 妯″紡妫€鏌ユ枃浠跺瓨鍦ㄦ€э紙鏃犳鍒欙級鎴栧唴瀹规鍒欏尮閰?
### 2.2 adapter_script 鈥?澶栭儴鑴氭湰閫傞厤鍣紙鏋佷綆闂ㄦ锛?
**缂栧啓浠绘剰璇█鐨勮剼鏈?*锛屽叾 stdout 杈撳嚭 JSON 鏁扮粍鍗宠嚜鍔ㄦ垚涓洪€傞厤鍣ㄥ彂鐜般€傞厤缃竴琛屽嵆鍙紩鍏ャ€?
**缂栧啓绀轰緥**锛圔ash 鑴氭湰 `/opt/asscor/scripts/my-monitor.sh`锛夛細

```bash
#!/bin/bash
echo '[{"id":"MON-001","title":"Disk usage","severity":"high","detail":"95% full"}]'
```

**閰嶇疆**锛坄config.ini`锛夛細

```ini
[adapter_script.my-monitor]
path = /opt/asscor/scripts/my-monitor.sh
```

**瀹夊叏闄愬埗**锛氳矾寰勫繀椤诲湪鐧藉悕鍗曠洰褰曚笅锛坄/opt/asscor/scripts/` 绛夛級锛岃剼鏈繀椤?root:root 涓旈潪 world-writable锛屾嫆缁濈鍙烽摼鎺ワ紝30 绉掕秴鏃讹紝1MB 杈撳嚭涓婇檺銆?
**JSON 瀛楁** (`scriptFinding`):

```go
type scriptFinding struct {
    ID          string `json:"id"`
    Title       string `json:"title"`       // 蹇呴』
    Severity    string `json:"severity"`    // critical/high/medium/low/info
    Detail      string `json:"detail"`
    Domain      string `json:"domain"`
    CheckID     string `json:"check_id"`
    FindingType string `json:"finding_type"` // vulnerability/misconfig/compliance/alert
}
```

### 2.3 Plugin SDK 鈥?鐙珛妯″潡寮€鍙戯紙Go 涓撲笟寮€鍙戯級

浣嶄簬 `pluginsdk/` 鐨勭嫭绔?Go 妯″潡銆傛彃浠堕€氳繃 **JSON-RPC 2.0 鍗忚** 缁?stdin/stdout 涓庡唴鏍搁€氫俊锛?*闆?ASSCOR 婧愮爜渚濊禆**銆?
**鏍稿績鎺ュ彛**锛?
```go
type Plugin interface {
    Init(config map[string]string) error
    HandleRequest(method string, params json.RawMessage) (json.RawMessage, error)
    Shutdown() error
}
```

**寮€鍙戞祦绋?*锛?
1. 澶嶅埗 `pluginsdk/cmd/myplugin/` 鈫?浣犵殑鎻掍欢鐩綍
2. 瀹炵幇 `HandleRequest()` 鏂规硶
3. `go build -o yourplugin`
4. 缂栧啓 `extension.json` manifest
5. `asscor> source deploy yourplugin`

**鏋舵瀯**锛堜綆鑰﹀悎锛夛細鎻掍欢浣滀负鐙珛杩涚▼杩愯锛岄€氳繃 stdin/stdout JSON-RPC 2.0 閫氫俊锛岄浂鍏变韩鍐呭瓨銆傚畨鍏ㄤ笂瀹炵幇杩涚▼闅旂銆丼HA-256 鏍￠獙鍜屻€乻ystemd scoping 璧勬簮闄愬埗銆?
### 2.4 check_module 鈥?瀹夊叏妫€鏌ラ」

妫€鏌ラ」鏄?ASSCOR 鏈€甯歌鐨勬墿灞曘€傛瘡涓鏌ラ」褰掑睘涓€涓瘎浼板煙锛岃緭鍑洪€氳繃/澶辫触涓庢墸鍒嗐€?
**鏍稿績缁撴瀯** (`internal/model/model.go`)锛?
```go
type CheckFunc func() (passed bool, detail string)

type PrivilegeLevel int
const (
    PrivNormal PrivilegeLevel = iota  // 鏅€氭潈闄?    PrivRoot                          // 闇€瑕?root
)

type CheckItem struct {
    ID            string          // 鍞竴鏍囪瘑锛屽 "KS-001"
    Domain        string          // 褰掑睘鍩燂紝濡?model.DomainKernelSecurity
    Name          string
    Description   string
    Delta         float64         // 澶辫触鏃舵墸鍒嗭紙璐熷€硷級
    ComplianceRef string          // 鍚堣寮曠敤锛屽 "GB/T 22239-2019"
    Platform      string          // "" = 鍏ㄥ钩鍙? "linux", "windows"
    Check         CheckFunc
    Privilege     PrivilegeLevel  // 闈?root 杩愯鏃?PrivRoot 妫€鏌ヨ嚜鍔ㄨ烦杩?}
```

**缂栧啓绀轰緥**锛?
```go
package mychecks

import (
    "os"
    "github.com/asscor/asscor/internal/checks"
    "github.com/asscor/asscor/internal/model"
)

func init() {
    checks.Register(model.CheckItem{
        ID:            "CU-001",
        Domain:        model.DomainOperationTrust,
        Name:          "鑷畾涔夐厤缃鏌?,
        Description:   "妫€鏌?/etc/myapp/secure.conf 鏄惁瀛樺湪涓旀潈闄愭纭?,
        Delta:         -8,
        ComplianceRef: "GB/T 22239-2019 8.1.3",
        Platform:      "linux",
        Privilege:     model.PrivNormal,
        Check: func() (bool, string) {
            info, err := os.Stat("/etc/myapp/secure.conf")
            if err != nil {
                return false, "閰嶇疆鏂囦欢涓嶅瓨鍦?
            }
            if info.Mode().Perm() != 0600 {
                return false, "閰嶇疆鏂囦欢鏉冮檺杩囧锛堝簲涓?0600锛?
            }
            return true, "閰嶇疆鏂囦欢鏉冮檺姝ｇ‘"
        },
    })
}
```

**瑕佺偣**锛?- `Check` 鍑芥暟鐢卞唴鏍稿湪鐙珛 goroutine 涓皟鐢紝鍐呯疆 panic 鎭㈠
- 闇€瑕?root 鐨勬鏌ヨ `Privilege: model.PrivRoot`锛孉gent 闈?root 杩愯鏃惰嚜鍔ㄨ烦杩囧苟鏍囪
- 鍛戒护鎵ц璇蜂娇鐢?`common.RunCmd`锛堝唴缃?shell 鍏冨瓧绗﹂槻鎶わ級

### 2.2 scoring_plugin 鈥?鑷畾涔夎瘎鍒嗗叕寮?
璇勫垎鍏紡灏嗗煙寰楀垎銆佸▉鑳佺郴鏁般€丼PC 鍒嗘暟銆佽竟缂樺洜瀛愯仛鍚堜负鏈€缁堝垎鏁般€?
**鍑芥暟绫诲瀷** (`ssam-lib/types.go`)锛?
```go
type ScoringFormula func(
    domainScores []DomainScore,      // 鍚勫煙寰楀垎
    weights      []WeightConfig,     // 鍚勫煙鏉冮噸
    threatCoeff  float64,            // 濞佽儊绯绘暟 渭 (0.60-1.0)
    spcScore     float64,            // SPC 鎬佸娍鍒嗘暟 (0.60-1.0)
    edgeFactors  []EdgeFactorResult, // 杈圭紭鍥犲瓙
) float64
```

**缂栧啓绀轰緥**锛?
```go
engine.RegisterFormula("my-strict-v1", func(
    ds []ssam.DomainScore, w []ssam.WeightConfig,
    threat, spc float64, ef []ssam.EdgeFactorResult) float64 {

    var sum, wsum float64
    for _, d := range ds {
        for _, cfg := range w {
            if cfg.Domain == d.Domain {
                sum += d.Score * cfg.Weight
                wsum += cfg.Weight
            }
        }
    }
    base := sum / wsum
    for _, f := range ef {
        if f.Active {
            base *= f.Factor  // 杈圭紭鍥犲瓙涔樻硶淇
        }
    }
    // 涓ユ牸妯″紡锛氬▉鑳佷笌鎬佸娍鐩存帴鐩镐箻
    return base * threat * spc
})
```

**瑕佺偣**锛?- 閫氳繃 `RegisterFormula(id, fn)` 娉ㄥ唽鍚庯紝璇?ID 鑷姩鎴愪负娲昏穬鍏紡
- 鑷畾涔夊叕寮?*浼樺厛浜?*鍐呯疆 SSAM V2.0 涓夊眰鍔犳潈骞冲潎鍏紡
- 鍐呯疆榛樿鍏紡涓?`ssam_v2.0`锛堜笁灞傚姞鏉冨钩鍧囷細Intrinsic 50% / Exposure 30% / Threat 20%锛?
### 2.3 adapter 鈥?澶栭儴宸ュ叿閫傞厤鍣?
閫傞厤鍣ㄥ皢澶栭儴瀹夊叏宸ュ叿锛堟壂鎻忓櫒銆佽祫浜х鐞嗙郴缁燂級鐨勮緭鍑鸿鑼冨寲涓?ASSCOR 妫€鏌ョ粨鏋溿€?
**鎺ュ彛** (`internal/adapter/adapter.go`)锛?
```go
type Adapter interface {
    ID() string
    Name() string
    Category() string    // "vulnerability" / "asset" / ...
    Priority() string    // "high" / "medium" / "low"
    Version() string
    Fetch(ctx context.Context, config map[string]string) ([]byte, error)
    Parse(raw []byte) ([]*NormalizedFinding, error)
    Map(findings []*NormalizedFinding) []*NormalizedFinding
    Validate(findings []*NormalizedFinding) ([]*NormalizedFinding, []error)
    IsEnabled(config map[string]string) bool
}
```

**鍥涢樁娈垫祦姘寸嚎**锛歚Fetch`锛堥噰闆嗭級鈫?`Parse`锛堣В鏋愶級鈫?`Map`锛堝瘜鍖?鏄犲皠锛夆啋 `Validate`锛堟牎楠岋級銆俙ExecuteAdapter` 鍦?Parse 鍚庤嚜鍔ㄨ皟鐢?`ApplyDelegation` 璺敱鍒版鏌?ID銆?
**缂栧啓绀轰緥锛堝祵鍏?BaseAdapter 鐪佸幓鏍锋澘锛?*锛?
```go
package myadapters

import (
    "context"
    "encoding/json"
    "github.com/asscor/asscor/internal/adapter"
)

type MyScanner struct {
    adapter.BaseAdapter
}

func NewMyScanner() *MyScanner {
    return &MyScanner{adapter.NewBaseAdapter(
        "myscan", "My Scanner", "vulnerability", "high", "1.0.0")}
}

func (a *MyScanner) Fetch(ctx context.Context, cfg map[string]string) ([]byte, error) {
    path := cfg["myscan.path"]
    if path == "" {
        path = "/usr/bin/myscan"
    }
    return adapter.RunTool(ctx, path, "--json")
}

func (a *MyScanner) Parse(raw []byte) ([]*adapter.NormalizedFinding, error) {
    var report struct {
        Vulns []struct {
            ID, Severity, Title string
        } `json:"vulnerabilities"`
    }
    if err := json.Unmarshal(raw, &report); err != nil {
        return nil, err
    }
    var findings []*adapter.NormalizedFinding
    for _, v := range report.Vulns {
        findings = append(findings, &adapter.NormalizedFinding{
            ID:          v.ID,
            Source:      "myscan",
            ToolName:    "My Scanner",
            FindingType: adapter.FindingVulnerability,
            Severity:    adapter.Severity(v.Severity),
            Title:       v.Title,
        })
    }
    return findings, nil
}

func (a *MyScanner) Map(f []*adapter.NormalizedFinding) []*adapter.NormalizedFinding {
    return adapter.DefaultMap(f)
}

func (a *MyScanner) Validate(f []*adapter.NormalizedFinding) ([]*adapter.NormalizedFinding, []error) {
    return adapter.DefaultValidate(f)
}

func init() {
    adapter.Register(NewMyScanner())
}
```

**Severity 鈫?Delta 鏄犲皠**锛歝ritical(-20) / high(-15) / medium(-10) / low(-5) / info(-2) / none(0)銆?
**濮旀墭璺敱**锛氬湪 `internal/adapter/delegation.go` 涓负閫傞厤鍣ㄦ坊鍔?`DelegationRule`锛屽皢鍙戠幇鏄犲皠鍒板疄闄呮鏌?ID 鍜屽煙銆?
### 2.4 hook 鈥?璇勪及娴佺▼閽╁瓙

閽╁瓙鍦ㄨ瘎浼版祦绋嬬殑 8 涓樁娈垫彃鍏ヨ嚜瀹氫箟閫昏緫銆?
**闃舵涓庣被鍨?* (`internal/engine/extensibility.go`)锛?
```go
type AssessmentPhase string
const (
    PhasePreCheck   AssessmentPhase = "pre_check"
    PhasePostCheck  AssessmentPhase = "post_check"
    PhasePreScore   AssessmentPhase = "pre_score"
    PhasePostScore  AssessmentPhase = "post_score"
    PhasePreEdge    AssessmentPhase = "pre_edge"
    PhasePostEdge   AssessmentPhase = "post_edge"
    PhasePreReport  AssessmentPhase = "pre_report"
    PhasePostReport AssessmentPhase = "post_report"
)

type AssessmentHook func(ctx context.Context, result *model.AssessmentResult) error
```

**缂栧啓绀轰緥**锛?
```go
assessor.RegisterHook("enrich-metadata", engine.PhasePostScore,
    func(ctx context.Context, result *model.AssessmentResult) error {
        // 璇勫垎鍚庝负楂橀闄╀富鏈洪檮鍔犲厓鏁版嵁
        if result.FinalScore < 60 {
            result.Metadata["alert_level"] = "high"
        }
        return nil
    }, 50)  // priority锛氭暟瀛楄秺灏忚秺鍏堟墽琛?```

### 2.5 domain 鈥?鏂板璇勪及鍩?
璇勪及鍩熸槸妫€鏌ラ」鐨勯€昏緫鍒嗙粍锛屾嫢鏈夌嫭绔嬫潈閲嶃€?
**缁撴瀯** (`internal/model/domain_registry.go`)锛?
```go
type DomainMeta struct {
    ID            string
    Label         string
    Description   string
    Category      DomainCategory  // CategoryCore / CategoryExtension
    DefaultWeight float64
}
```

**缂栧啓绀轰緥**锛?
```go
model.RegisterDomain(model.DomainMeta{
    ID:            "container_security",
    Label:         "瀹瑰櫒瀹夊叏",
    Description:   "Docker/K8s 鍔犲浐鎬佸娍",
    Category:      model.CategoryExtension,
    DefaultWeight: 10,
})
```

娉ㄥ唽鍚庡嵆鍙湪 check_module 涓皢妫€鏌ラ」鐨?`Domain` 璁句负 `"container_security"`銆傛潈閲嶅彲鍦?`config.ini` 鐨?`[weights]` 鑺傝鐩栥€?
### 2.6 edge_factor 鈥?杈圭紭淇鍥犲瓙

杈圭紭鍥犲瓙鏄法鍩熺殑鍏ㄥ眬涔樻硶淇椤癸紝缂哄け鍏抽敭闃叉姢鏃堕檷浣庢€诲垎銆?
**缁撴瀯** (`internal/model/edge_factor_chain.go`)锛?
```go
type EdgeFactor struct {
    ID          string
    Name        string
    Description string
    Factor      float64  // < 1.0 = 鎯╃綒涔樻暟
    Active      bool
    Priority    int      // 瓒婂皬瓒婂厛搴旂敤
}
```

**缂栧啓绀轰緥**锛?
```go
func init() {
    model.RegisterEdgeFactor(model.EdgeFactor{
        ID:          "EF-NO-MFA",
        Name:        "MFA 缂哄け",
        Description: "鏈己鍒跺鍥犵礌璁よ瘉",
        Factor:      0.85,
        Active:      false,
        Priority:    10,
    })
}
```

婵€娲诲€煎彲鍦?`config.ini` 鐨?`[edge_factors.custom]` / `[edge_factors.custom_triggers]` 鑺傞厤缃€?
### 2.7 cli_command 鈥?CLI 鍛戒护

涓轰氦浜掑紡 CLI 娣诲姞鑷畾涔夊懡浠ゃ€?
**缂栧啓绀轰緥锛圔aseCommand锛?*锛?
```go
cmd := cli.NewBaseCommand(
    cli.CommandInfo{
        Name:        "myscan",
        Description: "杩愯鑷畾涔夋壂鎻?,
        Category:    "custom",
        Usage:       "myscan [--target host]",
        Options: []cli.CommandOption{
            {Name: "target", Description: "鐩爣涓绘満"},
        },
    },
    func(ctx *cli.CommandContext) *cli.CommandResult {
        target := ctx.Options["target"]
        return &cli.CommandResult{
            ExitCode: cli.ExitOK,
            Output:   "鎵弿瀹屾垚: " + target + "\n",
        }
    },
)

cliModule.RegisterCommand(cmd)
```

**閫氳繃鎵╁睍鐐规敞鍐?*锛堟彃浠舵柟寮忥級锛?
```go
kc.Extensions().RegisterExtension("myplugin", "cli.command.register",
    func(ctx context.Context, data interface{}) error {
        cliMod := data.(cli.CLIInterface)
        return cliMod.RegisterCommand(cmd)
    }, 50)
```

### 2.8 custom 鈥?瀹屾暣鍐呮牳鎻掍欢

鏈€鐏垫椿鐨勬墿灞曞舰寮忥紝瀹炵幇瀹屾暣鐨?`kernel.Plugin` 鎺ュ彛锛屾嫢鏈夌敓鍛藉懆鏈熴€丏I 瀹瑰櫒璁块棶銆佷簨浠舵€荤嚎銆佹墿灞曠偣娉ㄥ唽鑳藉姏銆?
**鎺ュ彛** (`internal/kernel/plugin.go`)锛?
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

**缂栧啓绀轰緥**锛?
```go
type MyPlugin struct {
    state kernel.PluginState
}

func (p *MyPlugin) Info() kernel.PluginInfo {
    return kernel.PluginInfo{
        Name: "myplugin", Version: "1.0.0",
        Description: "鑷畾涔夋墿灞?, Author: "Me",
    }
}
func (p *MyPlugin) Dependencies() []kernel.PluginDependency { return nil }

func (p *MyPlugin) Init(ctx context.Context, kc kernel.KernelContext) error {
    // 娉ㄥ唽鑷畾涔夋墿灞曠偣
    kc.Extensions().RegisterPoint(kernel.ExtensionPoint{
        Name: "myplugin.event", Description: "鑷畾涔変簨浠?, Version: "1.0"})
    // 璁㈤槄浜嬩欢鎬荤嚎
    kc.Bus().Subscribe(kernel.TopicAssessorResult, "myplugin", p.onResult)
    // 浠?DI 瀹瑰櫒瑙ｆ瀽鍏朵粬妯″潡
    if impl, ok := kc.Container().Resolve((*kernel.SPCInterface)(nil)); ok {
        _ = impl.(kernel.SPCInterface)
    }
    p.state = kernel.PluginInitialized
    return nil
}

func (p *MyPlugin) Start(ctx context.Context) error {
    p.state = kernel.PluginStarted
    return nil
}
func (p *MyPlugin) Stop(ctx context.Context) error {
    p.state = kernel.PluginStopped
    return nil
}
func (p *MyPlugin) State() kernel.PluginState { return p.state }

func (p *MyPlugin) onResult(ctx context.Context, msg kernel.Message) error {
    // 澶勭悊璇勪及缁撴灉浜嬩欢
    return nil
}
```

鍐呮牳鎻掍欢閫氳繃 `PriorityPlugin` 鎺ュ彛鍙寚瀹氫紭鍏堢骇锛堝喅瀹?Init/Start 椤哄簭锛夛紝閫氳繃 `HealthCheckable` 鎺ュ彛鍙彁渚涘仴搴锋鏌ャ€?
---

## 3. 杩愯鏃舵墿灞曞寘锛圗xtensionManager锛?
瀵逛簬绗笁鏂瑰垎鍙戠殑鎵╁睍锛屼娇鐢?`ExtensionManager` 杩涜鐢熷懡鍛ㄦ湡绠＄悊銆?
### 3.1 鎵╁睍娓呭崟锛坢anifest锛?
缂栧啓 `extension.json`锛?
```json
{
  "id": "container-security-pack",
  "name": "Container Security Domain",
  "version": "1.2.0",
  "type": "check_module",
  "description": "Docker/K8s 鍔犲浐妫€鏌ラ」闆嗗悎",
  "author": "Security Team",
  "license": "Apache-2.0",
  "homepage": "https://github.com/example/container-security",
  "dependencies": [
    {"extension_id": "base-checks", "constraint": ">=1.0.0"}
  ],
  "source": {
    "url": "https://github.com/example/container-security.git",
    "type": "git",
    "branch": "main",
    "checksum": "sha256:abc123..."
  },
  "custom_config": {
    "category": "custom"
  }
}
```

### 3.2 瀹夎涓庣鐞?
```bash
# CLI 鍛戒护
asscor> source deploy container-security-pack --version 1.2.0
asscor> source enable container-security-pack
asscor> source disable container-security-pack
asscor> source uninstall container-security-pack
```

鎴栭€氳繃閰嶇疆鏂囦欢 `config.ini`锛?
```ini
[extension_manager]
enabled = true
extensions_dir = /var/lib/asscor/extensions
state_dir = /var/lib/asscor/extensions/state
auto_enable = false
allow_prerelease = false
execution_policy = whitelist
execution_timeout_s = 30

[extension_manager.repositories]
repo_1 = https://extensions.example.dev/index.json

[extension_manager.whitelist]
cmd_1 = python3
cmd_2 = bash
```

### 3.3 鐢熷懡鍛ㄦ湡

```
Install 鈫?Validate(SemVer+鏍￠獙鍜?渚濊禆) 鈫?Download(git/http/local)
        鈫?Extract(tar.gz/zip, Zip-Slip 闃叉姢) 鈫?Register
        鈫?[AutoEnable] 鈫?onExtensionInstalled(绫诲瀷鍒嗗彂)
Enable  鈫?婵€娲绘墿灞曪紙濡傝竟缂樺洜瀛愮敓鏁堬級
Disable 鈫?娉ㄩ攢妫€鏌ラ」/鍩?杈圭紭鍥犲瓙鎭㈠
Delete  鈫?Disable + 鍒犻櫎鏂囦欢
```

---

## 4. 瀹夊叏鎺у埗

ASSCOR 鎵╁睍绯荤粺鍐呯疆澶氬眰瀹夊叏闃叉姢锛?
| 鎺у埗 | 鏈哄埗 |
|------|------|
| **鐗堟湰闂ㄦ帶** | SemVer 姣斿锛屾嫆缁濆畨瑁呭悓鐗堟湰鎴栨棫鐗堟湰 |
| **瀹屾暣鎬ф牎楠?* | SHA-256 鏍￠獙鍜岄獙璇侊紙`sha256:<hex>`锛?|
| **Zip-Slip 闃叉姢** | 瑙ｅ帇鏃舵牎楠岀洰鏍囪矾寰勪笉閫冮€稿畨瑁呯洰褰?|
| **鍛戒护鐧藉悕鍗?* | 浠呭厑璁哥櫧鍚嶅崟鍛戒护鎵ц锛屽惈 symlink 瑙ｆ瀽闃茬粫杩?|
| **鐜鍙橀噺鍑€鍖?* | 鎷掔粷鍚?`=`/鎹㈣鐨勯敭鍚嶃€佸惈鎹㈣鐨勫€?|
| **鑴氭湰璺緞闃叉姢** | 鑴氭湰鎵ц璺緞蹇呴』浣嶄簬瀹夎鐩綍鍐?|
| **鎵ц绛栫暐** | allowed / whitelist锛堥粯璁わ級 / sandboxed / disabled 鍥涚骇 |
| **鎵ц瓒呮椂** | 榛樿 30 绉掔‖瓒呮椂 |

---

## 5. 鎵撳寘涓庡垎鍙?
### 5.1 缂栬瘧鏈熸墿灞曪紙鍗曚簩杩涘埗锛?
灏嗘墿灞曞寘鍔犲叆 import锛岄€氳繃 `init()` 鑷敞鍐岋紝閲嶆柊缂栬瘧鍐呮牳锛?
```go
// cmd/kernel/main.go 鎴栦笓鐢?imports 鏂囦欢
import (
    _ "github.com/yourorg/asscor-ext/mychecks"    // check_module
    _ "github.com/yourorg/asscor-ext/myadapters"  // adapter
)
```

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ASSCOR-kernel ./cmd/kernel/
```

**浼樺娍**锛氶浂杩愯鏃朵緷璧栵紝淇濇寔鍗曚簩杩涘埗閮ㄧ讲锛岀被鍨嬪畨鍏紝缂栬瘧鏈熸鏌ャ€?
### 5.2 杩愯鏃舵墿灞曞寘

鎵撳寘涓?tar.gz/zip锛屽寘鍚?`extension.json` + 鍙墽琛岃剼鏈?+ 璧勬簮锛岄€氳繃 git/http 浠撳簱鎴栨湰鍦拌矾寰勫垎鍙戯紝鐢?ExtensionManager 绠＄悊銆?
**浼樺娍**锛氭棤闇€閲嶆柊缂栬瘧鍐呮牳锛屾敮鎸佺儹鎻掓嫈锛岀嫭绔嬬増鏈紨杩涖€?
---

## 6. 鎵╁睍绫诲瀷閫夋嫨鎸囧崡

| 闇€姹?| 鎺ㄨ崘绫诲瀷 | 妯″紡 |
|------|----------|------|
| 鏂板涓€涓畨鍏ㄦ鏌?| `check_module` | 缂栬瘧鏈?|
| 瀵规帴涓€涓柊鎵弿宸ュ叿 | `adapter` | 缂栬瘧鏈?|
| 鑷畾涔夎瘎鍒嗙畻娉?| `scoring_plugin` | 杩愯鏃?|
| 鏂板涓€涓瘎浼扮淮搴?| `domain` + `check_module` | 缂栬瘧鏈?閰嶇疆 |
| 鍏ㄥ眬闃叉姢缂哄け鎯╃綒 | `edge_factor` | 缂栬瘧鏈?閰嶇疆 |
| 璇勪及娴佺▼娉ㄥ叆閫昏緫 | `hook` | 杩愯鏃?|
| 鏂板杩愮淮鍛戒护 | `cli_command` | 鎵╁睍鐐?|
| 澶嶆潅鏈夌姸鎬佸瓙绯荤粺 | `custom`锛圥lugin锛?| 鎻掍欢娉ㄥ唽 |
| 绗笁鏂瑰彲鎻掓嫈鍒嗗彂 | 浠绘剰绫诲瀷 + ExtensionManager | 杩愯鏃跺寘 |

---

## 7. 瀹屾暣绀轰緥锛氬鍣ㄥ畨鍏ㄦ墿灞?
浠ヤ笅灞曠ず涓€涓畬鏁寸殑瀹瑰櫒瀹夊叏鎵╁睍锛岀粍鍚?domain + check_module + edge_factor锛?
```go
package containersec

import (
    "os"
    "github.com/asscor/asscor/internal/checks"
    "github.com/asscor/asscor/internal/model"
)

func init() {
    // 1. 娉ㄥ唽鏂板煙
    model.RegisterDomain(model.DomainMeta{
        ID:            "container_security",
        Label:         "瀹瑰櫒瀹夊叏",
        Category:      model.CategoryExtension,
        DefaultWeight: 10,
    })

    // 2. 娉ㄥ唽杈圭紭鍥犲瓙
    model.RegisterEdgeFactor(model.EdgeFactor{
        ID:       "EF-NO-SECCOMP",
        Name:     "Seccomp 缂哄け",
        Factor:   0.90,
        Priority: 20,
    })

    // 3. 娉ㄥ唽妫€鏌ラ」
    checks.Register(
        model.CheckItem{
            ID:       "CS-001",
            Domain:   "container_security",
            Name:     "Docker daemon 瀹夊叏閰嶇疆",
            Delta:    -10,
            Platform: "linux",
            Check:    checkDockerDaemon,
        },
        model.CheckItem{
            ID:       "CS-002",
            Domain:   "container_security",
            Name:     "瀹瑰櫒闀滃儚绛惧悕楠岃瘉",
            Delta:    -8,
            Platform: "linux",
            Check:    checkImageSigning,
        },
    )
}

func checkDockerDaemon() (bool, string) {
    data, err := os.ReadFile("/etc/docker/daemon.json")
    if err != nil {
        return true, "鏈娴嬪埌 Docker"
    }
    // ...瑙ｆ瀽骞舵鏌ュ畨鍏ㄩ€夐」...
    _ = data
    return true, "Docker 瀹夊叏閰嶇疆鍚堣"
}

func checkImageSigning() (bool, string) {
    // ...妫€鏌?cosign/notary 閰嶇疆...
    return false, "鏈惎鐢ㄩ暅鍍忕鍚嶉獙璇?
}
```

鍦?`config.ini` 涓惎鐢細

```ini
[weights]
container_security = 10

[extensions]
container_security = on
```

---

## 8. 鍙傝€?
- 妫€鏌ラ」搴擄細`internal/checks/linux/checks.go`锛?6 涓唴缃鏌ラ」鍙傝€冨疄鐜帮級
- 閫傞厤鍣ㄧず渚嬶細`internal/adapter/scanner/`锛?1 涓帰娴嬪櫒锛夈€乣internal/adapter/management/`锛?0 涓鐞嗙被锛?- 鍐呮牳鎻掍欢绀轰緥锛歚internal/kernel/`锛?5 涓唴缃彃浠讹級
- 鎵╁睍绠＄悊鍣細`internal/extmgr/`
- SSAM 鎺ュ彛瑙勮寖锛歚docs/SSAM鎺ュ彛瑙勮寖涓庢帴鍏ユ寚鍗?md`
