# ASSCOR APT 鏀诲嚮鍒嗘瀽涓庢娴嬪寮虹櫧鐨功

> **鐗堟湰锛?* v1.2 | **閫傜敤锛?* ASSCOR v0.2.1 / ATT&CK Module v1.0.0 | **鏃ユ湡锛?* 2026-06-28  
> **閰嶅鏂囨。锛?* SSAM 2.0 鐧界毊涔︺€佸伐绋嬪疄鐜扮櫧鐨功銆丼PC 瀹夊叏鎬佸娍璁＄畻妯″潡鎶€鏈櫧鐨功

## 鎽樿

楂樼骇鎸佺画鎬у▉鑳侊紙Advanced Persistent Threat锛孉PT锛夋槸褰撳墠缃戠粶瀹夊叏棰嗗煙鏈€鍏风牬鍧忔€х殑鏀诲嚮褰㈡€併€備笌浼犵粺鏀诲嚮涓嶅悓锛孉PT 鏀诲嚮鑰呭叿澶囧浗瀹剁骇鎴栫粍缁囩骇璧勬簮锛岄噰鐢ㄥ闃舵銆佸鎴樻湳鐨勬敾鍑婚摼锛岄暱鏈熸綔浼忎簬鐩爣缃戠粶涓€備紶缁熺殑鍩轰簬绛惧悕鍜岄槇鍊肩殑妫€娴嬫柟娉曢毦浠ュ簲瀵?APT 鐨勪綆鎱㈠皬锛圠ow-and-Slow锛夌壒寰佸拰楂樺害瀹氬埗鍖栧伐鍏枫€?

ASSCOR v0.2.1 鍦?MITRE ATT&CK V19 妗嗘灦鍩虹涓婏紝鏋勫缓浜嗗畬鏁寸殑 APT 鏀诲嚮鍒嗘瀽涓庢娴嬪寮烘ā鍧椼€傝妯″潡閫氳繃鍥涘ぇ鏍稿績鑳藉姏鈥斺€旀敾鍑婚摼閲嶆瀯銆佽涓烘娴嬨€丄PT 褰掑洜鍜屽▉鑳佺嫨鐚庘€斺€斿疄鐜颁簡浠?鍗曠偣鍛婅"鍒?鏀诲嚮閾惧彲瑙嗗寲"鐨勮寖寮忚穬杩併€傛湰鐧界毊涔︾郴缁熼槓杩板悇鏍稿績鑳藉姏鐨勮璁″師鐞嗐€佺畻娉曞疄鐜般€佹暟鎹ā鍨嬪拰宸ョ▼瀹炶返锛屽苟璇存槑鍏朵笌 SSAM 璇勪及浣撶郴鐨勫崗鍚屾満鍒躲€?

## 1. 璁捐鍝插

### 1.1 浠庡崟鐐规娴嬪埌閾惧紡鍒嗘瀽

浼犵粺瀹夊叏妫€娴嬪叧娉?鏌愪釜浜嬩欢鏄惁寮傚父"锛岃€?APT 鍒嗘瀽鍏虫敞"涓€绯诲垪寮傚父浜嬩欢鏄惁鏋勬垚鏈夋剰涔夌殑鏀诲嚮閾?銆傝繖涓€鑼冨紡杞彉鐨勬牳蹇冩礊瀵熸槸锛?

> 鍗曚釜鍛婅鍙兘鏄鎶ワ紝浣嗘寜 ATT&CK 鎴樻湳椤哄簭鎺掑垪鐨勫涓憡璀︼紝鏋勬垚鏀诲嚮閾剧殑姒傜巼闅忛樁娈垫暟鎸囨暟澧為暱銆?

ASSCOR APT 妯″潡鐨勮璁￠伒寰笁涓師鍒欙細

| 鍘熷垯 | 鍚箟 | 宸ョ▼浣撶幇 |
|------|------|----------|
| **璇佹嵁铻嶅悎** | 涓嶄緷璧栧崟涓€鏁版嵁婧愶紝缁煎悎鍛婅銆佸紓甯搞€両OC 绛夊婧愯瘉鎹?| `ReconstructAttackChain` 鑱氬悎涓夌被璇佹嵁 |
| **鍙В閲婂綊鍥?* | 姣忎釜褰掑洜缁撹閮藉彲杩芥函鍒板叿浣撶殑鎶€鏈噸鍙犲拰 IOC 鍖归厤 | `AttributionResult.Evidence` 璁板綍瀹屾暣璇佹嵁閾?|
| **鍋囪椹卞姩** | 鐙╃寧涓嶆槸鐩茬洰鎼滅储锛岃€屾槸鍩轰簬鏀诲嚮杞Щ鐭╅樀鐢熸垚鍙獙璇佸亣璁?| `AutoGenerateHypotheses` 鍩轰簬杞Щ姒傜巼鐢熸垚鍋囪 |

### 1.2 涓?SSAM 璇勪及浣撶郴鐨勫叧绯?

APT 妯″潡涓嶆槸 SSAM 鐨勬浛浠ｏ紝鑰屾槸澧炲己銆備袱鑰呭舰鎴愬弻鍚戦棴鐜細

```
SSAM 璇勪及 鈫?妫€娴嬩綆鍒嗗煙 鈫?ATT&CK 宸窛鍒嗘瀽 鈫?缂撹В寤鸿 鈫?瀹夊叏鍔犲浐 鈫?SSAM 璇勫垎鎻愬崌
     鈫?                                                             鈹?
     鈹斺攢鈹€鈹€鈹€ APT 鏀诲嚮閾炬娴?鈫?绛栫暐鑱斿姩 鈫?鑷姩鍝嶅簲 鈫愨攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
```

- **姝ｅ悜璺緞**锛歋SAM 璇勪及鍙戠幇鏌愪富鏈洪煣鎬у煙寰楀垎鍋忎綆锛孉TT&CK 璇勪及瀛愭ā鍧楁墽琛屽樊璺濆垎鏋愶紝璇嗗埆闃插尽缂哄彛骞剁敓鎴愮紦瑙ｅ缓璁?
- **鍙嶅悜璺緞**锛欰PT 妯″潡妫€娴嬪埌鏀诲嚮閾撅紝閫氳繃浜嬩欢鎬荤嚎瑙﹀彂绛栫暐绠＄悊鍣ㄨ嚜鍔ㄥ搷搴旓紙濡傞殧绂讳富鏈猴級锛屽悓鏃跺奖鍝嶈涓绘満鐨?SSAM 璇勪及缁撴灉

## 2. 鏀诲嚮閾鹃噸鏋勫紩鎿?

### 2.1 闂瀹氫箟

APT 鏀诲嚮鐨勫吀鍨嬬壒寰佹槸澶氶樁娈点€佽法鎴樻湳鐨勬敾鍑婚摼銆備緥濡備竴娆″吀鍨嬬殑 APT28 鏀诲嚮鍙兘鍖呭惈锛?

```
楸煎弶閽撻奔 (TA0001/T1566) 鈫?PowerShell 鎵ц (TA0002/T1059) 鈫?鍑瘉杞偍 (TA0006/T1003) 鈫?妯悜绉诲姩 (TA0008/T1021) 鈫?C2 閫氫俊 (TA0011/T1071)
```

鏀诲嚮閾鹃噸鏋勫紩鎿庣殑鐩爣鏄細浠庢暎钀界殑鍛婅銆佸紓甯稿拰 IOC 璇佹嵁涓紝鑷姩璇嗗埆骞堕噸鏋勮繖鏍风殑澶氶樁娈垫敾鍑婚摼銆?

### 2.2 鏁版嵁妯″瀷

```go
type AttackChain struct {
    ID           string             // 鏀诲嚮閾惧敮涓€鏍囪瘑
    Name         string             // 鑷姩鐢熸垚鐨勯摼鍚嶇О
    HostIDs      []string           // 娑夊強鐨勪富鏈哄垪琛?
    Stages       []AttackStage      // 鎸夋垬鏈『搴忔帓鍒楃殑鏀诲嚮闃舵
    TotalScore   float64            // 閾剧患鍚堣瘎鍒?
    Severity     string             // 涓ラ噸绛夌骇 (critical/high/medium/low)
    Attribution  *AttributionResult  // 褰掑洜缁撴灉锛堝彲閫夛級
    Status       string             // 鐘舵€?(active/contained/resolved)
    FirstSeen    time.Time          // 鏈€鏃╄瘉鎹椂闂?
    LastSeen     time.Time          // 鏈€鏂拌瘉鎹椂闂?
    DetectedAt   time.Time          // 妫€娴嬫椂闂?
}

type AttackStage struct {
    Order         int       // 闃舵搴忓彿锛堟寜鎴樻湳椤哄簭锛?
    TacticID      string    // ATT&CK 鎴樻湳 ID (濡?TA0001)
    TacticName    string    // 鎴樻湳鍚嶇О
    TechniqueID   string    // ATT&CK 鎶€鏈?ID (濡?T1566)
    TechniqueName string    // 鎶€鏈悕绉?
    AlertIDs      []string  // 鍏宠仈鐨勫憡璀?ID
    HostIDs       []string  // 娑夊強鐨勪富鏈?
    IOCIDs        []string  // 鍏宠仈鐨?IOC
    AnomalyIDs    []string  // 鍏宠仈鐨勫紓甯镐簨浠?
    Confidence    float64   // 闃舵缃俊搴?(0-1)
    Evidence      []string  // 璇佹嵁鎻忚堪
    Timestamp     time.Time // 璇佹嵁鏃堕棿鎴?
}
```

### 2.3 閲嶆瀯绠楁硶

鏀诲嚮閾鹃噸鏋勯噰鐢ㄤ笁姝ユ祦绋嬶細

**绗竴姝ワ細璇佹嵁鏀堕泦**

浠庝笁绫绘暟鎹簮涓瓫閫変笌鐩爣涓绘満鐩稿叧鐨勮瘉鎹細

| 鏁版嵁婧?| 绛涢€夋潯浠?| 鏉冮噸 |
|--------|----------|------|
| 鍛婅 (DetectionAlert) | `HostID 鈭?hostIDs && !Acknowledged` | 楂?|
| 寮傚父 (AnomalyEvent) | `HostID 鈭?hostIDs && Score 鈮?0.5` | 涓?|
| IOC (IOCEntry) | 鍏ㄩ噺锛堜笌涓绘満鍏宠仈閫氳繃鍛婅闂存帴寤虹珛锛?| 浣?|

**绗簩姝ワ細闃舵鏋勫缓**

灏嗚瘉鎹寜 ATT&CK 鎴樻湳-鎶€鏈槧灏勬瀯寤烘敾鍑婚樁娈碉細

1. 姣忔潯鍛婅/寮傚父鎼哄甫 `TechniqueID` 鍜?`TacticIDs`
2. 鎸?ATT&CK 鎴樻湳椤哄簭锛圱A0001鈫扵A0002鈫掆€︹啋TA0011锛夋帓鍒?
3. 鍚屼竴鎴樻湳涓嬬殑澶氫釜鎶€鏈悎骞朵负鍚屼竴闃舵鐨勪笉鍚岃瘉鎹?
4. 璁＄畻姣忎釜闃舵鐨勭疆淇″害锛氬熀浜庤瘉鎹暟閲忓拰鏉ユ簮澶氭牱鎬?

**绗笁姝ワ細閾捐瘎鍒嗕笌褰掑洜**

- **閾剧患鍚堣瘎鍒?*锛氱患鍚堝悇闃舵缃俊搴﹀拰涓ラ噸绛夌骇
- **閾句弗閲嶇瓑绾?*锛氬彇鏈€楂橀樁娈典弗閲嶇瓑绾э紝鑻ヨ法鈮? 涓垬鏈垯鍗囩骇涓€绾?
- **鑷姩褰掑洜**锛氬閲嶆瀯鐨勬敾鍑婚摼鎵ц APT 褰掑洜鍒嗘瀽锛堣瑙佺 4 绔狅級

### 2.4 澶氫富鏈哄叧鑱?

鏀诲嚮閾鹃噸鏋勬敮鎸佽法涓绘満鍏宠仈銆傚綋鎸囧畾澶氫釜 `hostIDs` 鏃讹紝寮曟搸浼氾細

1. 鍒嗗埆鏀堕泦鍚勪富鏈虹殑璇佹嵁
2. 閫氳繃鍏变韩鐨?IOC锛堝鍚屼竴 C2 鍦板潃銆佸悓涓€鎭舵剰鏂囦欢鍝堝笇锛夊缓绔嬩富鏈洪棿鍏宠仈
3. 灏嗗叧鑱斾富鏈虹殑璇佹嵁鍚堝苟鍒板悓涓€鏀诲嚮閾句腑
4. 姣忎釜闃舵璁板綍娑夊強鐨?`HostIDs`锛屾敮鎸?涓绘満 A 琚挀楸尖啋涓绘満 B 琚í鍚戠Щ鍔?鐨勮法涓绘満閾捐矾

### 2.5 澶氭寚鏍囧叧鑱?

`CorrelateMultiIndicator` 鏂规硶鎻愪緵璺ㄦ寚鏍囩被鍨嬬殑鍏宠仈鍒嗘瀽锛?

```go
type MultiIndicatorCorrelation struct {
    ID              string    // 鍏宠仈鍞竴鏍囪瘑
    IndicatorIDs    []string  // 鍏宠仈鐨勬寚鏍?ID 鍒楄〃锛堟牸寮? "alert:ID"/"anomaly:ID"/"ioc:ID"锛?
    TechniqueIDs    []string  // 娑夊強鐨?ATT&CK 鎶€鏈?ID
    TacticIDs       []string  // 娑夊強鐨?ATT&CK 鎴樻湳 ID
    HostIDs         []string  // 娑夊強鐨勪富鏈哄垪琛紙鏀寔澶氫富鏈哄叧鑱旓級
    Score           float64   // 鍏宠仈璇勫垎 (0-1)
    Description     string    // 鍏宠仈鎻忚堪
    CorrelationType string    // 鍏宠仈绫诲瀷
    Timestamp       time.Time // 鍏宠仈鏃堕棿
}
```

鍏宠仈璇勫垎璁＄畻锛?

$$
Score = \min\left(1.0, \frac{AlertCount \times 0.3 + AnomalyCount \times 0.2 + IOCCount \times 0.3 + BeaconCount \times 0.2}{Threshold}\right)
$$

鍏朵腑 $Threshold = 2.0$锛堥粯璁ら槇鍊硷紝鍙厤缃級锛屽悇绫绘寚鏍囩殑鏉冮噸鍙嶆槧鍏惰瘉鎹己搴︼細鍛婅鍜?IOC 鏉冮噸杈冮珮锛?.3锛夛紝寮傚父鍜屼俊鏍囨潈閲嶈緝浣庯紙0.2锛夈€備粎褰?$SourceCount \geq 2$ 鏃舵墠杈撳嚭鍏宠仈缁撴灉銆?

## 3. 琛屼负妫€娴嬪紩鎿?

### 3.1 璁捐鍔ㄦ満

浼犵粺鍩轰簬绛惧悕鐨勬娴嬪宸茬煡鏀诲嚮鏈夋晥锛屼絾瀵?APT 鐨勫畾鍒跺寲宸ュ叿鍜岄浂鏃ユ紡娲炲嚑涔庢棤鏁堛€傝涓烘娴嬮€氳繃寤虹珛"姝ｅ父琛屼负鍩虹嚎"锛屾娴嬪亸绂诲熀绾跨殑寮傚父琛屼负锛屼粠鑰屽彂鐜版湭鐭ュ▉鑳併€?

### 3.2 琛屼负鎸囨爣浣撶郴

琛屼负鎸囨爣锛圔ehavioralIndicator锛夊畾涔変簡"浠€涔堟牱鐨勮涓烘槸鍙枒鐨?锛?

```go
type BehavioralIndicator struct {
    ID          string         // 鎸囨爣鍞竴鏍囪瘑
    Name        string         // 鎸囨爣鍚嶇О
    TechniqueID string         // 瀵瑰簲鐨?ATT&CK 鎶€鏈?ID
    TacticIDs   []string       // 瀵瑰簲鐨?ATT&CK 鎴樻湳 ID 鍒楄〃
    Category    string         // 鎸囨爣绫诲埆 (process/network/file/credential/privilege)
    Metric      string         // 鐩戞帶鎸囨爣鍚嶇О
    Operator    string         // 姣旇緝杩愮畻绗?(gt/lt/eq/gte/lte)
    Threshold   float64        // 闃堝€?
    Window      time.Duration  // 妫€娴嬬獥鍙?
    Severity    string         // 涓ラ噸绛夌骇
    Description string         // 鎻忚堪
    Enabled     bool           // 鏄惁鍚敤
}
```

**鎸囨爣绫诲埆涓庡吀鍨嬬ず渚嬶細**

| 绫诲埆 | 鐩戞帶鎸囨爣 | ATT&CK 鎶€鏈?| 绀轰緥闃堝€?|
|------|----------|-------------|----------|
| process | `process_create_rate` | T1059 鍛戒护鑴氭湰瑙ｉ噴鍣?| > 50/min |
| network | `outbound_connection_rate` | T1071 搴旂敤灞傚崗璁?| > 200/min |
| credential | `failed_login_rate` | T1110 鏆村姏鐮磋В | > 10/min |
| file | `sensitive_file_access_rate` | T1005 鏈湴鏁版嵁鏀堕泦 | > 5/min |
| privilege | `privilege_escalation_attempts` | T1068 婕忔礊鍒╃敤鎻愭潈 | > 0 |

### 3.3 琛屼负鍩虹嚎绠＄悊

姣忓彴涓绘満缁存姢鐙珛鐨勮涓哄熀绾匡細

```go
type BehavioralBaseline struct {
    HostID      string             // 涓绘満鏍囪瘑
    Metrics     map[string]float64 // 鍚勬寚鏍囩殑鍩虹嚎鍊?
    SampleCount int                // 閲囨牱娆℃暟
    Period      time.Duration      // 鍩虹嚎璁＄畻鍛ㄦ湡
    ComputedAt  time.Time          // 鍩虹嚎璁＄畻鏃堕棿
}
```

鍩虹嚎鏇存柊绛栫暐锛?

1. **鍐峰惎鍔?*锛氶娆￠噰闆嗙殑鎸囨爣鍊肩洿鎺ヤ綔涓哄垵濮嬪熀绾?
2. **娓愯繘鏇存柊**锛氬悗缁噰鏍锋寜鎸囨暟绉诲姩骞冲潎锛圗MA锛夋洿鏂板熀绾?

$$
Baseline_{new} = \alpha \times Metric_{current} + (1 - \alpha) \times Baseline_{old}
$$

鍏朵腑 $\alpha = 0.3$锛堝彲閰嶇疆锛夛紝骞宠　鐏垫晱搴﹀拰绋冲畾鎬с€?

3. **鍋忓樊妫€娴?*锛氬綋褰撳墠鎸囨爣鍊煎亸绂诲熀绾胯秴杩囬槇鍊兼椂瑙﹀彂琛屼负鍛婅

```go
type BehavioralAlert struct {
    ID            string            // 鍛婅 ID
    IndicatorID   string            // 瑙﹀彂鐨勮涓烘寚鏍?ID
    IndicatorName string            // 瑙﹀彂鐨勮涓烘寚鏍囧悕绉?
    TechniqueID   string            // ATT&CK 鎶€鏈?ID
    HostID        string            // 涓绘満鏍囪瘑
    ObservedValue float64           // 瑙傛祴鍊?
    BaselineValue float64           // 鍩虹嚎鍊?
    Deviation     float64           // 鍋忓樊绋嬪害
    Severity      string            // 涓ラ噸绛夌骇
    Fields        map[string]string // 闄勫姞瀛楁锛堝彲閫夛級
    Timestamp     time.Time         // 鍛婅鏃堕棿
}
```

### 3.4 C2 淇℃爣妫€娴?

鍛戒护涓庢帶鍒讹紙C2锛変俊鏍囨槸 APT 鏀诲嚮鏈€鍏稿瀷鐨勮涓虹壒寰佷箣涓€銆傝妞嶅叆鍚庨棬鐨勪富鏈轰細瀹氭湡鍚?C2 鏈嶅姟鍣ㄥ彂閫佸績璺冲寘锛堜俊鏍囷級锛屽叾杩炴帴闂撮殧閫氬父鍛堢幇浣庢姈鍔紙low jitter锛夌壒寰併€?

**妫€娴嬬畻娉曪細**

1. **鏃堕棿搴忓垪鏀堕泦**锛氭敹闆嗙洰鏍囦富鏈虹殑鍑虹珯缃戠粶杩炴帴鏃堕棿搴忓垪

```go
type TimeSeriesPoint struct {
    Timestamp time.Time // 杩炴帴鏃堕棿
    Value     float64   // 杩炴帴鎸囨爣锛堝瀛楄妭鏁帮級
}
```

2. **闂撮殧璁＄畻**锛氳绠楃浉閭昏繛鎺ョ殑鏃堕棿闂撮殧搴忓垪

3. **缁熻鐗瑰緛鎻愬彇**锛?
   - 鍧囧€奸棿闅?$\bar{I} = \frac{1}{n}\sum_{i=1}^{n} I_i$
   - 鏍囧噯宸?$\sigma_I = \sqrt{\frac{1}{n}\sum_{i=1}^{n}(I_i - \bar{I})^2}$
   - 鎶栧姩绯绘暟 $J = \frac{\sigma_I}{\bar{I}}$

4. **璇勫垎瑙勫垯**锛?

| 鎶栧姩绯绘暟 J | 淇℃爣璇勫垎 | 鍒ゅ畾 |
|------------|----------|------|
| J < 0.1 | 0.95 | 鏋佸己淇℃爣鐗瑰緛锛堟満姊板畾鏃讹級 |
| 0.1 鈮?J < 0.2 | 0.85 | 寮轰俊鏍囩壒寰?|
| 0.2 鈮?J < 0.3 | 0.70 | 涓瓑淇℃爣鐗瑰緛 |
| 0.3 鈮?J < 0.5 | 0.50 | 寮变俊鏍囩壒寰?|
| J 鈮?0.5 | 鈥?| 涓嶅垽瀹氫负淇℃爣锛堟甯告祦閲忥級 |

5. **鏈€浣庢暟鎹噺瑕佹眰**锛氳嚦灏?10 涓暟鎹偣锛岃嚦灏?5 涓湁鏁堥棿闅?

**妫€娴嬭緭鍑猴細**

```go
type BeaconDetection struct {
    ID          string    // 妫€娴?ID
    HostID      string    // 涓绘満鏍囪瘑
    Destination string    // 鐩爣鍦板潃
    Interval    float64   // 骞冲潎闂撮殧锛堢锛?
    Jitter      float64   // 鎶栧姩绯绘暟
    Score       float64   // 淇℃爣璇勫垎 (0-1)
    TechniqueID string    // ATT&CK 鎶€鏈?ID (T1071.001)
    DataPoints  int       // 鏁版嵁鐐规暟閲?
    FirstSeen   time.Time // 棣栨鍙戠幇
    LastSeen    time.Time // 鏈€杩戝彂鐜?
}
```

## 4. APT 褰掑洜寮曟搸

### 4.1 璁捐鐩爣

APT 褰掑洜寮曟搸鍥炵瓟涓€涓叧閿棶棰橈細**瑙傚療鍒扮殑鏀诲嚮琛屼负鏈€鍙兘鏉ヨ嚜鍝釜 APT 缁勭粐锛?*

褰掑洜涓嶆槸绮剧‘绉戝锛屼絾閫氳繃绯荤粺鍖栫殑璇佹嵁铻嶅悎鏂规硶锛屽彲浠ユ彁渚涙湁浠峰€肩殑缃俊搴﹁瘎浼帮紝杈呭姪瀹夊叏鍥㈤槦浼樺厛璋冩煡鏈€鍙兘鐨勫▉鑳佽涓轰綋銆?

### 4.2 澶氭簮璇佹嵁铻嶅悎绠楁硶

褰掑洜寮曟搸閲囩敤鍔犳潈澶氭簮铻嶅悎绛栫暐锛岀患鍚堜袱绫绘牳蹇冭瘉鎹細

**璇佹嵁婧愪竴锛歍TP 閲嶅彔锛堟潈閲?60%锛?*

璁＄畻瑙傚療鍒扮殑鎶€鏈笌宸茬煡 APT 缁勭粐鎶€鏈敾鍍忕殑鍔犳潈鍖归厤搴︼細

$$
S_{ttp}(g) = \frac{\sum_{t \in T_{observed} \cap T_{group}(g)} w_{obs}(t) \times w_{group}(t)}{\sum_{t \in T_{group}(g)} w_{group}(t)}
$$

鍏朵腑 $w_{obs}(t)$ 涓鸿瀵熷埌鐨勬妧鏈?$t$ 鐨勭疆淇″害鏉冮噸锛堟潵鑷憡璀?寮傚父锛夛紝$w_{group}(t)$ 涓鸿鎶€鏈湪 APT 缁勭粐鐢诲儚涓殑鏉冮噸銆傚垎姣嶄娇鐢?APT 缁勭粐鐨勫叏閮ㄦ妧鏈潈閲嶅拰锛屼娇璇勫垎鍙嶆槧"瑙傚療鍒扮殑琛屼负鍦ㄨ缁勭粐宸茬煡鐢诲儚涓殑鍗犳瘮"鈥斺€斿嵆绮剧‘鐜囧鍚戙€傝繖閬垮厤浜?澶ц€屽叏"鐨勭粍缁囷紙鎶€鏈敾鍍忚鐩栭潰骞匡級鍥犲垎姣嶅皬鑰岃幏寰楄櫄楂樺垎鏁扮殑闂锛岄檷浣庤褰掑洜椋庨櫓銆?

**璇佹嵁婧愪簩锛欼OC 鍖归厤锛堟潈閲?40%锛?*

璁＄畻 IOC 鎸囨爣涓庡凡鐭?APT 缁勭粐鐨勫叧鑱斿害锛?

$$
S_{ioc}(g) = \sum_{i \in IOC} c(i) \cdot \mathbb{1}[actor(i) = g]
$$

鍏朵腑 $c(i)$ 涓?IOC $i$ 鐨勭疆淇″害锛?\mathbb{1}$ 涓烘寚绀哄嚱鏁般€?

**缁煎悎璇勫垎锛?*

$$
S_{combined}(g) = 0.6 \times S_{ttp}(g) + 0.4 \times S_{ioc}(g)
$$

褰?TTP 鍜?IOC 璇佹嵁鍚屾椂鎸囧悜鍚屼竴缁勭粐鏃讹紝棰濆鍔犳垚 0.10锛?

$$
S_{combined}(g) = \min(1.0, S_{combined}(g) + 0.10) \quad \text{if } S_{ttp} > 0 \land S_{ioc} > 0
$$

**琛屼笟瀵归綈鍔犳垚锛?*

褰撴敾鍑荤洰鏍囪涓氫笌 APT 缁勭粐鐨勫凡鐭ョ洰鏍囪涓氬尮閰嶆椂锛岄澶栧姞鎴愶細

$$
S_{combined}(g) = \min(1.0, S_{combined}(g) + S_{sector} \times 0.15)
$$

### 4.3 褰掑洜缁撴灉

```go
type AttributionResult struct {
    PrimaryActor      string               // 鏈€鍙兘鐨?APT 缁勭粐鍚嶇О
    PrimaryGroupID    string               // 缁勭粐 ID (濡?G0007)
    Confidence        float64              // 褰掑洜缃俊搴?(0-1)
    Evidence          []AttributionEvidence // 璇佹嵁鍒楄〃
    AlternativeActors []AlternativeActor   // 鏇夸唬琛屼负浣擄紙鏈€澶?5 涓級
    Methodology       string               // 褰掑洜鏂规硶 (multi_source_fusion)
    Country           string               // 褰掑睘鍥藉锛堝彲閫夛級
    Motivation        string               // 鍔ㄦ満锛堝彲閫夛級
}

type AttributionEvidence struct {
    Type        string  // 璇佹嵁绫诲瀷 (ttp_overlap/ioc_match/target_sector/no_match)
    Description string  // 璇佹嵁鎻忚堪
    Weight      float64 // 璇佹嵁鏉冮噸
    Source      string  // 璇佹嵁鏉ユ簮
}

type AlternativeActor struct {
    GroupID    string  // 鏇夸唬缁勭粐 ID
    Name       string  // 缁勭粐鍚嶇О
    Confidence float64 // 缃俊搴?
    Reason     string  // 鍘熷洜鎻忚堪
}
```

### 4.4 缃俊搴﹀綊涓€鍖?

鍘熷缁煎悎璇勫垎闇€瑕佸綊涓€鍖栦负 0-1 鑼冨洿鐨勭疆淇″害锛?

$$
Confidence = \min(1.0, S_{combined} \times (1 + 0.05 \times \min(N_{overlap}, 10)) \times (1 + 0.02 \times \min(N_{evidence}, 10)))
$$

鍏朵腑 $N_{overlap}$ 涓烘妧鏈噸鍙犳暟閲忥紝$N_{evidence}$ 涓鸿瘉鎹€绘暟銆傝繖纭繚浜嗭細
- 灏戦噺鎶€鏈噸鍙狅紙1-2 涓級鐨勫綊鍥犵疆淇″害杈冧綆
- 澶ч噺鎶€鏈噸鍙狅紙5+ 涓級涓旀湁澶氭簮璇佹嵁鐨勫綊鍥犵疆淇″害杈冮珮
- 缃俊搴︿笂闄愪负 1.0

### 4.5 杩囨护闃堝€?

涓洪伩鍏嶄綆璐ㄩ噺褰掑洜缁撴灉骞叉壈鍒嗘瀽锛屽紩鎿庤缃渶浣庣疆淇″害闃堝€硷細

- 缁煎悎璇勫垎 < 0.10 鐨勫€欓€夐」鐩存帴杩囨护
- 鏇夸唬琛屼负浣撲粎淇濈暀缃俊搴?鈮?0.15 鐨勫墠 5 涓?
- 鏃犱换浣曞尮閰嶆椂杩斿洖 `PrimaryActor: "Unknown"`锛岀疆淇″害涓?0

## 5. 濞佽儊鐙╃寧妗嗘灦

### 5.1 鍋囪椹卞姩鐙╃寧

濞佽儊鐙╃寧閬靛惊"鍋囪鈫掗獙璇佲啋缁撹"鐨勭瀛︽柟娉曡锛?

```
鍋囪鐢熸垚 鈫?鍋囪绠＄悊 鈫?鍋囪鎵ц 鈫?缁撴灉纭 鈫?鐭ヨ瘑娌夋穩
```

涓庝紶缁?閽撻奔寮?鎼滅储涓嶅悓锛屽亣璁鹃┍鍔ㄧ嫨鐚庝粠宸茬煡鐨勬敾鍑绘妧鏈嚭鍙戯紝棰勬祴鏀诲嚮鑰呭彲鑳戒娇鐢ㄧ殑涓嬩竴姝ユ妧鏈紝涓诲姩瀵绘壘璇佹嵁楠岃瘉鎴栧惁瀹氬亣璁俱€?

### 5.2 鐙╃寧鍋囪妯″瀷

```go
type HuntHypothesis struct {
    ID          string    // 鍋囪 ID
    Name        string    // 鍋囪鍚嶇О
    Description string    // 鍋囪鎻忚堪
    TechniqueID string    // 鐩爣 ATT&CK 鎶€鏈?ID
    TacticIDs   []string  // 鐩爣鎴樻湳 ID 鍒楄〃
    DataSource  string    // 鏁版嵁鏉ユ簮绫诲瀷
    Query       string    // 鎼滅储鏌ヨ琛ㄨ揪寮?
    Priority    string    // 浼樺厛绾?(critical/high/medium/low)
    Status      string    // 鐘舵€?(active/confirmed/dismissed/expired)
    CreatedAt   time.Time // 鍒涘缓鏃堕棿
}
```

### 5.3 鑷姩鍋囪鐢熸垚

`AutoGenerateHypotheses` 鏂规硶鍩轰簬涓夌椹卞姩婧愯嚜鍔ㄧ敓鎴愮嫨鐚庡亣璁撅細

**椹卞姩婧愪竴锛氬憡璀﹂┍鍔紙Alert-Driven锛?*

褰撲富鏈轰骇鐢熸湭纭鍛婅鏃讹紝鍩轰簬鏀诲嚮鎶€鏈浆绉荤煩闃甸娴嬫敾鍑昏€呭彲鑳戒娇鐢ㄧ殑涓嬩竴姝ユ妧鏈細

$$
P(T_{next} | T_{current}) = \frac{TransCount(T_{current}, T_{next})}{\sum_{t} TransCount(T_{current}, t)}
$$

杞Щ鐭╅樀浠庡巻鍙叉敾鍑绘暟鎹拰 ATT&CK 妗嗘灦鐨勬垬鏈『搴忓叧绯绘瀯寤恒€傚浜庢瘡涓凡瑙傚療鎶€鏈紝鐢熸垚鍏?Top-K 鍚庣户鎶€鏈殑鐙╃寧鍋囪銆?

**椹卞姩婧愪簩锛氬紓甯搁┍鍔紙Anomaly-Driven锛?*

褰撲富鏈轰骇鐢熼珮鍒嗗紓甯革紙Score 鈮?0.5锛変笖寮傚父鍏宠仈浜?ATT&CK 鎶€鏈椂锛岀敓鎴?娣卞叆璋冩煡"绫诲亣璁撅細

```
鍋囪锛氬紓甯歌涓?{technique} 鍦ㄤ富鏈?{host} 涓婅妫€娴嬪埌锛岄渶瑕佽繘涓€姝ヨ皟鏌?
```

**椹卞姩婧愪笁锛氫俊鏍囬┍鍔紙Beacon-Driven锛?*

褰撲俊鏍囨娴嬪彂鐜?C2 閫氫俊鐗瑰緛鏃讹紝鐢熸垚涓?C2 鐩稿叧鎶€鏈殑鐙╃寧鍋囪锛?

- T1071.001锛圵eb 鍗忚淇℃爣锛?
- T1573.001锛堝姞瀵嗕俊閬撳绉板姞瀵嗭級
- T1105锛堝叆鍙ｅ伐鍏蜂紶杈擄級

### 5.4 鍋囪鎵ц涓庣‘璁?

```go
type HuntResult struct {
    ID            string    // 缁撴灉 ID
    HypothesisID  string    // 鍏宠仈鐨勫亣璁?ID
    HostID        string    // 鐩爣涓绘満
    Confirmed     bool      // 鏄惁纭
    Findings      []string  // 鍙戠幇鎻忚堪
    Confidence    float64   // 纭缃俊搴?
    ExecutedAt    time.Time // 鎵ц鏃堕棿
}
```

鍋囪鎵ц閫昏緫锛?

1. 鏍规嵁鍋囪鐨?`TechniqueID` 鏌ユ壘璇ヤ富鏈烘槸鍚﹀瓨鍦ㄧ浉鍏崇殑鏈‘璁ゅ憡璀?
2. 鏌ユ壘鏄惁瀛樺湪鐩稿叧鐨勫紓甯镐簨浠?
3. 鏌ユ壘鏄惁瀛樺湪鐩稿叧鐨勪俊鏍囨娴?
4. 缁煎悎浠ヤ笂璇佹嵁璁＄畻纭缃俊搴︼細

$$
Confidence = \min(1.0, N_{findings} \times 0.3)
$$

5. 纭鐨勫亣璁鹃€氳繃浜嬩欢鎬荤嚎鍙戝竷 `attck.apt.hunt_confirmed` 浜嬩欢

### 5.5 鍘婚噸鏈哄埗

鑷姩鐢熸垚鐨勫亣璁鹃€氳繃 `{TechniqueID}|{DataSource}` 缁勫悎閿幓閲嶏紝閬垮厤閲嶅鐢熸垚鐩稿悓鍋囪銆傚凡瀛樺湪鐨勫亣璁句笉浼氳瑕嗙洊锛屼粎鏂板涓嶉噸澶嶇殑鍋囪銆?

## 6. 涓?SSAM 璇勪及浣撶郴鐨勯泦鎴?

### 6.1 浜嬩欢鎬荤嚎闆嗘垚

APT 妯″潡閫氳繃 渭Kernel 浜嬩欢鎬荤嚎涓庡叾浠栨ā鍧楅€氫俊锛?

| 浜嬩欢涓婚 | 鍙戝竷鑰?| 璁㈤槄鑰?| 璇箟 |
|----------|--------|--------|------|
| `attck.apt.chain_detected` | APT 閾鹃噸鏋?| 绛栫暐绠＄悊鍣?| 鏀诲嚮閾捐妫€娴嬪埌锛屽彲鑳借Е鍙戣嚜鍔ㄥ搷搴?|
| `attck.apt.attribution` | APT 褰掑洜 | 鏃ュ織鏀堕泦鍣?| 褰掑洜缁撴灉闇€璁板綍瀹¤鏃ュ織 |
| `attck.apt.hunt_confirmed` | 濞佽儊鐙╃寧 | 绛栫暐绠＄悊鍣?| 鐙╃寧鍋囪琚‘璁わ紝鍙兘瑙﹀彂鍝嶅簲 |
| `attck.behavioral.alert` | 琛屼负妫€娴?| 绛栫暐绠＄悊鍣?| 琛屼负鍛婅瑙﹀彂鍝嶅簲 |
| `attck.behavioral.beacon` | 淇℃爣妫€娴?| 绛栫暐绠＄悊鍣?| C2 淇℃爣妫€娴嬭Е鍙戝搷搴?|
| `attck.detection.alert` | 妫€娴嬪紩鎿?| APT 閾鹃噸鏋?| 鏂板憡璀﹀彲鑳芥洿鏂版敾鍑婚摼 |

### 6.2 DI 瀹瑰櫒闆嗘垚

ATT&CK 妯″潡閫氳繃 `ATTACKInterface` 鎺ュ彛娉ㄥ唽鍒?DI 瀹瑰櫒锛屽叾浠栨ā鍧楀彲閫氳繃渚濊禆娉ㄥ叆鑾峰彇锛?

```go
type ATTACKInterface interface {
    // 妫€娴嬩笌鍒嗘瀽 (4 鏂规硶)
    RegisterDetectionRule(rule DetectionRule) error
    EvaluateDetectionRule(ruleID, hostID, rawLog string, fields map[string]string) (*DetectionAlert, error)
    GetAlerts(hostID, severity string, limit int) []DetectionAlert
    CorrelateAlerts(hostID string) []CorrelationResult

    // 濞佽儊鎯呮姤 (5 鏂规硶)
    AddIOC(entry IOCEntry) error
    SearchIOC(value string) []IOCEntry
    UpsertThreatActor(profile ThreatActorProfile) error
    MatchThreatActor(detectedTechniques []string) []APTMatchResult
    EnrichAlertWithTI(alertID string) (*DetectionAlert, map[string]interface{})

    // 瀵规墜浠跨湡 (4 鏂规硶)
    CreateScenario(scenario EmulationScenario) error
    GenerateScenarioFromActor(actorID string) (*EmulationScenario, error)
    RunEmulation(scenarioID, hostID string, safeMode bool) (*EmulationResult, error)
    GetEmulationResults(scenarioID string, limit int) []EmulationResult

    // 璇勪及涓庡伐绋?(4 鏂规硶)
    PerformGapAnalysis(hostID string) (*AssessmentReport, error)
    GetControlMapping(techniqueID string) *ControlMapping
    CreateImprovementTrack(track ImprovementTrack) error
    CalculateImprovementProgress(trackID string) (float64, error)

    // APT 澧炲己 (11 鏂规硶)
    ReconstructAttackChain(hostIDs []string) (*AttackChain, error)
    RegisterBehavioralIndicator(indicator BehavioralIndicator) error
    EvaluateBehavioralIndicators(hostID string, metrics map[string]float64) []BehavioralAlert
    DetectBeaconing(hostID string, events []TimeSeriesPoint) []BeaconDetection
    PerformAttribution(chainID string) (*AttributionResult, error)
    GenerateAPTAnalysisReport(hostIDs []string) (*APTAnalysisReport, error)
    CreateHuntHypothesis(hypothesis HuntHypothesis) error
    ExecuteHunt(hypothesisID string, hostID string) (*HuntResult, error)
    AutoGenerateHypotheses(hostID string) ([]HuntHypothesis, error)
    UpdateBaseline(hostID string, metrics map[string]float64)
    GetBaseline(hostID string) *BehavioralBaseline
}
```

> **娉?*锛氫互涓婁粎鍒楀嚭 28 涓牳蹇冩柟娉曘€傚畬鏁存帴鍙ｈ繕鍖呭惈瑕嗙洊鐜囧垎鏋愩€佹潃浼ら摼璇勪及銆侀闄╅娴嬨€佸樊璺濆垎鏋愩€乊ARA/Sigma 瑙勫垯寮曟搸銆佸洜鏋滄帹鐞嗐€佺兢浣撳熀绾裤€佽礉鍙舵柉褰掑洜銆佷俊鏍囦俊瑾夊簱杩囨护銆佽法涓绘満娴侀噺鍒嗘瀽绛夋墿灞曟柟娉曪紝鍏辫 60+ 鏂规硶銆傝瑙?`api/v1/` 涓殑鎺ュ彛瀹氫箟銆?

### 6.3 SPC 鑱斿姩

APT 褰掑洜缁撴灉鍙笌 SPC 鎬佸娍璁＄畻浜ゅ弶楠岃瘉锛?

- APT 褰掑洜璇嗗埆鐨勫▉鑳佽涓轰綋宸茬煡鐨勫埄鐢ㄥ亸濂斤紝鍙敤浜庨獙璇?SPC 鐨?CVE 鍖归厤缁撴灉
- 渚嬪锛欰PT29 鍋忓ソ鍒╃敤 CVE-202X-YYYY锛岃嫢 SPC 鍦ㄨ涓绘満涓婂尮閰嶅埌姝?CVE锛屽垯 $P_{score}$ 鐨勭疆淇″害鎻愬崌
- 鍙嶄箣锛岃嫢 SPC 鍖归厤鍒扮殑 CVE 涓庡綊鍥犵粍缁囩殑宸茬煡鍋忓ソ涓嶇锛屽彲鑳芥彁绀哄綊鍥犵粨鏋滈渶瑕侀噸鏂拌瘎浼?

### 6.4 绛栫暐鑱斿姩

APT 妫€娴嬬粨鏋滈€氳繃浜嬩欢鎬荤嚎瑙﹀彂绛栫暐绠＄悊鍣ㄧ殑鑷姩鍝嶅簲锛?

| APT 浜嬩欢 | 绛栫暐鍝嶅簲 | 鏉′欢 |
|----------|----------|------|
| 鏀诲嚮閾炬娴嬶紙severity=critical锛?| `isolate_host` | 閾捐法鈮? 涓垬鏈笖鍖呭惈鍑瘉璁块棶/妯悜绉诲姩 |
| 鏀诲嚮閾炬娴嬶紙severity=high锛?| `notify_admin` | 閾捐法鈮? 涓垬鏈?|
| 淇℃爣妫€娴嬶紙score鈮?.85锛?| `block_ip` + `notify_admin` | 寮轰俊鏍囩壒寰?|
| 琛屼负鍛婅锛坰everity=critical锛?| `increase_assessment` | 鎻愰珮璇勪及棰戠巼 |
| 鐙╃寧纭 | `notify_admin` | 浠讳綍纭鐨勭嫨鐚庡亣璁?|

## 7. 骞跺彂瀹夊叏璁捐

APT 妯″潡鐨勬墍鏈夊叡浜姸鎬侀€氳繃 `ATTACKModule.mu`锛坄sync.RWMutex`锛変繚鎶わ細

| 鏁版嵁瀛楁 | 璁块棶妯″紡 | 淇濇姢鏂瑰紡 |
|----------|----------|----------|
| `alerts` | 鍐欙細瑙勫垯璇勪及锛涜锛氭煡璇?鍏宠仈 | `Lock`/`RLock` |
| `anomalies` | 鍐欙細璁板綍寮傚父锛涜锛氭煡璇?鏀诲嚮閾?| `Lock`/`RLock` |
| `iocs` | 鍐欙細澧炲垹锛涜锛氭悳绱?褰掑洜 | `Lock`/`RLock` |
| `attackChains` | 鍐欙細閾鹃噸鏋勶紱璇伙細鏌ヨ | `Lock`/`RLock` |
| `baselines` | 鍐欙細鏇存柊鍩虹嚎锛涜锛氳瘎浼?| `Lock`/`RLock` |
| `beaconDetections` | 鍐欙細淇℃爣妫€娴嬶紱璇伙細鏌ヨ | `Lock`/`RLock` |
| `huntHypotheses` | 鍐欙細鍒涘缓/鍒犻櫎鍋囪锛涜锛氬垪琛?| `Lock`/`RLock` |

鎵€鏈夊叕寮€鏂规硶鍦ㄥ叆鍙ｅ鑾峰彇閿侊紝鍦?`defer` 涓噴鏀俱€傚啓鎿嶄綔浣跨敤 `Lock()`锛岃鎿嶄綔浣跨敤 `RLock()`锛岀‘淇濊澶氬啓灏戝満鏅笅鐨勫苟鍙戞晥鐜囥€?

## 8. 鎵╁睍鐐逛綋绯?

APT 妯″潡娉ㄥ唽浜?12 涓墿灞曠偣锛屾敮鎸佺涓夋柟鎻掍欢鍦ㄥ叧閿簨浠跺彂鐢熸椂娉ㄥ叆鑷畾涔夐€昏緫锛?

| 鎵╁睍鐐?| 瑙﹀彂鏃舵満 | 鍏稿瀷鐢ㄩ€?|
|--------|----------|----------|
| `attck.coverage.complete` | 瑕嗙洊鐜囧垎鏋愬畬鎴?| 鐢熸垚鍚堣鎶ュ憡 |
| `attck.apt.matched` | APT 缁勭粐鍖归厤 | 閫氱煡瀹夊叏杩愯惀鍥㈤槦 |
| `attck.risk.predicted` | 棰勬祴鎬ч闄╄瘎浼?| 璋冩暣闃插尽浼樺厛绾?|
| `attck.detection.alert` | 妫€娴嬪憡璀﹁Е鍙?| 闆嗘垚 SOAR 骞冲彴 |
| `attck.detection.anomaly` | 楂樺垎寮傚父妫€娴?| 瑙﹀彂娣卞害璋冩煡 |
| `attck.emulation.complete` | 瀵规墜浠跨湡瀹屾垚 | 鐢熸垚绾㈤槦鎶ュ憡 |
| `attck.assessment.complete` | 宸窛鍒嗘瀽瀹屾垚 | 鐢熸垚鏀硅繘璁″垝 |
| `attck.apt.chain_detected` | 鏀诲嚮閾鹃噸鏋?| 瑙﹀彂鑷姩鍝嶅簲 |
| `attck.apt.attribution` | APT 褰掑洜鎵ц | 閫氱煡濞佽儊鎯呮姤鍥㈤槦 |
| `attck.apt.hunt_confirmed` | 鐙╃寧鍋囪纭 | 鍚姩浜嬩欢鍝嶅簲 |
| `attck.apt.report_generated` | APT 鍒嗘瀽鎶ュ憡鐢熸垚 | 褰掓。涓庡垎浜?|
| `attck.behavioral.alert` | 琛屼负鍛婅瑙﹀彂 | 闆嗘垚 SIEM |
| `attck.behavioral.beacon` | C2 淇℃爣妫€娴?| 鑷姩闃绘柇 C2 閫氶亾 |

## 9. 鎬ц兘鑰冮噺

### 9.1 鏀诲嚮閾鹃噸鏋勬€ц兘

- 璇佹嵁鏀堕泦锛歄(A + N + I)锛屽叾涓?A 涓哄憡璀︽暟銆丯 涓哄紓甯告暟銆両 涓?IOC 鏁?
- 闃舵鏋勫缓锛歄(S 脳 T)锛屽叾涓?S 涓洪樁娈垫暟銆乀 涓烘瘡闃舵鎶€鏈暟
- 褰掑洜璁＄畻锛歄(G 脳 T_obs)锛屽叾涓?G 涓?APT 缁勭粐鏁般€乀_obs 涓鸿瀵熸妧鏈暟

鍏稿瀷瑙勬ā锛?00 鍛婅銆?0 寮傚父銆?0 APT 缁勭粐锛変笅锛屾敾鍑婚摼閲嶆瀯鑰楁椂 < 50ms銆?

### 9.2 淇℃爣妫€娴嬫€ц兘

- 闂撮殧璁＄畻锛歄(N)锛孨 涓烘暟鎹偣鏁?
- 缁熻璁＄畻锛歄(N)
- 鏈€浣庢暟鎹噺瑕佹眰锛?0 涓暟鎹偣

### 9.3 褰掑洜璁＄畻鎬ц兘

- TTP 閲嶅彔璁＄畻锛歄(G 脳 T_obs 脳 T_group)
- IOC 鍖归厤锛歄(I 脳 G)
- 鎺掑簭锛歄(G log G)

鍏稿瀷瑙勬ā锛?0 APT 缁勭粐銆?0 瑙傚療鎶€鏈€?00 IOC锛変笅锛屽綊鍥犺绠楄€楁椂 < 10ms銆?

## 10. 宸插疄鐜板寮轰笌鎸佺画婕旇繘

### 10.1 宸插疄鐜板寮猴紙v1.1锛?

| 澧炲己椤?| 瀹炵幇鏂规 | 浠ｇ爜浣嶇疆 | 鐘舵€?|
|--------|----------|----------|------|
| 鏀诲嚮閾惧洜鏋滄帹鐞?| 20 鏉″洜鏋滆鍒欐瀯寤烘湁鍚戝浘锛屾彁鍗囨椂搴忔帓搴忕簿搴﹀拰缃俊搴?| `attck_apt_causal.go` | 鉁?宸插疄鐜?|
| 缇や綋鍩虹嚎 | 鎸夎鑹茶仛鍚堝悓绫讳富鏈哄熀绾垮潎鍊硷紝缂撹В鍐峰惎鍔ㄨ鎶?| `attck_apt_enhanced.go` 鈥?`ComputeGroupBaseline/ApplyGroupBaseline` | 鉁?宸插疄鐜?|
| 璐濆彾鏂綊鍥?| 4 鑺傜偣璐濆彾鏂綉缁滐紙TTP閲嶅彔銆両OC鍖归厤銆佽涓氬榻愩€佹潃浼ら摼涓€鑷存€э級鈫?褰掑洜缃俊搴?| `attck_apt_enhanced.go` 鈥?`BuildBayesianAttributionNetwork/PerformBayesianAttribution` | 鉁?宸插疄鐜?|
| 淇℃爣淇¤獕搴撹繃婊?| 鍐呯疆 12 鏉′俊瑾夎鍒欙紙NTP/DNS/OS鏇存柊/寮€鍙戝伐鍏凤級锛岃繃婊ゅ悎娉曚綆鎶栧姩鏈嶅姟 | `attck_apt_enhanced.go` 鈥?`FilterBeaconWithReputation` | 鉁?宸插疄鐜?|
| YARA/Sigma 瑙勫垯寮曟搸 | 鍏抽敭璇嶅尮閰嶆ā寮忥紝鏀寔瑙勫垯鍔犺浇銆佸尮閰嶅拰缁撴灉杈撳嚭 | `attck_apt_enhanced.go` 鈥?`LoadYARARules/MatchYARARules/LoadSigmaRules/MatchSigmaRules` | 鉁?宸插疄鐜?|
| 璺ㄤ富鏈虹綉缁滄祦閲忓垎鏋?| 鎸夋簮涓绘満鑱氬悎寮傚父杩炴帴锛岃绠楁í鍚戠Щ鍔ㄨ瘎鍒?| `attck_apt_enhanced.go` 鈥?`AnalyzeCrossHostConnections` | 鉁?宸插疄鐜?|

### 10.2 鍥犳灉鎺ㄧ悊妯″瀷璇﹁В

鍥犳灉鎺ㄧ悊妯″瀷閫氳繃棰勫畾涔夌殑鍥犳灉瑙勫垯搴擄紙20 鏉?ATT&CK 鎶€鏈棿鍥犳灉鍏崇郴锛夛紝鍦ㄦ敾鍑婚摼閲嶆瀯闃舵鑷姩鎵ц浠ヤ笅澧炲己锛?

1. **鍥犳灉鍥炬瀯寤?*锛氬熀浜庡綋鍓嶆敾鍑婚樁娈电殑璇佹嵁鎶€鏈?ID锛屾瀯寤烘湁鍚戝洜鏋滃浘
2. **鍥犳灉閾炬帹鏂?*锛氬姣忓鐩搁偦闃舵妫€鏌ユ槸鍚﹀瓨鍦ㄥ洜鏋滆鍒欙紝璁＄畻鍥犳灉寮哄害
3. **缃俊搴︽彁鍗?*锛氬瓨鍦ㄥ洜鏋滃叧绯荤殑闃舵鑾峰緱鏈€楂?0.2 鐨勭疆淇″害鍔犳垚
4. **鎺掑簭浼樺寲**锛氬湪 ATT&CK 鎴樻湳椤哄簭鍩虹涓婏紝浼樺厛鎺掑垪鍥犳灉寮哄害楂樼殑闃舵

鍏抽敭鍥犳灉瑙勫垯绀轰緥锛?

```
T1566(閽撻奔) 鈫?T1059(鍛戒护鎵ц)   寮哄害 0.9
T1003(鍑瘉杞偍) 鈫?T1078(鏈夋晥璐︽埛) 寮哄害 0.85
T1190(鍏叡搴旂敤鍒╃敤) 鈫?T1059(鍛戒护鎵ц) 寮哄害 0.85
T1078(鏈夋晥璐︽埛) 鈫?T1021(杩滅▼鏈嶅姟) 寮哄害 0.8
```

### 10.3 璐濆彾鏂綊鍥犵綉缁滆瑙?

璐濆彾鏂綊鍥犵綉缁滃寘鍚?4 涓瘉鎹妭鐐瑰拰 1 涓洰鏍囪妭鐐癸細

| 鑺傜偣 | 鐘舵€佺┖闂?| 鍚箟 |
|------|----------|------|
| `ttp_overlap` | high / medium / low | TTP 涓庡凡鐭?APT 缁勭粐鐨勯噸鍙犲害 |
| `ioc_match` | strong / weak / none | IOC 璇佹嵁寮哄害 |
| `sector_alignment` | aligned / partial / none | 鐩爣琛屼笟瀵归綈搴?|
| `kill_chain_coherence` | coherent / partial / incoherent | 鏀诲嚮閾句笌宸茬煡鏂规硶璁轰竴鑷存€?|
| `attribution` | high_confidence / medium_confidence / low_confidence / unknown | 褰掑洜缃俊搴?|

鎺ㄧ悊娴佺▼锛氳瘉鎹妭鐐圭姸鎬佺敱鏀诲嚮閾惧垎鏋愯嚜鍔ㄧ‘瀹?鈫?鏌ヨ鏉′欢姒傜巼琛紙CPT锛夆啋 杈撳嚭褰掑洜姒傜巼鍒嗗竷銆?

### 10.4 鎸佺画婕旇繘鏂瑰悜

| 鏂瑰悜 | 璇存槑 | 浼樺厛绾?|
|------|------|--------|
| 鍥犳灉瑙勫垯搴撴墿灞?| 褰撳墠 20 鏉¤鍒欒鐩栦富瑕佹敾鍑昏矾寰勶紝闇€鎸佺画鎵╁睍鑷宠鐩?ATT&CK V19 鍏ㄩ儴鎴樻湳 | 楂?|
| YARA/Sigma 绮剧‘鍖归厤 | 褰撳墠涓哄叧閿瘝鍖归厤锛岄渶闆嗘垚 libyara 鍘熺敓寮曟搸 | 楂?|
| 璐濆彾鏂綉缁滃涔?| 褰撳墠 CPT 涓轰笓瀹惰瀹氾紝闇€浠庡巻鍙插綊鍥犳暟鎹腑瀛︿範鍙傛暟 | 涓?|
| 璺ㄤ富鏈烘椂搴忓叧鑱?| 褰撳墠妯悜绉诲姩鍒嗘瀽鍩轰簬杩炴帴缁熻锛岄渶澧炲姞鏃跺簭绐楀彛鍏宠仈 | 涓?|
| 淇¤獕搴撹嚜鍔ㄦ洿鏂?| 褰撳墠涓洪潤鎬佸唴缃紝闇€鏀寔浠庡▉鑳佹儏鎶ユ簮鑷姩鏇存柊 | 浣?|

## 鐗堟湰鍘嗗彶

- **v1.1** 鈥?2026-05-26 瀹炵幇鍥犳灉鎺ㄧ悊銆佺兢浣撳熀绾裤€佽礉鍙舵柉褰掑洜銆佷俊鏍囦俊瑾夊簱銆乊ARA/Sigma 瑙勫垯寮曟搸銆佽法涓绘満娴侀噺鍒嗘瀽鍏」澧炲己
- **v1.0** 鈥?2026-05-25 鍒濈锛屼笌 ASSCOR v0.1.3-mvp ATT&CK Module v1.0.0 鍚屾鍙戝竷
