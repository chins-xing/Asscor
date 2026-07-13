# ASSCOR 浣跨敤鎵嬪唽

> 鐗堟湰锛歷0.2.0 | SSAM 2.0 | 鏈€鍚庢洿鏂帮細2026-07-07

> 鈿狅笍 ASSCOR 杈撳嚭鐨勫垎鏁版槸涓€涓?*鏁板妯″瀷鐨勮绠楃粨鏋滐紝涓嶆槸缁濆鐨勫畨鍏ㄧ湡鍊笺€?*
> 璇峰皢璇勫垎浣滀负鍐崇瓥鍙傝€冭€岄潪鍐崇瓥鏇夸唬銆傛ā鍨嬭兘鎹曡幏宸茬煡鐨勫彲閲忓寲缁村害锛屼絾瀹夊叏鐨?
> 瀹屾暣鍥炬櫙杩滆秴浠讳綍鍏紡鐨勮鐩栬寖鍥淬€?

---

## 鐩綍

1. [姒傝堪](#1-姒傝堪)
2. [蹇€熷紑濮媇(#2-蹇€熷紑濮?
3. [閮ㄧ讲鏋舵瀯](#3-閮ㄧ讲鏋舵瀯)
4. [Kernel 閮ㄧ讲](#4-kernel-閮ㄧ讲)
5. [Agent 閮ㄧ讲](#5-agent-閮ㄧ讲)
6. [TLS 璇佷功绠＄悊](#6-tls-璇佷功绠＄悊)
7. [閰嶇疆鏂囦欢璇﹁В](#7-閰嶇疆鏂囦欢璇﹁В)
8. [SPC 瀹夊叏鎬佸娍妯″潡](#8-spc-瀹夊叏鎬佸娍妯″潡)
9. [绛変繚鏄犲皠涓庤瘎鍒嗛槇鍊糫(#9-绛変繚鏄犲皠涓庤瘎鍒嗛槇鍊?
10. [ATT&CK V19 濞佽儊鍒嗘瀽妯″潡](#10-attck-v19-濞佽儊鍒嗘瀽妯″潡)
11. [鏃ュ織绠＄悊](#11-鏃ュ織绠＄悊)
12. [瀹堟姢杩涚▼妯″紡](#12-瀹堟姢杩涚▼妯″紡)
13. [绂荤嚎璇勪及妯″紡](#13-绂荤嚎璇勪及妯″紡)
14. [鐜鍙橀噺鍙傝€僝(#14-鐜鍙橀噺鍙傝€?
15. [鏁呴殰鎺掓煡](#15-鏁呴殰鎺掓煡)

---

## 1. 姒傝堪

ASSCOR 鏄竴涓紑婧愮殑鍒嗗竷寮忓畨鍏ㄥ彲鎺ュ彈鎬ц瘎浼扮郴缁燂紝瀹炵幇浜嗙郴缁熷畨鍏ㄥ彲鎺ュ彈鎬фā鍨嬶紙SSAM锛?.0銆傜郴缁熼€氳繃鍥涗釜浜掓枼鏍稿績鍩熻瘎浼颁富鏈哄畨鍏ㄧ姸鎬侊紝骞堕泦鎴?MITRE ATT&CK V19 濞佽儊鍒嗘瀽妗嗘灦锛屾彁渚涗粠瀹夊叏璇勪及銆佸▉鑳佹娴嬪埌 APT 鏀诲嚮鍒嗘瀽鐨勫畬鏁磋兘鍔涢摼銆?
SSAM V2.0 寮曞叆涓夊眰璇箟妯″瀷锛堟湰寰?Intrinsic / 鏆撮湶 Exposure / 濞佽儊 Threat锛夛紝浠ヤ笁涓嫭绔嬮闄╁眰鍔犳潈骞冲潎鍙栦唬鏃х増 ThreatCoeff/SPCScore 鍙岄噸缃氬垎鏈哄埗锛屾彁鍗囪瘎鍒嗙殑鍙В閲婃€т笌鍏鎬с€傛牳蹇冪畻娉曞簱宸茬嫭绔嬩负 [github.com/chins-xing/ssam](https://github.com/chins-xing/ssam)锛坄ssam-lib/`锛夛紝闆跺閮ㄤ緷璧栥€佺函鍑芥暟寮忚璁°€侫SSCOR 骞冲彴閫氳繃 `internal/ssam/` 钖勯€傞厤灞傚鎵樿皟鐢ㄣ€?

| 鏍稿績鍩?| 鏉冮噸 | 璇勪及鍐呭 |
|--------|------|----------|
| 鏀诲嚮闈㈢鐞?| 35% | 鏃犵敤鏈嶅姟銆佸紑鏀剧鍙ｃ€佸己璁よ瘉銆丼SH 閰嶇疆 |
| 涓氬姟杩炵画鎬?| 25% | 鍏抽敭鏈嶅姟杩愯銆佸浠芥満鍒躲€佽祫婧愬厖瑁曞害 |
| 鎿嶄綔鍙俊搴?| 25% | 鏂囦欢鏉冮檺銆佸璁℃棩蹇椼€佸懡浠ゅ巻鍙查槻绡℃敼銆佷緵搴旈摼瀹屾暣鎬с€丼ELinux/AppArmor |
| 闊ф€?| 15% | 鑷姩灏佺绮惧害銆丼YN Cookie銆佽繛鎺ラ檺鍒躲€佸彲鎺ュ彈娌﹂櫡鎸囨爣锛圓CI锛?|

**闄勫姞妯″潡**锛?

| 妯″潡 | 鍔熻兘 |
|------|------|
| ATT&CK V19 | MITRE ATT&CK 妗嗘灦闆嗘垚锛屾娴嬪垎鏋愩€佸▉鑳佹儏鎶ャ€佸鎵嬩豢鐪熴€佽瘎浼板伐绋嬨€丄PT 鏀诲嚮鍒嗘瀽涓庢娴嬪寮?|
| SPC | 瀹夊叏鎬佸娍璁＄畻锛孨VD/EPSS/CISA KEV/CNNVD/CNVD 澶氭簮婕忔礊鎯呮姤涓庢湰鍦拌祫浜ф瘮瀵?|
| CTI | 缃戠粶濞佽儊鎯呮姤绠＄悊锛屽姩鎬佸▉鑳佺郴鏁?渭 璁＄畻 |

**璇勫垎鍏紡**锛?

```
SSAM_final = (危(S_i 脳 W_i) / 危W_i) 脳 螤M_j 脳 渭 脳 P_score
```

- `S_i`锛氭牳蹇冨煙鍒嗘暟锛?鈥?00锛?
- `W_i`锛氭牳蹇冨煙鏉冮噸锛堟€诲拰 100锛?
- `M_j`锛氳竟缂樺洜瀛愪箻鏁帮紙浠呭 Active 涓?Factor 鈭?(0,1) 鐨勫洜瀛愭墽琛岃繛涔橈級
- `渭`锛氬▉鑳佺郴鏁帮紙榛樿 1.0锛岀敱 CTI 妯″潡鍔ㄦ€佽皟鏁达級
- `P_score`锛歋PC 淇鍥犲瓙锛?.60鈥?.00锛屽熀浜?CVE 鍖归厤缁撴灉璁＄畻锛?

---

## 2. 蹇€熷紑濮?

### 2.1 鍓嶇疆鏉′欢

- 鐩爣涓绘満锛歀inux锛堟敮鎸?x86_64 / ARM64 / i386锛?
- Kernel 涓?Agent 闂寸綉缁滃彲杈?
- 锛堟帹鑽愶級NVD API Key锛氫粠 https://nvd.nist.gov/developers/request-an-api-key 鑾峰彇

### 2.2 鏈€灏忛儴缃诧紙鐢熶骇锛屾帹鑽愶級

```bash
# 1. 瀹夎骞跺惎鍔?Kernel锛堜竴鏉″懡浠ゅ畬鎴?systemd + FHS + PATH锛?
sudo ./ASSCOR-kernel-v0.2.1-linux-amd64 --install
sudo systemctl start asscor-kernel

# 2. 瀹夎骞跺惎鍔?Agent锛堢洰鏍囦富鏈猴級
sudo ./ASSCOR-agent-v0.2.1-linux-amd64 --install
sudo systemctl start asscor-agent

# 3. 杩炴帴 CLI 绠＄悊
asscor-cli               # status / plugins / history / exit
```

### 2.3 绂荤嚎璇勪及锛堟棤闇€ Kernel/Agent锛?

```bash
# 鍗曟満妯″紡锛氱洿鎺ュ湪鏈湴鎵ц璇勪及锛岀粨鏋滄墦鍗板埌缁堢
./ASSCOR-v0.2.1-linux-amd64 --config=/etc/asscor/config.ini          # 鏂囨湰鎶ュ憡
./ASSCOR-v0.2.1-linux-amd64 --config=/etc/asscor/config.ini -json    # JSON 鎶ュ憡
```

---

## 3. 閮ㄧ讲鏋舵瀯

```
鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
鈹?                 ASSCOR Kernel                    鈹?
鈹? 鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹?鈹?
鈹? 鈹侫ssess鈹?鈹侾olicy鈹?鈹?SPC  鈹?鈹?CTI  鈹?鈹侰mdr  鈹?鈹?
鈹? 鈹斺攢鈹€鈹攢鈹€鈹€鈹?鈹斺攢鈹€鈹攢鈹€鈹€鈹?鈹斺攢鈹€鈹攢鈹€鈹€鈹?鈹斺攢鈹€鈹攢鈹€鈹€鈹?鈹斺攢鈹€鈹攢鈹€鈹€鈹?鈹?
鈹? 鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹?                                     鈹?
鈹? 鈹侫TT&CK鈹? MITRE ATT&CK V19 濞佽儊鍒嗘瀽           鈹?
鈹? 鈹斺攢鈹€鈹攢鈹€鈹€鈹? 妫€娴?鎯呮姤/浠跨湡/璇勪及/APT澧炲己          鈹?
鈹?    鈹?       鈹?       鈹?       鈹?       鈹?     鈹?
鈹? 鈹屸攢鈹€鈹粹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹粹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹粹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹粹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹粹攢鈹€鈹?  鈹?
鈹? 鈹?        渭Kernel Plugin Bus              鈹?  鈹?
鈹? 鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?  鈹?
鈹?                  鈹?gRPC + mTLS                鈹?
鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹尖攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
                    鈹?
        鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹尖攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
        鈹?          鈹?          鈹?
   鈹屸攢鈹€鈹€鈹€鈹粹攢鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹粹攢鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹粹攢鈹€鈹€鈹€鈹?
   鈹?Agent A 鈹?鈹?Agent B 鈹?鈹?Agent C 鈹?
   鈹?host-01)鈹?鈹?host-02)鈹?鈹?host-03)鈹?
   鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
```

**缁勪欢璇存槑**锛?

| 缁勪欢 | 鑱岃矗 |
|------|------|
| Kernel | 寰唴鏍革紝绠＄悊鎻掍欢鐢熷懡鍛ㄦ湡銆乬RPC 鏈嶅姟銆丆LI 浜や簰 |
| Agent | 閮ㄧ讲鍦ㄨ璇勪及涓绘満锛屾敹闆嗘鏌ラ」鏁版嵁骞朵笂鎶?|
| CLI | Kernel 鍐呯疆浜や簰寮忕粓绔紝鎻愪緵鍛戒护琛岀鐞嗚兘鍔?|

---

## 4. Kernel 閮ㄧ讲

### 4.1 鍛戒护琛屽弬鏁?

```
ASSCOR-kernel [閫夐」]
```

| 鍙傛暟 | 榛樿鍊?| 璇存槑 |
|------|--------|------|
| `--config` | `config.ini` | 閰嶇疆鏂囦欢璺緞 |
| `--listen` | `:50051` | gRPC 鐩戝惉鍦板潃 |
| `--webui-port` | `8087` | Web 浠〃鐩樼鍙ｏ紙0 绂佺敤锛?|
| `--no-mtls` | `false` | 绂佺敤 mTLS锛?*浠呴檺寮€鍙戠幆澧?*锛?|
| `--cert-dir` | `certs` | TLS 璇佷功鐩綍 |
| `--verify-certs` | `false` | 楠岃瘉璇佷功閾句竴鑷存€у悗閫€鍑?|
| `--force-regen-certs` | `false` | 寮哄埗閲嶆柊鐢熸垚鎵€鏈?TLS 璇佷功 |
| `--daemon` | `false` | 浠ュ畧鎶よ繘绋嬫ā寮忚繍琛?|
| `--pid-file` | `ASSCOR-kernel.pid` | PID 鏂囦欢璺緞 |
| `--version` | 鈥?| 鏄剧ず鐗堟湰骞堕€€鍑?|
| `--install` | 鈥?| 瀹夎涓?systemd 鏈嶅姟锛堥渶 root锛?|
| `--uninstall` | 鈥?| 鍗歌浇 systemd 鏈嶅姟锛堥渶 root锛?|
| `--upgrade` | 鈥?| 鍘熷湴鍗囩骇宸插畨瑁呯増鏈紙闇€ root锛?|
| `--check-install` | 鈥?| 鏍￠獙瀹夎瀹屾暣鎬у悗閫€鍑?|
| `--cli <socket>` | 鈥?| 杩炴帴鍒拌繍琛屼腑鍐呮牳鐨?CLI锛圲nix socket锛?|
| `--log-format` | `json` | 鏃ュ織鏍煎紡锛歚json`銆乣text` |
| `--log-level` | `info` | 鏃ュ織绾у埆锛歚debug`銆乣info`銆乣warn`銆乣error` |
| `--log-output` | `stderr` | 鏃ュ織杈撳嚭锛歚stderr`銆乣stdout`銆佹垨鏂囦欢璺緞 |

### 4.2 鐢熶骇閮ㄧ讲锛坰ystemd + FHS锛屾帹鑽愶級

鍗曚簩杩涘埗鑷甫瀹夎鑳藉姏锛屼竴鏉″懡浠ゅ畬鎴?systemd 鏈嶅姟娉ㄥ唽銆丗HS 鐩綍甯冨眬銆丳ATH 绗﹀彿閾炬帴銆佺敤鎴峰垱寤猴細

```bash
# 瀹夎锛堥渶 root锛?
sudo ./ASSCOR-kernel-v0.2.1-linux-amd64 --install

# 鍚姩 + 寮€鏈鸿嚜鍚?
sudo systemctl start asscor-kernel
sudo systemctl enable asscor-kernel

# 瀹夎 Agent锛堝悓涓€涓绘満鎴栬璇勪及涓绘満锛?
sudo ./ASSCOR-agent-v0.2.1-linux-amd64 --install
sudo systemctl start asscor-agent
```

**FHS 鏂囦欢绯荤粺甯冨眬**锛?

```
/etc/asscor/config.ini              # 鍐呮牳閰嶇疆
/etc/asscor/agent.ini               # Agent 閰嶇疆
/etc/asscor/config/                 # 6 琛屼笟妯℃澘
/opt/asscor/ASSCOR-kernel           # 鍐呮牳浜岃繘鍒?
/opt/asscor/agent/ASSCOR-agent      # Agent 浜岃繘鍒?
/opt/asscor/asscor-cli.sock         # CLI Unix socket
/var/lib/asscor/                    # 鏁版嵁锛圕VE 缂撳瓨銆佽瘎浼拌褰曘€佸浠斤級
/var/lib/asscor/latest-assessment.json      # 鏈€鏂拌瘎浼版姤鍛?
/var/lib/asscor/assessments-<date>.jsonl     # 鍘嗗彶璇勪及璁板綍
/var/log/asscor/kernel.log          # 鍐呮牳鏃ュ織
/usr/bin/asscor                     # 鍏ㄥ眬鍛戒护锛堢鍙烽摼鎺ワ級
/usr/bin/asscor-cli                 # CLI 渚挎嵎鍖呰鑴氭湰
```

瀹夎鍚?`asscor` 涓?`asscor-cli` 鍦ㄤ换鎰忚矾寰勶紙鍚?`sudo`锛夊彲鐢ㄣ€?

### 4.3 systemctl 绠℃帶

| 鍛戒护 | 鏁堟灉 |
|------|------|
| `systemctl start asscor-kernel` | 鍚姩鏈嶅姟 |
| `systemctl stop asscor-kernel` | 鍋滄锛圫IGTERM 鈫?浼橀泤鍏抽棴锛屼繚瀛?CVE 缂撳瓨锛?|
| `systemctl reload asscor-kernel` | SIGHUP 鈫?鐑噸杞?config.ini锛堟潈閲?闃堝€?Prism/杈圭紭鍥犲瓙锛?|
| `systemctl status asscor-kernel` | 鏌ョ湅鐘舵€?|
| `journalctl -u asscor-kernel -f` | 瀹炴椂璺熻釜鏃ュ織 |

### 4.4 鐗堟湰鍗囩骇

```bash
# 鍘熷湴鍗囩骇锛堣嚜鍔ㄥ仠姝⑩啋澶囦唤鈫掓浛鎹⑩啋鍚姩锛屽け璐ヨ嚜鍔ㄥ洖婊氾級
sudo ./ASSCOR-kernel-v0.2.1-linux-amd64 --upgrade
asscor --version         # 纭鐗堟湰
```

鍗囩骇浼氳嚜鍔ㄨˉ寤?PATH 绗﹀彿閾炬帴骞朵繚鐣欐棫浜岃繘鍒朵簬 `.bak`銆?

### 4.5 杩滅▼ CLI

鍐呮牳浠?systemd 鏈嶅姟杩愯鏃讹紙鏃犱氦浜掔粓绔級锛岄€氳繃 Unix socket 杩炴帴 CLI锛?

```bash
asscor-cli               # 渚挎嵎鏂瑰紡锛堣嚜鍔ㄨ繛鎺?socket锛?
# 鎴?
asscor --cli /opt/asscor/asscor-cli.sock

asscor> status           # 鏌ョ湅鍐呮牳鐘舵€?
asscor> plugins          # 鎻掍欢鍒楄〃
asscor> exit             # 鏂紑锛堝唴鏍哥户缁繍琛岋級
```

> `exit`/`quit` 浠呮柇寮€褰撳墠 CLI 浼氳瘽锛屽唴鏍告寔缁繍琛屻€傚彧鏈?`systemctl stop` 鎵嶄細瀹屾暣閫€鍑哄唴鏍搞€?

### 4.6 鍛戒护琛屽弬鏁帮紙鎵嬪姩杩愯锛?

```bash
ASSCOR-kernel [閫夐」]
```

### 4.7 鍚姩绀轰緥

```bash
# 鏍囧噯鍚姩锛坢TLS 鍚敤锛?
./ASSCOR-kernel-v0.2.1-linux-amd64 --config=/etc/asscor/config.ini --listen=:50051

# 寮€鍙戞ā寮忥紙鏃?mTLS锛?
./ASSCOR-kernel-v0.2.1-linux-amd64 --no-mtls --log-level=debug --log-format=text

# 瀹堟姢杩涚▼妯″紡
./ASSCOR-kernel-v0.2.1-linux-amd64 --daemon --pid-file=/var/run/ASSCOR-kernel.pid

# 楠岃瘉璇佷功
./ASSCOR-kernel-v0.2.1-linux-amd64 --verify-certs --cert-dir=/etc/asscor/certs

# 閲嶆柊鐢熸垚璇佷功
./ASSCOR-kernel-v0.2.1-linux-amd64 --force-regen-certs --cert-dir=/etc/asscor/certs
```

### 4.3 鍚姩杈撳嚭

Kernel 鍚姩鍚庡皢鏄剧ず鍔犺浇鐘舵€侊細

```
ASSCOR 渭Kernel
  Framework: v0.2.1   SSAM: 2.0

  Listen:   :50051 (mTLS: true)
  Log:      json (info) -> stderr
  Plugins:  14 loaded
    {heartbeat} v1.0.0 鈥?Agent heartbeat tracking
    {spc} v1.0.0 鈥?Security Posture Calculator
    {cti} v1.0.0 鈥?Cyber Threat Intelligence
    {assessor} v1.0.0 鈥?SSAM security assessment engine
    {policy} v1.0.0 鈥?Policy enforcement and compliance
    {commander} v1.0.0 鈥?Agent command dispatch
    {log_collector} v1.0.0 鈥?Agent log collection
    {persistence} v1.0.0 鈥?Data persistence layer
    {concurrency} v1.0.0 鈥?Concurrency control
    {attck} v1.0.0 鈥?MITRE ATT&CK V19 threat analysis
    {config_watcher} v1.0.0 鈥?Configuration hot-reload
    {adapter_integration} v1.0.0 鈥?External adapter integration
    {source_manager} v1.0.0 鈥?External source management
    {cli} v1.0.0 鈥?Command-line interface
```

---

## 5. Agent 閮ㄧ讲

### 5.1 鍛戒护琛屽弬鏁?

```
ASSCOR-agent [閫夐」]
```

| 鍙傛暟 | 榛樿鍊?| 璇存槑 |
|------|--------|------|
| `--config` | `agent.ini` | Agent 閰嶇疆鏂囦欢璺緞 |
| `--kernel` | `127.0.0.1:50051` | Kernel 鍦板潃锛坔ost:port锛?|
| `--host-id` | 涓绘満鍚?| Agent 涓绘満鏍囪瘑绗?|
| `--tls` | `false` | 鍚敤 mTLS 杩炴帴 |
| `--tls-skip-verify` | `false` | 璺宠繃 TLS 璇佷功楠岃瘉锛?*浠呴檺寮€鍙戠幆澧?*锛?|
| `--cert-dir` | `certs` | TLS 璇佷功鐩綍 |
| `--install` | 鈥?| 瀹夎涓?systemd 鏈嶅姟锛堥渶 root锛?|
| `--uninstall` | 鈥?| 鍗歌浇 systemd 鏈嶅姟锛堥渶 root锛?|
| `--upgrade` | 鈥?| 鍘熷湴鍗囩骇锛堥渶 root锛?|
| `--version` | 鈥?| 鏄剧ず鐗堟湰骞堕€€鍑?|
| `--log-format` | `json` | 鏃ュ織鏍煎紡 |
| `--log-level` | `info` | 鏃ュ織绾у埆 |
| `--log-output` | `stderr` | 鏃ュ織杈撳嚭 |

### 5.2 閮ㄧ讲绀轰緥

```bash
# 鐢熶骇瀹夎锛坰ystemd锛?
sudo ./ASSCOR-agent-v0.2.1-linux-amd64 --install
sudo systemctl start asscor-agent

# 鎵嬪姩杩愯锛氳繛鎺ヨ繙绋?Kernel锛坢TLS锛?
./ASSCOR-agent-v0.2.1-linux-amd64 --kernel=192.168.1.10:50051 --tls --cert-dir=/etc/asscor/certs

# 鎸囧畾涓绘満 ID
./ASSCOR-agent-v0.2.1-linux-amd64 --kernel=10.0.0.5:50051 --tls --host-id=web-server-01

# 寮€鍙戞ā寮?
./ASSCOR-agent-v0.2.1-linux-amd64 --kernel=localhost:50051 --tls-skip-verify --log-level=debug
```

> Agent 闇€ root 杩愯浠ユ墽琛岀郴缁熺骇妫€鏌ワ紙璇诲彇 `/etc/shadow`銆乣iptables` 绛夛級銆傞潪 root 杩愯鏃堕渶瑕?root 鏉冮檺鐨勬鏌ラ」鑷姩璺宠繃骞舵爣璁般€?

### 5.3 Agent 閰嶇疆鏂囦欢

Agent 鏀寔鐙珛鐨?INI 閰嶇疆鏂囦欢锛堥粯璁?`agent.ini`锛夛紝鏍煎紡濡備笅锛?

```ini
[agent]
kernel_addr = 192.168.1.10:50051
host_id = web-server-01
tls_enabled = true
cert_dir = /etc/ASSCOR/certs

[logging]
format = json
level = info
output = /var/log/ASSCOR-agent.log
```

鍛戒护琛屽弬鏁颁紭鍏堢骇楂樹簬閰嶇疆鏂囦欢銆?

---

## 6. TLS 璇佷功绠＄悊

ASSCOR 浣跨敤 mTLS锛堝弻鍚?TLS锛変繚闅?Kernel 涓?Agent 闂寸殑閫氫俊瀹夊叏銆?

### 6.1 鑷姩璇佷功鐢熸垚

棣栨鍚姩鏃讹紝Kernel 鑷姩鍦ㄨ瘉涔︾洰褰曠敓鎴愪互涓嬫枃浠讹細

```
certs/
鈹溾攢鈹€ ca.crt        # CA 璇佷功
鈹溾攢鈹€ ca.key        # CA 绉侀挜
鈹溾攢鈹€ server.crt    # Kernel 鏈嶅姟绔瘉涔?
鈹溾攢鈹€ server.key    # Kernel 鏈嶅姟绔閽?
鈹溾攢鈹€ agent.crt     # Agent 瀹㈡埛绔瘉涔?
鈹斺攢鈹€ agent.key     # Agent 瀹㈡埛绔閽?
```

### 6.2 璇佷功鎿嶄綔

```bash
# 楠岃瘉璇佷功閾句竴鑷存€?
./ASSCOR-kernel-v0.2.1-linux-amd64 --verify-certs --cert-dir=/etc/asscor/certs

# 寮哄埗閲嶆柊鐢熸垚鎵€鏈夎瘉涔︼紙鏃ц瘉涔﹀皢琚垹闄わ級
./ASSCOR-kernel-v0.2.1-linux-amd64 --force-regen-certs --cert-dir=/etc/asscor/certs
```

### 6.3 璇佷功鍒嗗彂

灏?`ca.crt`銆乣agent.crt`銆乣agent.key` 鍒嗗彂鍒版瘡鍙?Agent 涓绘満鐨勮瘉涔︾洰褰曘€?

> **瀹夊叏鎻愮ず**锛氱閽ユ枃浠讹紙`.key`锛夋潈闄愬簲璁句负 0600锛屼粎闄?root 鐢ㄦ埛璇诲彇銆?

---

## 7. 閰嶇疆鏂囦欢璇﹁В

閰嶇疆鏂囦欢閲囩敤 INI 鏍煎紡锛岄粯璁よ矾寰?`config.ini`銆?

### 7.1 鏉冮噸閰嶇疆

```ini
[weights]
attack_surface = 35        # 鏀诲嚮闈㈢鐞嗘潈閲?
business_continuity = 25   # 涓氬姟杩炵画鎬ф潈閲?
operation_trust = 25       # 鎿嶄綔鍙俊搴︽潈閲?
resilience = 15            # 闊ф€ф潈閲?
```

> 鍥涢」鏉冮噸鎬诲拰蹇呴』涓?100銆?

### 7.2 鍙帴鍙楁€ч槇鍊?

```ini
[acceptability]
threshold = 80.0                       # SSAM 璇勫垎闃堝€?
compliance_framework = GB/T 22239-2019 Level 3  # 鍚堣妗嗘灦
```

闃堝€间笌绛変繚绛夌骇鑱斿姩锛?

| 绛変繚绛夌骇 | SSAM 闃堝€?|
|----------|-----------|
| 浜岀骇 | 鈮?65 |
| 涓夌骇锛堥粯璁わ級 | 鈮?80 |
| 鍥涚骇 | 鈮?90 |

### 7.3 杈圭紭鍥犲瓙

```ini
[edge_factors]
two_factor_failure = 0.85    # 鍙屽洜绱犺璇佺己澶辨椂涔樻暟

[edge_factors.level4_override]
two_factor_failure = 0.70    # 绛変繚鍥涚骇涓夊洜绱犺璇佺己澶辨椂涔樻暟
```

杈圭紭鍥犲瓙浠呭湪瀵瑰簲鏉′欢瑙﹀彂鏃跺弬涓庤繛涔橈紝鍙栧€艰寖鍥?(0, 1)銆?

### 7.4 濞佽儊閰嶇疆

```ini
[threat]
coefficient = 1.0     # 濞佽儊绯绘暟 渭锛堥粯璁?1.0锛岀敱 CTI 妯″潡鍔ㄦ€佽皟鏁达級
spc_enabled = true    # 鏄惁鍚敤 SPC 淇
```

### 7.5 妫€鏌ラ」 Delta 鍊?

```ini
[check_deltas]
AS-001 = -8      # 鏀诲嚮闈㈡鏌ラ」
OT-001 = -10     # 鎿嶄綔鍙俊搴︽鏌ラ」
RS-001 = -10     # 闊ф€ф鏌ラ」
BC-005 = -10     # 涓氬姟杩炵画鎬ф鏌ラ」
AC-001 = -15     # 绛変繚鍥涚骇澧炲己妫€鏌ラ」
EF-001 = 0       # 杈圭紭鍥犲瓙妫€鏌ラ」
```

Delta 鍊间负璐熸暟琛ㄧず妫€鏌ユ湭閫氳繃鏃剁殑鎵ｅ垎锛屾鏁拌〃绀鸿ˉ鍋垮姞鍒嗐€傛瘡涓鏌ラ」 ID 閬靛惊 `XX-NNN` 缂栧彿浣撶郴锛?

- `AS`锛氭敾鍑婚潰锛圓ttack Surface锛?
- `OT`锛氭搷浣滃彲淇″害锛圤peration Trust锛?
- `RS`锛氶煣鎬э紙Resilience锛?
- `BC`锛氫笟鍔¤繛缁€э紙Business Continuity锛?
- `AC`锛氱瓑淇濆洓绾у寮猴紙Additional Control锛?
- `EF`锛氳竟缂樺洜瀛愶紙Edge Factor锛?
- `KS`锛氬唴鏍稿畨鍏ㄦ墿灞曪紙Kernel Security锛?

### 7.6 鎵╁睍閰嶇疆

```ini
[extensions]
kernel_security = on        # 鍚敤鍐呮牳瀹夊叏鎵╁睍鍩?

[extension_weights]
kernel_security = 10        # 鍐呮牳瀹夊叏鎵╁睍鏉冮噸
```

---

## 8. SPC 瀹夊叏鎬佸娍妯″潡

SPC 妯″潡閫氳繃 NVD/EPSS/CISA KEV/CNNVD/CNVD 绛夊閮ㄦ紡娲炴暟鎹簮涓庢湰鍦拌祫浜ф瘮瀵癸紝杈撳嚭涓綋鍖栦慨姝ｅ洜瀛?P_score锛?.60鈥?.00锛夈€?

> 鈿狅笍 **璇勪及鏂规硶澹版槑锛堝凡鐭ュ眬闄愭€э級**锛歋PC 鐨勯獙璇侀€昏緫鍩轰簬 CPE 瀛楃涓插尮閰嶁€斺€斿皢宸插畨瑁呰蒋浠跺寘鍚嶇О/鐗堟湰涓?CVE 鏁版嵁搴撲腑鐨勫彈褰卞搷浜у搧鐗堟湰杩涜浜ゅ弶姣斿銆傚畠**涓嶆墽琛?*婕忔礊鍒╃敤楠岃瘉銆佽繍琛屾椂鍙揪鎬у垎鏋愩€佷簩杩涘埗鍒嗘瀽銆佹垨鏇夸唬缂撹В鎺柦楠岃瘉銆傚尮閰嶇粨鏋滃彲鑳戒骇鐢熷亣闃虫€э紙宸查€氳繃 WAF/铏氭嫙琛ヤ竵缂撹В浣嗘湭鏇存柊鐗堟湰鍙风殑婕忔礊锛夊拰鍋囬槾鎬э紙鐗堟湰鍙峰尮閰嶄絾瀛樺湪瀹氬埗鍙樼锛夈€係PC 瀹氫綅涓?婕忔礊鎯呮姤鑱氬悎涓庣増鏈瘮瀵瑰紩鎿?锛岃€岄潪"婕忔礊鍒╃敤楠岃瘉鍣?锛岀洰鍓嶆殏鏃犺鍒掑紩鍏ユ繁搴﹂獙璇佽兘鍔涖€?

### 8.1 鍩烘湰閰嶇疆

```ini
[spc]
enabled = true              # 鏄惁鍚敤
min_pscore = 0.60           # P_score 涓嬮檺
cache_retention_days = 365  # CVE 缂撳瓨淇濈暀澶╂暟
fetch_interval_h = 1        # 鑷姩鍒锋柊闂撮殧锛堝皬鏃讹級
```

### 8.2 NVD 鏁版嵁婧?

```ini
[spc.nvd]
base_url = https://services.nvd.nist.gov/rest/json/cves/2.0
api_key =                   # 鐣欑┖鍒欎粠鐜鍙橀噺 NVD_API_KEY 璇诲彇
sync_interval_h = 6         # 鍚屾闂撮殧
use_last_mod = true         # 澧為噺鍚屾妯″紡
no_rejected = true          # 杩囨护宸叉嫆缁濈殑 CVE
```

**API Key 璇存槑**锛?

- 鏃?Key锛氳姹傞€熺巼闄愬埗 5 娆?30绉掞紝绯荤粺鑷姩閲囩敤 4 骞跺彂鍒嗙墖绛栫暐
- 鏈?Key锛氳姹傞€熺巼闄愬埗 50 娆?30绉掞紝绯荤粺鑷姩閲囩敤 2 骞跺彂鍒嗙墖绛栫暐
- 鑾峰彇鍦板潃锛歨ttps://nvd.nist.gov/developers/request-an-api-key

### 8.3 EPSS 鏁版嵁婧?

```ini
[spc.epss]
enabled = true
data_url = https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
sync_interval_h = 24
```

### 8.4 CISA KEV 鏁版嵁婧?

```ini
[spc.cisa_kev]
enabled = true
catalog_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
sync_interval_h = 24
```

### 8.5 CNNVD 鏁版嵁婧?

```ini
[spc.cnnvd]
enabled = false
base_url = https://www.cnnvd.org.cn/home/data
api_key =                   # 鐣欑┖鍒欎粠鐜鍙橀噺 CNNVD_API_KEY 璇诲彇
sync_interval_h = 24
```

### 8.6 CNVD 鏁版嵁婧?

```ini
[spc.cnvd]
enabled = false
base_url = https://www.cnvd.org.cn/shareData
sync_interval_h = 24
```

### 8.7 MISP 鏁版嵁婧?

```ini
[spc.misp]
base_url =                  # MISP 鏈嶅姟鍣ㄥ湴鍧€
api_key =                   # 鐣欑┖鍒欎粠鐜鍙橀噺 MISP_API_KEY 璇诲彇
verify_tls = true
sync_interval_h = 1
tlp_filter = white          # TLP 鏍囩杩囨护
```

### 8.8 OSCAL 瀵煎叆

```ini
[spc.oscal]
enabled = false
input_format = json         # json / yaml / xml
results_path = ./oscal_results/
plan_path = ./oscal_plan/
```

### 8.9 CPE 鍖归厤鏈哄埗

Agent 鑷姩灏嗗凡瀹夎杞欢鍖呰浆鎹负 CPE 2.3 鏍煎紡锛坄cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`锛夛紝SPC 妯″潡鎸変互涓嬩紭鍏堢骇鍖归厤锛?

1. **绮剧‘鐗堟湰鍖归厤**锛圡atchExactVersion锛夛細vendor銆乸roduct銆乿ersion 瀹屽叏涓€鑷?
2. **鐗堟湰鑼冨洿鍖归厤**锛圡atchVersionRange锛夛細vendor銆乸roduct 涓€鑷达紝version 鍦ㄥ彈褰卞搷鑼冨洿鍐?
3. **浜у搧鍖归厤**锛圡atchProduct锛夛細vendor銆乸roduct 涓€鑷达紝鏃犵増鏈俊鎭?
4. **鍘傚晢鍖归厤**锛圡atchVendor锛夛細浠?vendor 涓€鑷?
5. **鎻忚堪鍖归厤**锛圡atchDescription锛夛細鍖呭悕鍑虹幇鍦?CVE 鎻忚堪涓?

---

## 9. 绛変繚鏄犲皠涓庤瘎鍒嗛槇鍊?

### 9.1 妫€鏌ラ」瑕嗙洊

| 绛変繚绛夌骇 | 鑷姩鍖栨鏌ラ」鏁?|
|----------|----------------|
| 涓夌骇 | 53 椤?|
| 鍥涚骇 | 53 + 9 = 62 椤?|

### 9.2 鏍稿績鍩熸鏌ラ」鍒嗗竷

| 鏍稿績鍩?| 妫€鏌ラ」鍓嶇紑 | 鏁伴噺锛堜笁绾э級 |
|--------|------------|--------------|
| 鏀诲嚮闈㈢鐞?| AS-001 ~ AS-017 | 17 |
| 鎿嶄綔鍙俊搴?| OT-001 ~ OT-022 | 22 |
| 闊ф€?| RS-001 ~ RS-012 | 12 |
| 涓氬姟杩炵画鎬?| BC-005 ~ BC-007 | 3 |
| 绛変繚鍥涚骇澧炲己 | AC-001 ~ AC-008 | 8锛堜粎鍥涚骇锛?|
| 杈圭紭鍥犲瓙 | EF-001 ~ EF-002 | 2 |

### 9.3 璇勫垎闃堝€艰仈鍔?

淇敼 `[acceptability] threshold` 鍊煎嵆鍙垏鎹㈢瓑淇濈瓑绾у搴旂殑闃堝€硷細

```ini
# 绛変繚浜岀骇
threshold = 65.0

# 绛変繚涓夌骇锛堥粯璁わ級
threshold = 80.0

# 绛変繚鍥涚骇
threshold = 90.0
```

---

## 10. ATT&CK V19 濞佽儊鍒嗘瀽妯″潡

ASSCOR v0.2.1 闆嗘垚 MITRE ATT&CK V19 妗嗘灦锛屼綔涓?渭Kernel 鎻掍欢锛坄attck`锛屼紭鍏堢骇 21锛岀増鏈?1.0.0锛夎繍琛屻€傛ā鍧楁彁渚涗粠妫€娴嬨€佹儏鎶ャ€佷豢鐪熷埌璇勪及鐨勫畬鏁村▉鑳佸垎鏋愯兘鍔涢摼锛屽苟鍦ㄦ鍩虹涓婃墿灞?APT 鏀诲嚮鍒嗘瀽涓庢娴嬪寮哄瓙妯″潡銆?

### 10.1 鍥涘ぇ鏍稿績瀛愭ā鍧?

| 瀛愭ā鍧?| 鏍稿績鑳藉姏 |
|--------|----------|
| **妫€娴嬩笌鍒嗘瀽** | 妫€娴嬭鍒欏紩鎿庯紙娉ㄥ唽/璇勪及/鍒犻櫎锛夈€佸紓甯镐簨浠惰褰曚笌鏌ヨ銆佸憡璀﹀叧鑱斿垎鏋愩€佹娴嬫憳瑕佺粺璁?|
| **濞佽儊鎯呮姤** | IOC 绠＄悊锛堝鍒犳煡鎼?杩囨湡娓呯悊锛夈€佸▉鑳佽涓轰綋鐢诲儚銆乀TP 杩借釜銆佸憡璀︽儏鎶ュ瘜鍖?|
| **瀵规墜浠跨湡涓庣孩闃?* | 浠跨湡鍦烘櫙绠＄悊銆佷粠 APT 缁勭粐鑷姩鐢熸垚鍦烘櫙銆佸畨鍏ㄦā寮忎豢鐪熸墽琛屻€佷豢鐪熺粨鏋滆褰?|
| **璇勪及涓庡伐绋?* | 宸窛鍒嗘瀽锛堥槻寰¤鐩栫巼锛夈€佸畨鍏ㄦ帶鍒舵槧灏勩€佺紦瑙ｅ缓璁敓鎴愩€佹寔缁敼杩涜拷韪?|

### 10.2 APT 鏀诲嚮鍒嗘瀽涓庢娴嬪寮?

鍦ㄥ洓澶у瓙妯″潡鍩虹涓婏紝APT 澧炲己灞傛彁渚涢珮绾у▉鑳佸垎鏋愯兘鍔涳細

| 鍔熻兘 | 鎻忚堪 |
|------|------|
| **鏀诲嚮閾鹃噸鏋?* | 鍩轰簬鍛婅銆佸紓甯搞€両OC 澶氭簮璇佹嵁锛屾寜 ATT&CK 鎴樻湳椤哄簭鑷姩閲嶆瀯澶氶樁娈垫敾鍑婚摼 |
| **琛屼负妫€娴?* | 琛屼负鎸囨爣娉ㄥ唽涓庤瘎浼般€佷富鏈鸿涓哄熀绾跨鐞嗐€丆2 淇℃爣妫€娴嬶紙闂撮殧鎶栧姩鍒嗘瀽锛?|
| **APT 褰掑洜寮曟搸** | 澶氭簮璇佹嵁铻嶅悎锛圱TP 閲嶅彔 60% + IOC 鍖归厤 40%锛夛紝APT 缁勭粐鍖归厤缃俊搴﹁瘎鍒?|
| **濞佽儊鐙╃寧妗嗘灦** | 鐙╃寧鍋囪 CRUD銆佸熀浜庢敾鍑昏浆绉荤煩闃佃嚜鍔ㄧ敓鎴愬亣璁俱€佸亣璁炬墽琛屼笌纭 |

### 10.3 涓?SSAM 璇勪及浣撶郴鐨勫崗鍚?

ATT&CK 妯″潡涓?SSAM 璇勪及浣撶郴褰㈡垚鍙屽悜澧炲己闂幆锛?

- **闊ф€у煙澧炲己**锛欰PT 鏀诲嚮閾炬娴嬬粨鏋滈€氳繃浜嬩欢鎬荤嚎娉ㄥ叆绛栫暐绠＄悊鍣紝褰卞搷涓绘満瀹夊叏鐘舵€佸垽瀹?
- **SPC 鑱斿姩**锛欰PT 褰掑洜寮曟搸杈撳嚭鐨勫▉鑳佽涓轰綋淇℃伅鍙笌 SPC 婕忔礊鎯呮姤浜ゅ弶楠岃瘉锛屽姩鎬佽皟鏁?P_score
- **CTI 鍗忓悓**锛欳TI 妯″潡鐨勫▉鑳佺郴鏁?渭 涓?ATT&CK 濞佽儊鎯呮姤瀛愭ā鍧楀叡浜暟鎹簮
- **绛栫暐鑱斿姩**锛欰PT 妫€娴嬪憡璀﹁Е鍙戠瓥鐣ョ鐞嗗櫒鑷姩鍝嶅簲鍔ㄤ綔

### 10.4 ATT&CK 閰嶇疆

```ini
[attck]
enabled = true                  # 鏄惁鍚敤 ATT&CK 妯″潡
version = v19                   # ATT&CK 妗嗘灦鐗堟湰
auto_hunt = false               # 鏄惁鑷姩鐢熸垚鐙╃寧鍋囪
beacon_threshold = 0.7          # 淇℃爣妫€娴嬭瘎鍒嗛槇鍊?
attribution_threshold = 0.6     # APT 褰掑洜缃俊搴﹂槇鍊?
safe_emulation = true           # 浠跨湡鏄惁榛樿瀹夊叏妯″紡
```

### 10.5 CLI 鎿嶄綔

閫氳繃 Kernel 浜や簰寮?CLI 鍙搷浣?ATT&CK 妯″潡锛?

```
# 鏌ョ湅妫€娴嬫憳瑕?
ASSCOR> attck summary

# 娉ㄥ唽妫€娴嬭鍒?
ASSCOR> attck rule add --name "suspicious_powershell" --technique T1059 --severity high

# 鏌ョ湅 IOC 鍒楄〃
ASSCOR> attck ioc list --type ip

# 鎵ц宸窛鍒嗘瀽
ASSCOR> attck gap --host=web-server-01

# 閲嶆瀯鏀诲嚮閾?
ASSCOR> attck chain --host=web-server-01

# 鎵ц APT 褰掑洜
ASSCOR> attck attribute --chain=<chainID>

# 鐢熸垚鐙╃寧鍋囪
ASSCOR> attck hunt generate --host=web-server-01

# 鎵ц瀵规墜浠跨湡
ASSCOR> attck emulate --scenario=<scenarioID> --host=web-server-01 --safe
```

---

## 11. 鏃ュ織绠＄悊

### 11.1 鏃ュ織閰嶇疆

```bash
# JSON 鏍煎紡锛堥粯璁わ紝閫傚悎鏃ュ織閲囬泦绯荤粺锛?
-log-format json -log-level info -log-output /var/log/ASSCOR-kernel.log

# 鏂囨湰鏍煎紡锛堥€傚悎浜哄伐闃呰锛?
-log-format text -log-level debug -log-output stderr
```

### 11.2 鏃ュ織绾у埆

| 绾у埆 | 鐢ㄩ€?|
|------|------|
| `debug` | 璇︾粏璋冭瘯淇℃伅锛屽寘鍚姹?鍝嶅簲缁嗚妭 |
| `info` | 姝ｅ父杩愯淇℃伅锛堟帹鑽愮敓浜х幆澧冿級 |
| `warn` | 璀﹀憡淇℃伅锛屽閰嶇疆缂哄け銆侀檷绾ц繍琛?|
| `error` | 閿欒淇℃伅锛岄渶瑕佸叧娉ㄥ鐞?|

### 11.3 鏃ュ織缁勪欢鍓嶇紑

姣忔潯鏃ュ織鍖呭惈缁勪欢鍓嶇紑锛屼究浜庤繃婊わ細

```
{"time":"...","level":"info","component":"spc","msg":"CVE cache loaded","count":1234}
{"time":"...","level":"warn","component":"kernel","msg":"NVD API key not configured"}
```

甯歌缁勪欢鍓嶇紑锛歚kernel`銆乣spc`銆乣cti`銆乣assessor`銆乣policy`銆乣commander`銆乣heartbeat`銆乣cli`銆乣tls`

---

## 12. 瀹堟姢杩涚▼妯″紡

```bash
# 鍚姩瀹堟姢杩涚▼
./ASSCOR-kernel-v0.2.1-linux-amd64 --daemon --pid-file=/var/run/ASSCOR-kernel.pid

# 鍋滄瀹堟姢杩涚▼
kill $(cat /var/run/ASSCOR-kernel.pid)
```

瀹堟姢杩涚▼妯″紡涓嬶紝鏃ュ織鑷姩閲嶅畾鍚戝埌 `ASSCOR-kernel.log`銆?

---

## 13. 绂荤嚎璇勪及妯″紡

`ASSCOR` 鍛戒护鎻愪緵鍗曟満绂荤嚎璇勪及锛屾棤闇€閮ㄧ讲 Kernel 鍜?Agent锛屽嵆鏃惰緭鍑哄埌缁堢锛?

```bash
# 鏂囨湰鎶ュ憡锛堢洿鎺ユ墦鍗板埌缁堢锛?
./ASSCOR-v0.2.1-linux-amd64 --config=/etc/asscor/config.ini

# JSON 鎶ュ憡锛堝彲閲嶅畾鍚戝埌鏂囦欢锛?
./ASSCOR-v0.2.1-linux-amd64 --config=/etc/asscor/config.ini -json > report.json
```

| 鍙傛暟 | 榛樿鍊?| 璇存槑 |
|------|--------|------|
| `--config` | `config.ini` | 閰嶇疆鏂囦欢璺緞 |
| `--json` | `false` | 浠?JSON 鏍煎紡杈撳嚭 |

鍗曟満妯″紡鐨勫畬鏁磋兘鍔涳細

- **鏍稿績妫€鏌?*锛?6+ 椤规湰鍦板畨鍏ㄦ鏌ワ紙鍚?KS 鍐呮牳瀹夊叏鍩燂級
- **SPC 鎬佸娍璁＄畻**锛氬宸查厤缃暟鎹簮鍒欒嚜鍔ㄦ媺鍙?NVD/EPSS/KEV 骞惰绠?
- **ATT&CK 鍒嗘瀽**锛氳鐩栧害銆並ill Chain銆丄PT 褰掑洜銆侀闄╅娴?
- **澶栭儴閫傞厤鍣ㄥ娲?*锛歝onfig.ini `[adapters]` 涓惎鐢ㄧ殑宸ュ叿锛圱rivy/Lynis/Suricata/ClamAV/AIDE 绛夛級鑷姩鎵ц骞跺皢鍙戠幇澶栨淳鍒板搴旀鏌ラ」
- **SRD/Prism 涓夊眰鍒嗘瀽**锛欳ore锛堝姩鎬佽瘎鍒嗭級鈫?Semantic锛堟ā绯婄姸鎬侊級鈫?Inference锛堣秼鍔块娴嬶級

> **鎶ュ憡浣嶇疆璇存槑**锛氬崟鏈烘ā寮忕殑鎶ュ憡**浠呰緭鍑哄埌缁堢/stdout**锛屼笉鍐欏叆纾佺洏銆傝嫢闇€鎸佷箙鍖栧巻鍙叉姤鍛婏紝璇蜂娇鐢?Kernel + Agent 妯″紡锛堟姤鍛婅嚜鍔ㄥ啓鍏?`/var/lib/asscor/`锛岃 搂4.2锛夈€?

### 13.1 鎶ュ憡浣嶇疆瀵圭収

| 妯″紡 | 鎶ュ憡浣嶇疆 |
|------|----------|
| 鍗曟満 `ASSCOR` | 缁堢 stdout锛坄-json > file` 鍙繚瀛橈級 |
| Kernel 鏈嶅姟妯″紡 | `/var/lib/asscor/latest-assessment.json`锛堟渶鏂帮級<br>`/var/lib/asscor/assessments-<date>.jsonl`锛堝巻鍙诧級<br>WebUI `http://<host>:8087` |

---

## 14. 鐜鍙橀噺鍙傝€?

| 鐜鍙橀噺 | 鐢ㄩ€?| 浼樺厛绾?|
|----------|------|--------|
| `NVD_API_KEY` | NVD API 瀵嗛挜 | 楂樹簬 config.ini 涓殑 `api_key` |
| `MISP_API_KEY` | MISP API 瀵嗛挜 | 楂樹簬 config.ini 涓殑 `api_key` |
| `CNNVD_API_KEY` | CNNVD API 瀵嗛挜 | 楂樹簬 config.ini 涓殑 `api_key` |

> **瀹夊叏鎻愮ず**锛欰PI Key 搴旈€氳繃鐜鍙橀噺浼犻€掞紝绂佹纭紪鐮佸埌閰嶇疆鏂囦欢鎴栧懡浠よ鍙傛暟涓€?

---

## 15. 鏁呴殰鎺掓煡

### 15.1 Kernel 鍚姩澶辫触

| 鐥囩姸 | 鍙兘鍘熷洜 | 瑙ｅ喅鏂规 |
|------|----------|----------|
| `FATAL: kernel bootstrap failed` | 鎻掍欢鍒濆鍖栧け璐?| 妫€鏌ユ棩蹇楄緭鍑猴紝纭閰嶇疆鏂囦欢鏍煎紡姝ｇ‘ |
| `WARN: server start failed` | 绔彛琚崰鐢?| 鏇存崲 `-listen` 鍦板潃鎴栭噴鏀剧鍙?|
| 璇佷功閿欒 | 璇佷功鏂囦欢鎹熷潖鎴栦笉鍖归厤 | 浣跨敤 `-force-regen-certs` 閲嶆柊鐢熸垚 |

### 15.2 Agent 杩炴帴澶辫触

| 鐥囩姸 | 鍙兘鍘熷洜 | 瑙ｅ喅鏂规 |
|------|----------|----------|
| `connection refused` | Kernel 鏈惎鍔ㄦ垨鍦板潃閿欒 | 纭 Kernel 鍦板潃鍜岀鍙?|
| `certificate verify failed` | 璇佷功涓嶅尮閰?| 閲嶆柊鍒嗗彂璇佷功锛岀‘璁?`cert_dir` 璺緞 |
| `agent: fatal` | 閰嶇疆閿欒 | 浣跨敤 `-log-level debug` 鏌ョ湅璇︾粏閿欒 |

### 15.3 SPC 鏁版嵁鍚屾闂

| 鐥囩姸 | 鍙兘鍘熷洜 | 瑙ｅ喅鏂规 |
|------|----------|----------|
| `CVE cache is empty` | 棣栨鍚屾鏈畬鎴?| 绛夊緟鍚庡彴鍚屾瀹屾垚锛堢害 1鈥? 鍒嗛挓锛?|
| `NVD API rate limited` | 鏃?API Key 鎴栬姹傝繃棰?| 閰嶇疆 `NVD_API_KEY` 鐜鍙橀噺 |
| `SPC cannot calculate risk` | 缂撳瓨涓虹┖ | 妫€鏌ョ綉缁滆繛鎺ワ紝纭鏁版嵁婧愬彲璁块棶 |

### 15.4 璇勫垎寮傚父

| 鐥囩姸 | 鍙兘鍘熷洜 | 瑙ｅ喅鏂规 |
|------|----------|----------|
| 璇勫垎濮嬬粓涓?100 | 鎵€鏈夋鏌ラ」閫氳繃 | 姝ｅ父鐜拌薄锛岃〃绀虹郴缁熷畨鍏ㄧ姸鎬佽壇濂?|
| 璇勫垎寮傚父鍋忎綆 | 妫€鏌ラ」 Delta 鍊艰繃澶?| 妫€鏌?`[check_deltas]` 閰嶇疆鏄惁鍚堢悊 |
| P_score 涓?0.60 | 瀛樺湪楂樺嵄 CVE 鍖归厤 | 浣跨敤 `spc cve` 鍛戒护鏌ョ湅鍖归厤鐨?CVE 璇︽儏 |

---

## 16. CLI 鍛戒护鍙傝€?

### 16.1 CLI 姒傝堪

ASSCOR Kernel 鍐呯疆浜や簰寮?CLI 缁堢锛孠ernel 鍚姩鍚庤嚜鍔ㄨ繘鍏ャ€侰LI 鎻愪緵鍛戒护娉ㄥ唽銆佽嚜鍔ㄨˉ鍏ㄣ€佸巻鍙茶褰曞拰鎻掍欢鎵╁睍鑳藉姏銆?

**杩涘叆 CLI**锛欿ernel 鍚姩鍚庯紝鏃ュ織鑷姩閲嶅畾鍚戝埌 `ASSCOR-kernel.log`锛岀粓绔繘鍏ヤ氦浜掓ā寮忥細

```
ASSCOR 渭Kernel
  Framework: v0.2.1   SSAM: 2.0
  Listen:   :50051 (mTLS: true)
  CLI active: logs redirected to ASSCOR-kernel.log

ASSCOR>
```

**鍛戒护璇硶**锛歚command <subcommand|param> [options]`銆傞€夐」浣跨敤 `--name=value` 鎴?`--name value` 鏍煎紡锛屽竷灏旈€夐」浣跨敤 `--flag` 寮€鍚€傝緭鍏?`Ctrl+D` 鎴?`Ctrl+C` 閫€鍑恒€?

### 16.2 閫氱敤閫夐」

| 閫夐」 | 鐭€夐」 | 璇存槑 |
|------|--------|------|
| `--verbose` | `-v` | 鏄剧ず璇︾粏杈撳嚭 |
| `--json` | `-j` | 浠?JSON 鏍煎紡杈撳嚭 |
| `--quiet` | `-q` | 鎶戝埗闈炲繀瑕佽緭鍑?|
| `--help` | `-h` | 鏄剧ず鍛戒护甯姪 |

### 16.3 鏍稿績鍛戒护

**help** 鈥?鏄剧ず鍛戒护甯姪鎴栧垪鍑烘墍鏈夊彲鐢ㄥ懡浠わ細`help [command]`

**version** 鈥?鏄剧ず ASSCOR 妗嗘灦鐗堟湰鍜?SSAM 妯″瀷鐗堟湰锛歚version`

**status** 鈥?鏄剧ず褰撳墠 Kernel 鐘舵€侊紝鍖呮嫭鎻掍欢鐘舵€併€佽繍琛屾椂闂村拰璧勬簮浣跨敤锛歚status [--format=json]`

### 16.4 璇勪及鍛戒护

**assess** 鈥?瑙﹀彂瀵规寚瀹氫富鏈虹殑瀹夊叏鍙帴鍙楁€ц瘎浼般€?

```
鐢ㄦ硶锛歛ssess [host] [options]
鍙傛暟锛歨ost 鈥?鐩爣涓绘満 ID锛堥粯璁?local锛?
閫夐」锛?-format=json, --domain=attack_surface|business_continuity|operation_trust|resilience
```

### 16.5 SPC 鍛戒护

**spc** 鈥?鏌ヨ SPC 妯″潡鐨?CVE 缂撳瓨銆丳-score銆並EV 鏁伴噺鍜屼慨姝ｆ暟鎹€?

```
鐢ㄦ硶锛歴pc <summary|cve|kev|score|fetch> [options]
閫夐」锛?-limit=N锛堥粯璁?0锛? --cvss-min=N, --kev-only, --host=HOST
绀轰緥锛?
  ASSCOR> spc summary
  ASSCOR> spc cve --cvss-min=9.0 --kev-only
  ASSCOR> spc score --host=web-server-01
  ASSCOR> spc fetch
```

### 16.6 Agent 绠＄悊鍛戒护

**agent** 鈥?绠＄悊宸叉敞鍐岀殑 Agent銆?

```
鐢ㄦ硶锛歛gent <list|status|start|stop|restart|config|command> [options]
閫夐」锛?-host=HOST, --all, --filter=key=value, --limit=N锛堥粯璁?0锛? --watch
绀轰緥锛?
  ASSCOR> agent list --filter=active=true
  ASSCOR> agent status --host=web-server-01
  ASSCOR> agent stop --host=db-master-01
  ASSCOR> agent command --host=web-01 --action=scan
```

**log** 鈥?鏌ョ湅銆佽繃婊ゅ拰瀵煎嚭 Agent 杩愯鏃ュ織銆?

```
鐢ㄦ硶锛歭og <show|export> [options]
閫夐」锛?-host=HOST, --level=debug|info|warn|error, --limit=N锛堥粯璁?0锛? --format=json|csv, --output=PATH
```

### 16.7 ATT&CK 鍛戒护

**attck** 鈥?鎿嶄綔 ATT&CK V19 妯″潡锛屽寘鎷娴嬭鍒欑鐞嗐€両OC 绠＄悊銆佸樊璺濆垎鏋愩€佹敾鍑婚摼閲嶆瀯銆丄PT 褰掑洜鍜屽▉鑳佺嫨鐚庛€?

```
鐢ㄦ硶锛歛ttck <summary|rule|alert|anomaly|ioc|actor|gap|control|chain|attribute|hunt|emulate|improve> [options]
閫夐」锛?-host=HOST, --severity=critical|high|medium|low, --technique=T1234, --limit=N锛堥粯璁?0锛? --format=json
```

鏍稿績瀛愬懡浠ょず渚嬶細

```
ASSCOR> attck summary                                      # 妯″潡姒傝
ASSCOR> attck rule add --name "suspicious_powershell" --technique T1059 --severity high
ASSCOR> attck ioc add --type=ip --value=10.0.0.1 --confidence=0.8 --technique=T1071
ASSCOR> attck gap --host=web-server-01                     # 闃插尽宸窛鍒嗘瀽
ASSCOR> attck chain --host=web-server-01                   # 鏀诲嚮閾鹃噸鏋?
ASSCOR> attck attribute --chain=CHAIN-20260525-001         # APT 褰掑洜
ASSCOR> attck hunt generate --host=web-server-01           # 鐢熸垚鐙╃寧鍋囪
ASSCOR> attck emulate generate --actor=APT29               # 鐢熸垚瀵规墜浠跨湡
ASSCOR> attck improve create --name="Harden credential policy"  # 鎸佺画鏀硅繘杩借釜
```

### 16.8 鎻掍欢绠＄悊鍛戒护

**plugin** 鈥?鍒楀嚭銆佹煡鐪嬪拰绠＄悊 Kernel 鎻掍欢銆?

```
鐢ㄦ硶锛歱lugin <list|info|health> [name]
绀轰緥锛?
  ASSCOR> plugin list
  ASSCOR> plugin info spc
  ASSCOR> plugin health
```

### 16.9 澶栭儴婧愮鐞嗗懡浠?

**source** 鈥?閮ㄧ讲銆侀厤缃€佸惎鍋滃拰瀹¤澶栭儴闆嗘垚婧愩€?

```
鐢ㄦ硶锛歴ource <list|info|deploy|enable|disable|update|uninstall|run|config|audit> [name] [options]
閫夐」锛?-category=scanner|management, --version=VERSION, --force, --limit=N锛堥粯璁?0锛?
```

### 16.10 绯荤粺鍛戒护

**config** 鈥?鏌ョ湅褰撳墠 Kernel 閰嶇疆锛歚config [key] [--format=json]`

**health** 鈥?瀵规墍鏈?Kernel 鎻掍欢鎵ц鍋ュ悍妫€鏌ワ細`health [--json]`

### 16.11 璋冭瘯鍛戒护

**history** 鈥?鏌ョ湅鍛戒护鎵ц鍘嗗彶璁板綍锛歚history [count] [--failed] [--clear]`

### 16.12 浜や簰寮忕粓绔姛鑳?

- **鑷姩琛ュ叏**锛氳緭鍏ュ懡浠ゅ悗鎸?`Tab` 閿Е鍙戯紙鍛戒护鍚嶃€佸瓙鍛戒护銆侀€夐」鍧囧彲琛ュ叏锛?
- **鍛戒护鍘嗗彶**锛氫娇鐢?`鈫慲/`鈫揱 绠ご閿祻瑙堝巻鍙插懡浠?
- **鑴氭湰闆嗘垚**锛氭墍鏈夊懡浠ゆ敮鎸?`--json` 閫夐」杈撳嚭缁撴瀯鍖?JSON锛歚echo "spc summary --json" | asscor-cli`
- **閫€鍑虹爜**锛?=鎴愬姛锛?=鎵ц閿欒锛?=鐢ㄦ硶閿欒锛?30=鐢ㄦ埛鍙栨秷

### 16.13 鎻掍欢娉ㄥ唽鑷畾涔夊懡浠?

```go
cliPlugin, ok := k.Container().Resolve((*cli.CLIInterface)(nil))
if ok {
    cliMod := cliPlugin.(cli.CLIInterface)
    cliMod.RegisterCommand(cli.NewBaseCommand(
        cli.CommandInfo{
            Name: "mycmd", Short: "My custom command",
            Usage: "mycmd [args]", Category: cli.CategoryPlugin,
        },
        func(ctx *cli.CommandContext) *cli.CommandResult {
            return &cli.CommandResult{ExitCode: cli.ExitOK, Output: "Custom command executed\n"}
        },
    ))
}

---

## 15. 鑷畾涔夋墿灞曪紙鏃犻渶缂栧啓 Go 浠ｇ爜锛?

ASSCOR 鏀寔涓夌被鏃犻渶缂栧啓 Go 浠ｇ爜鐨勬墿灞曟柟寮忥紝浠庨浂闂ㄦ鍒颁笓涓氬紑鍙戦€愮骇閫掕繘銆?

### 15.1 閰嶇疆鏂囦欢瀹氫箟妫€鏌ラ」 (`[user_check]`)

鍦?`config.ini` 涓洿鎺ユ坊鍔犲畨鍏ㄦ鏌ワ紝鏃犻渶浠讳綍缂栫▼锛?

```ini
# 鍛戒护妫€鏌ワ細鎵ц shell 鍛戒护锛宔xit 0 鎴栬緭鍑哄尮閰嶅瓧绗︿覆 = 閫氳繃
[user_check.nginx]
id = CU-001
domain = attack_surface
name = Nginx service status
description = Check if nginx is running
command = systemctl is-active nginx
delta = -8
output_match = active

# 鏂囦欢鍐呭妫€鏌ワ細妫€鏌ユ枃浠舵槸鍚﹀瓨鍦ㄣ€佸唴瀹规槸鍚﹀尮閰嶆鍒?
[user_check.auditd]
id = CU-002
domain = operation_trust
name = Auditd rules
description = Verify auditd has shadow watch rules
file_path = /etc/audit/audit.rules
file_regex = -w /etc/shadow -p wa
delta = -10
```

鏀寔鐨勫瓧娈碉細

| 瀛楁 | 蹇呴』 | 璇存槑 |
|------|------|------|
| `id` | 鉁?| 鍞竴妫€鏌?ID锛屽 `CU-001` |
| `domain` | 鉁?| 褰掑睘鍩燂紙attack_surface / business_continuity / operation_trust / resilience / kernel_security锛?|
| `name` | 鉁?| 妫€鏌ュ悕绉?|
| `command` | * | shell 鍛戒护锛坋xit 0 = 閫氳繃锛?|
| `output_match` | 鍚?| 杈撳嚭涓嚭鐜版瀛楃涓?= 閫氳繃 |
| `file_path` | * | 瑕佹鏌ョ殑鏂囦欢璺緞 |
| `file_regex` | 鍚?| 鏂囦欢鍐呭鍖归厤姝ゆ鍒?= 閫氳繃 |
| `delta` | 鍚?| 澶辫触鎵ｅ垎锛堥粯璁?-10锛?|

> *: `command` 鍜?`file_path` 鑷冲皯鎻愪緵涓€涓€備慨鏀瑰悗鎵ц `systemctl reload asscor-kernel` 鍗冲彲鐢熸晥銆?

### 15.2 澶栭儴鑴氭湰閫傞厤鍣?(`[adapter_script]`)

杩愯浠讳綍璇█缂栧啓鐨勮剼鏈紙Bash/Python/浠讳綍锛夛紝鍏?JSON stdout 鑷姩鎴愪负閫傞厤鍣ㄥ彂鐜帮細

```ini
[adapter_script.my-monitor]
path = /opt/asscor/scripts/my-monitor.sh
```

鑴氭湰 stdout 鏍煎紡锛圝SON 鏁扮粍锛夛細

```json
[
  {
    "id": "MON-001",
    "title": "Disk usage warning",
    "severity": "high",
    "detail": "/dev/sda1 is 95% full",
    "domain": "business_continuity",
    "finding_type": "alert"
  }
]
```

**瀹夊叏闄愬埗**:
- 鑴氭湰璺緞蹇呴』鍦?`/opt/asscor/scripts/` `/etc/asscor/scripts/` `/var/lib/asscor/scripts/`
- 鑴氭湰蹇呴』 root:root 涓旈潪 world-writable
- 鎷掔粷绗﹀彿閾炬帴
- 30 绉掓墽琛岃秴鏃?
- 1MB 杈撳嚭涓婇檺

### 15.3 Plugin SDK锛堢嫭绔?Go 妯″潡锛屼笓涓氬紑鍙戯級

`pluginsdk/` 鎻愪緵鐙珛 Go 妯″潡妯℃澘锛屾彃浠堕€氳繃 JSON-RPC (stdin/stdout) 涓庡唴鏍搁€氫俊锛?*闆?ASSCOR 婧愮爜渚濊禆**锛?

```
pluginsdk/
鈹溾攢鈹€ go.mod           # 鐙珛妯″潡瀹氫箟
鈹溾攢鈹€ sdk.go           # Plugin 鎺ュ彛 + JSON-RPC 寰幆
鈹溾攢鈹€ cmd/myplugin/    # 瀹屾暣绀轰緥鎻掍欢
鈹?  鈹溾攢鈹€ main.go
鈹?  鈹斺攢鈹€ extension.json
鈹斺攢鈹€ README.md
```

寮€鍙戞祦绋嬶細澶嶅埗妯℃澘 鈫?瀹炵幇 `HandleRequest()` 鈫?`go build` 鈫?`asscor> source deploy`銆?

---

## 16. 绠楁硶闃叉姢閰嶇疆 (`[integrity]`)

鎺у埗 ASSCOR 瀵?SSAM/Prism 鏍稿績绠楁硶鐨勫畬鏁存€т繚鎶わ細

```ini
[integrity]
sign_assessment = true    # 璇勪及鎶ュ憡 HMAC-SHA256 绛惧悕锛堥槻浼€犳姤鍛婏級
verify_algo = true        # 鍚姩鏃舵牎楠?SSAM/Prism 甯搁噺瀹屾暣鎬?
anti_debug = false        # Linux 鍙嶈皟璇曟娴嬶紙闇€鏄惧紡寮€鍚級
```

| 妯″紡 | 鍦烘櫙 |
|------|------|
| `sign=false, verify=false` | 鍗曚簩杩涘埗杞婚噺閮ㄧ讲 |
| `sign=true, verify=true` | 闃叉姢璇勪及鎶ュ憡浼€?+ 绠楁硶鏍￠獙锛堟帹鑽愶級 |
| `anti_debug=true` | 鏁忔劅鐜闄勫姞鍙嶈皟璇?|

---

## 鐗堟湰鍘嗗彶

| 鐗堟湰 | 鏃ユ湡 | 涓昏鍙樻洿 |
|------|------|----------|
| v0.2.1 | 2026-07-07 | 鍗曚簩杩涘埗瀹夎(--install/--uninstall/--upgrade/--version)锛汧HS甯冨眬(/etc/asscor,/var/lib/asscor,/var/log/asscor)锛泂ystemctl绠℃帶+SIGHUP鐑噸杞斤紱杩滅▼CLI(Unix socket, asscor-cli)锛汸ATH绗﹀彿閾炬帴(/usr/bin/asscor)锛涘崟鏈烘ā寮忔敮鎸侀€傞厤鍣ㄥ娲?SRD涓夊眰鍒嗘瀽锛汼SAM V2鍔犳潈骞冲潎璇勫垎锛沺ersistence璺緞淇锛沘gent蹇冭烦棰戠巼浼樺寲锛沜onfig瀹氫箟妫€鏌ラ」([user_check])锛涘閮ㄨ剼鏈€傞厤鍣?[adapter_script])锛汸lugin SDK(pluginsdk/)锛涚畻娉曢槻鎶ら厤缃?[integrity])锛汣LI diag/policy杩愮淮鍛戒护 |
| v0.2.1 | 2026-06-28 | CLI spc瀛愬懡浠?score/kev/fetch)瀹炵幇锛沰ernel鎺у埗鍙拌瘎浼版姤鍛?config.ini console_report)锛沘gent鏃ュ織鏍煎紡鍙厤缃?agent.ini log_format)锛泂ource deploy鍛戒护锛汚TT&CK鐗堟湰/浼樺厛绾т慨姝ｏ紱config鐑噸杞介粯璁ゅ紑鍚紱绠＄悊閫傞厤鍣≒arse鍗囩骇锛涚郴缁焏 service + Dockerfile |
| v0.1.4-mvp | 2026-06-09 | SSAM V2.0涓夊眰璇箟妯″瀷锛汚TT&CK V19妯″潡锛汼PC澶氭暟鎹簮(CNNVD/CNVD/MISP)锛涙墿灞曠鐞嗗櫒锛汸rism SRD寮曟搸 |
| v0.1.3-mvp | 2026-05-25 | gRPC/JSONRPC鍙屽崗璁爤锛涙潈閲嶇儹鍔犺浇锛汼PC纾佺洏鎸佷箙鍖栵紱閫傞厤鍣ㄩ泦鎴愭ā鍧?|
| v0.1.2 | 2026-05-22 | HMAC绛惧悕淇锛涘叧閿秷鎭疨ublishSync锛涚瓥鐣ョ鐞嗗櫒浜掓枼switch锛汣TI涓ラ噸绾у埆鍔犳潈 |
| v0.1.1 | 2026-05-16 | Agent蹇冭烦鏈哄埗锛涚紪璇戜骇鐗╃粺涓€build/鐩綍 |
| v0.1.0 | 2026-05-13 | 鍒濆鍙戝竷 |
```
