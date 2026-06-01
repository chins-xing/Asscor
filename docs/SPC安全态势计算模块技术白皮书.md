# ASSCOR 安全态势计算模块（SPC）技术白皮书

> **版本：** v2.0 | **适用：** ASSCOR v0.2.0 / SSAM 2.0 | **日期：** 2026-05-28

## 1. 概述

安全态势计算模块（Security Posture Calculator，SPC）是 SSAM 2.0 的核心创新之一。它解决了一个关键问题：**全局漏洞情报如何转化为单台主机的个体化风险修正？**

传统安全评估使用统一的漏洞评分（如 CVSS），但同一 CVE 对不同主机的实际威胁差异巨大——一个运行 OpenSSL 3.0 的公网服务器与一个不运行 OpenSSL 的内网数据库，面对 CVE-2024-1234 时的风险完全不同。SPC 通过将全球漏洞情报与本地资产清单交叉比对，为每台受管主机生成独立的态势修正因子 $P_{score}$（0.60–1.00），作为乘数进入 SSAM 最终公式。

### 1.1 设计目标

| 目标 | 说明 |
|------|------|
| 个体化 | 每台主机的 $P_{score}$ 基于其实际安装的软件包计算，而非全局统一值 |
| 实时性 | CVE 缓存持续同步 NVD/EPSS/CISA KEV，评估结果随威胁环境变化 |
| 可解释 | 每个 $P_{score}$ 值都可追溯到具体的 CVE、匹配方式、影响因子 |
| 防触底 | $P_{score}$ 下限 0.60，防止 SPC 单方面"杀死"主机评分 |
| 高性能 | 预计算包名集合与 CPE 索引，O(n) 匹配复杂度，671 包 × 955 CVE < 100ms |

### 1.2 在 SSAM 公式中的位置

$$
SSAM_{final} = \left( \frac{\sum_{i=1}^{4} (S_i \times (W_i + P_{weight}(i)))}{100} \right) \times \prod_{j=1}^{m} M_j \times \mu \times P_{score}
$$

$P_{score}$ 作为最终乘数，直接影响安全可接受性判定。例如 $P_{score}=0.89$ 意味着即使核心域得分达到阈值，最终分数也会被下调 11%。

## 2. 评估方法声明（已知局限性）

> ⚠️ **重要声明**：SPC 模块的验证逻辑基于 **CPE（Common Platform Enumeration）字符串匹配**——即将已安装软件包的名称/版本与 CVE 数据库中记录的受影响产品版本进行交叉比对。它**不执行**以下任何深度验证：
>
> - **不尝试实际利用漏洞**：不进行任何形式的漏洞利用验证（无 PoC 执行、无 exploit 测试）
> - **不进行运行时可达性分析**：不检查漏洞触发路径是否在目标部署环境中实际存在
> - **不执行二进制分析或模糊测试**：不进行代码级漏洞确认
> - **不验证替代缓解措施**：不检查补丁是否已通过 WAF 规则、虚拟补丁、配置缓解等替代控制措施实际生效
> - **不进行攻击面可达性分析**：不评估漏洞是否可被网络路径可达（即不检查受影响服务是否实际对外暴露且可被攻击者访问）
>
> 因此，SPC 的匹配结果可能产生两类误差：
> - **假阳性**：已通过其他方式缓解（如 WAF 拦截、配置禁用、非默认编译选项）但未更新版本号的漏洞被标记为受影响
> - **假阴性**：版本号匹配但实际存在定制变种或上游 backport 引入的漏洞未被检测（如发行版独立维护的补丁分支）
>
> **设计定位**：SPC 定位为"漏洞情报聚合与版本比对引擎"，而非"漏洞利用验证器"。其设计目标是提供快速、低成本的漏洞态势感知，辅助安全团队优先排查而非替代深度渗透测试。我们明确承认这一局限性，目前暂无计划引入漏洞利用验证或运行时可达性分析能力。

## 3. 数据源体系

SPC 采用三级数据源架构，从全球到本地逐层聚焦：

### 2.1 一级数据源：全球漏洞库

| 数据源 | 用途 | 同步策略 |
|--------|------|----------|
| **NVD** (National Vulnerability Database) | CVE 元数据、CVSS 评分、CPE 配置、引用链接 | API 2.0，120 天窗口分片请求，并发分片（无 Key: 4×30d，有 Key: 2×60d），指数退避重试 |
| **CNNVD** (中国国家信息安全漏洞库) | 中文 CVE 补充、国产软件漏洞 | REST API，中文严重等级映射（严重/高危/中危/低危） |
| **CNVD** (国家信息安全漏洞共享平台) | 中国特色漏洞通告 | REST API，中文严重等级映射 |

### 2.2 二级数据源：利用情报

| 数据源 | 用途 | 同步策略 |
|--------|------|----------|
| **EPSS** (Exploit Prediction Scoring System) | 漏洞利用概率预测（0–1.0） | 全量 CSV/GZIP 下载，约 30 万条记录 |
| **CISA KEV** (Known Exploited Vulnerabilities Catalog) | 已知在野利用的漏洞目录 | JSON 拉取，标记 `InKEV=true` |

### 2.3 三级数据源：本地资产

| 数据 | 采集方式 | 用途 |
|------|----------|------|
| **软件包列表** | Agent 通过 `rpm -qa` / `dpkg-query -W` 采集 | CVE→资产匹配 |
| **安装的 CPE** | 从软件包元数据自动生成（已实现） | 精确版本匹配 |
| **服务与端口** | Agent 检查项采集 | 暴露面判定 |
| **安全控制措施** | Agent 检查项结果 | 控制级别判定 |

## 3. 核心算法

### 3.1 匹配流程

SPC 的核心是将 CVE 的受影响产品列表（AffectedCPEs）与主机安装的软件包进行交叉匹配。匹配流程如下：

```
Agent 上报 packages[] ──▶ extractPkgNames() ──▶ pkgNameSet (map)
                                                       │
NVD/EPSS/KEV ──▶ cveCache[] ──▶ cpeIndex[]  ──────────┤
                                                       ▼
                                              逐 CVE 匹配
                                                   │
                              ┌────────────────────┼────────────────────┐
                              │                    │                    │
                        CPE Product 匹配     CPE Vendor 匹配     Description 子串匹配
                        (O(1) map 查找)      (O(1) map 查找)     (O(n) fallback)
                              │                    │                    │
                              └────────────────────┼────────────────────┘
                                                   ▼
                                            匹配成功 → 计算 Penalty
                                            匹配失败 → 跳过此 CVE
```

### 3.2 包名提取（extractPkgNames）

Agent 上报的包名格式为 `name-version-release.arch`（如 `openssl-libs-1.1.1k-12.el8.x86_64`）。`extractPkgNames` 函数执行以下处理：

1. **提取核心包名**：移除版本、发行号、架构后缀
2. **移除常见后缀**：`-libs`、`-devel`、`-utils`、`-debuginfo`、`-doc` 等，提取核心产品名（如 `openssl-libs` → `openssl`）
3. **保留原始包名**：同时保留原始包名和核心包名，增加匹配覆盖面

### 3.3 CPE 匹配策略

CPE（Common Platform Enumeration）格式为 `cpe:2.3:part:vendor:product:version:...`。SPC 采用多级匹配策略：

| 优先级 | 匹配方式 | MatchType | Factor | 说明 |
|--------|----------|-----------|--------|------|
| 1 | CPE 精确版本匹配 | `MatchExactVersion` | 1.0 | InstalledCPE 与 AffectedCPE 版本完全一致 |
| 2 | CPE 版本范围匹配 | `MatchVersionRange` | 0.7 | InstalledCPE 版本在 AffectedCPE 的 versionStart/versionEnd 范围内 |
| 3 | CPE Product 匹配 | `MatchCPEProduct` | 0.3 | `pkgNameSet[cpe.product]` 命中 |
| 4 | CPE Vendor 匹配 | `MatchCPEVendor` | 0.3 | `pkgNameSet[cpe.vendor]` 命中（vendor ≥ 2 字符） |
| 5 | Description 子串匹配 | `MatchCPEProduct` | 0.3 | 包名出现在 CVE 描述中 |
| 6 | CPE 子串匹配 | `MatchCPEProduct` | 0.3 | 包名是 CPE 字符串的子串 |

> **v1.3 更新：** 精确版本匹配（Factor=1.0）和版本范围匹配（Factor=0.7）已启用。Agent 端通过包名-版本解析和 vendor-product 映射表自动生成 InstalledCPEs（CPE 2.3 格式字符串），Kernel 端在匹配时优先使用精确版本匹配。

### 3.4 暴露面判定（ExposureLevel）

根据主机的网络位置判定 CVE 的暴露程度：

| ExposureLevel | Factor | 判定条件 |
|---------------|--------|----------|
| `ExposurePublic` | 1.0 | 主机有公网 IP 或对外暴露端口 |
| `ExposureDMZ` | 0.7 | 主机位于 DMZ 区域 |
| `ExposureInternal` | 0.4 | 主机仅内网可达（默认） |
| `ExposureLocalhost` | 0.1 | 主机仅本地访问 |

### 3.5 安全控制级别（ControlLevel）

根据主机已部署的安全控制措施判定缓解程度：

| ControlLevel | Factor | 判定条件 |
|--------------|--------|----------|
| `ControlNone` | 1.0 | 无任何安全控制措施 |
| `ControlPartial` | 0.5 | 部分控制措施（如仅有 IDS） |
| `ControlEffective` | 0.2 | 完整控制措施（IDS + EDR + SIEM + 自动封禁） |

## 4. Penalty 计算公式

每个匹配的 CVE 产生一个 Penalty 值，所有 Penalty 通过平方和开方聚合为总惩罚值。

### 4.1 单个 CVE 的 Penalty

$$
Penalty_i = Impact_i \times LocalFactor_i \times TimeWindow_i
$$

#### 4.1.1 Impact（影响因子）

$$
Impact = 0.20 \times f_{cvss} + 0.50 \times f_{epss} + 0.30 \times f_{kev}
$$

| 因子 | 计算方式 | 说明 |
|------|----------|------|
| $f_{cvss}$ | $\min(1.0, CVSS/10)$ | CVSS 评分归一化 |
| $f_{epss}$ | $\min(1.0, -\ln(1-EPSS)/5)$ | EPSS 对数缩放，突出高概率漏洞 |
| $f_{kev}$ | 1.0（在 KEV 中）/ 0.3（仅有 PoC）/ 0.0 | 在野利用权重最高 |

**EPSS 对数缩放的意义：** EPSS 线性值 0.01 和 0.50 的实际威胁差异远超 50 倍。对数缩放 `-ln(1-EPSS)/5` 使 EPSS=0.01 → 0.002，EPSS=0.50 → 0.139，EPSS=0.97 → 0.710，更准确反映利用概率的影响。

**附加乘数：**
- ATT&CK 技术关联：$Impact \times (1 + 0.1 \times n_{techniques})$
- APT 组织关联：$Impact \times (1 + 0.2 \times n_{apt\_groups})$

#### 4.1.2 LocalFactor（本地化因子）

$$
LocalFactor = MatchType.Factor \times ExposureLevel.Factor \times ControlLevel.Factor
$$

示例：一个 CPE Product 匹配的 CVE，在公网暴露且无安全控制的主机上：
$$
LocalFactor = 0.3 \times 1.0 \times 1.0 = 0.3
$$

同一 CVE 在内网主机上且有完整安全控制：
$$
LocalFactor = 0.3 \times 0.4 \times 0.2 = 0.024
$$

后者的影响仅为前者的 8%，体现了个体化评估的价值。

#### 4.1.3 TimeWindow（时间衰减因子）

$$
TimeWindow = \max(0.3, 1.0 - days/90)
$$

- 发布 0 天：TimeWindow = 1.0
- 发布 30 天：TimeWindow = 0.67
- 发布 63 天：TimeWindow = 0.30（下限）
- 发布 90+ 天：TimeWindow = 0.30

时间衰减反映新漏洞的紧迫性，但不会完全忽略旧漏洞（下限 0.3）。

### 4.2 总惩罚值与 P_score

$$
TotalPenalty = \sqrt{\sum_{i=1}^{n} Penalty_i^2}
$$

$$
P_{score} = \max(0.60, 1.00 - TotalPenalty)
$$

**平方和开方的意义：** 防止大量低危 CVE 过早触底。线性求和时，10 个 Penalty=0.04 的 CVE 总惩罚为 0.40（$P_{score}=0.60$），而平方和开方仅为 0.126（$P_{score}=0.874$），更合理地反映"多个低危不等于一个高危"。

### 4.3 动作分类

$P_{score}$ 自动映射为建议动作：

| $P_{score}$ 范围 | 动作 | 说明 |
|------------------|------|------|
| ≥ 0.95 | `none` | 无需额外行动 |
| 0.85 – 0.95 | `notify_admin` | 通知管理员关注 |
| 0.75 – 0.85 | `patch_recommended` | 建议修补 |
| 0.65 – 0.75 | `priority_fix` | 优先修复 |
| < 0.65 | `isolate_host` | 建议隔离主机 |

## 5. 数据同步机制

### 5.1 NVD API 2.0 合规性

SPC 严格遵循 NVD API 2.0 规范：

| 规范要求 | 实现方式 |
|----------|----------|
| 日期参数必须配对 | `pubStartDate` + `pubEndDate` 或 `lastModStartDate` + `lastModEndDate` |
| 日期范围 ≤ 120 天 | 120 天窗口分片请求，自动分页 |
| 无 API Key 速率限制 | 5 次/30 秒，并发分片 4×30 天窗口，每次请求后等待 6.5 秒 |
| 有 API Key 速率限制 | 50 次/30 秒，并发分片 2×60 天窗口，每次请求后等待 0.6 秒 |
| 分页每页 ≤ 2000 条 | 使用 `startIndex` 参数分页 |
| 429 响应指数退避 | 退避间隔 = `min(60s, (1 << retryCount) * time.Second)`，最大重试 5 次 |
| 请求超时控制 | 45 秒 context 超时 |
| 并发窗口控制 | WorkerPool 信号量限制最大并发度 |

### 5.2 同步策略

| 场景 | 策略 | 时间范围 |
|------|------|----------|
| 首次同步（`lastUpdate` 为零） | 拉取最近 120 天的 CVE | `pubStartDate=now-120d` |
| 增量同步 | 拉取上次同步后的变更 | `lastModStartDate=lastUpdate` |
| API 失败 | Fallback 到 Sample CVE（10 条） | — |

### 5.3 Sample CVE 数据

当 NVD API 不可用或返回空结果时，SPC 使用内置的 10 条 Sample CVE 作为 fallback，覆盖常见高风险软件：

| CVE ID | CVSS | 产品 | 特征 |
|--------|------|------|------|
| CVE-2024-3094 | 10.0 | xz | XZ Utils 后门，KEV+PoC |
| CVE-2024-6387 | 8.1 | openssh | regreSSHion，KEV+PoC |
| CVE-2024-1234 | 9.8 | openssl | TLS 握手 RCE，KEV+PoC |
| CVE-2024-2961 | 8.8 | glibc | iconv 缓冲区溢出，PoC |
| CVE-2024-1086 | 7.8 | linux_kernel | netfilter UAF，KEV+PoC |
| CVE-2023-4911 | 7.8 | glibc | Looney Tunables，KEV+PoC |
| CVE-2023-44487 | 7.5 | nginx, apache | HTTP/2 Rapid Reset，KEV+PoC |
| CVE-2024-5678 | 7.5 | nginx | HTTP/3 DoS |
| CVE-2024-21626 | 8.6 | runc | 容器逃逸，PoC |
| CVE-2024-9012 | 5.3 | php | 信息泄露 |

> **警告：** Sample CVE 仅用于演示和测试，不适用于生产环境。请配置 NVD API Key 以获取实时漏洞数据。

## 6. 缓存与持久化

### 6.1 内存缓存

- CVE 缓存使用 `[]SPCCVEScore` 切片 + `map[string]int` 索引
- 资产缓存使用 `map[string]LocalAsset`
- KEV 目录使用 `map[string]bool`
- 所有缓存由 `sync.RWMutex` 保护，支持并发读写

### 6.2 磁盘持久化

| 操作 | 文件 | 说明 |
|------|------|------|
| 启动加载 | `data/spc-cve-cache.json` | 从磁盘恢复 CVE 缓存 |
| 退出保存 | `data/spc-cve-cache.json` | 将内存缓存写入磁盘 |
| 缓存容量 | 默认 100,000 条 | 超出后停止添加新 CVE |

### 6.3 缓存 TTL

CVE 缓存无固定 TTL，通过增量同步（`lastModStartDate`）持续更新。资产缓存由 Agent 心跳实时更新。

## 7. CVE 报告输出

### 7.1 Agent 端显示

SPC 在 Agent 评估报告中输出匹配的 CVE 详情，按 CVSS 降序排列：

```
---------------------------------------------------------------
[ SPC: Matched CVEs (5) ]
---------------------------------------------------------------
  CVE-2024-3094  CVSS:10.0  EPSS:0.97  Penalty:0.0843  [KEV] [PoC]  (xz)
  CVE-2024-6387  CVSS:8.1   EPSS:0.56  Penalty:0.0512  [KEV] [PoC]  (openssh)
  CVE-2024-2961  CVSS:8.8   EPSS:0.38  Penalty:0.0387  (glibc)
  CVE-2024-1086  CVSS:7.8   EPSS:0.61  Penalty:0.0421  [KEV] [PoC]  (linux_kernel)
  CVE-2023-4911  CVSS:7.8   EPSS:0.45  Penalty:0.0356  [KEV] [PoC]  (glibc)
---------------------------------------------------------------
```

标签含义：
- **[KEV]** — 在 CISA 已知被利用漏洞目录中
- **[PoC]** — 有公开概念验证代码
- **(product)** — 受影响的产品名

### 7.2 API 数据结构

CVE 信息通过 `HeartbeatResponse.AssessmentResult.SpcCVEs` 返回：

```go
type SPCCVEInfo struct {
    CVEID   string  `json:"cve_id"`      // CVE 编号
    CVSS    float64 `json:"cvss"`         // CVSS 评分 (0-10)
    EPSS    float64 `json:"epss"`         // EPSS 利用概率 (0-1)
    InKEV   bool    `json:"in_kev"`       // 是否在 CISA KEV 中
    HasPoC  bool    `json:"has_poc"`      // 是否有公开 PoC
    Penalty float64 `json:"penalty"`      // 对 P_score 的影响值
    Product string  `json:"product,omitempty"` // 受影响产品
}
```

### 7.3 Penalty Breakdown

每个 CVE 的完整惩罚分解通过 `SPCCorrection.PenaltyBreakdown` 提供：

```go
type CVEPenalty struct {
    CVEID        string  `json:"cve_id"`
    CVSS         float64 `json:"cvss"`
    EPSS         float64 `json:"epss"`
    InKEV        bool    `json:"in_kev"`
    HasPoC       bool    `json:"has_poc"`
    Impact       float64 `json:"impact"`       // 综合影响因子
    CVSSFactor   float64 `json:"cvss_factor"`  // CVSS 归一化值
    EPSSFactor   float64 `json:"epss_factor"`  // EPSS 对数缩放值
    KEVFactor    float64 `json:"kev_factor"`   // KEV/PoC 因子
    LocalFactor  float64 `json:"local_factor"` // 本地化因子
    TimeFactor   float64 `json:"time_factor"`  // 时间衰减因子
    Penalty      float64 `json:"penalty"`      // 最终惩罚值
    Products     string  `json:"products"`     // 受影响产品列表
}
```

## 8. 配置参数

### 8.1 config.ini 中的 SPC 相关配置

```ini
[spc]
enabled = true
nvd_api_key =                    ; NVD API Key（可选，无 Key 时速率限制 5次/30s）
nvd_base_url = https://services.nvd.nist.gov/rest/json/cves/2.0
epss_enabled = true
epss_url = https://epss.cyentia.com/epss_scores-current.csv.gz
kev_enabled = true
kev_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
min_p_score = 0.60               ; P_score 下限
max_cache_size = 100000          ; CVE 缓存最大条目数
sync_interval = 3600000000000    ; 同步间隔（纳秒，默认 1 小时）
```

### 8.2 Agent 端包采集配置

Agent 通过以下命令采集软件包列表：

| 包管理器 | 命令 | 适用系统 |
|----------|------|----------|
| RPM | `/usr/bin/rpm -qa --qf '%{NAME}\n'` | RHEL/CentOS/Alibaba Cloud Linux |
| DPKG | `dpkg-query -W -f '${Package}\n'` | Debian/Ubuntu |
| Pacman | `pacman -Q` | Arch Linux |

采集的包列表通过 `HeartbeatRequest.Packages` 字段上报到 Kernel。

## 9. 性能优化

### 9.1 预计算优化

| 优化项 | 优化前 | 优化后 | 说明 |
|--------|--------|--------|------|
| 包名提取 | 每次 CVE 匹配时调用 `extractPkgNames` | 预计算 `pkgNameSet` (map) | O(n) → O(1) 查找 |
| CPE 解析 | 每次 CVE 匹配时 `SplitN+ToLower` | 预构建 `cpeIndex` (vendor/product) | 避免重复解析 |
| 匹配策略 | 全量 `strings.Contains` | 优先 map 查找，fallback 子串 | O(n²) → O(n) |

### 9.2 性能基准

测试环境：671 个包 × 955 个 CVE

| 指标 | 优化前 | 优化后 |
|------|--------|--------|
| Calculate 耗时 | >10s（超时） | <100ms |
| Heartbeat 响应 | 超时断开 | 正常 |
| 内存占用 | ~50MB | ~50MB（无变化） |

## 10. TLS/mTLS 安全通信

SPC 模块运行在 Kernel 端，Agent 通过 mTLS 加密的 gRPC 通道上报包信息和接收 CVE 报告。

### 10.1 证书管理

- Kernel 启动时自动生成 CA/Server/Agent 证书（自签名）
- 证书签名自检：启动时验证 Server 证书是否由 CA 签名
- 自检失败时重新生成所有证书并写入磁盘
- 磁盘-内存一致性校验：确保写入的证书与内存中一致

### 10.2 Agent 证书加载

- 每次连接时从磁盘重新读取证书（避免使用缓存旧证书）
- 首次 TLS 连接失败后自动重试（重新读取证书）
- 详细的证书指纹日志（SHA256 前 16 位）

## 11. 故障排查

### 11.1 SPC Score 始终为 1.00

**可能原因及排查步骤：**

| 原因 | 排查方法 | 解决方案 |
|------|----------|----------|
| CVE 缓存为空 | 检查 Kernel 日志是否有 "CVE cache is empty" | 等待 NVD 同步完成或配置 API Key |
| Agent 未上报包信息 | 检查 Agent 日志是否有 "collected packages" 且 count > 0 | 确保 `rpm`/`dpkg-query` 命令在白名单中 |
| 包名与 CPE 不匹配 | 检查 Kernel 日志的 "match_stats" | 优化 `extractPkgNames` 移除常见后缀 |
| NVD API 不可达 | 检查 Kernel 日志是否有 "NVD API fetch failed" | 配置代理或使用 Sample CVE fallback |

### 11.2 TLS 证书验证失败

**症状：** `x509: certificate signed by unknown authority`

**排查步骤：**

1. 检查 Kernel 和 Agent 的 CA 证书指纹是否一致
2. 删除两端的 `certs/` 目录
3. 重启 Kernel（自动生成新证书）
4. 重启 Agent（从磁盘加载新证书）

### 11.3 NVD Fetch 返回 0 个 CVE

**可能原因：**
- 首次同步仅拉取 7 天数据（已修复为 120 天）
- 网络不可达或被防火墙拦截
- NVD API 速率限制（429 响应）

**解决方案：** 配置 NVD API Key 可大幅提升速率限制（5次/30s → 50次/30s）。

## 12. 后续规划

| 功能 | 优先级 | 说明 | 状态 |
|------|--------|------|------|
| InstalledCPEs 生成 | 高 | 从软件包元数据自动生成 CPE 条目，启用精确版本匹配 | ✅ 已实现 |
| CNNVD/CNVD 接入 | 中 | 补充中国特色漏洞数据 | ✅ 已实现 |
| MISP 威胁情报集成 | 中 | 从 MISP 实例拉取事件和星系标签 | ✅ 已实现 |
| OSCAL 导入 | 低 | 支持 OSCAL 格式的安全评估结果导入 | ✅ 已实现 |
| 版本范围匹配 | 高 | 利用 CPE 的 versionStart/versionEnd 实现精确版本范围匹配 | ✅ 已实现 |
| 缓存增量更新优化 | 中 | 仅更新变更的 CVE，减少全量替换开销 | ✅ 已实现 |
| NVD 并发分片请求 | 高 | 无 Key 时 4×30d 并发，有 Key 时 2×60d 并发 | ✅ 已实现 |
| 指数退避重试 | 高 | 替代固定间隔重试，避免 429 速率限制 | ✅ 已实现 |

---

> **说明：** SPC 是 SSAM 2.0 的核心组件，当前版本 v2.0。ASSCOR 是实现 SSAM 的开源项目框架，当前版本 v0.2.0。两者版本号独立演进。
>
> **V2.0 变更：** 在 SSAM V2.0 中，原有的 SPCScore 系数已重构至三层语义模型的 Exposure 层（RiskContext.Exposure），为基于漏洞的风险贡献提供了显式归因。
