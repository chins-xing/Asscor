# ASSCOR 外部接入源完整清单

**版本**：v1.6
**日期**：2026-06-28  
**状态**：发布 — 全部 21 个接入源已实现并测试通过  
**配套文档**：ASSCOR 扩展白皮书（内核安全域）、ASSCOR 工程实现白皮书

---

## 一、探测器类（11 项）

发现安全漏洞、配置缺陷、异常行为的外部工具。

### P0（核心，必须首批接入）

| ID | 工具 | 探测领域 | 输出格式 | 适配难度 | 接入价值 | 接入状态 |
|:---|:---|:---|:---|:---|:---|:---:|
| **SC-001** | **Trivy** | 容器镜像漏洞、依赖库漏洞、IaC 配置缺陷 | JSON | 低 | 覆盖 CVE 漏洞扫描，替代 KS-001 内核漏洞检测、SC-002 依赖库漏洞 | ✅ 已实现 |
| **SC-002** | **Nuclei** | Web 应用漏洞、配置缺陷、暴露面板 | JSON | 低 | 覆盖 Web 层攻击面，等保 L3-CE-23 端口检查可委派 | ✅ 已实现 |
| **SC-003** | **Lynis** | 系统安全审计、合规检查 | 文本/JSON | 中 | 覆盖大量等保二级/三级系统配置检查，与 ASSCOR 内置检查互补 | ✅ 已实现 |

### P1（安全纵深，第二批接入）

| ID | 工具 | 探测领域 | 输出格式 | 适配难度 | 接入价值 | 接入状态 |
|:---|:---|:---|:---|:---|:---|:---:|
| **SC-004** | **OpenSCAP** | 合规扫描（等保/CIS/STIG） | XCCDF/OVAL | 中 | 提供官方等保合规扫描能力，与 ASSCOR 自研检查交叉验证 | ✅ 已实现 |
| **SC-005** | **Wazuh** | HIDS 告警、文件完整性、异常检测 | JSON API | 低 | 替代 RS-006 HIDS 部署检查，直接读取告警数据 | ✅ 已实现 |
| **SC-006** | **Suricata** | NIDS 告警、协议解析、流量异常 | EVE JSON | 低 | 替代 RS-006 NIDS 部署检查，网络攻击检测数据源 | ✅ 已实现 |
| **SC-007** | **Falco** | 容器运行时安全、系统调用异常 | JSON | 低 | 云原生安全域核心数据源，内核层行为检测 | ✅ 已实现 |
| **SC-008** | **ClamAV** | 病毒扫描、恶意代码检测 | 文本 | 中 | 替代 RS-008 反病毒部署检查 | ✅ 已实现 |

### P2（增强覆盖，第三批接入）

| ID | 工具 | 探测领域 | 输出格式 | 适配难度 | 接入价值 | 接入状态 |
|:---|:---|:---|:---|:---|:---|:---:|
| **SC-009** | **OSV-Scanner** | 开源依赖漏洞 | JSON | 低 | 补充 SC-002 依赖库漏洞，专注开源生态 | ✅ 已实现 |
| **SC-010** | **AIDE** | 文件完整性检查 | 文本 | 中 | 替代 OT-013 文件完整性监控 | ✅ 已实现 |
| **SC-011** | **Nikto** | Web 服务器配置缺陷 | 文本/HTML | 中 | 补充 Nuclei 未覆盖的 Web 服务器专项检查 | ✅ 已实现 |

---

## 二、管理类（10 项）

提供资产上下文、配置预期状态、身份数据、任务编排、工单跟踪的外部平台。

### P0（配置管理 + 资产管理，必须首批接入）

| ID | 工具 | 管理领域 | 接口方式 | 适配难度 | 接入价值 | 接入状态 |
|:---|:---|:---|:---|:---|:---|:---|
| **MG-001** | **Ansible** | 配置管理、预期状态 | inventory 文件 / facts 缓存 | 低 | 提供"预期状态"参照系，检测配置漂移 | ✅ 已实现 |
| **MG-002** | **NetBox** | 资产管理（DCIM/IPAM） | REST API | 低 | 提供资产角色、位置、业务关键度，用于 SPC 本地化因子 | ✅ 已实现 |
| **MG-003** | **Snipe-IT** | IT 资产管理 | REST API | 低 | 补充 NetBox，适合非数据中心场景 | ✅ 已实现 |

### P1（身份治理 + SIEM + 任务编排）

| ID | 工具 | 管理领域 | 接口方式 | 适配难度 | 接入价值 | 接入状态 |
|:---|:---|:---|:---|:---|:---|:---|
| **MG-004** | **FreeIPA** | 身份治理、账户管理 | JSON-RPC / CLI | 中 | 提供权威身份数据，检测禁用账户，增强操作可信度域评估 | ✅ 已实现 |
| **MG-005** | **Keycloak** | 现代身份与访问管理 | REST API | 中 | 补充 FreeIPA，适合云原生环境 | ✅ 已实现 |
| **MG-006** | **Wazuh SIEM** | 安全信息与事件管理 | REST API | 低 | 双向对接：读取告警→ASSCOR 评估；ASSCOR 分数→SIEM 仪表板 | ✅ 已实现 |
| **MG-007** | **Rundeck** | 任务编排、作业调度 | REST API | 中 | 将 ASSCOR 修复建议转化为可追踪的执行任务 | ✅ 已实现 |

### P2（工单 + IaC 左移）

| ID | 工具 | 管理领域 | 接口方式 | 适配难度 | 接入价值 | 接入状态 |
|:---|:---|:---|:---|:---|:---|:---|
| **MG-008** | **Jira** | 工单跟踪 | REST API | 中 | 评估发现严重问题时自动创建工单 | ✅ 已实现 |
| **MG-009** | **Terraform** | 基础设施即代码 | .tf 文件 / state 解析 | 中 | 部署前安全评估，左移安全 | ✅ 已实现 |
| **MG-010** | **OpenTofu** | 基础设施即代码（开源替代） | .tf 文件 / state 解析 | 中 | Terraform 的开源替代，同等能力 | ✅ 已实现 |

---

## 三、接入源总统计

### 3.1 接入完成度

| 状态 | 数量 | 占比 |
|:---|:---:|:---:|
| ✅ 已实现 | **21** | **100%** |
| 🚧 开发中 | 0 | 0% |
| ⏳ 待接入 | 0 | 0% |
| **合计** | **21** | **100%** |

### 3.2 按类别与优先级统计

| 类别 | P0 | P1 | P2 | 小计 |
|:---|:---:|:---:|:---:|:---:|
| 探测器 | 3 | 5 | 3 | **11** |
| 管理类 | 3 | 4 | 3 | **10** |
| **合计** | **6** | **9** | **6** | **21** |

### 3.3 测试覆盖

| 类别 | 测试文件 | 测试用例数 |
|:---|:---|:---:|
| 探测器适配器 | `internal/adapter/scanner/..._test.go` | 100+ |
| 管理类适配器 | `internal/adapter/management/management_test.go` | 50+ |

---

## 四、接入后检查项委派对照

接入外部源后，ASSCOR 现有检查项的委派情况：

| 域 | 总检查项 | 委派给外部 | 保留自检 | 外部工具 |
|:---|:---:|:---:|:---:|:---|
| 攻击面管理 | 17 | 2 | 15 | Nuclei（端口扫描）、Trivy（漏洞） |
| 业务连续性 | 3 | 0 | 3 | 全部自检 |
| 操作可信度 | 22 | 4 | 18 | Lynis（审计）、AIDE（完整性）、FreeIPA（账户治理） |
| 韧性 | 12 | 6 | 6 | Wazuh（HIDS）、Suricata（NIDS）、ClamAV（反病毒） |
| 韧性(ACI) | 8 | 0 | 8 | 全部自检（沦陷后指标，外部工具无法替代） |
| 内核安全 | 12 | 1 | 11 | Trivy（内核 CVE）、其余 sysctl/module 检查自检 |
| **合计** | **74** | **13** | **61** | |

---

## 五、实施路线

| 阶段 | 接入源 | 时间 | 交付物 | 状态 |
|:---|:---|:---|:---|:---:|
| **Phase 1** | P0 全部 6 项 | 3-4 周 | Trivy/Nuclei/Lynis 适配器 + Ansible/NetBox/Snipe-IT 适配器 | ✅ 已完成 |
| **Phase 2** | P1 探测器 5 项 | 3-4 周 | OpenSCAP/Wazuh/Suricata/Falco/ClamAV 适配器 | ✅ 已完成 |
| **Phase 3** | P1 管理类 4 项 | 3-4 周 | FreeIPA/Keycloak/Wazuh SIEM/Rundeck 适配器 | ✅ 已完成 |
| **Phase 4** | P2 全部 6 项 | 4-5 周 | OSV-Scanner/AIDE/Nikto/Jira/Terraform/OpenTofu 适配器 | ✅ 已完成 |

---

## 六、配置文件模板

```ini
# ===== 探测器适配器 =====
# 注意：所有适配器默认关闭，需根据实际部署环境手动开启
[adapters]
trivy = off
nuclei = off
lynis = off
openscap = off
wazuh_agent = off
suricata = off
falco = off
clamav = off
osv_scanner = off
aide = off
nikto = off

[adapter_paths]
trivy = /usr/local/bin/trivy
nuclei = /usr/local/bin/nuclei
lynis = /usr/local/sbin/lynis
openscap = /usr/bin/oscap
falco = /usr/bin/falco
clamav = /usr/bin/clamscan
osv_scanner = /usr/bin/osv-scanner
aide = /usr/bin/aide
nikto = /usr/bin/nikto

[trivy]
target_images = 

[nuclei]
templates = 
target = 

# ===== 管理类适配器 =====
[management_adapters]
ansible = off
netbox = off
snipe_it = off
freeipa = off
keycloak = off
wazuh_siem = off
rundeck = off
jira = off
terraform = off
opentofu = off

[ansible]
inventory_path = /etc/ansible/hosts
facts_path = /etc/ansible/facts.d

[netbox]
api_url = https://netbox.internal
api_token = ${NETBOX_TOKEN}

[snipe_it]
api_url = https://snipeit.internal
api_token = ${SNIPEIT_TOKEN}

[wazuh_siem]
api_url = https://wazuh.internal:55000
username = ASSCOR
password = ${WAZUH_PASSWORD}

[terraform]
plan_dir = .

[opentofu]
plan_dir = .
```

---

## 七、安全注意事项

### 7.1 API Key 来源审计

ASSCOR 对外部接入源的 API Key 实施来源审计，确保密钥来源可追溯：

- **环境变量优先**：NVD API Key（`NVD_API_KEY`）、MISP API Key（`MISP_API_KEY`）、NetBox Token（`NETBOX_TOKEN`）、Wazuh Password（`WAZUH_PASSWORD`）等均优先从环境变量读取
- **配置文件次之**：若环境变量未设置，则从 config.ini 对应段读取
- **审计日志**：无论 Key 从哪个来源加载，系统均记录日志（如 `config: NVD API key loaded from environment variable` 或 `config: NVD API key loaded from configuration file`），便于安全审计追溯

### 7.2 适配器执行安全

- **默认关闭**：所有适配器默认 `off`，需管理员按需开启，避免意外执行外部工具
- **命令白名单**：ExtensionExecutor 通过白名单限制可执行路径，并解析符号链接防止绕过
- **超时控制**：所有适配器执行均有超时限制（默认 60 秒），防止挂起

---

这份清单与《ASSCOR 检查项完整清单 v2.0》（140 项）、《内核安全扩展白皮书》（12 项）配套，共同构成 ASSCOR 从独立扫描器到安全治理中枢的完整路线图。

---

---

> ⚠️ **SPC 评估方法声明**：SPC 模块的验证逻辑基于 CPE 字符串匹配（软件包名称/版本 ↔ CVE 受影响产品版本），不执行漏洞利用验证、运行时可达性分析或二进制分析。SPC 定位为"漏洞情报聚合与版本比对引擎"，而非"漏洞利用验证器"。详见 [SPC 安全态势计算模块技术白皮书](SPC安全态势计算模块技术白皮书.md)。

## 版本历史

- **v1.0** — 2026-05-14，初始版本，覆盖全部外部接入源与适配器清单。
- **v1.1** — 2026-05-20，更新检查项统计（攻击面管理 14→16，韧性域统计修正为 12）；补充 API Key 来源审计说明（环境变量优先于配置文件）。
- **v1.2** — 2026-05-20，修正配置模板与 config.ini 一致（所有适配器默认 off）；修正委派对照表计数（AS 16→17，OT 19→22，新增 ACI 行 8 项，合计 62→74）；补充 adapter_paths（falco/osv_scanner/nikto）和配置段（[snipe_it]/[terraform]/[opentofu]）；新增第七章安全注意事项（API Key 来源审计、适配器执行安全）。
- **v1.3** — 2026-05-21，确认全部 21 个适配器已实现完整四阶段流水线（Fetch→Parse→Map→Validate）并通过代码验证；AdapterIntegrationModule 注册修复：已加入 Kernel 插件列表使后台定时同步、事件总线发布、按需拉取功能生效；补充接入方式完整性检查报告（注册链路、配置映射、执行流水线、结果注入）。