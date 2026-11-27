# 未完成项总览（2026-11-27 结案）

> **当前 open 项：0。** 2026-11-27 对剩余 10 项做结案处理：3 项完成、5 项延后（带触发条件）、2 项接受/不做；
> 其余 30 项此前已完成/已验证。延后项不是“已实现”，触发条件满足时重新开项。

## 结案决定（剩余 10 项）

| ID | 类别 | 处置 | 说明 / 重新开项触发条件 |
|---|---|---|---|
| A1 | 微内核 | **部分推进/延后** | collector 已具备进程模式试点（`fa08dfa`，`collector,collector_proc`）；其余模块迁移仍需选型/端口/证书与部署改造。**v2.4 微内核里程碑**继续 |
| A3 | 微内核 | **延后** | 当前 RPC ~15ms/次、30 节点无压力。**节点 >100 或单次 RPC >50ms** 时做多路复用/并发池 |
| A5 | 微内核 | **延后** | 纯逻辑拆独立 module 与 A7/L-2 同批。**发布体积目标或打包重构启动**时处理 |
| A7 | 内核 | **延后** | 当前 full 22MB 可接受。**发版瘦身批次**统一处理动态插件/单协议/可选二进制拆分 |
| B1 | 研究 | **延后** | 跨环境 ROC 需第二拓扑（VLAN-aware）与 8 轮随机事实；**拓扑 B 就绪**后重开 |
| B2 | 研究 | **延后** | AUC 深化依赖多跳 ACL 与风险真值数据；**真值数据集就绪**后重开 |
| B3 | 安全边界 | **接受** | demo 为 token+HTTP；D-01 已 fail-closed 兜底。生产部署需 mTLS，按部署项处理，不再作为代码未完成项 |
| B4 | 环境 | **关闭（不做）** | lab 已停机，HMAC 下发属部署配置；agent 代码路径已支持 `hmac_key_file`/env |
| B5 | 可选 | **关闭（不做）** | securemode 审计可用“不含 securemode tag 的 agent”构建替代，非产品缺陷 |
| L-2 | 架构 | **延后** | 大包拆分与 A5/A7 同属长期重构；**打包重构启动**时统一评估 |

## 完成统计

- 已完成 / 已验证：**33 项**
- 接受风险：1 项（B3）
- 关闭（不做）：2 项（B4、B5）
- 延后（带触发条件）：7 项（A1、A3、A5、A7、B1、B2、L-2）
- **open：0**

---

## 已完成 / 已验证（33 项）

| ID | 事项 | 结论 |
|---|---|---|
| A9 | 扩展点数量文档核对 | **已验证后修正**：早期 89 计数漏算 `engine.*` 动态注册；C4 复核为 **96**（90 平台 + 6 生命周期），README 已更新 |
| D1 | 拓扑停机 + asc 池 46 资源 `onboot=0` | 已完成（进程隔离 v0.4 仅在快照中） |
| A12 | legacy 路径边因子硬编码 | **已完成**（`6cc0f3e`）：`legacyDefaultCustomFactors` 改读 `cfg.EdgeFactors`，5 个字面量移除；engine/assessor/edgefactor 测试全绿 |
| A13 | `[resilience] aci_*` 死配置 | **已完成**（`6aa0069`）：删除 7 个从未被消费的字段/解析/校验与 config.ini 段；`[resilience.circuit]` 保留 |
| D-07 | gRPC 客户端明文回退 | **已完成**（`3175f5d`）：`AllowInsecure` 默认 false，TLS 关闭时拒绝明文；新增测试 |
| A14 | EF-3FA 硬编码 0.82 | **已完成**（`3175f5d`）：`EdgeFactors.ThreeFactorFailure` + `[edge_factors] three_factor_failure`；SSAM/legacy 均读配置 |
| A17 | CTI 系数/间隔硬编码 | **已完成**（`3175f5d`）：`[cti] coefficient` / `update_interval_min`，含校验；基础系数用于运行时扣减 |
| A18 | 研究引擎默认参数硬编码 | **已完成**（`31069e8`）：`predictor.Params`/`attackerstate.Params` + `NewEngineWithParams`；engagement 已有 `PlannerParams`；默认值集中在 `DefaultParams`，并有覆盖测试 |
| A15 | ATT&CK 15 技术转移矩阵硬编码 | **已完成**（`bf1e0df`）：支持 `[attck] transition_matrix_file` JSON 覆盖，校验后合并；非法文件回退默认并告警 |
| A16 | SPC 影响权重硬编码 | **已完成**（`48438eb`）：`[spc] impact_cvss/epss/kev_weight、subtech_growth、apt_growth、poc_factor`；默认值不变 |
| C1 | main 文档 18 处悬空链接 | **已完成**（main `9475168`）：更新到现有文档/目录或标注历史数据未迁移；`check-doc-refs.sh` 在 main 为 0 |
| C2 | WHITEPAPER_GAP_ANALYSIS 三条过时 | **已完成**（`09a1dc9`）：新增 2026-11-22 复核记录，CTI/delegation/ATT&CK 乘数三条关闭并附代码证据 |
| C4 | 扩展点执行清单 | **已完成**（`e76a59f`）：生成全量清单；实际 **96** 点（90 平台+6 生命周期），**90** 有执行者、**6** 仅注册；README 计数已修正 |
| C3 | TECHNICAL_DEBT_BACKLOG 遗留项 | **已完成（复核）**（`09a1dc9`）：M-4 缓解、M-6/L-6 关闭、L-1 部分关闭；L-2 与 RC-M4（A18）继续跟踪 |
| D-01 | 联邦鉴权 fail-open | **已完成**（`aeb1ccc`）：master 非 loopback 且 token 空时拒绝启动；`config_test.go` 覆盖 |
| D-02 | NaN 配置绕过 | **已完成**（`aeb1ccc`）：`validateRanges` 对 weights/threshold/threat/ACI/edge/delta/confidence/SPC/ATT&CK 全部拒绝 NaN/Inf；回归测试 |
| D-03 | gRPC 无角色隔离 | **已完成（Agent 侧）**（`aeb1ccc`）：Agent 证书按指纹绑定只允许访问自身 host；运维证书仍跨主机（角色分离留后续） |
| D-04 | 注册任意 host_id | **已验证**：`BindAgentCert` 已保证一证书一 host；新增 host 仍依赖人工签发（provisioning 可再加） |
| D-05 | CTI 无上限读取 | **已完成**（`aeb1ccc`）：`LimitReader(32 MiB)` |
| D-06 | 联邦 HTTP 缺超时 | **已完成**（`aeb1ccc`）：Read 15s / Write 30s / Idle 60s |
| A11 | `level4_override` 无条件覆盖 | **已完成**（`d635197`）：仅 `compliance_framework` 含 Level 4/等保四级时应用；Level 3 默认用 `[edge_factors]` 值；新增回归测试 |
| A10 | 依赖漏洞（govulncheck 26 可达） | **已完成**（`a980344`）：Go 1.26.11 + grpc v1.83.2 + x/net v0.60.0；默认/全 tag 复扫均 0 可达 |
| A8 | proc 模式未进打包/CI | **已完成**（`38a3fc8`）：`scripts/build.sh` 增加 `ASSCOR-kernel-proc` + `federation-mod`；CI 增加 proc kernel/child 构建与测试 |
| A2 | federation-mod 无自动重启 | **已完成**（`324ae9c`）：Proxy supervisor 每 2s ping，失败后指数退避（1s→60s）重启并重配/重推快照；smoke 实测 kill 后 ~2s 拉起 |

| A4 | 快照间隔=上报周期 | **已完成**（`4c25520`）：`[federation] snapshot_interval_sec` 独立配置 |
| A6 | adapterhub/attck/comms 决策 | **已完成**（`e26cc19`）：ADR-001/002/003，adapterhub 冻结 |
| A19 | resilience.circuit 未解析 | **已完成**（`4a92321`）：阈值/窗口/冷却配置化并启动注入 |
| D-08 | 命令未来时间戳/重放 | **已完成**（`8d46197`）：未来 >1min 拒绝 + 10 分钟重放缓存 |
| D-09 | git 参数/解压炸弹 | **已完成**（`8d46197`）：`git clone --` + 解压 512MiB 上限 |
| D-10 | 多处忽略错误 | **已完成**（`8d46197`）：SPC 读取、trace/session 回退、解压 mkdir |
| D-11 | gRPC/联邦限速 | **已完成**（`95e85f1`）：gRPC 200/s + 流 256；联邦 50/s/IP |
| D2 | GitHub CI 未确认 | **已完成**（`33861f9`）：main `b2f3413` run success |
| D3 | 部署脚本一次性 | **已完成**（`57fa6bd`）：`scripts/deploy-federation.sh` |

## 说明

- 延后项保留在本文档的结案表中，不再作为 open 项；触发条件满足时由维护者重新开项。
- 本文档是清单，不是路线图；路线图另见 `docs/1-current/design/ARCH_DECISIONS_2026-11-27.md` 与各专题审计。
