# 未完成项总览（2026-11-05，2026-11-13 按优先级重排）

> 汇总当前**仍未完成 / 待决策 / 待验证**的条目；本版按 **P0 → P3** 重新排序，不再按模块分组。
> 图例：`[未开始]` `[进行中]` `[待决策]` `[待验证]` `[文档待更新]` `[环境约束]` `[demo 级]` `[可选]`
> 排序依据：安全可利用性 > 正确性/发布阻断 > 可用性/实验缺口 > 文档/清理。

## P0 — 立即处理（安全或会静默出错）

> 当前 P0 已清空；A10/A11 见下方“已关闭”。


| 优先级 | ID | 类别 | 事项 | 状态 | 关键位置 / 下一步 |
|---|---|---|---|---|---|
| — | — | — | **当前无 P0 项** | — | — |

## P1 — 近期处理（高危或发布/可用性阻断）

| 优先级 | ID | 类别 | 事项 | 状态 | 关键位置 / 下一步 |
|---|---|---|---|---|---|
| P1 | A13 | 正确性 | `[resilience] aci_*` 7 个权重被解析但全仓无消费点（死配置） | [未开始] | `internal/config/config.go:38-44,326-346`；接入评分或删除 |
| A12 | legacy 路径边因子硬编码 | **已完成**（`6cc0f3e`）：`legacyDefaultCustomFactors` 改读 `cfg.EdgeFactors`，5 个字面量移除；engine/assessor/edgefactor 测试全绿 |

## P2 — 排期处理（研究缺口、加固、技术债）

| 优先级 | ID | 类别 | 事项 | 状态 | 关键位置 / 下一步 |
|---|---|---|---|---|---|
| P2 | D-07 | 加固 | gRPC 客户端 TLS 关闭时静默退回明文 | [未开始] | `internal/comms/grpc_server.go:345-353`；显式 dev 开关 / fail-closed |
| P2 | A1 | 微内核 | 进程隔离仅覆盖 federation；assessor/topology/SPC/CTI 仍在进程内 | [进行中] | 按风险低→高迁下一个模块（CTI/SPC/collector） |
| P2 | A3 | 微内核 | 内核↔子进程 RPC 单飞（一次一请求） | [未开始] | 改多路复用/并发池 |
| P2 | A4 | 微内核 | 快照推送间隔 = `report_interval_sec`（30s），分数最多滞后一个周期 | [待决策] | 推送与上报周期解耦（增量快照/5s） |
| P2 | A5 | 微内核 | 内核二进制未因进程隔离减重（纯逻辑仍与 Proxy 同包） | [未开始] | 纯逻辑拆独立 module，Proxy 只依赖协议 |
| P2 | A6 | 架构 | 联动审计 §7.4：adapterhub 孤儿、attck 双形态、comms_on 手工装配 9 模块 | [待决策] | `docs/3-audits/MODULE_LINKAGE_AUDIT_2026-10-29.md` §7.4 |
| P2 | A7 | 内核 | 内核瘦身：拆可选模块二进制、动态插件、单协议 | [未开始] | 内核体积审计（minimal 9.3MB → full 22.2MB） |
| P2 | A14 | 参数化 | SSAM 路径 `EF-3FA` 因子硬编码 0.82（含 CascadeValue） | [未开始] | `internal/engine/ssam/adapter.go:69`；参数化或标为常量 |
| P2 | A15 | 参数化 | ATT&CK 15 技术转移矩阵硬编码，无配置入口 | [未开始] | `internal/attck/attck.go:987+`；实验注入或文档标常量 |
| P2 | A16 | 参数化 | SPC 影响权重硬编码（0.20/0.50/0.30、APT×1.2、子技术×1.1） | [未开始] | `internal/spc/spc.go:535-544` |
| P2 | A17 | 参数化 | CTI 系数 1.0、更新间隔 15m 硬编码 | [未开始] | `internal/cti/cti.go:70-71` |
| P2 | A18 | 参数化 | 研究引擎默认参数硬编码（predictor/engagement/attackerstate，RC-M4） | [未开始] | `predictor.go:71`、`engagement.go:62`、`attackerstate/state.go:106,132` |
| P2 | B1 | 研究 | T4 跨环境 ROC（第二拓扑/VLAN 隔离、8 轮、95% CI） | [未开始] | `docs/1-current/design/SRD_V2.3_PLAN_2026-10-27.md` §T4 |
| P2 | B2 | 研究 | AUC 深化：多跳 ACL / 风险真值 / 参数敏感性 | [未开始] | 现有二元可达性下三 profile AUC 完全一致 |
| P2 | B3 | 安全边界 | 联邦 demo 为共享 token + 明文 HTTP，生产需 mTLS + 独立凭证 | [demo 级] | 与 D-01 一并收口 |
| P2 | B4 | 环境 | agent 未配置 HMAC key（commander 远程命令会被拒） | [环境约束] | `/root/t4` 遗留；需先下发 `agent-hmac.key` |
| P2 | B5 | 可选 | securemode 把 agent.ini 加密成 `.enc`，配置不可审计 | [可选] | 需审计时用不含 securemode tag 的 agent 重建 |
| P2 | C1 | 文档 | main 文档 18 处悬空链接（legacy 指向 clab-lab/superpowers/v0.3.0 等） | [待修] | `scripts/check-doc-refs.sh` 在 main 复现；逐条改路径或归档 |
| P2 | C2 | 文档 | `WHITEPAPER_GAP_ANALYSIS` 三条已过时（CTI 实拉取、delegation 39 条、SPC 乘数已存在） | [文档待更新] | 关闭三条 gap 并注明验证位置 |
| P2 | C3 | 文档 | `TECHNICAL_DEBT_BACKLOG_2026-09-08` 仍列 M-4/M-6/L-1/L-2/L-6/RC-M4 | [待复核] | 逐条对照当前代码关闭/降级/更新 |
| P2 | C4 | 文档 | 扩展点执行清单：89 个点实际被 Execute 的约 16 个 | [未开始] | 产出"点 × 执行者"清单，删除/标注纯预留 |
| P2 | D2 | 运维 | GitHub CI 最新 run 未确认 | [待验证] | 本地等价 CI 已 `CI_ALL_OK`；GitHub 侧确认 |
| P2 | D3 | 运维 | 内核/子进程部署脚本仍是一次性命令 | [未开始] | 纳入 `scripts/` 做可重复部署（含 federation-mod 分发） |

## P3 — 低优先（加固/清理）

| 优先级 | ID | 类别 | 事项 | 状态 | 关键位置 / 下一步 |
|---|---|---|---|---|---|
| P3 | D-08 | 加固 | 命令时间戳未来值可通过、无 nonce 去重（5 分钟窗口可重放） | [未开始] | `internal/agent/agent.go:1016-1024`；未来时间窗 + nonce 缓存 |
| P3 | D-09 | 加固 | 扩展 git clone URL 未加 `--`；解压无总量上限（压缩炸弹） | [未开始] | `internal/extmgr/extension_installer.go:85-92,310-410` |
| P3 | D-10 | 健壮性 | 多处忽略错误（SPC ReadAll、解压 MkdirAll、trace rand、session 回退） | [未开始] | `spc_fetch_cn.go:69,220`、`extension_installer.go:324/328/395`、`logger/observability.go:64`、`services.go:709-715` |
| P3 | D-11 | 加固 | gRPC/联邦缺速率与连接配额 | [未开始] | 按证书/连接限速 |
| P3 | A19 | 参数化 | `[resilience.circuit]` 未解析；熔断默认 5 次/5 分钟/1 分钟硬编码 | [未开始] | `internal/resilience/circuit.go:71` |

## 已关闭 / 已验证（保留记录，不再计入未完成）

| ID | 事项 | 结论 |
|---|---|---|
| A9 | 扩展点数量文档核对 | **已验证**：89 = 83 平台（`platform_extensions.go`）+ 6 内核生命周期（`kernel.go:49-78`），README 无需改 |
| D1 | 拓扑停机 + asc 池 46 资源 `onboot=0` | 已完成（进程隔离 v0.4 仅在快照中） |
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

## 排序说明

- **P0 判据**：无需特殊条件即可远程/本地触发的鉴权缺陷；或会静默产生错误评分的配置缺陷；已有 26 个可达依赖漏洞。
- **P1 判据**：需要有效证书/密钥或特定部署条件，但影响面大；发布阻断（proc 打包/CI）；配置静默无效。
- **P2 判据**：需要更高权限/组合条件；研究缺口；技术债；文档一致性。
- **P3 判据**：低概率/低影响加固，或仅在开发/实验路径触发。
- 原 A/B/C/D/F 分组已拆散到此表；各条目的证据仍可在对应审计文档中查到。
