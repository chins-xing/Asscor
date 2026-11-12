# 未完成项总览（2026-11-05）

> 汇总当前**仍未完成/待决策/待验证**的条目。每条给出来源与下一步动作。
> 图例：`[未开始]` `[进行中]` `[待决策]` `[待验证]` `[文档待更新]`

## A. 微内核与架构

| ID | 事项 | 状态 | 依据 / 下一步 |
|---|---|---|---|
| A1 | 进程隔离仅覆盖 **federation** 一个模块；assessor/topology/SPC/CTI 等仍在进程内 | [进行中] | `docs/2-experiments/T4_FEDERATION_PROCESS_2026-10-29.md`；按风险低→高迁下一个模块（CTI/SPC/collector） |
| A2 | `federation-mod` 崩溃**不会自动重启**（需重启 kernel） | [未开始] | 同上 §5；Proxy 加 supervisor（指数退避 + 事件上报） |
| A3 | 内核↔子进程 RPC **单飞**（一次一请求） | [未开始] | `proc_proxy.go` procClient 串行；改多路复用/并发池 |
| A4 | 快照推送间隔 = `report_interval_sec`（30s），分数最多滞后一个周期 | [待决策] | 推送与上报周期解耦（增量快照/5s） |
| A5 | 内核二进制**未因进程隔离减重**（纯逻辑仍与 Proxy 同包） | [未开始] | 把 federation 纯逻辑拆独立 module，Proxy 只依赖协议 |
| A6 | 联动审计 §7.4 三项：`adapterhub` 整包孤儿、`internal/attck` kernel 内不启动（provider 注入形态）、`comms_on.go` 手工装配 9 模块 | [待决策] | `docs/3-audits/MODULE_LINKAGE_AUDIT_2026-10-29.md` §7.4 |
| A7 | 内核瘦身：拆可选模块二进制、动态插件、单协议（gRPC/JSONRPC 二选一） | [未开始] | 内核体积审计结论（minimal 9.3MB → full 22.2MB；业务符号仅 4.1%） |
| A8 | **打包/CI 未覆盖进程隔离**：`scripts/build.sh` 无 `federation`/`federation_proc`/`cmd/federation-mod`；CI 只构建/测试进程内 federation | [未开始] | `scripts/build.sh:11`；`.github/workflows/ci.yml:62-65` |
| A11 | `[edge_factors] two_factor_failure` 被 `[edge_factors.level4_override]` **无条件覆盖**（配 0.85 实际永远 0.70） | [未开始] | `config/config.go:275-307`；按等级 gate 或删/改名 + 回归测试；审计 `MODEL_PARAMETERIZATION_AUDIT_2026-11-12.md` |
| A12 | **legacy 评分路径** 5 个边因子硬编码（0.75/0.80/0.82/0.90/0.88），不读 `[edge_factors]` | [未开始] | `internal/engine/assessor.go:562-570`；决定废弃 legacy 或改为读 cfg |
| A13 | `[resilience] aci_*` 7 个权重被解析但**全仓无消费点**（死配置） | [未开始] | `internal/config/config.go:38-44,326-346`；接入 SPC/assessor 或删除 |
| A14 | SSAM 路径 `EF-3FA` 因子硬编码 **0.82**（含 CascadeValue） | [未开始] | `internal/engine/ssam/adapter.go:69`；参数化或标为模型常量 |
| A15 | ATT&CK **15 技术转移矩阵**硬编码（专家先验），无配置入口 | [未开始] | `internal/attck/attck.go:987+`；实验注入或文档标常量 |
| A16 | SPC 影响权重硬编码：`0.20*cvss+0.50*epss+0.30*kev`、APT `×1.2`、子技术 `×1.1`、PoC `0.3` | [未开始] | `internal/spc/spc.go:535-544` |
| A17 | CTI 系数 `1.0`、更新间隔 `15m` 硬编码（仅 OTX/MISP 凭据可配） | [未开始] | `internal/cti/cti.go:70-71` |
| A18 | 研究引擎默认参数硬编码：predictor 动作收益、engagement `1.0/0.8/0.6/1.2`、attackerstate `0.1/0.15`（RC-M4） | [未开始] | `predictor.go:71`、`engagement.go:62`、`attackerstate/state.go:106,132` |
| A19 | `[resilience.circuit]` 未解析；熔断默认 5 次/5 分钟/1 分钟硬编码 | [未开始] | `internal/resilience/circuit.go:71` |
| A10 | **govulncheck 审计：26 个可达漏洞**（Go 1.26.3 stdlib 22 + grpc 4）；修复需 Go ≥1.26.10、grpc ≥v1.83.1、x/net ≥v0.60.0 | [未开始] | `docs/3-audits/VULNCHECK_AUDIT_2026-11-09.md`；升级后复扫目标 0 可达 |
| A9 | 扩展点数量文档核对 | **已验证** | 实际 89 = 83 平台（`platform_extensions.go`）+ 6 内核生命周期（`kernel.go:49-78`），README 无需改 |

## B. 实验与研究

| ID | 事项 | 状态 | 依据 / 下一步 |
|---|---|---|---|
| B1 | **T4 跨环境 ROC**（SRD v2.3 P1）：第二拓扑（3–4 网段 + VLAN 隔离）、每环境 8 轮随机事实、95% CI、两环境 AUC 对比 | [未开始] | `docs/1-current/design/SRD_V2.3_PLAN_2026-10-27.md` §T4；需 VLAN-aware bridge 或 VM 网络 |
| B2 | AUC 深化：多跳 ACL / 风险真值（攻击链成功）/ 三 profile 参数敏感性 | [未开始] | 现有二元可达性下三 profile AUC 完全一致（`T4_FEDERATION_AUC_LARGE`） |
| B3 | 联邦安全边界：demo 为共享 token + 明文 HTTP | [demo 级] | 生产需 mTLS + 独立凭证 |
| B4 | agent 未配置 HMAC key（commander 远程命令会被拒） | [环境约束] | `/root/t4` 时代遗留；要测命令下发需先下发 `agent-hmac.key` |
| B5 | securemode 把 agent.ini 加密成 `.enc`，配置不可审计 | [可选] | 如需可审计，用不含 securemode tag 的 agent 重建 |

## C. 文档与仓库

| ID | 事项 | 状态 | 依据 / 下一步 |
|---|---|---|---|
| C1 | main 文档 **18 处悬空链接**（legacy 文档指向 旧 clab-lab 数据目录（未跟踪）、`docs/superpowers/plans/...`、`docs/v0.3.0/...` 等已移动/未跟踪文件） | [待修] | 用 `scripts/check-doc-refs.sh` 在 main 复现；逐条改指新路径或归档 |
| C2 | `WHITEPAPER_GAP_ANALYSIS` 三条已过时：CTI 已真实拉取 OTX/MISP（`internal/cti/cti.go:181/276`）、delegation 已有 39 条规则、SPC 已含 `1+0.1n` 乘数（`internal/spc/spc.go:539`） | [文档待更新] | 关闭这三条 gap 并注明验证位置 |
| C3 | `TECHNICAL_DEBT_BACKLOG_2026-09-08` 仍列 M-4/M-6/L-1/L-2/L-6/RC-M4（2026-09 基线） | [待复核] | 逐条对照当前代码：关闭/降级/更新 |
| C4 | 扩展点执行清单：89 个点里实际被 `Execute` 的约 16 个（assessor 15 + srd 1），其余仅注册 | [未开始] | 产出"点 × 执行者"清单，删除/标注纯预留 |

## D. 运维与环境（状态记录，非缺陷）

| ID | 事项 | 状态 | 说明 |
|---|---|---|---|
| D1 | 拓扑已停机 + asc 池 46 资源 `onboot=0` | 已完成 | 进程隔离 v0.4 只在快照（`t4-fed-proc-*`）中，未长期部署运行 |
| D2 | GitHub CI 最新 run 未确认 | [待验证] | 本地等价 CI（gofmt/vet/build/test/pluginsdk）已 `CI_ALL_OK`；GitHub 侧需看 push 结果 |
| D3 | 内核/子进程部署脚本仍是一次性命令 | [未开始] | 可纳入 `scripts/` 做可重复部署（含 federation-mod 分发） |

## E. 建议优先级

- **P0**：A8（打包/CI 覆盖 proc 模式）→ 否则进程隔离不可发布；A2（auto-restart）→ 可用性；C1（main 悬空链接）
- **P1**：A1（迁移第二个模块）、A6（adapterhub/attck/comms 决策）、A5（拆 module 减重）、B1（T4 跨环境 ROC）
- **P2**：A3/A4（RPC 并发/快照周期）、B2（风险真值）、B3/B4/B5（安全边界）、C2/C3/C4（文档/清单）
