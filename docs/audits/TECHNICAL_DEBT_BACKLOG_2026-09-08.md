# ASSCOR 历史债务与未完成项清单（2026-09-08）

**版本基线**: main v0.2.3（`0682d6d`）+ ASSCOR-Research-Core（`ab33d72`）
**来源综合**: SECURITY_ISSUES_AUDIT_2026-09-08（34 项）· COUPLING_AUDIT_2026-09-03 · Secure Mode 各轮审查 deferred · 研究方向需求（2026-09-08）
**维护**: 每轮关闭/新增后更新本文档并提交（两分支各自归档）

---

## 〇、状态总览（截至 2026-09-08）

| 类别 | 总数 | 已关闭 | 剩余 |
|---|---|---|---|
| 安全审计 Critical | 3（C-1/C-2/C-3） | **3** ✅ | 0 |
| 安全审计 High（main H-1..H-5 + ARC RC-H1/RC-H3） | 8 | **8** ✅ | 0 |
| 安全审计 Medium/Low（main M/L + ARC RC-M/RC-L） | 23 | M-1/M-5/RC-L2 + RC-M1/RC-M2 + RC-H2(High 并入上) | **19** |
| 耦合审计（COUPLING 2026-09-03） | 8（C1/C2/F1..F8） | C1/C2/F2/F3 | **F4/F5/F6/F7**（4） |
| Secure Mode deferred minors | 12+ | 全部（23ca6cd..d9c23d9） | **0** ✅ |
| 研究方向 | 2 | ①（可信度原生变量） | **②**（边缘因子向量图变量化） |
| 工程债（论文/拆包/超时等） | — | — | 见 §五 |

**Secure Mode 与安全审计 Critical/High 已全闭合**；剩余集中于 Medium/Low、耦合 Minor、研究方向② 与工程债。

---

## 一、安全审计 Medium/Low 剩余（SECURITY_ISSUES_AUDIT_2026-09-08，main 通用）

| 编号 | 项 | 位置 | 修复方向 | 备注 |
|---|---|---|---|---|
| M-2 | runCommand 冗余分支 | `internal/agent/agent.go` | `IsShellCommandAllowed` 与 `ParseCommand` 两分支同逻辑，删冗余统一走 ParseCommand+RunCmdTimeout | 已核实属实 |
| M-3 | HMAC 密钥相对路径 | `internal/commander/commander.go`、`internal/integrity/sign.go`（`certs/ASSCOR-*-key`） | 用配置 `cert_dir` 或绝对路径 | systemd WorkingDirectory 不同会生成新密钥 |
| M-4 | agent.ini 明文 hmac_key | `cmd/agent/main.go loadConfigFile` | 废弃配置字段，强制环境变量/密钥文件 | |
| M-6 | 配置数值无范围校验 | `internal/config/config.go` | Parse 阶段权重/阈值/因子范围校验+告警 | |
| L-1 | 安全关键包零测试 | `internal/integrity`/`resilience`/`topology`/`version`/`api/v1` | 补单元测试 | C-1 已补 algo 测试，其余待 |
| L-2 | 大包拆包 | `internal/attck`(8.3k行)/`kernel`(7.7k)/`engine`(6k)/`cli`(5.9k)/`adapter`(5.6k) | 按子领域拆分 | 长期 |
| L-3 | Docker HEALTHCHECK 误匹配 | Dockerfile `pgrep -f ASSCOR-kernel` | PID 文件/端口探测 | |
| L-4 | Dockerfile 未用 wget | Dockerfile | 移除 | |
| L-5 | config.ini 版本号滞后 | config.ini（标注 v0.2.1） | 统一 v0.2.3 | |
| L-6 | 扩展安装权限未最小化 | `internal/extmgr/extension_installer.go` | 统一 0755/0644 清特殊位 | |

## 二、安全审计 RC 剩余（ARC securemode/研究专属）

| 编号 | 项 | 位置 | 修复方向 | 备注 |
|---|---|---|---|---|
| RC-M3 | 自恢复阈值短+静默丢配置 | `internal/agent/securemode.go secureSelfRecover` | 延长阈值/仅显式信号触发+告警 | **设计权衡**：spec §8.2 语义，SecureModeNoSecret 已可立即短路；列为可选调参 |
| RC-M4 | 研究引擎权重全硬编码 | `internal/predictor`/`engagement`/`attackerstate` | 权重参数化+实验配置注入 | 与方向②耦合，可并入 |
| RC-M5 | exprunner 命令注入风险 | `cmd/exprunner/main.go dockerExec` | 移除 bash -c / 过滤 shell 元字符 | 值当前硬编码不可达 |
| RC-M6 | 仓库混入非代码 | lunwen/ docs/audits/ docs/en/ | 独立仓库/子模块 | **与用户决策冲突**（lunwen 白名单跟踪刻意为之），不采纳 |
| RC-L1 | decoyd 无访问控制 | `cmd/decoyd/main.go` | 连接限速+hits 上限 | 实验工具 |
| RC-L3 | argon2id t 偏低 | `internal/securemode/crypt.go`（N=1） | OWASP t≥3 | 参数可调，GPU 对抗弱 |
| RC-L4 | 研究模块状态无持久化 | attackerstate/defensecycle/engagement/predictor | 持久化接口 | 研究阶段可接受，需文档标注 |
| RC-L5 | 新模块无测试 | agentinstall/semver/decoyd/exprunner/tracecheck | 补基础测试 | |

## 三、耦合审计 Minor 剩余（COUPLING_AUDIT_2026-09-03；C1/C2/F2/F3 已修 268cca9）

| 编号 | 项 | 方向 |
|---|---|---|
| F4 | comms 消费方式不统一（直接函数调用 vs kernel SPI） | 统一经 kernel 声明接口 |
| F5 | 孤儿包 `internal/oscal`/`semver`/`adapterhub`（0 import）；`historicalstore` 默认-on 无 tag | 下沉并入调用方 / 加 tag / 移 optional |
| F6 | config→checks 反向依赖（地基层向上依赖检查注册表） | 依赖显式化/解耦 |
| F7 | ACL 四包默认-on 无 tag（attackerstate/predictor/engagement/defensecycle） | 加 tag 与 optional 叙述对齐 |

## 四、研究方向

| # | 内容 | 状态 |
|---|---|---|
| ① | SSAM/SRD 情报可信度作为算法层原生变量（贝叶斯置信区间） | ✅ 完成（584b418/14652db/1bc2938 + 内仓 d21efc0/cd2c60b） |
| ② | 边缘因子耦合放大缺理论边界 → 基于真实数据的**向量图** + 边缘因子**变量化**（非常量进算法） | ❌ 未开始（设计文档待产出，含 v0.3.0 计划参考 docs/v0.3.0/VERSION_v0.3.0_PLAN.md） |

## 五、工程/研究债（非审计项）

| 项 | 说明 |
|---|---|
| 论文数字验证 | trace/敏感性表必须经 `cmd/tracecheck`（tag tracecheck）对照真实引擎验证；含 intent=unknown→maintain +3.0 陷阱 |
| E1–E9 上限标注 | 100% 意图追踪须保留"理想环境上限"限定，不得回退 |
| 扩展检查 sh -c 无超时 | `extmgr.buildExtCheckFunc` 命令分支无 context 超时（H-3 修路径未修执行超时） |
| gofmt 门禁 | CI 已加（本清单后 0682d6d/ab33d72 修复两分支），后续提交须过 |

## 六、建议下一批处理顺序

1. **快清项**（1-2 行级）：L-3/L-4/L-5、RC-L5 部分
2. **中等**：M-2、M-3、M-4、RC-L3
3. **设计类**：方向②（大）、RC-M4（并入方向②）、F4–F7（架构）
4. **不采纳/可延**：RC-M6（用户决策）、RC-L4、L-2
