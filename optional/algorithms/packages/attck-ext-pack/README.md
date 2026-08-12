# ATT&CK V19 Extension Pack 使用指南

## 概述

MITRE ATT&CK V19 框架的威胁分析扩展包。提供检测分析、威胁情报、对手仿真、评估工程、APT 归因和威胁狩猎六大能力。

## 安装与启用

### 方式 1: Build Tag (推荐)

```bash
# 构建带 ATT&CK 模块的内核
go build -tags attck_ext -o ASSCOR-kernel-linux ./cmd/kernel/

# 验证
./ASSCOR-kernel-linux --version
# 输出: ASSCOR Kernel v0.2.2 (SSAM 2.0)
# 日志中应包含: "plugin registered name=attck"  (17 plugins total)
```

### 方式 2: 检查当前是否已启用

```bash
/opt/asscor/ASSCOR-kernel --version
# 查看插件列表是否包含 attck
# CLI 中执行: attck summary

# 未启用时 CLI 显示: "ATT&CK module is not loaded"
```

## 模块组成

| 子模块 | 文件 | 功能 |
|------|------|------|
| **核心** | `attck.go` | 14 战术/180+ 技术矩阵、覆盖率、杀伤链、APT 匹配、风险预测 |
| **检测** | `attck_detection.go` | 10 条默认检测规则、告警关联、行为分析 |
| **威胁情报** | `attck_ti.go` | IOC 管理、威胁行为体画像、TTP 追踪 |
| **仿真** | `attck_emulation.go` | 场景管理、APT→场景自动生成 |
| **评估** | `attck_assessment.go` | 差距分析、控制映射、缓解建议 |
| **APT 归因** | `attck_apt_*.go` (5 文件) | 攻击链重构、贝叶斯归因、行为/信标检测、威胁狩猎、因果推断 |
| **增强** | `attck_apt_enhanced.go` | YARA/Sigma 规则、信誉管理、跨主机分析 |

## 配置

在 `config.ini` 中启用：

```ini
[attck]
enabled = true
version = "v19"
beacon_threshold = 0.7
attribution_threshold = 0.6
safe_emulation = true
```

## 扩展点

模块触发 13 个扩展点：

| 扩展点 | 时机 |
|------|------|
| `attck.coverage.complete` | 覆盖率分析完成后 |
| `attck.detection.alert` | 检测规则触发告警 |
| `attck.detection.anomaly` | 高分异常检测 |
| `attck.behavioral.alert` | 行为指标评估触发 |
| `attck.behavioral.beacon` | C2 Beaconing 检测到 |
| `attck.emulation.complete` | 对手仿真完成 |
| `attck.apt.hunt_confirmed` | 狩猎假设确认 |
| `attck.apt.chain_detected` | 攻击链重构完成 |
| `attck.apt.matched` | APT 组织匹配 |
| `attck.apt.attribution` | 贝叶斯归因执行 |
| `attck.risk.predicted` | 预测性风险评估完成 |
| `attck.assessment.complete` | 差距分析完成 |
| `attck.apt.report_generated` | APT 分析报告生成 |

## 测试

```bash
go test -tags attck_ext ./internal/kernel/ -run "TestATTACK|TestAPT|TestKillChain|TestPredictive"
```

## 许可证

MIT — 与 ASSCOR 主项目相同
