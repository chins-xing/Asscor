# ACL — Attacker Cognitive Loop 扩展包

**Attacker Cognitive Loop**（ACL）是 ASSCOR 的引导式主动防御扩展：持续估计攻击者状态、预测下一动作概率分布、按效用函数选择欺骗干预，并由闭环控制器在 contain / collect / engage 三策略间切换。

- 论文：*"Attacker Cognitive Loop: An Interpretable Rule-Based Engine for Estimating, Predicting, and Engaging Adaptive Attackers"*（`lunwen/paper/`）
- 实验手册与数据：`lunwen/attachment/`

## 组件清单

| 模块 | 位置 | 说明 |
|------|------|------|
| 状态引擎 | `internal/attackerstate/` | OldState + Evidence → NewState（意图推断/TTP→意图表） |
| 预测引擎 | `internal/predictor/` | 六动作分布（评分+softmax）、TTP 投影 |
| 对抗规划 | `internal/engagement/` | 效用 U=α·IG+β·DP+γ·AV−δ·Risk、诱饵目录 |
| 闭环控制器 | `internal/defensecycle/` | contain/collect/engage 策略、决策锐度 |
| 轻量诱饵 | `optional/adversary/packages/mitre-engage/` | 蜜罐端口/蜜标/蜜凭证（传感器） |
| 实验编排器 | `cmd/exprunner/`（tag `expr`） | 闭环实验（E1-E9 + 对比组） |
| 诱饵守护 | `cmd/decoyd/`（tag `decoyd`） | 容器内诱饵监听 |
| 复现校验 | `cmd/tracecheck/`（tag `tracecheck`） | 复现论文 trace/敏感性表 |

## 安装

### 前置条件

- Go ≥ 1.26
- 仓库在 `ASSCOR-Research-Core` 分支（ACL 所在分支）
- （复现实验）WSL2 + Docker + containerlab + 24 节点拓扑资产（`lunwen/clab-lab/`）

### 步骤

```bash
# 1. 进入分支
git checkout ASSCOR-Research-Core

# 2. 构建（引擎是 internal 包，随主仓库编译；工具用 build tag 独立构建）
go build ./...                          # 引擎 + 内核
GOOS=linux go build -tags tracecheck -o tracecheck ./cmd/tracecheck   # 复现校验工具
GOOS=linux go build -tags expr   -o exprunner ./cmd/exprrunner        # 实验编排器
GOOS=linux go build -tags decoyd -o decoyd   ./cmd/decoyd             # 诱饵守护

# 3. 运行单元测试（引擎自检）
go test ./internal/attackerstate/ ./internal/predictor/ ./internal/engagement/ ./internal/defensecycle/
```

## 配置

### 引擎参数（默认值，位于 `internal/predictor/predictor.go`、`internal/engagement/engagement.go`）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `w_int`（意图延续权重） | 3.0 | 当前意图对应动作的加分 |
| `T`（softmax 温度） | 1.0 | 分布尖锐度 |
| `θ`（锐度阈值） | 0.3 | 低于→collect，高于→engage |
| `α,β,γ,δ`（效用权重） | 1.0, 0.8, 0.6, 1.2 | IG/DP/AV/Risk 权重 |
| 诱饵目录 | 5 类 | fake SSH/credential/document/web/scan port |

### 部署到 24 节点实验拓扑

```bash
# 拓扑与 kernel/agent 部署（见 lunwen/attachment/manual/EXPERIMENT_MANUAL.md）
cp build/ASSCOR-kernel-v0.2.3-linux-amd64 /tmp/ASSCOR-kernel
cp build/ASSCOR-agent-v0.2.3-linux-amd64  /tmp/ASSCOR-agent
cp lunwen/clab-lab/kernel-config.ini      /tmp/kernel-config.ini
bash lunwen/clab-lab/scripts/exp_deploy_all.sh   # kernel + CA + 18 agents
```

## 复现

### 1. 论文 trace / 敏感性表

```bash
go run -tags tracecheck ./cmd/tracecheck
# 输出：4 轮闭环 trace（R1 contain→R4 engage）+ w_int/T 敏感性表
```

### 2. 完整实验（E1-E9 + 对比组）

```bash
# 前置：24 节点拓扑已部署、kernel + 18 agents 运行
cp build/exprunner-linux-amd64 /tmp/exprunner
cp build/decoyd-linux-amd64    /tmp/decoyd

# E1-E9（ACL 动态模式）
bash lunwen/clab-lab/scripts/exp_rerun_all.sh

# 对比组 C1/C2/C3（同一凭据攻击场景，三种干预模式）
bash lunwen/clab-lab/scripts/exp_cr_final.sh

# 分析
python3 lunwen/clab-lab/scripts/exp_final_summary.py
```

### 3. 数据与结果

- 原始 JSONL：`lunwen/clab-lab/data/experiments-final/`（E1-E9 + CR-C1/C2/C3）
- 每轮记录：round/mode/evidence/intent/sharpness/strategy/deployed_ports/decoy_hits/ground_truth/latency_ms
- 论文结果表：tex `tab:results` / `tab:cr`；md `11.1.5 Results`

## 删除

### 完全移除扩展（引擎不参与编译）

```bash
# 1. 停止实验相关进程
docker exec <target> pkill -9 -x decoyd        # 用 -x 精确匹配（-f 会误杀 exprunner）
pkill -f exprunner

# 2. 从构建中排除（如需）：
#    internal/ 的四个 ACL 包是普通包，随 go build 编译。
#    若要整体移除，删除以下目录并清理引用：
git rm -r internal/attackerstate internal/predictor internal/engagement internal/defensecycle
git rm -r cmd/exprunner cmd/decoyd cmd/tracecheck
git rm -r optional/adversary/packages/acl
#    （诱饵 mitre-engage 如不再需要：）
git rm -r optional/adversary/packages/mitre-engage

# 3. 移除实验数据/附件（lunwen/ 本就不被 git 跟踪，直接删除目录）
rm -rf lunwen

# 4. 确认构建干净
go build ./...
go test ./...
```

### 恢复

```bash
git checkout ASSCOR-Research-Core -- internal/attackerstate internal/predictor \
  internal/engagement internal/defensecycle cmd/exprunner cmd/decoyd cmd/tracecheck \
  optional/adversary/packages/acl optional/adversary/packages/mitre-engage
```

## 安全注意

- 仅用于**合法防御场景**（授权环境内的红队/蓝队演练）
- 诱饵部署遵循 sufficiency 原则：诱饵是短暂的、与生产 air-gapped，出站连接即重置（防跳板）
- 实验数据（JSONL）仅来自本仓库拓扑上的真实运行

## 许可证

Apache License 2.0（与 ASSCOR 主仓库一致）。
