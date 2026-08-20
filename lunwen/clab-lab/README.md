# ASSCOR Containerlab 多主机测试环境 — 归档与复现说明

**归档日期**: 2026-08-16 | **关联审计**: `docs/audits/MULTIHOST_TOPO_AWARENESS_ASSESSMENT_2026-08-16.md`、`docs/audits/TOPO_COMPLEX_AUDIT_T1_T11_2026-08-16.md`

本目录归档 Containerlab 多主机 + 中形/复杂网络测试环境（18 节点 v3 拓扑）的可复现资产：拓扑定义、FRR 配置、部署/实验脚本、实验数据。

## 环境依赖

| 依赖 | 说明 |
|------|------|
| WSL2 + Containerlab ≥ 0.78 | 本机经 `ssh clab@localhost -p 2222`（免密） |
| Docker | WSL 内原生 docker（dockerd 需代理拉镜像，见 `scripts/make_base_img.sh`） |
| 本地镜像 | `asscor-node:base`（ubuntu 24.04 + iproute2/iputils-ping，一次性制作，之后零下载） |
| `frrouting/frr:latest` | FRR 路由器镜像（本地缓存） |
| 物理网卡（可选） | Intel 82580 经 Windows Hyper-V 外部交换机接入 s5720 真实网络（192.168.1.0/24），r1 MASQUERADE NAT 出口 |

## 拓扑（v3 — 18 节点）

```
s5720 ── 82580 ── r1 (核心, NAT+OSPF 默认宣告) ── edge0 (ASSCOR-kernel :50051)
  汇聚层环形冗余: r2─r3─r4─r5─r2 (4 条环链 → ECMP 多路径)
  接入: r2→host1/2/9, r3→host3/4/10, r4→host5/6/11, r5→host7/8/12
  12 台主机分属 12 个独立 /24，独立 mTLS 证书
```

## 复现步骤

```bash
# 1. 上传资产到 clab 主机
scp -P 2222 -r docs/clab-lab/* clab@localhost:~/clab/asscor/

# 2. 制作本地基础镜像（一次性，需代理）
bash scripts/make_base_img.sh        # 依赖代理 http://<WSL网关>:58187

# 3. 部署拓扑
cd ~/clab/asscor
sudo containerlab deploy -t asscor.clab.yml

# 4. 部署 kernel + 12 agents（脚本内置：kernel 启动、CA 导出、host1-12 证书签发、分发、启动）
bash scripts/deploy_v3_all.sh

# 5. 触发全量评估并采集
bash scripts/baseline.sh

# 6. 网络/拓扑验证
bash scripts/verify_v3.sh    # 环路稳定 + 跨子网 + 真实网络出口
bash scripts/ecmp_check.sh   # ECMP 多路径

# 7. T1-T11 实验（audit 用）
bash scripts/t5_t8.sh   # 节点上下线 + 单点失效
bash scripts/t6.sh      # 路由变化
bash scripts/t7.sh      # 服务迁移
bash scripts/t9t10t11.sh # 噪声/聚焦/复杂拓扑
```

## 已知注意事项（复现踩坑记录）

1. **ubuntu 容器缺 iproute2/iputils-ping** → `asscor-node:base` 镜像预装（exec 不再 apt，省 VPN 流量）
2. **默认路由**：containerlab mgmt 默认路由优先级高，主机需 `ip route replace default via <网关>`；汇聚路由器删 mgmt 默认 + 静态默认经 OSPF 对端
3. **agent `--cert-dir` 必须显式传**（flag 默认值 "certs" 非空，覆盖配置文件 cert_dir）
4. **进程管理**：容器内用 `pgrep -x ASSCOR-agent`（`-f` 会匹配 bash 自身导致自杀）
5. **kernel 日志**：拓扑/网络信息是 Debug 级，需 `--log-level=debug` 采集
6. **省流量**：destroy/deploy 复用 `asscor-node:base`（零下载）；仅 `make_base_img.sh` 与首次拉 frr/ubuntu 消耗 VPN

## 数据文件

| 文件 | 内容 |
|------|------|
| `data/assessments-v3.jsonl` | 12 台主机多轮评估（含 propagation_edges、PRISM 状态） |
| `data/assessments-r2/r3.jsonl` | 差异化实验轮（host1 合规/坏配置对比） |
| `data/latest-assessment.json` | kernel 持久化的最新评估快照 |
