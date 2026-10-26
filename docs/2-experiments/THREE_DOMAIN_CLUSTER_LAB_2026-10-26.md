# 三域集群实验环境（PVE SDN + OVS）2026-10-26

> 目的：用**单台 PVE + OVS** 搭出"三个域、两个 VLAN 隔离、一个三层 NAT"的真实网络，
> 供拓扑感知 / 跨域传播 / 隔离策略实验复用。**这是长期资产**，不要重复搭建。

## 1. 底座

| 组件 | 配置 |
|---|---|
| PVE | 9.2.21（kernel 7.0.14-25-pve） |
| OVS | **3.5.0**（`openvswitch-switch`，本次安装） |
| OVS 桥 | **`ovsbr0`**（无物理上行，纯实验 underlay） |
| SDN zone | **`asc3d`**：`type=vlan`，`bridge=ovsbr0` |
| vnet | `vnetA` tag **101**（域A）· `vnetB` tag **102**（域B）· `vnetC` tag **200**（域C 传输） |

SDN 对象由 PVE API 创建（`pvesh create /cluster/sdn/zones …` + `/cluster/sdn/vnets …` +
`pvesh set /cluster/sdn`）。应用后 OVS 上可见三个带 tag 的内部端口 `ln_vnetA/ln_vnetB/ln_vnetC`。

## 2. 节点清单

| CTID | 名称 | 角色 | 网络 | 核/内存 |
|---|---|---|---|---|
| **920** | `asc-domC-router` | **域C：三层 + NAT + VLAN 划分**（privileged） | `eth0` vnetA `172.22.10.1/24` · `eth1` vnetB `172.23.10.1/24` · `eth2` vnetC `100.64.0.1/24` · `eth3` vmbr0 `192.168.30.60/24` | 2 / 1024 MB |
| 921 | `asc-domA-web` | 域A 业务（agent `domA-web`） | vnetA `172.22.10.11/24` gw .1 | 1 / 512 MB |
| 922 | `asc-domA-db` | 域A 核心（agent `domA-db`） | vnetA `172.22.10.12/24` gw .1 | 1 / 512 MB |
| 923 | `asc-domB-web` | 域B 业务（agent `domB-web`） | vnetB `172.23.10.11/24` gw .1 | 1 / 512 MB |
| 924 | `asc-domC-mon` | 域C 监控（agent `domC-mon`） | vnetC `100.64.0.11/24` gw .1 | 1 / 512 MB |

既有资产：VM **910 `asc-kernel-vm`**（kernel，`192.168.30.50`，mTLS `:50051`）+ CT 911/912/913（平面 agent）。

## 3. 域C 的路由与策略（CT 920 内）

```
sysctl net.ipv4.ip_forward=1        # /etc/sysctl.d/99-asc-forward.conf
nft:  nat postrouting  oifname eth3 ip saddr {172.22.10.0/24,172.23.10.0/24,100.64.0.0/24} masquerade
nft:  filter forward   policy drop
      ct state established,related accept
      iifname eth0 oifname eth1 drop     # 域A → 域B 显式阻断
      iifname eth1 oifname eth0 drop     # 域B → 域A
      accept                              # 其余受控转发（含各域 → kernel）
```

## 4. 实测结果（2026-10-26）

| 检查 | 结果 |
|---|---|
| 域A 内部（921→922 同子网） | ✅ 通 |
| **域A ↔ 域B** | ✅ **双向阻断**（VLAN 隔离 + 域C forward 策略） |
| 域A → 域C 网关 | ✅ 通 |
| **域A → kernel（经域C NAT）** | ✅ 通 |
| **域B → kernel（经域C NAT）** | ✅ 通 |
| 域C → kernel | ✅ 直连 |
| agent 注册 | **7/7 active**（911/912/913 + domA-web/domA-db/domB-web/domC-mon），各自独立证书 |
| kernel 拓扑视图 | **7 节点、4 个子网段**：`192.168.30.5x/24`×3、`172.22.10.0/24`×2、`172.23.10.0/24`×1、`100.64.0.0/24`×1 |

⇒ 按现行拓扑判定（同子网 ⇒ 互达），预期传播边只有 **域A 内 1 条**（domA-web ↔ domA-db），
域B / 域C 与其它域**无边**（跨 VLAN/三层隔离）——这正是"三个域"要验证的形状。

## 5. 本次暴露的两个问题（待跟进，不在本文件范围外悄悄修）

1. **kernel 重启后 agent 不重新注册**：日志 `loaded identity bindings count=7` 后，agent 只发心跳；
   `topology list` 与 `agent list` 会显示 0 节点 / 全部 inactive，直到 `systemctl restart asscor-agent`
   让 agent 重新走注册路径。⇒ 需要"心跳即可重建拓扑/存活"的修复，或 kernel 启动后触发 re-register。
2. **~~多主机评估结果的落库路径未在日志中观测到~~（2026-10-27 查清：**是我看错了日志文件**，评估一直在跑、也在落库）**

   真因：`internal/cli/module.go:608` 在 CLI 启动后把 logger **重定向到相对路径
   `ASSCOR-kernel.log`**；systemd 的 cwd 是 `/` ⇒ 真实日志在 **`/ASSCOR-kernel.log`**，
   而单元里 `StandardOutput=append:/var/log/asscor-kernel.log` 只留下了启动段。
   这解释了"日志里一条评估都没有"的假象。

   实测（2026-10-27 01:2x，7 个真实 agent、三域）：

   | 证据 | 数值 |
   |---|---|
   | `/ASSCOR-kernel.log` 里 `msg="assessment result"` | **340 条** |
   | `/ASSCOR-kernel.log` 里 `heartbeat received` | 3250 条 |
   | `/var/lib/asscor/assessments-20261026.jsonl` | **7.6 MB**（持续追加） |
   | `/var/lib/asscor/latest-assessment.json` | 22477 字节 |
   | 逐主机分数样本 | `domC-mon` 40.42/40.53（80 检查）· `asc-agent-ct`/`ct2`/`ct3`/`domA-web`/`domA-db`/`domB-web` **均 46.75**（81 检查） |

   ⇒ **多主机评估是跑通的**（agent 心跳携带 81 条检查结果 → `EvaluateFromResults` → JSONL 落盘）。
   两个**真缺陷**（与"没落库"无关）已于 **2026-10-27 修复并部署验证**（提交 `e0e2819`）：
   - ~~日志重定向用相对路径~~ **已修**：只在 stdout 是终端时才重定向，路径一律绝对
     （`ASSCOR_LOG_FILE` > `ASSCOR_LOG_DIR` > `/var/log`）。
     部署验证：新 kernel 启动后 `/ASSCOR-kernel.log` **不再产生**；
     `/var/log/asscor-kernel.log` 内 `heartbeat received` 17 条、`processing check results` 7 条、
     `assessment result` 7 条（同一批 agent 重连后一分钟内）。
   - ~~gRPC 传输层丢字段~~ **已修**：`PBHeartbeatRequest` 补齐
     `InstalledCPEs`/`NetworkInfo`/`SecureMode`，并加 JSON codec
     （`grpc.ForceServerCodec`/`ForceCodec`；PB 类型是手写结构体、没有 `ProtoReflect`，
     默认 proto codec 编不了）。新增 `pbToHeartbeatRequest`/`heartbeatRequestToPB` 逐字段搬运，
     测试钉住往返一致。**注**：`[grpc]` 与 JSONRPC 仍同占 `.50051`（gRPC 启动报
     `address already in use`，`grpc=false`），这是**另一个**待办：给 gRPC 单独端口或默认关闭。

   **本次复现到的现象**：6 台 CT agent 分数**完全相同（46.75）**，只有 `domC-mon` 不同（40.4x）——
   正是 2026-08-16 审计里"同质主机同分"的结论，在真实三域多主机上再次出现。

## 6. 复用步骤

```bash
# 现状复核
pvesh get /cluster/sdn/vnets --output-format yaml
ovs-vsctl show | sed -n '/ovsbr0/,/ovs_version/p'
pct list | grep -E '^(920|921|922|923|924)'
# 域C 策略是否还在
pct exec 920 -- nft list ruleset
# 隔离验收
pct exec 921 -- ping -c1 -W1 172.23.10.11   # 必须失败
pct exec 921 -- ping -c1 -W1 192.168.30.50  # 必须成功（经 NAT）
# 拓扑视图
ssh -i /root/.ssh/asc_kernel asc@192.168.30.50 \
  'printf "topology list\nexit\n" | sudo -n ./asscor/bin/kernel --cli /opt/asscor/asscor-cli.sock'
```

## 7. 与 30 节点混沌设计的距离

本三域是**阶段 1**：VRF/重叠地址、非对称路由、VXLAN/GRE 叠加、OVS 流表旁路、混沌注入点
（`ovs-ofctl`/tc/BGP flap）、观测降级（cgroup 限额）都**尚未实现**；30 节点清单里的
FRR/OPNsense/VyOS/Suricata/ntopng 组件也都还没上。
下一步建议：先在域A/域B 各加 2–3 个同子网节点（验证"同域扩散"），再引 FRR-RR 做 underlay
与 VRF/重叠地址，最后才是混沌注入与观测降级。
