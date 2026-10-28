# T4 联邦实验环境（主 kernel + 3 节点 kernel + 30 agent）2026-10-28

> **状态（2026-10-28 13:xx）**：本文是**配置与验收资产**的落地说明；仓库内新增
> `configs/federation/`、`scripts/gen-agent-configs.sh`、`scripts/federation-verify.sh`。
> PVE 侧 CT 创建/证书签发由基建子代理执行（CT 930/931/932 已 running，agent CT 940-969 待建）。
> 联邦代码 `internal/federation` 由 federation-dev 并行实现，本文中标 **TODO(federation-dev)**
> 的端点/命令名以最终实现为准。
>
> 目标：**同一张网络**里跑**三套不同模型参数**的 SRD 评估，用"主 kernel 汇总 + 3 个节点
> kernel 各自评估"的联邦形态演示"单网络、多配置、多模型"。

## 1. 总体结构与"数据面 / 控制面分离"

```
                         控制面（vmbr0 / 192.168.30.0/24）
   ┌──────────────────────────────────────────────────────────────────┐
   │                     主 kernel  VM 910 / 192.168.30.50             │
   │  :50051 JSON-RPC（既有 10 个实验 agent）  :50052 gRPC（既有）      │
   │  [federation] role=master  HTTP :5099 ← 只收节点摘要（每 30s）     │
   │  CLI: federation status（TODO 命令名）                            │
   └───────────────▲──────────────────────────▲───────────────▲───────┘
                   │ HTTP 上报（token=asscor-t4-demo）          │
        ┌──────────┴─────────┐      ┌─────────┴──────────┐   ┌─┴──────────────────┐
        │ 节点 kernel nk1     │      │ 节点 kernel nk2     │   │ 节点 kernel nk3     │
        │ CT 930 .71:50051    │      │ CT 931 .72:50051    │   │ CT 932 .73:50051    │
        │ 独立 CA + nk1.ini   │      │ 独立 CA + nk2.ini   │   │ 独立 CA + nk3.ini   │
        └──▲───▲───▲───▲──────┘      └──▲──▲──▲──▲─────────┘   └──▲──▲──▲──▲────────┘
           │   │   │   │  10 agents      │  │  │  │ 10 agents       │  │  │  │ 10 agents
        CT 940-949                CT 950-959                  CT 960-969
           │ eth1 mgmt .101-.110    eth1 .111-.120              eth1 .121-.130
           │ eth0 数据面 vnetA/B/C/D 轮转（172.22 / 172.23 / 100.64 / 172.26）
           ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ 数据面（OVS ovsbr0 + SDN asc3d）：只承载 agent→agent 的业务拓扑   │
   │ 节点 kernel 与主 kernel 都**不进数据面** —— 联邦层只传聚合摘要   │
   └──────────────────────────────────────────────────────────────────┘
```

要点：

1. **控制面** = `vmbr0` 管理网 `192.168.30.0/24`：节点 kernel 的 `:50051`（agent 上报）、
   主 kernel 的 `:5099`（节点摘要收集）全在这张网；agent 用 eth1 接管理网。
2. **数据面** = 既有 SDN `vnetA/B/C/D`：agent 用 eth0 接入，节点 kernel **只有一张 mgmt 网卡**，
   看不到数据面。这样"拓扑在图里"与"联邦在上报里"彻底分离。
3. **agent 只能连所属节点 kernel** 不靠配置自觉，靠 mTLS：每节点 kernel 首次启动生成**自己的 CA**，
   该节点 10 张 agent 证书由它签发；主 kernel（910）**没有**给这 30 个 agent 签任何证书，
   指纹绑定（`BindAgentCert`）也不存在 ⇒ 即使 agent 把地址改成 192.168.30.50，
   TLS 握手就会因 CA 不匹配被拒。
4. 节点 kernel 的 `[topology] exclude_cidrs` 显式排除 `192.168.30.0/24`，否则 10 台 agent
   共享 mgmt /24 会被判"全互达"（P0-2/T4 假传播）。

## 2. CT / 网络规划

### 2.1 既有资产（本实验不动）

| 资产 | 说明 |
|---|---|
| VM **910** `asc-kernel-vm` | 主 kernel，`192.168.30.50`；`:50051` JSON-RPC、`:50052` gRPC（mTLS） |
| CT **911/912/913** | 平面实验 agent（`.51/.52/.53`），保持连接主 kernel |
| CT **920-927** | 三域背景（router/pivot/shadow 等），占用 vnetA-D 的 `.1/.11/.12/.20` |

### 2.2 本实验新增（33 台）

| 角色 | CT | hostname | 控制面 mgmt | 数据面 | 规格 |
|---|---|---|---|---|---|
| 节点 kernel | **930** | `asc-nk1` | `192.168.30.71/24` | 无（单网卡） | 2C/1024MB/8G |
| 节点 kernel | **931** | `asc-nk2` | `192.168.30.72/24` | 无 | 2C/1024MB/8G |
| 节点 kernel | **932** | `asc-nk3` | `192.168.30.73/24` | 无 | 2C/1024MB/8G |
| agent ×10 | **940-949** | `asc-agt-nk1-01..10` | `192.168.30.101-110` | eth0 vnet 轮转 | 1C/256MB |
| agent ×10 | **950-959** | `asc-agt-nk2-01..10` | `192.168.30.111-120` | eth0 vnet 轮转 | 1C/256MB |
| agent ×10 | **960-969** | `asc-agt-nk3-01..10` | `192.168.30.121-130` | eth0 vnet 轮转 | 1C/256MB |

> `/root/t4/inventory.tsv` 是**唯一事实来源**（基建子代理维护：vmid、hostname、模板、vnet、
> mgmt IP、所属节点 kernel、cert 指纹）。本文表格与 `scripts/gen-agent-configs.sh` 的内置清单
> 按同一规划生成；若基建清单不同，以 inventory 为准（脚本支持 `--manifest` 覆盖）。

### 2.3 vnet 分配（复用既有 SDN，不新建）

| vnet | SDN tag | 子网 | 网关 | 本实验 agent 数据 IP | 既有占用（避开） |
|---|---|---|---|---|---|
| `vnetA` | 101 | `172.22.10.0/24` | 172.22.10.1（CT 920） | `.101-.108` | `.1` `.11` `.12` |
| `vnetB` | 102 | `172.23.10.0/24` | 172.23.10.1 | `.101-.108` | `.1` `.11` `.20` |
| `vnetC` | 200 | `100.64.0.0/24` | 100.64.0.1 | `.101-.107` | `.1` `.11` |
| `vnetD` | 300 | `172.26.0.0/24` | 172.26.0.1 | `.101-.107` | `.1` `.11` `.12` `.20` |

**轮转规则**：按全局序号 `n = vmid - 940`，`vnet = [A,B,C,D][n % 4]`；每个 vnet 内序号从 `.101`
递增。因此**每个节点组内部**都同时覆盖 4 个 vnet（不是"一组一个 vnet"），节点 kernel 的
拓扑才有多子网形状。30 行明细见 §5。

## 3. 模板差异

### 3.1 CT 模板（三套，供 30 个 agent 轮转，避免"30 台一模一样"）

| 模板 | 用途 | 差异 |
|---|---|---|
| `tpl-asscor-min` | 最小镜像 | 基础系统 + openssh + chrony |
| `tpl-asscor-web` | Web/加固型 | + nginx/常见 web 包；sshd 收紧、umask 022 |
| `tpl-asscor-mon` | 监控/日志型 | + rsyslog/sysstat、日志轮转配置 |

每组 10 台按 4/3/3 轮转三套模板（具体以 inventory.tsv 的"模板"列为准）。

### 3.2 节点 kernel 配置模板差异（本实验核心：同网络、不同模型）

| 参数 | `nk1.ini`（CT 930） | `nk2.ini`（CT 931） | `nk3.ini`（CT 932） |
|---|---|---|---|
| `[prism] debt_alpha` | 1.2 | 1.5 | 1.8 |
| `[prism] path_decay` | 0.80 | 0.65 | 0.50 |
| `[prism] max_path_depth` | 5 | 7 | 9 |
| `[prism] aggregation` | `rss` | `max` | `linear` |
| `[prism] prop_cap / debt_cap` | 0.25 / 0.30 | 0.30 / 0.35 | 0.35 / 0.40 |
| `[prism] debt_norm_days` | 1500 | 1200 | 900 |
| `[prism] score_floor` | 0.15 | 0.20 | 0.25 |
| `[prism] collapse_beta` | 1.5 | 1.8 | 2.2 |
| `[prism] horizon_days` | 7 | 14 | 21 |
| `[prism] default_transmission` | 0.30 | 0.35 | 0.40 |
| `[prism] 语义阈值 stable/degraded/untrusted` | .90/.70/.50 | .92/.72/.52 | .95/.75/.55 |
| `[srd] layered_graph` | true | true | true |
| `[srd] roles` | 无（对照组） | 4 条，2 类角色：`db`×2、`web`×2 | 4 条，3 类角色：`monitor`、`shadow`、`router`×2 |
| `[srd] horizon_days / sync_interval_sec` | 7 / 3600 | 14 / 1800 | 21 / 900 |
| `[federation]` | `role=node, node_id=nk1, master_url=http://192.168.30.50:5099, report_interval_sec=30, token=asscor-t4-demo` | 同理 `node_id=nk2` | 同理 `node_id=nk3` |

三套配置共同的约定：

- `[log] format=text`（验收脚本 grep `prism effective config` / `heartbeat received` 更稳）；
- `[grpc] enabled=false, listen_addr=:50052`（agent 走 `--listen :50051` 的 JSON-RPC over mTLS；
  `[grpc]` 与 `--listen` 同端口会让 kernel 启动即失败，2026-10-27 已踩过）；
- `[comms] require_mtls=true`；
- `[topology] exclude_cidrs = 192.168.30.0/24,127.0.0.0/8,169.254.0.0/16`；
- TLS 证书目录**不是配置键**，是启动参数 `--cert-dir /etc/asscor/certs`；
- 未写出的键使用内置默认值（例如 `[spc]` 默认关闭，避免 3 个节点重复拉 CVE 源）。

`roles` 左侧主机名必须等于该节点下 agent 的 `host_id`（内置清单为 `asc-agt-nk<g>-<idx>`）；
若基建实际 hostname 不同，部署前按 inventory 替换，否则角色不生效（但 `roles` 条数仍会计入
`SRD effective config` 的日志）。

## 4. 证书与身份绑定（"agent 只连所属节点"的强制手段）

```
每个节点 kernel 首启（--cert-dir /etc/asscor/certs）：
  /etc/asscor/certs/ca.crt|ca.key        ← 本节点独立 CA（三节点互不相同）
  /etc/asscor/certs/server.crt|server.key← 本节点 gRPC/JSON-RPC 服务端证书
  /etc/asscor/certs/agent.crt|agent.key  ← 首启生成的默认客户端证书（多 agent 时不用它）

为每个 agent 单独签发（必须在节点 kernel 自己的 CT 内、用它的 CA）：
  kernel --issue-agent-cert <host_id> --cert-dir /etc/asscor/certs \
         --issue-out /root/t4/certs/<host_id>
  # 产出：/root/t4/certs/<host_id>/<host_id>.crt 与 .key
然后推进 agent CT：
  /etc/asscor/certs/ca.crt     ← 节点 930 的 ca.crt
  /etc/asscor/certs/agent.crt  ← <host_id>.crt
  /etc/asscor/certs/agent.key  ← <host_id>.key
```

为什么必须一 agent 一证书：kernel 把 `host_id` 与证书指纹绑定，**共用同一张 agent.crt 的
第二个 agent 会注册失败**（`certificate identity conflict`）。

agent 的 `tls_server_name` 必须写成**所属节点 kernel 的 hostname**（`asc-nk1/2/3`）：
节点 kernel 首启生成的 `server.crt` 只含 DNS SAN（CommonName、`localhost`、签发时的本机
hostname），**不含** `192.168.30.7x` 的 IP SAN。agent 用 IP 直连 + 显式 `tls_server_name`
才能通过证书校验，从而避免 `tls_skip_verify=true`。

## 5. 30 个 agent 分组表

| vmid | hostname | 节点 kernel | mgmt IP | 数据面 |
|---|---|---|---|---|
| 940 | `asc-agt-nk1-01` | nk1 / `192.168.30.71:50051` | 192.168.30.101 | vnetA `172.22.10.101` |
| 941 | `asc-agt-nk1-02` | nk1 | 192.168.30.102 | vnetB `172.23.10.101` |
| 942 | `asc-agt-nk1-03` | nk1 | 192.168.30.103 | vnetC `100.64.0.101` |
| 943 | `asc-agt-nk1-04` | nk1 | 192.168.30.104 | vnetD `172.26.0.101` |
| 944 | `asc-agt-nk1-05` | nk1 | 192.168.30.105 | vnetA `172.22.10.102` |
| 945 | `asc-agt-nk1-06` | nk1 | 192.168.30.106 | vnetB `172.23.10.102` |
| 946 | `asc-agt-nk1-07` | nk1 | 192.168.30.107 | vnetC `100.64.0.102` |
| 947 | `asc-agt-nk1-08` | nk1 | 192.168.30.108 | vnetD `172.26.0.102` |
| 948 | `asc-agt-nk1-09` | nk1 | 192.168.30.109 | vnetA `172.22.10.103` |
| 949 | `asc-agt-nk1-10` | nk1 | 192.168.30.110 | vnetB `172.23.10.103` |
| 950 | `asc-agt-nk2-01` | nk2 / `192.168.30.72:50051` | 192.168.30.111 | vnetC `100.64.0.103` |
| 951 | `asc-agt-nk2-02` | nk2 | 192.168.30.112 | vnetD `172.26.0.103` |
| 952 | `asc-agt-nk2-03` | nk2 | 192.168.30.113 | vnetA `172.22.10.104` |
| 953 | `asc-agt-nk2-04` | nk2 | 192.168.30.114 | vnetB `172.23.10.104` |
| 954 | `asc-agt-nk2-05` | nk2 | 192.168.30.115 | vnetC `100.64.0.104` |
| 955 | `asc-agt-nk2-06` | nk2 | 192.168.30.116 | vnetD `172.26.0.104` |
| 956 | `asc-agt-nk2-07` | nk2 | 192.168.30.117 | vnetA `172.22.10.105` |
| 957 | `asc-agt-nk2-08` | nk2 | 192.168.30.118 | vnetB `172.23.10.105` |
| 958 | `asc-agt-nk2-09` | nk2 | 192.168.30.119 | vnetC `100.64.0.105` |
| 959 | `asc-agt-nk2-10` | nk2 | 192.168.30.120 | vnetD `172.26.0.105` |
| 960 | `asc-agt-nk3-01` | nk3 / `192.168.30.73:50051` | 192.168.30.121 | vnetA `172.22.10.106` |
| 961 | `asc-agt-nk3-02` | nk3 | 192.168.30.122 | vnetB `172.23.10.106` |
| 962 | `asc-agt-nk3-03` | nk3 | 192.168.30.123 | vnetC `100.64.0.106` |
| 963 | `asc-agt-nk3-04` | nk3 | 192.168.30.124 | vnetD `172.26.0.106` |
| 964 | `asc-agt-nk3-05` | nk3 | 192.168.30.125 | vnetA `172.22.10.107` |
| 965 | `asc-agt-nk3-06` | nk3 | 192.168.30.126 | vnetB `172.23.10.107` |
| 966 | `asc-agt-nk3-07` | nk3 | 192.168.30.127 | vnetC `100.64.0.107` |
| 967 | `asc-agt-nk3-08` | nk3 | 192.168.30.128 | vnetD `172.26.0.107` |
| 968 | `asc-agt-nk3-09` | nk3 | 192.168.30.129 | vnetA `172.22.10.108` |
| 969 | `asc-agt-nk3-10` | nk3 | 192.168.30.130 | vnetB `172.23.10.108` |

## 6. 启动顺序（严格按序）

前提：仓库代码包含 `federation` 插件（federation-dev 交付），且 kernel 二进制用
`-tags "…,engine,…,federation"` 构建（`engine` 必须有，否则日志里没有
`prism effective config`，验收项 8 无法完成；`federation` 缺了节点不会上报、master 不监听
`:5099`）。

1. **构建/分发 kernel 二进制**（主机 `/root/t4/build` 源码树）：

   ```bash
   cd /root/t4/build
   MODULE_TAGS="heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine,oscal,expr,edgeexp,federation"
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags "$MODULE_TAGS" -o /tmp/asscor-kernel-fed ./cmd/kernel
   ```

2. **节点 kernel 配置与首启**（3 台依次，先起 kernel 再签发 agent 证书）：

   ```bash
   # 配置：仓库 configs/federation/nk{1,2,3}.ini → CT 930/931/932:/etc/asscor/kernel.ini
   pct push 930 /root/t4/configs/nk1.ini /etc/asscor/kernel.ini
   # 二进制
   pct push 930 /tmp/asscor-kernel-fed /opt/asscor/bin/kernel --perms 0755
   # systemd 单元（ExecStart 关键行）
   #   /opt/asscor/bin/kernel --config /etc/asscor/kernel.ini \
   #       --listen :50051 --cert-dir /etc/asscor/certs \
   #       --log-format text --log-level info
   pct exec 930 -- systemctl enable --now asscor-kernel
   # 首启会生成 /etc/asscor/certs/ca.{crt,key}、server.{crt,key}
   pct exec 930 -- ls -la /etc/asscor/certs
   ```

   预期日志：`gRPC server ...`（若启用）/`CA SHA256` /`prism effective config`
   `debt_alpha=1.2 path_decay=0.8 max_path_depth=5 aggregation=rss`。

3. **签发 10 张 agent 证书并下发**（每个节点用**自己的** CA）：

   ```bash
   for i in $(seq -w 1 10); do
     pct exec 930 -- /opt/asscor/bin/kernel --issue-agent-cert "asc-agt-nk1-$i" \
       --cert-dir /etc/asscor/certs --issue-out /root/t4/certs/asc-agt-nk1-$i
   done
   # 每个 agent CT：/etc/asscor/certs/{ca.crt=<nk1 ca.crt>,agent.crt=<host>.crt,agent.key=<host>.key}
   ```

4. **agent 配置与启动**（30 台；`agent.ini` 由生成脚本产出）：

   ```bash
   # 在宿主生成（已内置清单；也可 --manifest 用 inventory 转换后的 6 列 TSV）
   bash /root/t4/scripts/gen-agent-configs.sh
   # /root/t4/agent-configs/<hostname>.ini → CT:/etc/asscor/agent.ini（+ 证书）
   ```

   关键键（来自 agent 代码真实读取的 `[agent]` 键，非猜测）：`kernel_addr`、`host_id`、
   `hostname`、`heartbeat_sec=30`、`check_interval_sec=120`、`check_timeout_sec=10`、
   `max_retries=3`、`reconnect_sec=5`、`tls_enabled=true`、`tls_skip_verify=false`、
   `tls_server_name=<asc-nk1/2/3>`、`cert_dir=/etc/asscor/certs`、`log_format=text`。

   ⚠️ **agent.ini 不够，运行参数必须显式给 `--kernel` 与 `--cert-dir`**：
   `cmd/agent/main.go` 在加载配置后执行 `cfg.KernelAddr = *kernelAddr`（无条件覆盖），
   而 `--kernel` 的默认值是 `127.0.0.1:50051`；`cfg.CertDir` 也会被 `--cert-dir`
   的默认值 `certs` 覆盖。也就是说 agent.ini 里的 `kernel_addr` / `cert_dir` 单独放
   **不会生效**。systemd 单元必须写成（示例）：

   ```ini
   [Service]
   ExecStart=/usr/local/bin/asscor-agent --config /etc/asscor/agent.ini \
       --kernel 192.168.30.71:50051 --tls --cert-dir /etc/asscor/certs \
       --log-format text --log-level info
   ```

   （`--kernel`/`--cert-dir` 每台按所属节点 kernel 的 IP 填 `192.168.30.71/72/73`；
   验收脚本第 3 项会同时检查 agent.ini 与进程 cmdline，缺一即 FAIL。）

5. **主 kernel 合并 `[federation]` 并重启**（**不要覆盖** `/home/asc/asscor/etc/kernel.ini`）：

   ```bash
   ssh -i /root/.ssh/asc_kernel asc@192.168.30.50
   cp /home/asc/asscor/etc/kernel.ini /home/asc/asscor/etc/kernel.ini.bak-$(date +%F-%H%M%S)
   cat /root/t4/configs/master.ini >> /home/asc/asscor/etc/kernel.ini   # 只追加 [federation] 段
   sudo systemctl restart asscor-kernel
   ```

   重启会短暂断开 910 上既有 10 个实验 agent（属预期，会自动重连）。

6. **等待 60-180s**（节点每 30s 上报；agent 首轮完整评估 `check_interval_sec=120`），
   然后跑验收：`bash /root/t4/scripts/federation-verify.sh`。

## 7. 验收命令与预期输出

### 7.1 一键验收

```bash
# 在 PVE 宿主 dl360gen9 上（root）
bash /root/t4/scripts/federation-verify.sh; echo rc=$?
```

预期（全部就绪时，PASS=18 FAIL=0）：

```
[PASS] 1) 33 台 CT 全部 running（930 931 932 + 940-969）
[PASS] 2.1) CT 930 (asc-nk1/nk1) 配置正确：role=node, debt_alpha=1.2 path_decay=0.80 depth=5 aggregation=rss, kernel active
[PASS] 2.2) CT 931 (asc-nk2/nk2) 配置正确：role=node, debt_alpha=1.5 path_decay=0.65 depth=7 aggregation=max, kernel active
[PASS] 2.3) CT 932 (asc-nk3/nk3) 配置正确：role=node, debt_alpha=1.8 path_decay=0.50 depth=9 aggregation=linear, kernel active
[PASS] 3) 30 个 agent.ini 均指向所属节点 kernel（…），TLS/cert_dir/心跳参数正确
[PASS] 4.1) CT 930 (asc-nk1) :50051 上有 10 条会话（≥10）
[PASS] 4.2) CT 931 (asc-nk2) :50051 上有 10 条会话（≥10）
[PASS] 4.3) CT 932 (asc-nk3) :50051 上有 10 条会话（≥10）
[PASS] 5.1) CT 930 (asc-nk1) 日志：10/10 agent 心跳（heartbeat received=…），assessment result=…
…（5.2/5.3 同）
[PASS] 6) 主 kernel 192.168.30.50 :50051 无 30 个 agent 的会话（ss 比对 30 个 mgmt IP，日志无 host_id 命中）
[PASS] 7) 主 kernel federation status 列出 nk1 nk2 nk3（CLI 可用）
[PASS] 8.1/8.2/8.3) …prism 生效参数 = …（与 nk*.ini 一致）
[PASS] 8.9) 三节点 prism 参数两两不同（nk1: … | nk2: … | nk3: …）
[PASS] 9) 三节点 kernel CA 指纹互不相同（各节点 agent 证书由各自 CA 签发 ⇒ mTLS 强制隔离）
SUMMARY: PASS=18 FAIL=0 WARN=0 INFO=0
RESULT: PASS（rc=0）
```

脚本内部检查项（输出 PASS/FAIL，rc=1 表示失败；WARN/INFO 不影响 rc）：

1. 33 台 CT running（930-932、940-969）；
2. 3 个节点 kernel 的 `/etc/asscor/kernel.ini` 的 `[federation]` 与 `[prism]` 参数与模板一致、
   服务 `active`，并检查 `[topology] exclude_cidrs`（缺失只 WARN）；
3. 解析 30 个 `agent.ini`：`kernel_addr` 必须等于所属节点 IP、`host_id` 等于 CT 实际 hostname、
   `tls_enabled=true`、`cert_dir=/etc/asscor/certs`、`tls_server_name=asc-nk<g>`、
   心跳/评估/重连参数正确；
4. 每个节点 `:50051` 会话数 ≥10；
5. 每个节点 kernel 日志有本组 10 个 agent 的 `heartbeat received` 与至少 1 条 `assessment result`；
6. 主 kernel `:50051` 上**没有** 30 个 agent 的 mgmt IP 会话，且主日志无这些 `host_id`；
7. 主 kernel 能列出 nk1/nk2/nk3（`federation status` 或 `GET /federation/nodes`，后者需 token 头）；
8. 三节点 `prism effective config` 的 `debt_alpha/path_decay/max_path_depth/aggregation`
   与模板一致且两两不同；
9. （附加）三节点 CA 指纹互不相同。

### 7.2 分项手工核对

```bash
# a) 33 台 CT
pct list | grep -E '^(930|931|932|9[4-6][0-9])\s'

# b) agent 指向所属节点（示例：940 必须是 .71，不是 .50）
pct exec 940 -- grep -E '^(kernel_addr|host_id|tls_server_name|cert_dir)' /etc/asscor/agent.ini

# c) 节点 kernel 连接数（期望 10）
pct exec 930 -- ss -tn | awk '$4 ~ /:50051$/ {c++} END{print c+0}'
pct exec 930 -- grep -c 'heartbeat received' /var/log/asscor-kernel.log   # 或 journalctl -u asscor-kernel

# d) 主 kernel 上没有这 30 个 agent 的会话（输出应为空）
ssh -i /root/.ssh/asc_kernel asc@192.168.30.50 'sudo -n ss -tn' \
  | awk '$4 ~ /:50051$/ {split($5,a,":"); print a[1]}' | grep -E '^192\.168\.30\.(10[1-9]|1[12][0-9]|130)$'

# e) 主 kernel 列出 3 个节点
ssh -i /root/.ssh/asc_kernel asc@192.168.30.50 \
  'printf "federation status\nexit\n" | sudo -n /home/asc/asscor/bin/kernel --cli /opt/asscor/asscor-cli.sock'
ssh -i /root/.ssh/asc_kernel asc@192.168.30.50 \
  'curl -fsS -H "X-Federation-Token: asscor-t4-demo" http://127.0.0.1:5099/federation/nodes'

# f) 三份 prism 生效参数互不相同
for id in 930 931 932; do
  pct exec "$id" -- grep -m1 'prism effective config' /var/log/asscor-kernel.log
done
```

## 8. 已知风险与 TODO

1. **联邦端点/命令已落定**（federation-dev 实现）：`POST /federation/report`（节点上报）、
   `GET /federation/nodes`（收集结果，**必须带 `X-Federation-Token` 头**）、
   CLI `federation status [--json]`。验收脚本优先用 CLI，CLI 不可用时回退到带 token 的
   curl；两者都不可用时报 FAIL 并打印差值 rc 与排查提示（不会静默通过）。
   若后续实现改动路径/命令名，以 `internal/federation/master.go` 与
   `internal/cli/federation_commands.go` 为准，并同步 `scripts/federation-verify.sh` 顶部变量。
2. **配置段白名单已补齐**：`internal/config/config.go` 的 `buildAdapterConfig` 已把
   `federation` 段加入白名单，插件通过 `cfg.Get("federation.*")` 读取 role/listen_addr/token
   均生效。**无需再改代码**（这是 federation-dev 2026-10-28 的改动）。
3. **build tag 依赖**：kernel 必须 `-tags …,engine,…,federation`。缺 `engine` ⇒ 无
   `prism effective config` 日志（验收项 8 必 FAIL）；缺 `federation` ⇒ 节点不上报、
   master 不监听 `:5099`（验收项 5/7 会失败）。注意 `scripts/build.sh` 的 `MODULE_TAGS`
   当前**未包含** `federation`（截至 2026-10-28），构建 kernel 时需显式追加（本文 §6 第 1 步
   给了完整命令；等 Lead 统一更新 build.sh 后可简化）。
4. **主 kernel 重启影响既有实验**：910 上现有 10 个 agent 会断连重连（`Restart=always` 正常
   恢复）；重启前先备份 `kernel.ini`（`master.ini` 文件头给了命令）。
5. **`tls_server_name` 与节点 hostname 强绑定**：节点 kernel 的 `server.crt` 只含
   DNS SAN（首启时的 hostname）。若基建改了节点 CT 的 hostname，agent 必须相应改
   `tls_server_name` 或重签 server 证书；**不要**用 `tls_skip_verify=true` 绕过。
6. **每 agent 一张证书**：共享 `agent.crt` 会被 `certificate identity conflict` 拒绝；
   签发必须在所属节点 kernel 的 CT 内做（用它的 `ca.key`）。
7. **`[srd] roles` 依赖真实 hostname**：模板里写的是 `asc-agt-nk<g>-<idx>`；若 inventory
   的 hostname 不同，按 inventory 替换（否则角色不生效，但条数仍会体现在日志）。
8. **资源与并发**：30 个 agent 的评估并发会占节点 kernel CPU（节点 CT 2 核）；
   `check_interval_sec=120` 已比生产 300s 更密，若观测到节点 kernel 过载，
   把三个节点一起调到 300s（验收项 5 需相应放宽等待时间）。
9. **数据面 IP 与旧实验的重叠风险**：本规划只用每张 vnet 的 `.101+`；若基建把 agent 数据 IP
   分配到 `.1/.11/.12/.20` 会与 920-927 冲突，必须改。
10. **验收脚本耗时**：`pct exec` 每次约 0.9s CPU，30 台就绪时脚本约 40-60s；建议直接
    在宿主跑（不要套过多层 ssh）。
11. **agent 的 `--kernel` / `--cert-dir` 必须显式传**（见 §6 第 4 步）：`cmd/agent/main.go`
    用 flag 默认值无条件覆盖 `cfg.KernelAddr`（`127.0.0.1:50051`）和 `cfg.CertDir`（`certs`），
    只写 `agent.ini` 会导致 agent 连本机、证书目录找不到。验收脚本第 3 项会同时核对
    agent.ini 与运行中的 cmdline，两者不一致即 FAIL。
12. **节点 kernel 日志位置**：infra 目前用 journald（CT 内无 `/var/log/asscor-kernel.log`），
    验收脚本会自动回退到 `journalctl -u asscor-kernel`；若改回文件日志（
    `StandardOutput=append:/var/log/asscor-kernel.log`）脚本同样支持，两条路径都可。

## 9. 相关文件

| 文件 | 说明 |
|---|---|
| `configs/federation/nk1.ini` / `nk2.ini` / `nk3.ini` | 三套节点 kernel 配置（差异化模型参数） |
| `configs/federation/master.ini` | 主 kernel `[federation]` 合并片段（含合并/回滚步骤） |
| `scripts/gen-agent-configs.sh` | 生成 30 个 `agent.ini` 到 `/root/t4/agent-configs/` |
| `scripts/federation-verify.sh` | 联邦验收（PASS/FAIL 汇总，rc≠0 即失败） |
| `docs/2-experiments/T4_FEDERATION_DESIGN_2026-10-28.md` | 联邦总体设计（架构/协议/安全边界） |
| `/root/t4/inventory.tsv` | 基建侧唯一事实来源（vmid/hostname/vnet/mgmt IP/节点/证书指纹） |
