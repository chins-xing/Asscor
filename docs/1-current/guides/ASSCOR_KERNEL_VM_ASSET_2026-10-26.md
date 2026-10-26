# ASSCOR kernel VM 资产登记（dl360gen9 / VM 910）

> 这是**长期资产**，不是一次性实验环境：后续所有需要"kernel 侧"的测试都复用它，**不要重复建**。
> 建立于 2026-10-26；基线快照 `baseline-direction1-20261026`。

## 1. 资产身份

| 项 | 值 |
|---|---|
| 宿主 | `dl360gen9`（PVE 8.x，46 GiB 可用内存 / 36 核） |
| VMID / 名称 | **910 / `asc-kernel-vm`** |
| 规格 | 8 GiB（`balloon=0`）· 4 核 · `cpu=host` · `scsihw=virtio-scsi-pci` · `ostype=l26` |
| 系统盘 | `RAID-Mirror:vm-910-disk-0`（20 GiB，ZFS 镜像池） |
| 系统 | Debian 12.15（`6.1.0-54-cloud-amd64`），cloud-init 用户 **`asc`**（sudo NOPASSWD） |
| 网络 | `eth0` = `vmbr1`（DHCP，出外网，实测 `192.168.1.5`）；`eth1` = `vmbr0`（**静态 `192.168.30.50/24`**，管理 VLAN） |
| 启动 | `onboot=1`、`startup order=10`（宿主重启后自动起来） |
| 访问 | 宿主密钥 **`/root/.ssh/asc_kernel`**（`ssh -i /root/.ssh/asc_kernel asc@192.168.30.50`） |
| 基线快照 | **`baseline-direction1-20261026`**（回滚点：`qm rollback 910 baseline-direction1-20261026`） |

## 2. 资产内已装的东西

| 路径 | 内容 |
|---|---|
| `/home/asc/asscor/bin/{kernel,agent,asscor}` | 从仓库 **HEAD 构建**的二进制（全模块 tag，见 §4） |
| `/home/asc/asscor/etc/kernel.ini` | kernel 运行配置（含 `[confidence] enabled=true` + `[grpc] enabled=true/tls_enabled=true` + `[comms] require_mtls=true`） |
| `/home/asc/asscor/etc/config.ini` | 基线配置（`[confidence] enabled=false`，供 A/B 对照） |
| `/home/asc/asscor/etc/config-conf.ini` / `config-def05.ini` | 方向① A/B 用的两份变体（规则表 / default=0.5） |
| `/home/asc/asscor/certs/` | mTLS 证书（`ca.crt`、`server.crt/key`、`agent.crt/key`），`--force-regen-certs` 生成 |
| `/etc/systemd/system/asscor-kernel.service` | 服务单元（`Restart=always`，日志 `append:/var/log/asscor-kernel.log`） |
| `/var/log/asscor-kernel.log` | kernel 运行日志 |

服务管理：`sudo systemctl {start|stop|restart|status} asscor-kernel`；开机自启用 `systemctl enable`（当前已 `enabled`）。

## 3. 配套 AGENT（可由本资产派生的"客户端"）

| 项 | 值 |
|---|---|
| CT | **911 / `asc-agent-ct`**（`RAID-Mirror:8`，1 GiB / **8 核**（`cpuunits=4096`），`192.168.30.51`，`onboot=1`） |
| agent | `/opt/asc-agent`；证书在 `/etc/asscor/certs/{ca.crt,agent.crt,agent.key}` |
| 启动 | **systemd 单实例 `asscor-agent.service`**（`Restart=always`）：`systemctl {start|stop|restart|status} asscor-agent` |
| 已验证 | kernel 日志 `msg=registered session_id=sess-asc-agent-ct-…`；`ss` 一条 ESTAB（单实例） |

> **CPU 规则（2026-10-26 定）**：agent 侧**默认给 8 核**（至少 6），`cpuunits=4096`。
> 背景：911 曾出现 CPU PSI `some avg10=91%` —— 根因是**4 个重复 agent 进程**（每次手工
> `setsid nohup` 启动都留下一个）叠在 2 核上，而不是"核数不够"。改成 systemd 单实例 + 8 核后
> **PSI 0.00 / 单进程 CPU 0%**。
> 另：agent 每 30s 心跳会重算 `collectPackages`/`collectCPEs`（日志 `generated CPEs from packages`），
> 这是常态开销；**不要再手工 `setsid nohup` 起 agent**，一律用 systemd 单元，避免进程堆积。

> ⚠️ CT 的 agent **需要** `kernel.ini` 里 `[comms] require_mtls=true` 与证书配对；
> 若要临时免 TLS（仅隔离环境），只能改 `require_mtls=false` 并给 kernel 加 `--no-mtls` —— **不要**在生产沿用。

## 4. 重建 / 刷新步骤（新代码要上资产时）

```bash
# 1) 宿主上准备干净检出（GitHub 从宿主不可达 ⇒ 用 bundle 传）
git bundle create /tmp/argus.bundle HEAD          # 在开发机（有仓库的地方）
scp argus.bundle root@dl360gen9:/root/t6/verify/
ssh dl360gen9 'cd /root/t6/verify && rm -rf head && git clone argus.bundle head'

# 2) 宿主构建（Go 1.27.1；内核必须带全模块 tag，漏 comms 会没有 gRPC，漏 heartbeat 会注册失败）
cd /root/t6/verify/head
TAGS=agent,adapter,checks,engine,assessor,persistence,edgeexp,expr,comms,heartbeat,commander,cti,spc,sourcemanager,securemode,integrity,resilience,policy,collector,attck_ext,srdwrapper
go build -tags "$TAGS" -o build/kernel ./cmd/kernel
go build -tags "$TAGS" -o build/agent  ./cmd/agent

# 3) 换二进制：**必须先停服务**（运行中的可执行文件不能被覆盖：text file busy）
ssh -i /root/.ssh/asc_kernel asc@192.168.30.50 'sudo systemctl stop asscor-kernel'
scp build/kernel asc@192.168.30.50:/home/asc/asscor/bin/kernel.new
ssh -i /root/.ssh/asc_kernel asc@192.168.30.50 \
  'mv ~/asscor/bin/kernel.new ~/asscor/bin/kernel && chmod +x ~/asscor/bin/kernel && sudo systemctl start asscor-kernel'

# 4) 证书若失效（换机/过期）：VM 上
sudo ./bin/kernel --cert-dir certs --force-regen-certs     # 注意：**不能**加 --daemon（会先 fork 直接 return）
```

## 5. 复用步骤（每次要做 kernel 侧测试时）

```bash
# 连通性
ssh -i /root/.ssh/asc_kernel asc@192.168.30.50 'hostname; sudo systemctl is-active asscor-kernel; sudo ss -ltn | grep 50051'
# 对端 agent（若 CT 未起）
pct start 911
pct exec 911 -- sh -c 'pgrep -x asc-agent || (setsid nohup /opt/asc-agent --kernel 192.168.30.50:50051 --host-id asc-agent-ct --tls --cert-dir /etc/asscor/certs --tls-server-name asc-kernel-vm > /var/log/asc-agent.log 2>&1 &)'
# 方向① 三组对照（在 VM 内）
cd /home/asc/asscor
sudo ./bin/asscor --config etc/config.ini        -json > /tmp/a.json
sudo ./bin/asscor --config etc/config-conf.ini   -json > /tmp/b.json
sudo ./bin/asscor --config etc/config-def05.ini  -json > /tmp/c.json
```

## 6. 运维注意

- **改配置**：改 `/home/asc/asscor/etc/kernel.ini` 后 `sudo systemctl restart asscor-kernel`；
  改 `[confidence]` 无需重启（配置热加载会生效，但为确定性建议重启）。
- **agent 侧**：`pct set <vmid> --cores 8 --cpuunits 4096`（新建 agent CT 就按这个给），且**只允许**通过 `asscor-agent.service` 启动，禁止 `setsid nohup` 手工起（会堆进程）。
- **不要**用 `pkill -f 'bin/kernel'` —— 会把**执行命令的 SSH shell 自己也匹配杀掉**（本项目实测踩过两次）。
  用 `systemctl` 或 `pkill -x kernel`（进程名精确匹配）。
- **快照是回滚点**：破坏性试验前先 `qm snapshot 910 before-<事由>`；回滚 `qm rollback 910 <name>`。
- 该 VM 属**资产**：不要 `qm destroy 910`；不要把它当一次性实验机、也不要重复新建同类 VM。
