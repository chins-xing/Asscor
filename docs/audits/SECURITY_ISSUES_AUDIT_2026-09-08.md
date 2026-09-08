
> 归档说明：2026-09-08 外部安全审计（34 项），基线 main v0.2.3 + ASSCOR-Research-Core @268cca9。
> 处置决策：Critical+High 中 main 存在的 7 项（C-1/C-2/H-1..H-5）在 main 修复；RC-H1/RC-H3（securemode 专有）在 ARC 补修；
> C-3（module 改名）单独评估；核实不成立/设计取舍项不入本轮（详见修复提交说明）。
# ASSCOR 审计问题清单（仅问题）

审计对象：main 分支（v0.2.3）+ ASSCOR-Research-Core 分支（v0.2.3，commit 268cca9）
审计方法：源码通读 + go build + go test + go vet + 关键路径验证
统计：共 **34 项** = Critical 3 / High 8 / Medium 12 / Low 11（main 遗留 20 项，Research-Core 新增 14 项）

---

## 一、严重问题（Critical）

### C-1 算法完整性校验为自引用恒真式
- **位置**：`internal/integrity/algo.go`（build tag: integrity）
- **问题**：`init()` 与运行时调用同一函数 `computeAlgoDigest()`，从同一份内存常量计算哈希并比较。常量被篡改后两侧同步变化，比较永远为 true。
- **影响**：完整性防护形同虚设，无法检测任何运行时篡改；Secure Mode 引入后该失效声明与内存加固（mprotect）形成虚假的安全假象。
- **修复**：预期哈希改为编译期常量或外部签名文件，而非运行时自计算。

### C-2 特权代理 UID 校验在查找失败时静默放行
- **位置**：`internal/agent/privileged.go` `LookupUID` / `verifyPeer`
- **问题**：用户名查找失败返回 0（root UID），`verifyPeer` 在 `AllowedPeerUID <= 0` 时条件短路跳过校验。
- **影响**：本地任意用户可连接 root 特权代理，触发 `isolate_host` 将主机 INPUT 链改为 DROP，造成断网（含 SSH）拒绝服务。
- **修复**：`LookupUID` 失败返回错误；`AllowedPeerUID <= 0` 时拒绝连接。

### C-3 Go module 路径与仓库地址不匹配
- **位置**：`go.mod`（module `github.com/chins-xing/asscor`）
- **问题**：module 路径与实际仓库 `github.com/chins-xing/Asscor` 不一致，`ssam`/`prism` 依赖通过 replace 指向本地目录。
- **影响**：外部用户无法 `go get` 导入，社区生态为零；CI 中 `pluginsdk` 独立模块存在同样问题。
- **修复**：module 改为 `github.com/chins-xing/asscor` 并同步 import 路径。

---

## 二、高危问题（High）

### H-1 检查超时后 goroutine 泄漏
- **位置**：`internal/agent/agent.go` `runCheckWithTimeout`
- **问题**：`time.After` 超时后，执行 `c.Run()` 的 goroutine 不被取消继续运行；检查含阻塞操作时每次超时泄漏一个 goroutine。
- **影响**：80 个检查项 × 多轮评估场景下 goroutine 持续增长，可耗尽资源。
- **修复**：改用 `context.WithTimeout` 并传递 context。

### H-2 扫描器适配器二进制路径无校验
- **位置**：`internal/adapter/scanner/nuclei.go`、`trivy.go`、`lynis.go`、`p1_scanners.go`、`p2_scanners.go`
- **问题**：`adapter_paths.*` 直接来自配置并 `exec.CommandContext` 执行，无白名单/路径/属主校验；空路径时依赖 PATH 查找。
- **影响**：配置被篡改或错误配置时，kernel 进程上下文执行任意程序，且绕过 agent 侧 `RunCmdTimeout` 的白名单。
- **修复**：白名单限定已知二进制或强制绝对路径 + 属主校验。

### H-3 扩展二进制校验和为可选
- **位置**：`internal/extmgr/extension_executor.go:344`、`extension_spec.go:295`
- **问题**：`Checksum == ""` 时跳过完整性验证；git 类型下载源完全不调用 `VerifyIntegrity`。
- **影响**：中间人篡改或扩展仓库被投毒时恶意代码直接执行。
- **修复**：生产环境强制校验和；git 源校验 commit hash 或 tag 签名。

### H-4 TLS ServerName 硬编码为 localhost
- **位置**：`internal/agent/agent.go:350` 与 `:397`（Research-Core 分支新增第二处）
- **问题**：远程部署时 SNI/证书 SAN 校验针对 "localhost"，握手必然失败，诱导管理员启用 `--tls-skip-verify`。
- **影响**：证书验证被整体绕过，叠加 H-3 的口令明文传输即构成中间人截获链。
- **修复**：`ServerName` 从 `KernelAddr` 解析主机名或提供独立 `--tls-server-name`。

### H-5 isolate_host 可被远程触发导致主机断网
- **位置**：`internal/agent/privileged.go` `executeIsolation`
- **问题**：将 INPUT 链默认策略改为 DROP 仅保留已建立连接，无二次确认/冷却/管理端口例外；结合 C-2 可被本地任意用户触发。
- **影响**：单点操作即断网（含 SSH），kernel 被入侵时所有受管主机可被同时隔离。
- **修复**：二次确认 + 冷却时间 + 保留管理端口例外规则。

### RC-H1 Secure Mode 入口无口令强度校验
- **位置**：`internal/securemode/controller.go` `EnterRun`；`password.go` `Set`
- **问题**：仅拒绝空口令，不校验长度/复杂度/熵值；操作员可用 "1" 作为 run mode 口令。
- **影响**：argon2id 参数虽合理，但弱口令下配置加密可被暴力破解。
- **修复**：口令最小长度（≥12）+ 熵值检查。

### RC-H2 kernel run-mode 口令明文驻留堆内存
- **位置**：`internal/securemode/controller.go` `runPassword` 字段
- **问题**：run-mode 口令以普通 string 驻留整个周期，不受 MemoryGuard 的 mprotect 保护，无 coredump 禁用。
- **影响**：`/proc/pid/mem`、coredump、swap 均可提取口令。
- **修复**：mlock / 纳入加固存储 / `prctl(PR_SET_DUMPABLE, 0)` / 无注册需求时清除。

### RC-H3 agent 临时口令经心跳明文上报
- **位置**：`internal/agent/securemode.go` `attachSecureModeReport`
- **问题**：32B 临时解锁口令在每次心跳中明文传输直至确认注册；kernel 端 `SecretRegistry` 内存明文存储。
- **影响**：启用 `--tls-skip-verify` 时口令可被中间人截获；agent 被入侵后重放口令可获取配置。
- **修复**：传输与存储双层加密，注册确认后轮换。

---

## 三、中危问题（Medium）

### M-1 ScriptAdapter 符号链接检测失效
- **位置**：`internal/adapter/script.go` `validateScriptPath`
- **问题**：使用 `os.Stat`（跟随符号链接）而非 `os.Lstat`，`ModeSymlink` 位永远为 0。
- **影响**：可在允许目录放置指向任意二进制的符号链接绕过"必须常规文件"检查。
- **修复**：改用 `os.Lstat`。

### M-2 agent runCommand 冗余分支逻辑混乱
- **位置**：`internal/agent/agent.go` `runCommand`
- **问题**：`IsShellCommandAllowed` 与 `ParseCommand` 两个分支执行完全相同操作，前者判断完全冗余。
- **影响**：代码可读性差，后续维护时易引入白名单不一致。
- **修复**：删除冗余分支，统一走 `ParseCommand` + `RunCmdTimeout`。

### M-3 密钥文件使用相对路径
- **位置**：`internal/commander/commander.go`、`internal/integrity/sign.go`（`certs/ASSCOR-*-key`）
- **问题**：路径相对于进程工作目录；systemd 下 WorkingDirectory 不同会生成新密钥，agent 侧 HMAC 验证失败。
- **修复**：使用配置的 `cert_dir` 或绝对路径。

### M-4 agent.ini 支持明文配置 HMAC 密钥
- **位置**：`cmd/agent/main.go` `loadConfigFile`
- **问题**：`hmac_key` 可直接写入 agent.ini 明文落盘，可能进入版本控制或备份。
- **修复**：废弃配置文件字段，强制环境变量/密钥文件。

### M-5 测试代码复制锁值
- **位置**：`internal/kernel/workerpool_test.go:164`
- **问题**：含 `sync.Mutex` 的 `WorkerPoolMetrics` 按值传入 `t.Errorf`，go vet 告警。
- **修复**：传指针或实现 `String()`。

### M-6 配置数值无范围校验
- **位置**：`internal/config/config.go`
- **问题**：权重、阈值、边缘因子、ACI 扣分等解析后不校验范围，异常值直接进入评分公式。
- **修复**：Parse 阶段范围校验并记录警告。

### RC-M1 Startup residue 检测 TOCTOU 竞态
- **位置**：`internal/securemode/controller.go` `Startup`
- **问题**：`Vault.State()` 对 plaintext 与 .enc 两次独立 `os.Stat`，期间文件可被创建/删除。
- **影响**：fail-closed 安全模型下存在竞态窗口。
- **修复**：单次目录扫描或文件描述符级原子检查。

### RC-M2 MemoryGuard 基线哈希不受只读页保护
- **位置**：`internal/securemode/memguard.go`
- **问题**：`baseline` 存普通堆内存，不在 mprotect 页面内；攻击者可同时篡改 `data`（先解除只读）与 `baseline`。
- **影响**：`IntegrityOK()` 可被伪造返回 true，内存加固降级为攻击门槛而非检测手段。
- **修复**：基线同样放入只读加固存储。

### RC-M3 Agent 自恢复阈值过短且静默丢失配置
- **位置**：`internal/agent/securemode.go` `secureSelfRecover`
- **问题**：连续 3 次心跳（约 15 秒）未解锁即触发自恢复，重新加密后旧配置（hmac_key/user_checks/check_deltas）全部丢失。
- **影响**：kernel 短暂重启或网络抖动即触发不可逆的配置重置；无运维告警。
- **修复**：延长阈值或仅由 `SecureModeNoSecret` 显式信号触发。

### RC-M4 研究引擎权重全部硬编码
- **位置**：`internal/predictor/predictor.go`、`engagement/engagement.go`、`attackerstate/state.go`
- **问题**：意图延续 +3.0、经验/知识/AI 系数、效用权重 αβγδ、诱饵检测率等全部硬编码，无配置化接口；`cmd/tracecheck` 已手动复制权重做敏感性分析，证明存在参数化需求。
- **影响**：无法进行系统化的敏感性实验与实证校准。
- **修复**：权重参数化并支持实验配置注入。

### RC-M5 exprunner 命令拼接存在注入风险
- **位置**：`cmd/exprunner/main.go` `dockerExec`
- **问题**：`docker exec ... bash -c cmd`，命令模板含 `%DECOYPORT%`/`%TARGETIP%` 变量替换；当前值硬编码，一旦外部化即引入 shell 注入。
- **修复**：移除 `bash -c` 或对替换值做 shell 元字符过滤。

### RC-M6 仓库混入大量非代码内容
- **位置**：`lunwen/`（论文 LaTeX 模板、clab 实验拓扑）、`docs/audits/`（50+ 审计文档）、`docs/en/`
- **问题**：884 个文件近半非代码；审计文档含内部讨论与漏洞细节，增加克隆体积、审查复杂度和信息泄露面。
- **修复**：论文/审计文档移至独立仓库或子模块。

---

## 四、低危问题（Low）

### L-1 安全关键包无测试
- **位置**：`internal/integrity`、`internal/resilience`、`internal/topology`、`internal/version`、`api/v1`
- **问题**：完整性校验等安全层零测试覆盖，C-1 的失效未被自动化检测。
- **修复**：为安全关键包补充单元测试。

### L-2 包体积过大、内聚不足
- **位置**：`internal/attck`（8,337 行）、`internal/kernel`（7,717 行）、`internal/engine`（5,958 行）、`internal/cli`（5,924 行）、`internal/adapter`（5,641 行）
- **问题**：单包跨多个子领域（ATT&CK 数据/规则/APT 匹配/模拟等）。
- **修复**：按子领域拆分包。

### L-3 Docker 健康检查可能误匹配
- **位置**：`Dockerfile` HEALTHCHECK `pgrep -f ASSCOR-kernel`
- **问题**：`-f` 匹配完整命令行，可误匹配含该字符串的其他进程。
- **修复**：PID 文件或端口探测。

### L-4 Dockerfile 安装未使用的 wget
- **位置**：`Dockerfile` `apk add --no-cache wget`
- **问题**：运行时未使用，增加镜像体积与攻击面。
- **修复**：移除。

### L-5 配置版本与项目版本不一致
- **位置**：`config.ini` 标注 v0.2.1，项目为 v0.2.3。
- **修复**：统一版本号。

### L-6 扩展安装权限未最小化
- **位置**：`internal/extmgr/extension_installer.go`
- **问题**：目录 0755，文件权限直接取自 tar header，setuid/setgid 位未清除。
- **修复**：安装后统一 0755/0644 并清除特殊位。

### RC-L1 decoyd 监听无访问控制
- **位置**：`cmd/decoyd/main.go`
- **问题**：监听 0.0.0.0 无连接限速；`hits` 切片无限增长导致内存泄漏。
- **修复**：连接限速 + 日志滚动/上限。

### RC-L2 PasswordVerifier 文件权限依赖 umask
- **位置**：`internal/securemode/password.go`
- **问题**：`os.WriteFile(..., 0o600)` 受 umask 影响，umask=0000 时可能变 0666。
- **修复**：写入后显式 `os.Chmod(0600)`。

### RC-L3 argon2id 时间成本偏低
- **位置**：`internal/securemode/crypt.go` `DefaultKDFParams`（N=1, 64MiB, p=4）
- **问题**：OWASP 建议 t=3；N=1 在 GPU/ASIC 对抗中偏弱。
- **修复**：提升至 N≥3 或等效参数。

### RC-L4 研究模块状态无持久化
- **位置**：`internal/attackerstate`、`defensecycle`、`engagement`、`predictor`
- **问题**：攻击者状态仅存内存，kernel 重启即丢失，闭环防御有效性无法连续。
- **修复**：提供持久化接口（研究阶段可接受，需文档标注）。

### RC-L5 新增模块无测试
- **位置**：`internal/agentinstall`、`internal/semver`、`cmd/decoyd`、`cmd/exprunner`、`cmd/tracecheck`
- **修复**：为工具链补充基础测试。

