# Secure Mode 复审审计（2026-09-03，多轮审查后的独立复核）

- **日期**：2026-09-03
- **分支**：ASSCOR-Research-Core
- **性质**：复审审计 + 归档（本模块已历 12 任务 SDD + 最终全分支审查 + deferred 修复 + 集群测试；本次为收口复核）
- **范围**：`internal/securemode/` 全部文件 + `cmd/kernel/securemode_*.go` + `cmd/agent/securemode_*.go` + `internal/agent/securemode*.go` + `internal/comms` 登记接线 + `deploy/deploy-securemode.sh`

---

## 一、审计方法

逐文件读源码核对 + 对照 spec（docs/superpowers/specs/2026-08-21-secure-mode-design.md）与既有修复记录（audit 归档、final-fix-report、deferred-fix-report）。重点复核：并发正确性、错误处理、边界条件、状态机完整性、安全弱点、新代码（mprotect/anti-debug/cert reset）质量、测试盲点。

## 二、逐文件结论

| 文件 | 审查结论 |
|---|---|
| `crypt.go` | ✅ 信封加密(AES-256-GCM+argon2id)正确；nonce 长度/KDF 四参数精确校验(防 panic/OOM)；密钥 zeroize；统一错误消息防口令 oracle |
| `password.go` | ✅ 常量时间比较(hmac.Equal)；KDF 参数/版本校验(防恶意文件)；原子 tmp+rename 写；边界检查完整 |
| `registry.go` | ✅ 证书指纹主键(one-cert-one-identity)；条目级校验；Marshal 明文/Unmarshal 拒 null+零值条目；锁完整 |
| `persist.go` | ✅ tmp+rename+fsync+dir-sync 原子写；fail-closed 保留损坏文件；default 模式 no-op；错误传播到调用方(comms 检查) |
| `state.go` | ✅ marker 哈希+版本校验；corrupt≠missing fail-closed；原子写 |
| `vault.go` | ✅ 三段式原子转换(先 fsync 明文→写 .enc→round-trip 验证→删明文)；错误路径清理 tmp；无受保护段 fail-safe |
| `controller.go` | ✅ SetPassword 两段式+回滚；Startup 半态检测(default/run × enc-only × verifier) fail-closed；releaseGuard 防 mmap 泄漏；debugger 检查注入点可测 |
| `memguard.go` + `ro_storage_*` | ✅ 明文驻留 mmap mprotect(PROT_READ)(linux)；篡改检测(子进程 SIGSEGV 实测)；Replace 重建区+释放旧 mmap；非 linux 降级堆副本 |
| `cli.go` | ✅ 命令族完整；HandleConfigSet 全程 RLock；--temp/--persist 两段式；status 经 ListEntries 不泄露 secret |
| `debug_linux.go` | ✅ TracerPid 检测(与 integrity.IsDebugged 同机制,独立实现免 tag 纠缠) |
| `cmd/kernel/securemode_*.go` | ✅ on/off 配对；run 标记启动提示不阻塞；config 回灌钩子；CLI 交互密码提示(脱敏) |
| `internal/agent/securemode*.go` | ✅ locked/unlock/self-recover/rotate 状态机完整；bootstrap 明文引导段恢复；flag 显式语义 |
| `internal/comms` 登记接线 | ✅ 指纹校验+Register+PersistSecrets 错误处理；SecureModeNoSecret 信号 |
| `deploy/deploy-securemode.sh` | ✅ 三后端统一；CLI socket 隔离；agent.ini 写后回读校验；setsid 防会话死亡；shellcheck 0 告警 |

## 三、观察项（全部为 Minor / 设计已覆盖，无 Critical/Important）

1. **EnterRun/ExitRun 中间失败 → 磁盘半态**（WriteMarker 失败 / DecryptFile 循环中断）：函数返回错误、内存 Mode 未更新，磁盘处于 enc-only+verifier+旧 marker 或明文+enc 共存。
   - **已覆盖**：Startup 半态检测 fail-closed（controller_test.go 224-284 行有专门测试：default marker + enc-only + verifier 必须拒绝启动），落入 spec §11 人工恢复路径——与进程在转换中途崩溃等价，属设计范畴而非缺陷。
2. **agent exit/rotate 密码经 commander 通道 params 下发**：内核把登记的临时密码放进 EnqueueCommand。
   - **设计使然**：agent 本地无密码（内核托管,spec P1-1），通道为 mTLS + pending command（exit/rotate 时 hmac_key 已恢复可验签）。
3. **Unlock 后内核下发密码存 agent 内存**：`unlockWithPassword` 设 `a.secure.password`。
   - **设计使然**：agent 需要密码解密 .enc 并用于后续 rotate/exit；临时秘密随进程重启轮换（spec §3.1），不落盘。
4. **agent.ini 顶层无 [bootstrap] 段时全文件加密**（cluster 测试曾用无 bootstrap 模板）：agent 重启需靠 --kernel flag 显式传入才可连内核。
   - 官方 deploy 脚本已生成 [bootstrap] 段；文档化边界。非缺陷。

## 四、测试覆盖复核

- 新增测试均通过：argon2id KAT(17 向量)、registry 条目校验、Vaults[0] 护栏、mprotect 只读页(子进程 SIGSEGV)+ 篡改检测、anti-debug 拒绝路径、cert reset 三路径、controller guard 释放。
- 既有多轮测试(controller/vault/crypt/registry/persist/state/e2e)维持全绿。
- 本模块测试密度高（~160+ Test），本轮未发现需立即补测的关键盲点。

## 五、结论

**Secure Mode 模块经多轮审查（12 任务 SDD → 最终全分支审查 → deferred 修复 → 集群测试 → 本复审）后状态健康**：安全加固项（KDF 精确校验/常量时间比较/fail-closed/原子转换/只读页硬化）齐全且不回退；本轮复核未发现 Critical/Important 级新问题；观察项均为设计内边界，有既有测试与 spec §11 恢复路径覆盖。

**无需立即修复项**。归档备查。
