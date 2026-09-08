# Secure Mode 测试问题归档

- **日期**：2026-08-29
- **分支**：ASSCOR-Research-Core
- **范围**：Secure Mode 模块（build-tag `securemode`）全部测试历程复盘——SDD 任务级审查（12 任务）+ 最终全分支审查 + 集群集成测试（A-1 18 节点 / WSL2 14 节点）
- **性质**：归档记录（不触发新修复；已修复项标注提交，未修复项记录为 deferred）

---

## 1. 安全缺陷类（测试发现并修复的真实漏洞）

| 级别 | 问题 | 发现场景 | 根因 | 修复提交 |
|---|---|---|---|---|
| Critical | `.enc` 头部 nonce 长度≠12 → `gcm.Open` **panic 崩溃进程** | Task 2 审查（探针实测复现） | 攻击者可控 nonceLen 字段无语义校验；Go crypto/cipher 对 nonce≠12 直接 panic（含 fips140 实现） | `b18cd2a`：`len(h.Nonce)==gcm.NonceSize()` 前置校验 |
| Critical | `ArgonP=256` 倍数经 `uint8(p)` 窄化为 0 → argon2 **panic** | Task 2 审查（实测复现） | KDF 参数校验只看 uint32 零值，窄化后 0 穿透；argon2 对 threads<1 panic | `b18cd2a`：KDF 四参数 `==DefaultKDFParams()` 精确校验 |
| Critical | `ArgonN/ArgonR` 无上限 → **OOM（~4.4TB）/ CPU 耗尽 DoS** | Task 2 审查 | 成本参数攻击者可控、无上界；argon2 initBlocks make 巨大内存 / processBlocks 无限循环，认证前触发 | `b18cd2a`：同上精确校验（一次根除三类） |
| Critical | PasswordVerifier 恶意文件（keyLen=0/N=0/p=256）→ **argon2 panic** | Task 5 审查（实测复现，含 nil 指针 panic） | Verify 不校验 KDF 参数直接 deriveKey，与 Decrypt 防御不同构；实现者"风险低"评估被驳回 | `ad39e18`：Verify 同构校验 version==1 + KDF 四参数 |
| Important | 两密码锁死：SetPassword 最后一步失败 → 新旧密码全部失效、无 API 恢复 | Task 8 审查 | 提交顺序缺陷（先重加密 vault 后 Set verifier）；EnterRun 同源卡死 | `4d784ad`：两段式（预检→Set verifier→逐 vault EncryptContent→失败 rollbackSetPassword，需 old+new 双密码） |
| Important | EnterRun 崩溃半态：verifier 写后、marker 写前崩溃 → **静默降级 default 丢配置** | Task 8 审查 | 残留组合（default 标记 + enc-only + verifier）未被 Startup 检测 | `4d784ad`：Startup 一致性检查 fail-closed |

## 2. 设计/架构缺陷类（测试暴露的规范违反）

| 级别 | 问题 | 发现场景 | 说明 |
|---|---|---|---|
| Important | 内核 run 模式重启后配置未接入运行时：`config.Load` 先于 `initSecureMode`、unlock 不回灌 cfg、run 模式 config-set 不生效 | 最终全分支审查 | spec §8.1/§9 核心场景只实现一半——重启后内核静默跑默认配置（保护设置丢失） |
| Important | agent 锁定态死锁：kernel 登记表不可恢复时 agent 永久 locked，无 spec §8.2 自恢复路径 | 最终全分支审查 | 仅手工删 .enc 恢复；kernel 换实例后存活 agent 不感知登记丢失并重报 |
| Important | 锁定态 agent 无 hmac_key → pending command HMAC 必失败 → unlock 死锁 | Task 11 审查 | hmac_key 在受保护 [agent] 段；锁定态无法校验任何指令 |
| Important | HandleConfigSet 锁窗口竞态（RLock 后立即释放，Verify/guard 窗口内并发 EnterRun/ExitRun） | Task 9 审查 | 可致残留态或修改静默丢失 |
| Important | 内核侧未实际下发 unlock/exit/rotate 指令（CLI 占位 "instruction prepared"） | Task 11 审查 | mode agent 指令链路未交付 |

## 3. 集群集成测试暴露的工程问题

| 问题 | 发现场景 | 根因/影响 |
|---|---|---|
| agent.ini 写入失败静默 | A-1 18 节点 | 部署脚本 heredoc 转义 → agent.ini 缺失 → agent 用默认 host_id（主机名）→ 注册身份冲突 |
| 证书身份冲突残留 | A-1 | kernel 重启后 identity 绑定（heartbeat_identity.json）保留旧指纹，新签发证书无法注册 |
| kernel 默认 CLI socket 冲突 | A-1 | 旧 systemd kernel 与 kernel-sm 监听同一 `/opt/asscor/asscor-cli.sock`，连接错实例导致 "Unknown command: mode" |
| host13/14 数据面不通 | WSL2 14 节点 | 扩展节点 OSPF 缺 `redistribute connected`（已知坑复现，r2 需配置） |
| clab veth 重建后丢失 | WSL2 | destroy+deploy 才能恢复 veth（--reconfigure 不重建） |
| 环境资源边界 | A-1 24 进程 | 2 核 3.4GB 跑 24 agent 压垮 sshd（banner exchange 超时），需云控制台重启恢复 |

## 4. 已记录未修（deferred / minor，非阻塞）

- ~~口令 oracle：Decrypt 错误消息区分"密码错误"vs"数据损坏"~~ → **已修**（`fb40b3e` 统一文案）
- ~~CLI history 明文密码~~ → **已修**（`23ca6cd` 脱敏 + `021f2c2` client 侧交互输入）
- argon2id KAT 测试向量缺失：确定性测试无法区分正确 KDF 与任意派生函数（建议 RFC 9106 向量）
- mprotect/anti-debug 未实现（spec §7 第三项；P1-3 定位为 hardening 非防篡改保证）
- Unmarshal 条目级校验缺失（`{"fp1":null}` 零值条目；有 `sec.Password != ""` 兜底）
- Vaults[0] 空列表无护栏（生产恒传 1+ vault）
- runPassword 内存硬化缺失（Go string 无法 zeroize，spec P1-3 下可接受）
- 标记文件 hash 无密钥（防意外损坏非恶意伪造，文档已声明边界）
- gRPC 通道 PB 不含 SecureMode 字段（agent 走 JSONRPC 完整）

## 5. 总体评估与模式教训

**正面**：9 个 Critical/Important 安全/架构缺陷全部在测试中被发现并修复，验证测试流程有效；加密原语层（KDF 精确校验、zeroize、GCM 信封、nonce 新鲜度）质量高。

**暴露的模式问题**：
1. **brief 参考代码带病**：Task 2/5 的 Critical 均源于照抄参考代码（nonce 校验缺失、KDF 参数宽松校验）——实现者照抄与审查兜底的张力，审查是必要防线
2. **跨任务交接缺口**：Task 10→11 的 Ruling 2/3（unlock 配置回灌、agent 自恢复）是典型的"上一任务留坑、下一任务填"模式，交接项需显式传递
3. **集群环境敏感**：Secure Mode 依赖 mTLS 证书/身份绑定，环境重建（kernel 重启/证书轮换）时残留状态（heartbeat_identity.json、.asscor-mode、CLI socket）处理不友好，需显式清理流程
4. **配置写入路径脆弱**：agent.ini 经脚本/heredoc 写入时静默失败，暴露配置加载错误处理不够显式（默认值遮蔽）

## 6. 建议后续动作（不强制）

- 集群测试中发现的部署脚本问题：提供官方 `deploy-securemode.sh` 脚本（含证书签发/分发/身份清理/OSPF 配置）
- kernel 重启后身份绑定残留：提供 `mode certs reset` 或文档化清理步骤
- argon2id KAT 测试向量补充（RFC 9106）
