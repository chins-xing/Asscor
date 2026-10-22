# 检查系统验证 — E18–E28 实验

**日期**: 2026-08-16 | **版本**: v0.2.3 | **环境**: Containerlab v3（host1 受控对象 / kernel 下发 user_check CU-001~005）

## 实验设计

通过 kernel config.ini 下发 5 个 user_check（CU-001 PASS / CU-002 FAIL / CU-003 边界 / CU-004 执行异常 / CU-005 空输出），在 agent 容器内控制文件/命令状态精确制造各场景，观察检查项行为与结果。

## 结果

| # | 测试项 | 操作 | 结果 | 判定 |
|:-:|--------|------|------|:---:|
| E18 | 单检查项 PASS | CU-001 file_path 文件存在 | `passed=true` "file exists (0 bytes)" | ✅ |
| E19 | 单检查项 FAIL | CU-002 file_path 文件缺失 | `passed=false` "cannot read ...: no such file" | ✅ |
| E20 | PASS/FAIL 边界值 | CU-003 `file_regex=^OK$`：内容 OK ↔ OKX 翻转 | OK→PASS / OKX→FAIL，翻转对称、恢复正确 | ✅ |
| E21 | 检查项执行异常 | CU-004 `command=systemctl is-active`（容器无 systemctl） | `passed=false` "command failed: exec: ... not found"，异常被捕获并带 detail | ✅ |
| E22 | 检查项超时 | 无 shell 白名单限制下无法制造挂起命令 | ⚠️ 端到端受限：代码审查确认 30s context 超时 + "command timed out after 30s" 分支；agent 侧 check_timeout_sec=10 配置存在 | ⚠️ 部分 |
| E23 | 检查项返回空结果 | CU-005 `command=ss -l`（无监听输出空） | `passed=true` "command succeeded"（空输出+exit 0 → PASS 合理） | ✅ |
| E24 | 单检查项重复执行 | CU-001 多轮评估 | 多轮 passed 一致（无随机/漂移） | ✅ |
| E25 | 多检查项并发执行 | 5 个 user_check 同轮（check_count 80→85） | 全部正常返回，无卡死/串扰 | ✅ |
| E26 | 单检查项失败污染 | CU-002 FAIL 与 CU-001 PASS 同轮 | 同轮并存：CU-001 true、CU-002 false，**互不影响** | ✅ |
| E27 | 检查项动态启停 | 删除 config.ini 的 CU-002 段 → kernel 重启 → agent 同步 | 同步日志 user_checks 5→4；评估中 **CU-002 消失**，其余 4 个保留 | ✅ |
| E28 | 检查项版本变化一致性 | 改 CU-001 file_path → 不存在文件 | **PASS→FAIL**（"cannot read gone.conf"），版本变化后结果正确翻转 | ✅ |

## 关键观察

- **user_check 全链路**：kernel config → CheckConfig 同步（version 指纹 1250c073→4e82d37c）→ agent 应用（user_checks 5→4）→ 执行 → 上报，工作正常。
- **异常/边界处理**：文件缺失、exec 失败、空输出、正则不匹配均被正确捕获为 FAIL（带语义 detail），无 panic/挂死。
- **隔离性**：单检查项 FAIL 不影响同轮其他检查项（E26）。
- **动态性**：检查项可增删（E27）、可变更（E28），结果随配置正确变化。

## E22 说明（受限项）

user_check 命令受无 shell 白名单约束（安全修复 P0-2 的设计），容器内无可用挂起命令，无法端到端触发超时。超时保护经代码审查确认：`userCheckCommandTimeout = 30s` + `context.WithTimeout` + 超时分支返回 "command timed out after 30s"；agent 侧整体检查超时 `check_timeout_sec = 10`（agent.ini）。如需端到端验证，可在白名单临时加入可挂起命令后复测。

## 结论

**检查系统 E18-E28 除 E22（环境受限）外全部通过**：PASS/FAIL 判定、边界值、异常捕获、空结果、重复一致性、并发、隔离、动态启停、版本一致性均正确。user_check 作为可编程检查扩展（CU- 前缀 + 无 shell 安全执行）功能完整可靠。

*数据：`docs/clab-lab/data/assessments-checks.jsonl`。*
