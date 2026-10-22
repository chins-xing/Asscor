# ASSCOR 全量项目完成度审查报告

**审查日期**: 2026-06-18 | **项目版本**: v0.2.0 | **代码库**: ~135个Go文件

---

## 一、总览矩阵

| 子系统 | 文件数 | 完成度 | 关键缺口 |
|--------|--------|--------|----------|
| **内核微服务** (kernel) | 47 | **80%** | 6/14 模块有缺口 |
| **Agent** | 2 | **95%** | Windows包采集缺失 |
| **CLI** | 7 | **80%** | SPC子命令stub, 无readline |
| **WebUI** | 2 | **90%** | 无认证, 无WebSocket |
| **gRPC服务** | 4 | **85%** | proto不同步 |
| **评分引擎** (ssam) | 6+lib | **100%** | 无 |
| **SPC态势计算** | 5 | **90%** | O(N*P*A) 性能瓶颈 |
| **ATT&CK V19** | 12 | **95%** | 分析历史无驱逐 |
| **适配器框架** | 17 | **60%** | 11/21生产就绪 |
| **检查项库** | 2 | **95%** | 76项全部实现 |
| **SRD/Prism** | 7 | **100%** | 无 |
| **扩展管理器** | 5 | **85%** | RefreshRepositories stub |
| **密码学** | 1 | **100%** | 无 |
| **配置系统** | 1+6 | **100%** | 30+节解析, 6行业模板 |
| **测试覆盖** | 24文件 | **55%** | 11包零测试 |
| **构建部署** | — | **10%** | 无CI/CD/Docker |
| **文档** | 15文件 | **95%** | 缺AGENTS.md |
| **整体** | **~200** | **75%** | — |

---

## 二、内核模块逐项审查

### 2.1 完整模块 (8/14)

| 模块 | 文件 | 评级 | 备注 |
|------|------|------|------|
| **Policy** | `policy.go:185` | COMPLETE | 4级阈值, 3类动作, 总线集成 |
| **Config Watcher** | `config_watcher.go:243` | COMPLETE | 轮询+SIGHUP, 权重热加载, 路径解析 |
| **Server** | `server.go:306` | COMPLETE | 连接管理, TLS, Keepalive, 优雅关闭 |
| **gRPC Server** | `grpc_server.go:398` | COMPLETE | mTLS, 双协议栈, 客户端 |
| **Interceptor** | `interceptor.go:226` | COMPLETE | 限流/熔断/审计三拦截器 |
| **Circuit Breaker** | `circuitbreaker.go:290` | COMPLETE | 三态转换, 滑动窗口, 可配阈值 |
| **Rate Limiter** | `ratelimit.go:125` | COMPLETE | 令牌桶, 每客户端跟踪, 自动清理 |
| **Crypto** | `crypto.go:331` | COMPLETE | CA/Server/Agent三证, RSA 4096/2048, PEM |

### 2.2 部分完成模块 (6/14)

| 模块 | 缺口 | 严重度 |
|------|------|--------|
| **Heartbeat** | Agent记录永不删除 (map无界增长) | 中 |
| **Commander** | 待执行命令无TTL过期 (永不过期) | 中 |
| **CTI** | OTX/MISP外部威胁源集成**完全stub** | 高 |
| **Persistence** | 每日JSONL文件无保留策略 (永不清除) | 中 |
| **AdapterIntegration** | `Stop()` 不终止 syncLoop goroutine (泄漏) | 中 |
| **WorkerPool** | `peakActiveWorkers` 指标声明但从未更新 | 低 |

---

## 三、Agent/CLI/WebUI

### 3.1 Agent — 95%

| 功能 | 状态 |
|------|------|
| 心跳循环 + 指数退避重连 | COMPLETE |
| HMAC-SHA256 指令验证 + 白名单执行 | COMPLETE |
| mTLS (CA+Agent证书加载) | COMPLETE |
| 包采集 (rpm/dpkg/pacman) | COMPLETE |
| CPE 2.3 生成 (108条目vendor-product映射) | COMPLETE |
| 并发检查执行 (信号量10, 60s超时) | COMPLETE |
| ASCII-art 评估报告打印 | COMPLETE |
| 信号处理 (SIGINT/SIGTERM) | COMPLETE |
| **Windows 包采集** | **缺失** |
| `cachedPackages` 永不失效 | 瑕疵 |

### 3.2 CLI — 80%

| 功能 | 状态 |
|------|------|
| help/version/status/plugin/config/health/history | COMPLETE |
| agent list/status/start/stop/restart/config/command | COMPLETE |
| agent logs (show/export, JSON/CSV) | COMPLETE |
| source list/info/enable/disable/update/uninstall/run/config/audit | COMPLETE |
| ATT&CK (summary/coverage/killchain/apt/detect/ti) | COMPLETE |
| assess (触发评估) | COMPLETE |
| 权限系统 (4级) | COMPLETE |
| 命令别名 (?/ls/v/st/h/ag/ak) | COMPLETE |
| **SPC cve/kev/score/fetch** | **全部STUB** |
| **source deploy** | **未实现** |
| **Readline/历史回退** | **缺失** |
| **Tab补全** | **基础设施存在但未接线** |
| `--watch` 标志 | **声明但未实现** |
| `CheckPermission()` | **STUB (始终返回true)** |

### 3.3 WebUI — 90%

| 功能 | 状态 |
|------|------|
| Dashboard (总览+主机列表) | COMPLETE |
| 主机详情报告 (域/边缘/SPC/ATT&CK) | COMPLETE |
| 历史时间序列 | COMPLETE |
| 嵌入式SPA (~325行 vanilla JS + CSS) | COMPLETE |
| 历史管理 (每主机200条, FIFO) | COMPLETE |
| 认证 | **缺失** |
| CORS | **缺失** |
| WebSocket实时推送 | **缺失** |

---

## 四、适配器完成度

### 4.1 生产就绪 (11/21 = 52%)

| 适配器 | 类型 | 亮点 |
|--------|------|------|
| **Trivy** | 扫描器 P0 | 完整JSON反序列化, CVSS V3提取 |
| **Nuclei** | 扫描器 P0 | JSONL逐行解析, CVE/CVSS三级提取 |
| **Lynis** | 扫描器 P0 | 正则14域映射, 8级严重度 |
| **Suricata** | 扫描器 P1 | JSON+文本双解析, 4专项测试 |
| **Falco** | 扫描器 P1 | JSON+文本双解析, 8级优先权 |
| **ClamAV** | 扫描器 P1 | JSON+文本, 感染文件提取, 4测试 |
| **OSV-Scanner** | 扫描器 P2 | JSON + CVE别名解析, 3测试 |
| **Ansible** | 管理 P0 | 完整INI解析, 组/主机/变量 |
| **NetBox** | 管理 P0 | HTTP API, JSON+严重度映射 |
| **Snipe-IT** | 管理 P0 | HTTP API, 状态→严重度映射 |
| **Terraform** | 管理 P2 | 二进制执行+JSON获取(但仅子串解析) |

### 4.2 部分完成 (10/21 = 48%)

| 适配器 | Fetch | Parse状态 |
|--------|-------|-----------|
| OpenSCAP | `oscap eval`→XML | 仅grep stdout |
| Wazuh Agent | `wazuh-control` | 仅检查"running", JSON struct死代码 |
| AIDE | `aide --check` | 仅统计变更行数 |
| Nikto | `nikto -h` | 仅关键字检测 |
| FreeIPA | `ipa user-find` | 仅计数 |
| Keycloak | HTTP GET | **无认证**, 仅连通性探测 |
| Wazuh SIEM | HTTP POST | 获取token但不调用数据端点 |
| Rundeck | HTTP GET | 仅连通性探测 |
| Jira | HTTP GET | 仅连通性探测 |
| OpenTofu | `tofu show -json` | 仅子串计数 |

---

## 五、检查项库

| 系列 | 数量 | 状态 | 方法 |
|------|------|------|------|
| AS (攻击面) | 17 | 全部实现 | `os.ReadFile`, `common.RunCmd` |
| OT (操作可信度) | 22 | 全部实现 | 文件权限, 审计日志, 供应链 |
| RS (韧性) | 12 | 全部实现 | sysctl, iptables, fail2ban |
| BC (业务连续性) | 3 | BC-005~007 | `systemctl`, `ss`, `df` |
| AC (ACI指标) | 8 | 全部实现 | 网络分段, EDR, DLP |
| EF (边缘因子) | 2 | EF-001/002 | 2FA/3FA检查 |
| KS (内核安全) | 12 | 全部实现 | 内核参数, eBPF, SecureBoot |
| **总计** | **76** | **100%** | — |

---

## 六、测试覆盖

| 度量 | 数值 |
|------|------|
| 测试文件 | 24 |
| Test函数 | 139 |
| Benchmark | 6 |
| **零测试包** | **11** |

### 零测试包清单
| 包 | 严重度 | 原因 |
|----|--------|------|
| `internal/adapterhub` | 高 | 适配器管理中心 |
| `internal/agent` | 高 | 核心Agent逻辑 |
| `internal/config` | 高 | 674行配置解析器 |
| `internal/model` | 中 | 数据模型 |
| `internal/prism` | 中 | Prism适配层 |
| `internal/webui` | 中 | Web仪表盘 |
| `cmd/kernel` | 高 | 入口点 |
| `cmd/agent` | 高 | 入口点 |
| `cmd/asscor` | 高 | 入口点 |
| `internal/common` | 中 | 共享工具 |
| `internal/version` | 低 | 常量 |

---

## 七、部署基础设施

| 制品 | 状态 |
|------|------|
| **Makefile** | 缺失 |
| **CI (GitHub Actions)** | 缺失 |
| **Dockerfile** | 缺失 |
| **docker-compose** | 缺失 |
| **build/目录** | 缺失 |
| **跨平台支持** | Unix+Windows daemonization |
| **交叉编译** | `GOOS=linux GOARCH=amd64` |

---

## 八、总体评估

**项目完成度: 75%**

| 层级 | 完成度 | 评价 |
|------|--------|------|
| **核心算法** (SSAM V2.0) | 100% | 三层语义模型, DSL/AST, IR, 顶级质量 |
| **安全计算** (SPC) | 90% | 6数据源融合, 性能需优化 |
| **威胁分析** (ATT&CK V19) | 95% | 8子系统, 60+测试, 深度集成 |
| **内核微服务** | 80% | 6个模块有未完成边缘功能 |
| **适配器层** | 60% | 52%生产就绪, 管理适配器浅层解析 |
| **界面层** (CLI/WebUI) | 85% | CLI部分stub, WebUI无实时推送 |
| **基础设施** | 55% | 文档齐全, 测试/CI/部署缺失 |

### 优先修复建议

**P0 — 阻塞生产:**
1. CTI 模块集成真实威胁源 (OTX/MISP)
2. 管理适配器 Parse 层 (6个连通性探测 → 结构化数据提取)
3. CLI SPC 子命令实现 + `source deploy`

**P1 — 影响稳定性:**
4. Heartbeat Agent 清理 (防内存泄漏)
5. Commander 命令队列 TTL (防内存泄漏)
6. Persistence 日志保留策略
7. AdapterIntegration Stop() goroutine 泄漏
8. 11个零测试包补充测试
9. CI/CD 管道搭建

**P2 — 完善体验:**
10. WebUI 认证 + WebSocket
11. CLI Readline + Tab补全
12. Proto 同步 + gRPC Heartbeat 返回评估结果
13. Docker 支持
