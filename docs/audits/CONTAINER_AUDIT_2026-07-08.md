# ASSCOR 容器化专项审计报告

**日期**: 2026-07-08 | **版本**: v0.2.0 | **文件**: 4 个 (Dockerfile, docker-compose.yml, config.docker.ini, .dockerignore)

---

## 审计结论：基本就绪，已修复 3 项关键问题

---

## 一、Dockerfile 审计

| # | 检查项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | 多阶段构建 (builder + runtime) | ✅ | golang:1.26-alpine → alpine:3.20 |
| 2 | 静态编译 (CGO_ENABLED=0) | ✅ | 纯静态二进制 |
| 3 | 构建加固 (-trimpath -s -w) | ✅ | 源码路径剥离 + 符号表去除 |
| 4 | 非 root 运行 (USER asscor) | ✅ | 最小权限原则 |
| 5 | HEALTHCHECK | ✅ | wget /api/health, 30s 间隔, 5s 超时 |
| 6 | STOPSIGNAL | ✅ | SIGTERM (优雅关闭, 本次修复) |
| 7 | FHS 布局 | ✅ | /etc/asscor, /var/lib/asscor, /var/log/asscor |
| 8 | 层缓存优化 (go.mod→go.sum→src) | ✅ | 依赖先复制, 源码变更不触发重下载 |
| 9 | certs/ 目录创建 | ✅ | 本次审计已确认 |
| 10 | 多架构支持 | ⚠️ | 仅 amd64, 缺 arm64 GOARCH 参数 |

---

## 二、docker-compose.yml 审计

| # | 检查项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | 双服务编排 (kernel+agent) | ✅ | depends_on: condition=service_healthy |
| 2 | 持久化卷 (data/logs/certs/cli) | ✅ | 5 个 named volume, 重启不丢失 |
| 3 | read_only 根文件系统 | ✅ | 本次修复重复项 (原 YAML 语法错误) |
| 4 | 资源限制 (memory/cpu) | ✅ | 2G 上限, 512M 预留 |
| 5 | 健康检查 | ✅ | 与 Dockerfile 参数一致 |
| 6 | 日志轮转 (json-file max-size) | ✅ | 10MB × 3 文件 |
| 7 | 扩展兼容 (scripts/cli socket/tmpfs) | ✅ | 本次审计确认全部 6 种扩展方式可用 |
| 8 | Agent 运行模式 (host网络+privileged) | ⚠️ | 安全风险: 共享主机网络和进程空间 |

---

## 三、config.docker.ini 审计

| # | 检查项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | data_dir 正确 | ✅ | /var/lib/asscor (data 卷路径) |
| 2 | console_report 关闭 | ✅ | 容器用 JSON 日志 |
| 3 | weights_hotload | ✅ | 启用, 30s 轮询 |
| 4 | [integrity] 节 | ✅ | 本次补充 (sign+verify on, anti-debug off) |
| 5 | [spc] 节 | ⚠️ | 缺省 NVD/EPSS/KEV 等子节 |
| 6 | [attck] 节 | ⚠️ | 缺失 |
| 7 | [prism] 节 | ⚠️ | 缺失 |

---

## 四、.dockerignore 审计

| # | 检查项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | .git/ | ✅ | |
| 2 | build/ | ✅ | |
| 3 | docs/ | ✅ | 文档不打包进镜像 |
| 4 | certs/ | ✅ | 密钥不打包, 运行时挂载 |
| 5 | scripts/ | ✅ | 本次补充 |
| 6 | *.bak | ✅ | 本次补充 |
| 7 | vendor/ | ✅ | |

---

## 五、扩展性兼容确认

| 扩展方式 | 容器化兼容 | 机制 |
|---------|-----------|------|
| user_check | ✅ | config.ini 只读挂载 |
| adapter_script | ✅ | scripts/ 只读挂载 + tmpfs |
| CLI socket | ✅ | ASSCOR_CLI_SOCKET 环境变量 + cli 共享卷 |
| Plugin SDK | ✅ | tmpfs + data 卷 (extensions 目录) |
| extmgr | ✅ | data 卷覆盖 /var/lib/asscor |
| WebUI 路由 | ✅ | 进程内注册, 无影响 |

---

## 六、待改进项 (非阻塞)

| 优先级 | 项目 | 建议 |
|--------|------|------|
| P2 | 多架构支持 | Dockerfile 添加 `ARG TARGETARCH`, buildx 构建 amd64/arm64 |
| P2 | Agent privileged 模式 | 考虑用 capabilities 替代 `privileged: true` |
| P3 | config.docker.ini 补齐 | 添加 [spc]/[attck]/[prism] 节 |
| P3 | 构建缓存 | 添加 `--mount=type=cache,target=/root/.cache/go-build` |
