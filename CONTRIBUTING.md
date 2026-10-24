# 贡献指南 (Contributing Guide)

感谢你对 ASSCOR 的兴趣！本指南帮助你在 **10 分钟内** 完成从 clone 到跑通全部测试，并了解项目的构建、测试与贡献规范。

---

## 1. 项目是什么

ASSCOR（ASSess + CORe）是一个 **安全可接受性评估运行时**：聚合漏洞扫描器、SIEM、主机检查的结果，用量化模型（SSAM 2.0）输出 0–100 的安全可接受性分数。

- **微内核架构**：内核（`internal/kernel/`）只保留扩展框架（Plugin 接口、DI 容器、事件总线、扩展点注册表、生命周期引擎）。**全部功能模块是 build-tag 可选插件**，默认构建零膨胀。
- **两个独立算法库**（零外部依赖、纯函数）：
  - `ssam-lib/` → SSAM 2.0 评估模型（`github.com/chins-xing/ssam`）
  - `prism-lib/` → Prism/SRD 三层风险引擎（`github.com/chins-xing/prism`）
- 两者通过 `go.mod` 的 `replace` 指令本地引用，代码文件由本仓库直接跟踪。

---

## 2. 环境要求

| 依赖 | 版本 | 说明 |
|------|------|------|
| Go | **1.26+** | `go.mod` 声明 `go 1.26` |
| 操作系统 | Linux（主）/ Windows（开发） | 检查项与特权 Agent 面向 Linux；Windows 仅用于开发与测试 |

> Windows 已知问题：部分包（`common`、`engine/srd`）的测试可能被杀毒软件拦截（测试二进制写入被拒绝），属环境问题而非代码缺陷。在 Linux 上运行完整测试。

---

## 3. 快速开始

```bash
# 1. 克隆（代码完整，ssam-lib/prism-lib 文件已包含）
git clone <repo-url> ASSCOR && cd ASSCOR

# 2. 最小内核构建（无 build-tag，零膨胀）
go build ./cmd/kernel/

# 3. 全功能内核构建（18 个模块全开）
go build -tags "heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine" ./cmd/kernel/

# 4. 一键构建全部三个二进制（Linux amd64）→ build/
./scripts/build.sh

# 5. 测试（无 tag：内核与常编译包）
go test ./internal/...

# 6. 测试（全 tag：所有模块）
go test -tags "heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine" ./internal/...
```

> 没有独立 tag 的 `go test ./internal/assessor/` 会报 "build constraints exclude all Go files" —— 这是**预期行为**：可选模块需要对应 tag 才有内容。

---

## 4. 模块与 build-tag 依赖关系

每个功能模块是独立 Go 包 + build-tag 门控。模块间依赖关系（新增模块时必须遵守）：

```
engine  ──依赖──► adapter, checks
assessor ──依赖──► kernel 契约 (EngineScorer/ScoringEngineProvider)   [不依赖 engine 包]
attck    ──依赖──► kernel 契约 (ATTACKProvider)                       [不依赖 engine 包]
srdwrapper ──依赖──► engine/srd  ⚠️ 需要 engine tag 一起编译
comms    ──依赖──► 各模块接口契约
```

**原则**：
- 模块的接口契约（`AssessorEngine`/`ATTACKProvider`/`SPCProvider`/`EngineScorer` 等）定义在 `internal/kernel/engine_types.go`（常编译），**模块只依赖契约，不依赖实现包**。
- 例外：`srdwrapper` 包装 `engine/srd` 的实现类型，必须 `-tags "srdwrapper,engine"` 一起编译。
- 新模块请先定义契约（kernel 包），再实现（独立包 + build-tag + `cmd/kernel/xxx_on.go`/`xxx_off.go` 接线桩）。

**验证模块独立编译**（新增模块后必须）：

```bash
go build -tags <mytag> ./internal/<mymodule>/   # 应通过（除非该模块声明依赖其他 tag）
```

---

## 5. 代码约定

### 5.1 提交信息（中文）

```
<主题>: <详细描述>

示例：
agent权限拆分: 主进程(非root)+特权进程(root)分离架构 — 主agent降权User=asscor...
```

### 5.2 审计 vs 检查（重要约定）

| 术语 | 含义 | 动作 |
|------|------|------|
| **审计 (audit)** | 分析问题、归档报告，**不立即修复** | 报告存入 `docs/3-audits/` |
| **检查 (check)** | 发现代码问题并**立即修复** | 直接改代码，不归档 |

### 5.3 代码风格

- 构造函数 `New*`；Getter 不加 `Get` 前缀（`Container()` 而非 `GetContainer()`）
- 接口：Provider 后缀（`*Provider`）、能力接口 `*able` 后缀（`HealthCheckable`）
- JSON tag 用 snake_case + `omitempty`
- 编译时接口断言：`var _ kernel.Plugin = (*MyModule)(nil)`
- 提交前必须 `gofmt -w`（全仓库已格式化，CI 会检查）
- `go vet ./internal/... ./cmd/...` 零警告

---

## 6. 目录结构速览

```
cmd/kernel/        内核入口（含各模块 on/off 接线桩）
cmd/agent/         Agent 入口（主进程 + 特权进程 --privileged）
cmd/asscor/        CLI / 独立评估工具
internal/kernel/   微内核：Plugin/DI/Bus/扩展点/生命周期（常编译）
internal/<module>/ 功能模块（build-tag 可选，如 assessor/attck/spc/policy/comms...）
internal/model/    数据模型（CheckItem/AssessmentResult/DomainScores）
internal/checks/   80 项检查（//go:build checks，linux 实现）
internal/adapter/  21 个外部工具适配器
optional/          可选扩展：algorithms/(多算法/attck-ext-pack) + pkgmgr + SCHEMA.md
pluginsdk/         JSON-RPC 独立进程插件 SDK（RPCPlugin）
ssam-lib/          SSAM 2.0 算法库（独立 module）
prism-lib/         Prism/SRD 算法库（独立 module）
api/v1/            gRPC protobuf 定义
configs/           行业配置模板（银行/政府/医院/教育等 8 套）
docs/              白皮书 / 审计报告 / 架构审查（20 章中英双语）
```

---

## 7. 如何贡献

### 社区模式与许可证

本项目采用 **Apache License 2.0**（见仓库 [LICENSE](../LICENSE)）。主仓库与 `main` 分支由维护者**单人开发与合入**，采用"上游谨慎、下游自由"模式：

- **想合入上游**：Fork → 修改 → PR → 维护者 review 后合入 `main`
- **想独立发展**：直接 Fork 自由分支，可二次开发、分发、**闭源**（Apache 2.0 允许），无需等待上游
- `main` 分支始终为 CI 全绿的可发布状态；实验性方向以可选模块/扩展包形式存在，不进 `main`

### 贡献流程

1. **Fork 并创建分支**：`git checkout -b feat/<your-change>`
2. **实现**：遵守 §5 约定；新功能优先考虑"模块/扩展包"形式而非改动内核
3. **验证**：§3 的构建 + 测试全绿；新增代码带测试（`*_test.go`）
4. **提交**：中文提交信息（§5.1）
5. **发起 PR**：描述改动、测试结果、与现有模块的关系；CI 全绿后由维护者 review 合入

### 贡献类型参考

| 类型 | 落点 | 示例 |
|------|------|------|
| 新检查项 | `internal/checks/linux/` + 注册 | 新增合规检查 |
| 新适配器 | `internal/adapter/` | 接入新的扫描器 |
| 新模块 | 独立包 + build-tag + 接线桩 | 新的算法引擎 |
| 扩展包 | `optional/<category>/packages/` | 生态扩展（见 `optional/SCHEMA.md`） |
| 文档 | `docs/` | 白皮书/审计/手册 |

---

## 8. 常见问题

| 问题 | 解答 |
|------|------|
| `go build ./cmd/kernel/` 报错？ | 检查 Go 版本 ≥ 1.26 |
| 单 tag 编译失败？ | 确认模块依赖的 tag 已带上（见 §4 依赖表） |
| Windows 上测试失败？ | 检查是否杀毒拦截测试二进制；在 Linux 上复验 |
| 想提交 ssam-lib/prism-lib 的改动？ | 它们是独立仓库，代码由本仓库跟踪，但独立 git 历史在各自目录中 |
| 扩展点不够用？ | 扩展点定义是平台专属（`RegisterPoint`），模块只能订阅；新增扩展点需先讨论 |

## 9. 本地开发已知坑（先读，避免把"环境红"当成"代码红"）

以下每一条都**在本仓真实踩过**，并会让门禁看起来像失败。判断纪律：**先确认是哪一类，再下结论。**

| 现象 | 真实原因 | 正确做法 |
|---|---|---|
| `gofmt -l` 列出**几百个**文件 | `core.autocrlf=true`：工作树是 CRLF，入库是 LF，`gofmt` 按工作树字节判断 | 按**入库内容**算：`git ls-files --eol` 看 `i/lf`，或把跟踪文件以 LF 写进临时树再 `gofmt -l`。本仓真实债是 **15 个**既有不合规文件，不是 325 个 |
| `go test` 报 `open ...\xxx.test.exe: Access is denied` | Windows 临时目录/杀毒拦截测试二进制（**不是**断言失败） | 重跑一次；仍失败就 `go test -c -o <显式路径> ./包/` 再直接运行该 exe。**不要**据此判定代码红 |
| `go test ./...` 偶发 `directory is not empty` | Windows `TempDir` 清理竞态（`securemode`/`agent` 偶现） | 单包复跑；两次都绿即环境问题 |
| Git Bash 里 `python3` 提示 "Python was not found" | 命中 Windows Store 的 `python3` 别名 | 用 shim：`PYTHONUTF8=1 /c/Python314/python.exe "$@"`，并把它放到 `PATH` 前面 |
| `bash script.sh \| tail` 的 `$?` 恒为 0 | **管道返回的是 `tail` 的 rc** | 直接跑再 `echo rc=$?`，或取 `${PIPESTATUS[0]}`。**判 rc 绝不许用管道** |
| `git cat-file blob X \| git hash-object --stdin` 得到的 sha 不对 | PowerShell 管道会改写行尾/编码 | 用 `git rev-parse HEAD:<path>` 取 blob id |
| PowerShell `Get-Content -Raw` + `Set-Content` 改中文文件后乱码 | 往返会把 UTF-8 中文写成替换字符并加 BOM | 改文本用编辑器/`write` 工具；校验用 `python -c "open(p,'rb').read().decode('utf-8')"` |
| `git check-ignore -v` 返回 0 却以为"被忽略" | 命中**否定规则**时它同样返回 0 | 判"是否会被跟踪"只信 `git check-ignore -q`（rc=1 = 会被跟踪） |
| `lab-diff` / `test-matrix-classification` 在 Windows 必红 | 前者需 `unshare -rm`；后者需 exec bash 桩（Windows 上 `WinError 193`） | 这两组只在 Linux 上算数；在 Windows 上请给出"干净 HEAD 同样红"的对照再下结论 |
| `git push` 报 `Failed to connect to github.com port 443`，但 `ping 223.5.5.5` 通 | **本地代理没起**（该环境下 GitHub 需经代理） | 先确认代理端口在监听（`Test-NetConnection 127.0.0.1 -Port <端口>`），再用 `git -c http.proxy=http://127.0.0.1:<端口> push`。**推送失败不要反复重试**，确认代理后推一次即可；本地提交不会丢 |
| 直接 `gofmt -l` 与"按入库内容算"结果差几百个 | `git archive` 默认也受 `core.autocrlf` 影响（会导出 CRLF） | 要用 `git -c core.autocrlf=false archive HEAD \| tar -x -C <dir>` 再 `gofmt -l`，那才是**入库内容**的真实形态 |

内仓提醒：`ssam-lib/` 与 `prism-lib/` **各自是独立 git 仓库**，外层按普通目录跟踪其文件。
改这两个库时，**外层提交 + 内仓提交要都做**（否则内仓会出现"旧代码 + 一堆未提交改动"）。

---

*本指南与 `README.md`、`docs/` 保持同步。发现不一致请提交 issue。*
