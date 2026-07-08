# ASSCOR 扩展体系模块分类审计

**日期**: 2026-07-08 | **文件**: extmgr/extension_spec.go, extension_manager.go

---

## 一、 形式扩展类型 (extmgr 注册) — 9 种

| # | 类型常量 | 值 | Validate | onExtensionInstalled | 说明 |
|---|---------|-----|----------|---------------------|------|
| 1 | `ExtTypeCheckModule` | `check_module` | ✅ | ✅ 注册检查项到 checks registry | 新增安全检查 |
| 2 | `ExtTypeScoringPlugin` | `scoring_plugin` | ✅ | ⚠️ 仅日志, 未实际注册公式 | 自定义评分算法 |
| 3 | `ExtTypeAdapter` | `adapter` | ✅ | ⚠️ 仅日志, 未桥接 adapter.Register | 第三方工具适配 |
| 4 | `ExtTypeHook` | `hook` | ✅ | ✅ 注册到引擎 PhasePostScore | 评估流程钩子 |
| 5 | `ExtTypeDomain` | `domain` | ✅ | ✅ 调用 model.RegisterDomain | 新增评估维度 |
| 6 | `ExtTypeEdgeFactor` | `edge_factor` | ✅ | ✅ 调用 model.RegisterEdgeFactor | 边缘修正因子 |
| 7 | `ExtTypeCLICommand` | `cli_command` | ✅ | ⚠️ 仅日志, 未桥接 CLI 注册 | CLI 新命令 |
| 8 | `ExtTypeWebPanel` | `web_panel` | ✅ | ⚠️ 仅日志, 未桥接 webui.RegisterHandler | Web 运维面板 |
| 9 | `ExtTypeCustom` | `custom` | ✅ | ⚠️ 仅日志, 无具体操作 | 完整内核插件 |

## 二、 非形式扩展机制 (config/进程级) — 4 种

| # | 机制 | 注册入口 | 门槛 | 说明 |
|---|------|----------|------|------|
| 1 | `user_check` | config.ini `[user_check.*]` | 零门槛 | 配置定义检查项 |
| 2 | `adapter_script` | config.ini `[adapter_script.*]` | 极低门槛 | 运行任意脚本 |
| 3 | Plugin SDK | stdin/stdout JSON-RPC | Go 开发 | 独立进程插件 |
| 4 | 内核 Plugin 接口 | cmd/kernel/main.go plugins 注册 | Go 编译 | 编译期插件 |

## 三、 分类问题 (3 项)

| # | 问题 | 严重度 | 说明 |
|---|------|--------|------|
| 1 | **ScoringPlugin 安装时不注册公式** | 🟡 | onExtensionInstalled 仅打印日志, 未调用 Engine.RegisterFormula。插件安装后公式不生效, 需手动注册。 |
| 2 | **Adapter/WebPanel/CLICommand/Custom 安装时仅日志** | 🟡 | 4 个类型的 onExtensionInstalled 分支都是 "type handled by..." 的纯日志。实际注册需在扩展点执行, 但 extmgr 未触发这些扩展点。 |
| 3 | **非形式扩展未纳入 extmgr 类型系统** | 🟢 | user_check/adapter_script/PluginSDK 作为扩展机制存在但不属于 ExtensionType 枚举。设计上合理——它们是配置驱动, 非 extmgr 管理。 |

## 四、 模块分类整理建议

| 层级 | 类型 | 接入方式 | extmgr 管理 | 文档覆盖 |
|------|------|----------|------------|----------|
| L0 零门槛 | user_check | 编辑 config.ini | ❌ | ✅ 使用手册 §15.1 |
| L0 零门槛 | adapter_script | config + 脚本 | ❌ | ✅ 使用手册 §15.2 |
| L1 低门槛 | check_module | 编译期 init() | ✅ | ✅ 扩展指南 §2.4 |
| L1 低门槛 | domain | config/extmgr | ✅ | ✅ 扩展指南 §2.8 |
| L1 低门槛 | edge_factor | 编译期 init()/extmgr | ✅ | ✅ 扩展指南 §2.9 |
| L1 低门槛 | adapter | 编译期 init() | ✅ | ✅ 扩展指南 §2.6 |
| L2 中门槛 | scoring_plugin | extmgr/RegisterFormula | ✅ ⚠️ | ✅ 扩展指南 §2.5 |
| L2 中门槛 | hook | extmgr/RegisterHook | ✅ | ✅ 扩展指南 §2.7 |
| L2 中门槛 | cli_command | extmgr/扩展点 | ✅ ⚠️ | ✅ 扩展指南 §2.10 |
| L2 中门槛 | web_panel | extmgr/扩展点 | ✅ ⚠️ | ✅ 扩展指南 §2.11 |
| L3 高门槛 | custom (Plugin) | 编译期注册 | ✅ ⚠️ | ✅ 扩展指南 §2.12 |
| L3 高门槛 | Plugin SDK | 独立进程 JSON-RPC | ❌ | ✅ 使用手册 §15.3 |

## 五、 结论

**13 种扩展方式, 分类清晰, 分层合理。** 
- 9 种通过 extmgr 统一管理, 4 种为非形式扩展(配置/进程级)。
- ⚠️ 4 个 extmgr 类型 (ScoringPlugin/Adapter/WebPanel/CLICommand) 的 onExtensionInstalled 实现不完整, 仅日志记录, 未桥接到实际注册 API。
- ✅ 文档覆盖完整, 使用手册+扩展指南覆盖全部 13 种方式。
