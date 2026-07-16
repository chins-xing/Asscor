# ASSCOR Extension Package Manifest Schema

版本: 1.0 | 最后更新: 2026-07-17

## 文件位置

每个扩展包的根目录下必须包含一个 `package.json` 文件。

## 完整 Schema

```json
{
  "name": "string (required) — unique package identifier",
  "version": "string (required) — SemVer 2.0",
  "description": "string — human-readable description",
  "author": "string",
  "license": "string — SPDX identifier",

  "modules": [
    {
      "id": "string (required) — module identifier within package",
      "path": "string (required) — relative path to module directory",
      "type": "single | library — default: single",
      "entry": "string — Go import path override"
    }
  ],

  "external_sources": [
    {
      "repo": "string (required) — git repository URL (https:// or git@)",
      "ref": "string — branch/tag/commit (default: main)",
      "path": "string — subdirectory within the repo to extract",
      "target": "string (required) — local target directory under this package",
      "strip_prefix": "string — path prefix to strip from repo contents"
    }
  ],

  "dependencies": [
    {
      "package": "string — package name",
      "version": "string — version constraint (>=1.0.0, ~1.2.3, ^1.0.0, 1.x)",
      "optional": "boolean — default: false"
    },
    {
      "repo": "string — direct git dependency",
      "ref": "string — branch/tag/commit"

    }
  ],

  "conflicts": [
    {
      "package": "string — conflicting package name",
      "versions": "string — affected version range",
      "reason": "string — explanation of conflict"
    }
  ],

  "compatibility": {
    "asscor_version": "string (required) — ASSCOR version constraint",
    "go_version": "string — Go version constraint",
    "ssam_version": "string — SSAM version constraint",
    "platform": ["linux", "darwin", "windows"]
  },

  "build": {
    "tags": ["string — Go build tags to apply"],
    "ldflags": "string — linker flags",
    "env": { "KEY": "value" },
    "pre_build": "string — shell command to run before build",
    "post_build": "string — shell command to run after build"
  },

  "hooks": {
    "assessor.pre_score": "string — extension point name to subscribe",
    "assessor.post_evaluate": "string",
    "cli.command.register": "string"
  }
}
```

## 版本约束语法

| 语法 | 含义 | 示例 |
|------|------|------|
| `>=1.0.0` | 不低于 | `">=0.2.1"` |
| `<=2.0.0` | 不高于 | `"<=1.0.0"` |
| `>1.0.0` | 严格高于 | `">1.0.0"` |
| `<2.0.0` | 严格低于 | `"<2.0.0"` |
| `^1.2.3` | 兼容更新 (>=1.2.3 <2.0.0) | `"^0.2.1"` |
| `~1.2.3` | 近似版本 (>=1.2.3 <1.3.0) | `"~0.2.1"` |
| `1.0.0 - 2.0.0` | 范围 | `"0.2.0 - 0.3.0"` |
| `1.x` | 通配符 | `"0.2.x"` |
| `1.0.0` | 精确 | `"0.2.1"` |

## external_sources 工作流

1. `asscor-pkg resolve` 扫描所有本地包的 `package.json`
2. 对每个 `external_sources` 条目:
   - 克隆 `repo` 到临时目录
   - Checkout `ref` (如果指定)
   - 提取 `path` 子目录内容到 `target`
   - 可选地用 `strip_prefix` 剥离路径前缀
3. 检测 `target` 中是否有 `package.json` — 如果有，递归解析
4. 验证所有依赖的版本约束
5. 输出依赖图和未解决的冲突
