# 离线判据（`lunwen/clab-lab/tests/`）

**为什么在这里**：这些夹具此前都放在 `build/` 下，而 `build/` 被 `.gitignore` 整个忽略
（`git ls-files build` 为空）⇒ **克隆者拿不到任何判据**，回归能力只存在于开发机上
（Task 4D Fix round 2 复审的 N-1）。现在它们在仓内可跟踪位置，并有统一入口。

```bash
bash lunwen/clab-lab/tests/run-all.sh          # 全部 5 组
bash lunwen/clab-lab/tests/run-all.sh edge-lab # 只跑一组（名字取文件名去掉 .sh）
```

**期望通过数**（任何一条不到就是回归；`run-all.sh` 会逐组比对）：

| 夹具 | 通过数 | 钉住什么 |
|---|---|---|
| `test-agent-readiness.sh` | **3** | agent 就绪判据：pid 列表 ⇒ 必须回出 paw（旧布局把 pid 列表喂 stdin 时**恒回空**，于是"目标上有没有活着的 agent"恒为否）；空列表回空；旧布局回空（回归钉） |
| `test-edge-lab.sh` | **26** | 基质层：clab 分支命令序列逐行不变、lxd 分支在假 `lxc` 上真干活、`lab_up/down` 响亮失败、非法基质名中止调用方、`EDGEEXP_DOCKER_BIN` 覆盖生效且不泄漏到拓扑级、detached argv 保真，以及 **G 段**：STOPPED 的实例**不得**被判成"已就绪"（旧写法 0 轮就通过） |
| `test-edge-probe.sh` | **20** | 条件探针：六因子的探针判据体、探针根配错 ⇒ rc=2（不得产出"看似有效的结论"） |
| `lab-diff.sh` | **31** | 基质抽象的**真基线**差分：`git archive <base>` 取抽象前的整棵树，两侧跑同一份假 CLI（clab/docker/curl），比较调用序列 / stdout / stderr / 退出码 / 产物 |
| `test-chain-derivation.sh` | **8** | L2 标签口径：从 `edge_attack.sh` **抽出**判据块，用 Step 3B 两条真实 chain 跑（策略在 ⇒ `compromised=false`；旧口径在同一条链上给 `true`；`-3` 不算被拦住；缺少目标 link ⇒ 响亮失败） |

**纪律**：全部**只读、离线** —— 不碰 clab / LXD / 容器 / Caldera，不写仓库（临时目录在 `$HOME` 或 `/tmp`）。
`lab-diff.sh` 需要一个 git 仓库（它用 `git archive` 取真基线）；默认 `base = 97581d8`，
可用 `bash …/lab-diff.sh <commit>` 换基线。

**与 `build/` 的关系**：开发机上 `build/` 里仍有同名副本（历史习惯路径）。**判据的权威版本是这里**；
两边同时改就会漂移，故只在 `build/` 留一份薄壳（`build/<name>.sh` → 转发到本目录）。
