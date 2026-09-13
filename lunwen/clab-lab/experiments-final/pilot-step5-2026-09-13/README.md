# Step 5 试点（Task 4D，2026-09-13）—— 三个条件的原始证据

**环境**：A-1 远程服务器，LXD 基质（`EDGEEXP_SUBSTRATE=lxd`），目标实例 `asc-tgt-1`
（Step 3 硬化：六个控制齐备；Step 3B 的真实 AppArmor 限制策略）
**harness**：`EDGEEXP_SUBSTRATE=lxd` 的 `edge_reset.sh`（幂等准备实例）→ `edge_attack.sh` → `edge_collect.sh`
**剧本**：自建 pair adversary `a5c0ffee-0000-4000-8000-0000000003c2`
（两条 ability：`…3b1` = `head -1 /etc/shadow`；`…3c1` = 写 `/tmp/t4d-control-marker`）
**投送范围**：`EDGEEXP_ATTACK_GROUP=t4d-ttp`（A-1 上另有控制侧的 `probe-ot005` agent，组 `red`；
未声明组时 `edge_attack.sh` 在 `basis=targeted_ttp` 下**直接失败**，因为"目标 TTP 在别的机器上成功"
与"目标机被攻陷"在派生代码里同形）
**策略规则**：`raw.apparmor = 'audit deny /etc/shadow r,'`（"在"）；`lxc config unset` + 重启（"不在"）

## 三个条件的读数（全部取自下面的原始文件）

| # | 条件 | `meta.env` | 目标 ability | `compromised` | `block_effective` | `ttc`(s) | `ttps` | 失败检查 | 总分/阈值 | `basis` |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 策略**在** | `a1-lxd` | 读 `/etc/shadow` | **false** | true | 5 | 1 | 41 | 69.72 / 80 | `targeted_ttp` |
| 2 | 策略**不在** | `a1-lxd-off` | 读 `/etc/shadow` | **true** | false | 47 | 2 | 42 | 68.78 / 80 | `targeted_ttp` |
| 3 | 策略**在** | `a1-lxd-on-marker-target` | 写 marker（不撞策略） | **true** | false | 36 | 1 | 41 | 69.72 / 80 | `targeted_ttp` |

- 观测主体三条都是 `node:asc-tgt-1 (substrate=lxd, hostname=asc-tgt-1)`；门禁②（round-trip）残差全部 **+0**。
- 条件 1 与条件 3 的**宿主状态完全相同**（同一轮复位、同一条策略、同一份检查结果 41 条失败），
  只有"目标 ability"不同 ⇒ `compromised` 因此取到 `false` / `true` 两个值。
- 三个条件里**对照/通道**侧的 link 都是成功的（`t4d-control` 一路 `status=0`）
  ⇒ 条件 1 的 `false` 不是"通道或执行器坏了"。

## 试点要回答的三个问题

1. **`compromised` 是否真的取到了 `true` 与 `false` 两个值？** —— **是**。而且是在**同一宿主状态**
   （策略在）下取到的：目标=读 `/etc/shadow` ⇒ `false`（策略把 TTP 拦住），目标=写 marker ⇒ `true`。
   策略不在时同一条 TTP ⇒ `true`。⇒ 标签跟的是**该场景的目标 TTP 是否成功**，不是"策略在不在"。
2. **分数是否出现了第三个数据点（不是 68.78 的重述）？** —— **是：69.72**。但**成因必须写清**：
   差值来自**恰好一条检查** `AS-012`（幽灵账户检测，`Delta=-6`）。策略在时它读不到 `/etc/shadow`，
   框架把"只因权限被拒而失败"的检查转成 **skip（`passed=true`、`Delta=0`）**
   （`internal/model/model.go` 的 `IsPermissionDeniedDetail` 分支）⇒ 失败检查 42→41、总分 68.78→69.72。
   ⇒ **这 0.94 分不是"硬化提升了安全分"，也不能当"标签与分数耦合"的证据**：条件 3 证明分数 69.72
   可以配 `compromised=true`（分数只跟宿主检查状态走）。写进论文时按此口径。
3. **固定 `Discovery` 背景测量（恒为真）的报告** —— **本试点没有重跑它**（本轮三个条件的剧本都是
   T4D pair adversary，不是 `Discovery`）。已有的诚实读数：Step 3B 在**同一台硬化实例**上跑固定
   `Discovery` 剧本，**13/14 条 ability 成功**；Step 3 的基线记录（`basis=recon_playbook`）里
   `compromised=true`。⇒ 固定剧本的标签**恒为真、不产生方差**，这正是 L2 裁定要把
   `basis=recon_playbook` 的记录**排除出决策层指标**的原因（`cmd/edgecompare` 的标签依据守卫）。
   **本轮未跑 ⇒ 不得按"本轮已验证"引用。**

## 文件

| 文件 | 内容 |
|---|---|
| `records-a1-lxd-policy-on.jsonl` | 条件 1 的记录（`edge_collect.sh` 写出；单行 JSONL） |
| `records-a1-lxd-policy-off.jsonl` | 条件 2 的记录 |
| `records-a1-lxd-policy-on-marker-target.jsonl` | 条件 3 的记录 |
| `attack-S0-policy-on.json` | 条件 1 的 harness 产物（含 `target_ttp` / `control` / `other_links` / `attack`） |
| `attack-S0-policy-off.json` | 条件 2 的 harness 产物 |
| `attack-S0-policy-on-marker-target.json` | 条件 3 的 harness 产物 |

记录里的 `ground_truth` 段（三条都带 `basis` 与 `target_ability`）：

```json
{"compromised": false, "time_to_compromise_s": 5, "ttps_achieved": 1, "nodes_affected": 1,
 "block_effective": true, "basis": "targeted_ttp",
 "target_ability": {"id": "a5c0ffee-…3b1", "name": "T4D Step 3B: read /etc/shadow (AppArmor target TTP)"}}
```

## 复现（A-1 上）

```bash
# 条件 1：策略在（复位 → 攻击 → 采集；env=a1-lxd）
EDGEEXP_SUBSTRATE=lxd EDGEEXP_TARGET=asc-tgt-1 EDGEEXP_POLICY_ON=1 ./scripts/edge_reset.sh S0-baseline
# 条件 2：策略不在（EDGEEXP_POLICY_ON=0 ⇒ 复位会 unset raw.apparmor 并重启实例、重新拉起 sandcat）
# 条件 3：同条件 1，但把 EDGEEXP_TARGET_ABILITY 与 EDGEEXP_CONTROL_ABILITY 互换
```

`EDGEEXP_EDGESCEN` / `EDGEEXP_CONFIG` / `EDGEEXP_DATA_DIR` / `EDGEEXP_ENV` / `EDGEEXP_RECORDS`
按 A-1 上的路径给（见 Task 4D 报告「Step 4 / Step 5」节的逐条命令）。
