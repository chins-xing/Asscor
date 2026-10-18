# `run.d-t21-qemu-rpt/` —— 重复批（Task 21）**存活下来的**运行级碎片（Task 23 入库）

本目录**不是**「重复批的全部运行级证据」，而是宿主 `/root/t6/t21-data/edgefactors/run.d/`
在两次跑批都结束后**实际存留下来的那一份**（2026-10-19 原样拷入仓，未做任何编辑）。

为什么必须写清楚这一页：`run.d/` 是**固定目录名**（`edge_matrix.sh` 里 `RUN_D="$DATA_DIR/run.d"`），
而 targeted 段与非 targeted 段用的是**同一个 `DATA_DIR`** ⇒ 后跑的段会把先跑段的同名碎片覆盖掉，
而且**只留下最后一轮**（每一轮都覆盖同名文件）。所以下面按「哪一段、哪一轮」逐组标注来源，
不要把它当成「三段都齐全」。

## 一、文件分组与来源（本地时间 = UTC+8）

| 文件（组） | mtime | 属于哪一段哪一轮 | 是什么 |
|---|---|---|---|
| `collect-<场景>-r3.json` × 11 | 2026-10-18 16:39–21:19 | **非 targeted 段第 3 轮** | `edgescen` 逐实例采集自检产物，含 `gate2_round_trip`（逐条 \|复算−记录\|，不通过即拒绝写出该条记录） |
| `reset-<场景>-r3.json` × 11 | 2026-10-18 16:12–20:53 | 同上 | 逐实例复位产物（qemu 基质：幂等的「准备成实验条件」） |
| `.edgescen-<非 targeted 场景>.{out,err}` × 11 组 | 2026-10-18 16:39–21:19 | 同上 | 该实例 `edgescen` 的 stdout/stderr（`err` 全为 0 字节 = 采集没有报错） |
| `gate-gate1.json` / `gate-inputs.json` / `.gate1.err` / `.gate1.out` / `.state.json` | 2026-10-18 21:19:55 | 同上（该段第 3 轮收尾） | 门禁① 的机读结果与工具 stderr；`.state.json` 是该轮运行状态（`failed.reason` 见下） |
| `.edgescen-<targeted 场景>.{out,err}` × 11 组 | 2026-10-18 05:57–06:57（= 2026-10-17 21:57–22:57Z） | **targeted 段第 3 轮** | 那一段的采集自检输出（被后续覆盖后**只剩这一份**同名文件） |
| `.gate2.err` / `.gate2.out` | 2026-10-18 06:57（= 2026-10-17 22:57Z） | **targeted 段第 3 轮** | 门禁② **离线半边**（`edgecompare -candidate legacy`）的 stderr/stdout；`.gate2.err` 全文是「`-weights` 本次未参与计算（66 条记录全部自带 observed.effective_weights）」 |

## 二、**缺**的文件，以及为什么会缺（这一节是重点）

1. **没有 `gate-gate2.json`（两段都没有）**。
   - targeted 段：该段确实跑过门禁② 的离线半边（`.gate2.err/.gate2.out` 就是它的产物、且
     `run-20261017-targeted-r{1,2,3}.json` 的 `gate2_offline_compare.exit_code` 都是 `0`），
     但**机读的 `gate-gate2.json` 被随后那段覆盖**了。
   - 非 targeted 段：**根本没跑**。`edge_matrix.sh` 的门禁② 离线块排在门禁① **之后**，而门禁①
     在这一段三轮都判失败（第三态修复前，全 recon 口径被记成 `exit=1`）⇒ 整轮短路 ⇒ 门禁② 离线
     块一次都没执行（实测复现：`edgecompare` 让门禁① 失败的夹具轮同样**不产出** `gate-gate2.json`，
     见 Task 23 报告 §1.3 的 `run-fix_broken/run.d` 文件清单）。
   - **门禁② 的实质**（逐条复算）由 `edgescen` 的进程内自检承担，它在两段都有、且都在仓内：
     非 targeted 段 = 本目录的 11 份 `collect-*-r3.json`；targeted 段 = 三轮
     `run-20261017-targeted-r*.json` 里的 `gate2_round_trip`（每轮 22 条、最大偏差 0）。
2. **没有 targeted 段自己的 `run.d/`**：它是同一个 `DATA_DIR` 的固定目录，被后面那一段覆盖；
   targeted 段的逐轮运行级证据以 `run-20261017-targeted-r{1,2,3}.json`（矩阵 run.json 的不可变副本）
   的形式入库，其中每一份都带 `gate1_offline_compare` / `gate2_round_trip` /
   `injection_vs_collection` / `chain_factor_set_equality` / `condition_summary` / `observation_target`。
3. **没有第 1、2 轮的 `run.d` 碎片**：每轮都写同名文件 ⇒ 只有最后一轮活下来。
   第 1、2 轮的**轮级**事实（写入条数、文件总行数、`record_counts_ok`、门禁① exit）仍在
   `run-20261017-{targeted,nontargeted}-r{1,2}.json` 里。

## 三、仓内可复核范围（据此判断能断言什么、不能断言什么）

可以（只靠仓内文件）：
- 每一轮的 `record_counts_ok`、`records_written_this_run`、`records_file_total_lines`、
  `records_expected`（`run-20261017-*.json`）；
- 每一轮的**门禁①**：`gate1_offline_compare.exit_code` / `records`（同上）+ 非 targeted 段第 3 轮
  的 `gate-gate1.json` 与工具 stderr 原文（本目录）；
- 每一轮的**门禁② 实质**：`gate2_round_trip.per_scenario` 的 `recomputed/recorded/delta/tolerance`
  （同上），非 targeted 段另有逐实例的 `collect-*-r3.json`；
- 条件与观测主体：`condition_summary`（11 个场景 × 2 臂 = 22 实例，`recon_playbook_instances=0`）、
  `observation_target = asc-vm910`、`chain_factor_set_equality.all_ok`、`injection_vs_collection.all_ok`。

**不能**（仓内没有对应文件）：
- 复算 targeted 段的**逐实例** `edgescen` 进程内自检原文（只有其汇总）；
- 复核两段「真实跑过」的**外部**证据（VM 910 已销毁、Caldera 只读、无第三方时间戳）——
  能证明的仍只是「记录 + 运行级产物在算术与口径上自洽」；
- 第 1、2 轮的 `run.d` 碎片内容（只在 `run.json` 的汇总里）。

> 脱敏：本目录与 `run-20261017-*.json` 均扫过 `ADMIN123` 与 `192.168.30.156`，**0 命中**
> （Task 23 报告 §5.3）。文件里出现的 `/root/t6/...` 是**实验宿主路径**（与主批
> `run.d-qemu-20261016/` 入库时的口径一致），不是凭据。
