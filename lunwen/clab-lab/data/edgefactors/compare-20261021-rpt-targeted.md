# 边缘因子模型对比报告

生成时间: 2026-10-20T18:43:51Z｜场景数: 66

判定口径: 离线分数 = 引擎总分（`ssam.SSAMV20Formula`，与在线评分同一公式；域级修正经 `RegisterDomainAdjust`/`RegisterEdgeFactorStrategy` 注入，legacy 零注册）；阈值 = 引擎决策线（`Acceptable = 总分 ≥ threshold`）

权重口径: 66 条取记录自带 `observed.effective_weights`／0 条回退 `-weights`（`-weights` 本次未参与计算）

标签依据口径: 参与决策层 66 条（targeted_ttp=66）｜过滤前共 66 条

| 模型 | 决策一致率 | 漏判率 | 误阻断率 | Spearman | Kendall | AUC | N |
|---|---|---|---|---|---|---|---|
| chain | 0.500 | 0.000 | 0.500 | -0.004 | -0.006 | 0.500 | 66 |
| graph | 0.500 | 0.000 | 0.500 | -0.004 | -0.006 | 0.500 | 66 |
| legacy | 0.500 | 0.000 | 0.500 | 0.012 | 0.015 | 0.500 | 66 |
| vector | 0.500 | 0.000 | 0.500 | -0.004 | -0.006 | 0.500 | 66 |

**本次比较无区分力：未选模**（全部候选的三层判据逐位相同：漏判率、误阻断率、AUC 全等；此时「最优候选」只会是模型名字典序的产物，故不给出结论）

[edge_factors.model]
model = chain
p_floor = 0.5
lambda.attack_surface = 1
lambda.business_continuity = 1
lambda.operation_trust = 1
lambda.resilience = 1
lambda.kernel_security = 1
vector.EF-002FA = 0.2,0.1,0.3,0.05,0.05
vector.EF-3FA = 0.15,0.05,0.3,0.05,0.1
vector.EF-APPARMOR = 0.15,0.05,0.2,0.05,0.3
vector.EF-NO-IDS = 0.2,0.05,0.25,0.25,0.05
vector.EF-NO-SIEM = 0.1,0.05,0.3,0.25,0.05
vector.EF-SELINUX = 0.15,0.05,0.2,0.05,0.3
vector.EF-SYNCOOKIE = 0.3,0.15,0.1,0.2,0.05
coupling.EF-002FA.EF-SELINUX = 0.15
coupling.EF-3FA.EF-002FA = 0.4
coupling.EF-NO-IDS.EF-SYNCOOKIE = 0.1
coupling.EF-NO-SIEM.EF-NO-IDS = 0.3
coupling.EF-SELINUX.EF-APPARMOR = 0.35
chain.window_seconds = 300
