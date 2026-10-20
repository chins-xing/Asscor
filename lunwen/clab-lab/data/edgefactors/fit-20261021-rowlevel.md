# 边缘因子拟合报告

交叉验证平均对数损失（k 折）: 3.491897
模型: graph｜p_floor = 0.5｜先验边: EF-002FA|EF-3FA=0 EF-002FA|EF-SELINUX=0 EF-APPARMOR|EF-SELINUX=0 EF-NO-IDS|EF-NO-SIEM=0 EF-NO-IDS|EF-SYNCOOKIE=0
标签依据口径: 参与拟合 22 条（targeted_ttp=22）｜**跳过 11 条**（recon_playbook=11，侦察口径=背景测量、不是标签）｜过滤前共 33 条

重抽样单位: **逐行**（k 折与自助法都按记录行切；同一实例的多条记录可能同时进训练与验证 —— 历史口径，既有产物即此口径）

| 列 | 系数 β | 自助法 95% 区间 | 折回的参数 |
|---|---|---|---|
| (intercept) | 0 | [-67.96175662148116, 47.6783018473287] | (不映射：截距吸收基线概率) |
| EF-002FA | 0 | [-15.753737070732273, 14.197744903526486] | f_EF-002FA = 1 |
| EF-002FA\|EF-3FA | 0 | [0, 0] | coupling 不写（β ≤ 0） |
| EF-002FA\|EF-SELINUX | 0 | [-105.02491380488793, 94.65163269017968] | coupling 不写（β ≤ 0） |
| EF-3FA | 0 | [-63.872561033754835, 60.759630152435115] | f_EF-3FA = 1 |
| EF-APPARMOR | 0 | [-188.4558968029626, 244.17737217348224] | f_EF-APPARMOR = 1 |
| EF-APPARMOR\|EF-SELINUX | 0 | [-1597.5274756923425, 2590.7222767992967] | coupling 不写（β ≤ 0） |
| EF-NO-IDS | 0 | [-455.3847591198971, 319.84506415592773] | f_EF-NO-IDS = 1 |
| EF-NO-IDS\|EF-NO-SIEM | 0 | [-404.6478541074847, 342.66010678409697] | coupling 不写（β ≤ 0） |
| EF-NO-IDS\|EF-SYNCOOKIE | 0 | [-314.9985537784816, 310.7885281569901] | coupling 不写（β ≤ 0） |
| EF-NO-SIEM | 0 | [-38.84619399431759, 32.895370251269675] | f_EF-NO-SIEM = 1 |
| EF-SELINUX | 0 | [-460.7117362782147, 409.3852968976315] | f_EF-SELINUX = 1 |
| EF-SYNCOOKIE | 0 | [-30.239861162732808, 29.835698703072232] | f_EF-SYNCOOKIE = 1 |

映射规则（写死，近似性见 fit.go 注释）：主效应 `β_i > 0 ⇒ Factors[i] = clip(1 − β_i, 1e-3, 1)`、`β_i ≤ 0 ⇒ Factors[i] = 1`；交互 `β_ij > 0 ⇒ Coupling[i][j] = min(β_ij, 1)`、`β_ij ≤ 0 ⇒ 不写`。该映射是对数优势比尺度的启发式换算，**不是**参数标定；本轮结论口径限『哪些边显著 + 决策层改善』，标定后置。

[edge_factors.model]
model = graph
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
