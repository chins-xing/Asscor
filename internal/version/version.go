package version

const (
	SSAMVersion   = "2.0"
	ASSCORVersion = "v0.2.3"

	// SRDVersion 是 SRD（Systemic Risk Dynamics）模型版本。
	// v2.0：多层拓扑图（L1 链路 / L2 广播域 / L3 路由 / L4 策略 / L5 资产）
	//       + 会话语义策略 + 接口级 ACL 解析；默认开启分层构边。
	// v2.1：语义补完与数据接线 —— L2 广播域闸门（同子网不同 VLAN 不连通）、
	//       区域（Zone）→ 资产关键性接线、分层图规模统计（可观测性）。
	// v2.2：把 v2.1 的未覆盖项做完 —— L1 链路事实、域内/主机级入向 ACL、
	//       容器内 VLAN 运维覆盖、L5 业务角色（角色优先于区域）。
	// v2.2.1：修复配置接线 —— Config.Get 补上（此前 [srd] 配置被静默忽略），
	//         transmission/max_path_depth/path_decay/prop_cap/aggregation/horizon_days
	//         全部接入并可调；启动日志输出 "SRD effective config"。
	SRDVersion = "2.2.1"
)
