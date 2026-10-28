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
	// v2.2.2：修复 A-1 —— Init 解包配置适配器（kc.GetConfigObj() 返回的是适配器），
	//         [srd] 参数在启动时真正生效（现场验证：false/0.42/7/0.65/max 全对）。
	// v2.2.3：审计收口 —— A-7 zone 推断（IPv6 链路本地/ULA 不再算公网）、
	//         A-8 SIGTERM 后立即退出、A-4/A-5 补方向性与 ct state 用例。
	// v2.2.4：A-7c —— CGNAT(100.64/10) 等保留网段不再算公网（实验网 domC 就在 100.64 段）。
	// v2.2.5：A-4 —— 入向 ACL 按会话语义双向生效（回程包被丢 ⇒ 反向会话也 blocked）。
	// v2.2.6：A-5 —— 入向规则支持 daddr-only 与首条匹配顺序；A-3 可观测性（facts 日志含 VLAN 数）。
	// v2.3.0：T1 域内 ACL —— 主机 IP 参与匹配（/32 规则）、OUTPUT 出向策略建模。
	// v2.3.1：T2 状态化建模 —— ct state established,related accept 放行回程，双向不对称。
	// v2.3.2：T3 可观测 —— `srd check <src> <dst>` CLI（verdict/路径/阻断点/未知项）。
	// v2.3.3：T3 修正 —— 直连快捷路径的 blocked 补出具体原因与阻断点。
	// v2.3.4：T3 收尾 —— CLI 错误落到 Output、兼容位置参数；blocked 原因无条件补齐。
	SRDVersion = "2.3.4"
)
