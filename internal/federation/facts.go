package federation

// HostFact 是节点上报的**单主机事实**（v0.2 起随 NodeReport 上报）。
//
// 设计取舍：demo 级联邦需要"主端合并图"才能回答跨节点可达性，
// 因此节点必须上报图事实（主机、子网、策略、链路），而不只是聚合摘要。
// 为控制体积，只上报与可达性/关键性相关的最小字段。
type HostFact struct {
	ID            string          `json:"id"`
	IPs           []string        `json:"ips,omitempty"`
	Subnets       []string        `json:"subnets,omitempty"`
	Zone          string          `json:"zone,omitempty"`
	SSAM          float64         `json:"ssam,omitempty"`
	Forwards      bool            `json:"forwards,omitempty"`
	StatefulInput bool            `json:"stateful_input,omitempty"`
	Inbound       []PolicyFact    `json:"inbound,omitempty"`
	Outbound      []PolicyFact    `json:"outbound,omitempty"`
	Links         map[string]bool `json:"links,omitempty"`
}

// PolicyFact 是一条策略结论（转发或主机入/出向）。
type PolicyFact struct {
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Allow bool   `json:"allow"`
}

// MAX_HOST_FACTS / MAX_POLICY_FACTS 限制单节点上报体积（demo 级防滥用）。
const (
	MaxHostFacts   = 2000
	MaxPolicyFacts = 5000
)
