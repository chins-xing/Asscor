package federation

import "encoding/json"

// 进程隔离协议（v0.4）：内核侧代理 ⇄ 联邦子进程，按行分隔 JSON。
//
// 设计取舍：不引入新的独立 module（避免与 pluginsdk 的 RPC 语义纠缠），
// 直接把"配置 / 快照 / 状态 / 查询"四类消息定义在扩展包内，子进程只依赖
// 本包中被抽出的纯逻辑（master/collector/reporter/merge），不接触 kernel 包。

// rpcRequest 是内核 → 子进程的请求。
type rpcRequest struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// rpcResponse 是子进程 → 内核的响应。
type rpcResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// ConfigureParams 下发 [federation] 配置。
type ConfigureParams struct {
	Role              string `json:"role"`
	NodeID            string `json:"node_id"`
	MasterURL         string `json:"master_url"`
	ListenAddr        string `json:"listen_addr"`
	Token             string `json:"token"`
	ReportIntervalSec int    `json:"report_interval_sec"`
}

// SnapshotParams 是内核推给子进程的"本地事实 + 节点摘要"。
type SnapshotParams struct {
	Report       NodeReport   `json:"report"`
	Hosts        []HostFact   `json:"hosts,omitempty"`
	Policies     []PolicyFact `json:"policies,omitempty"`
	PolicyKnown  bool         `json:"policy_known"`
	CapturedUnix int64        `json:"captured_unix"`
}

// CheckParams 是 `federation check` 的跨节点查询。
type CheckParams struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

const (
	methodPing      = "ping"
	methodConfigure = "configure"
	methodSnapshot  = "snapshot"
	methodStatus    = "status"
	methodCheck     = "check"
	methodExport    = "export"
	methodReportNow = "report-now"
	methodShutdown  = "shutdown"
)
