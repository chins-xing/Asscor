package kernel

// SecureModeAgentSecrets 是 comms 对 secure-mode 控制器的消费契约（kernel
// SPI，与 HeartbeatInterface 等模块接口同位，耦合审计 F4）：心跳处理时按
// mTLS 证书指纹查询/登记 agent 临时口令，并在登记/轮换后加密落盘（重启可
// 恢复，spec §10.1）。
//
// 装配根（cmd/kernel）将 securemode.Controller 经本接口注入 comms；注入
// nil 表示 secure-mode 未启用（comms 保持空转，与既有 nil 容忍一致）。
type SecureModeAgentSecrets interface {
	// Lookup 返回指定证书指纹登记的 agent 临时口令。
	Lookup(fingerprint string) (password string, ok bool)
	// Register 登记/轮换某指纹对应的 agent 临时口令。
	Register(fingerprint, agentID, password string) error
	// PersistSecrets 将内存登记表加密落盘（run 模式下；default 模式无操作）。
	PersistSecrets() error
}
