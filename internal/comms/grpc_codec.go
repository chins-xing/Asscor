//go:build comms

package comms

import (
	"encoding/json"
	"fmt"
)

// jsonCodec 是 gRPC 传输层的编解码器。
//
// 为什么不能用默认的 proto codec：`api/v1` 的 `PB*` 类型是**手写结构体**
// （只有 protobuf tag，没有 `ProtoReflect()`，不是 `proto.Message`），
// 默认 codec 在运行时根本编不了它们 —— 也就是说 gRPC 通道此前从未真正可用，
// 所有 RPC 都只能走 JSONRPC 的整包直传。
//
// 这里显式改用 JSON 编解码：字段带 `json` tag，两边结构一致即可往返，
// 也让 `NetworkInfo` / `SecureModeReport` 这类字段能随心跳一起过线
// （否则 gRPC agent 的拓扑永远不会被 kernel 记录）。
type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) Marshal(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json codec marshal: %w", err)
	}
	return data, nil
}

func (jsonCodec) Unmarshal(data []byte, v interface{}) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("json codec unmarshal: %w", err)
	}
	return nil
}
