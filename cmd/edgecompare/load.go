//go:build edgeexp

package main

import (
	"time"

	"github.com/chins-xing/asscor/internal/edgeexp"
)

// 读取层：实验 JSONL（spec §5.1 schema）→ []Record。
//
// **本文件是薄封装，不是实现**。类型、存在性口径与全部校验判据都在
// `internal/edgeexp`（无 build tag 的共享契约包），未来的采集器 `cmd/edgescen` 与
// 本工具消费**同一份**实现 —— 这个项目已经因为"生产者的写出与消费者的读入各写一份"
// 被咬过一次：spec §5.1 的示例记录当时被自己的读取层拒绝，而采集器是照着那份示例写的。
//
// 保留的类型别名与转发的函数是**零改动**契约：`main.go` / `metrics.go` / `score.go` /
// `fit.go` / `report.go` 与全部既有用例一行都不用改，且错误信息逐字不变
// （前缀仍是 `edgecompare: `、坏行仍带行号、空行仍跳过、文件头 BOM 仍剥离）。
//
// 判据的归属（改动前先读 `internal/edgeexp` 的包注释）：
//   - 读取层契约（存在性 + 值域；**不含重复/折叠判据 —— 链是列表，同一 ID 可出现多次**）→ `edgeexp.Record.Validate`（由 LoadRecords 调用）；
//   - 记录构造要求（规范因子 ID、触发交叉校验、生效权重）→ **生产者侧**自检函数，
//     本工具作为消费者**不得**因为它们而拒收历史/手写数据集（消费侧的归一化在装配期发生）。

type Record = edgeexp.Record
type Observed = edgeexp.Observed
type CheckObs = edgeexp.CheckObs
type ChainObs = edgeexp.ChainObs
type GroundTruth = edgeexp.GroundTruth
type Meta = edgeexp.Meta

// recordsTool 是错误信息里的工具名前缀，必须逐字保持 `edgecompare`（CLI 的错误面属可观测行为）。
const recordsTool = "edgecompare"

// LoadRecords 读取实验 JSONL（spec §5.1 schema）。
func LoadRecords(path string) ([]Record, error) { return edgeexp.LoadFileAs(recordsTool, path) }

// parseTS 解析 RFC3339 时间戳（空串合法；非空但解析不了即坏值）——转发到共享实现，
// 让"什么算合法时间戳"只有一处定义。
func parseTS(v string) (time.Time, error) { return edgeexp.ParseTS(v) }
