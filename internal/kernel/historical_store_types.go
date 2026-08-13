package kernel

type HostTrend struct {
	HostID        string  `json:"host_id"`
	Date          string  `json:"date"`
	AvgScore      float64 `json:"avg_score"`
	MinScore      float64 `json:"min_score"`
	MaxScore      float64 `json:"max_score"`
	Count         int     `json:"count"`
	AcceptablePct float64 `json:"acceptable_pct"`
}
