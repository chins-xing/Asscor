package kernel

type CTIInterface interface {
	GetCoefficient() float64
	ReportThreat(severity string)
	ClearThreat()
}
