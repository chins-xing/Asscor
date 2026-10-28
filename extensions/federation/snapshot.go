package federation

import (
	"time"

	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/topology"
)

// BuildNodeReport 构建上报给 master 的节点摘要（v0.4：进程隔离后由内核侧
// 代理调用，再把结果通过 RPC 推给独立的联邦进程）。
//
// 它只依赖 KernelContext 的公开能力（拓扑注册表 + assessor 容器接口），
// 因此内核内插件与进程代理可以共用同一份实现。
func BuildNodeReport(kc kernel.KernelContext, cfg Config) NodeReport {
	var cfgObj interface{}
	if kc != nil {
		cfgObj = kc.GetConfigObj()
	}
	params := effectiveParams(cfgObj)
	report := NodeReport{
		NodeID:     cfg.NodeID,
		ConfigHash: ConfigHash(params),
		Params:     params,
		ReportedAt: time.Now().UTC(),
	}

	nodes := topology.ListNodes()
	report.Hosts = len(nodes)
	report.HostFacts, report.PolicyFacts, report.PolicyKnown = collectFacts(nodes)
	if len(nodes) == 0 {
		return report
	}

	assessor := resolveAssessor(kc)
	zoneCfg := configZones(cfgObj)

	type acc struct {
		hosts  int
		scored int
		sum    float64
	}
	perZone := make(map[string]*acc)
	for _, n := range nodes {
		zone := n.Zone
		if zone == "" && zoneCfg != nil {
			zone = zoneCfg[n.HostID]
		}
		if zone == "" {
			zone = "unknown"
		}
		a := perZone[zone]
		if a == nil {
			a = &acc{}
			perZone[zone] = a
		}
		a.hosts++
		if assessor != nil {
			if res := assessor.GetResult(n.HostID); res != nil {
				a.scored++
				a.sum += res.FinalScore
			}
		}
	}

	report.Zones = make(map[string]ZoneSummary, len(perZone))
	for zone, a := range perZone {
		zs := ZoneSummary{Hosts: a.hosts, Scored: a.scored}
		if a.scored > 0 {
			zs.AvgSSAM = a.sum / float64(a.scored)
		}
		report.Zones[zone] = zs
	}
	report.AvgSSAM = report.OverallAvgSSAM()
	return report
}
