package webui

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/asscor/asscor/internal/model"
)

// ──────────────────────────────── Routes ────────────────────────────────

func (m *Module) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", m.handleIndex)
	mux.HandleFunc("/api/health", m.handleHealth)
	mux.HandleFunc("/api/dashboard", m.handleDashboard)
	mux.HandleFunc("/api/hosts", m.handleHosts)
	mux.HandleFunc("/api/hosts/", m.handleHostDetail)
}

// ──────────────────────────── Static Page ───────────────────────────────

func (m *Module) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

// ──────────────────────────── API: Health ────────────────────────────────

func (m *Module) handleHealth(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	hostCount := len(m.latest)
	var acceptable int
	var totalScore float64
	for _, ar := range m.latest {
		if ar.Acceptable {
			acceptable++
		}
		totalScore += ar.FinalScore
	}
	m.mu.RUnlock()

	avgScore := 0.0
	if hostCount > 0 {
		avgScore = totalScore / float64(hostCount)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"hosts":        hostCount,
		"acceptable":   acceptable,
		"unacceptable": hostCount - acceptable,
		"avg_score":    avgScore,
	})
}

// ──────────────────────────── API: Dashboard ────────────────────────────

type dashboardResponse struct {
	TotalHosts    int             `json:"total_hosts"`
	Acceptable    int             `json:"acceptable"`
	Unacceptable  int             `json:"unacceptable"`
	AvgScore      float64         `json:"avg_score"`
	Hosts         []hostSummary   `json:"hosts"`
}

type hostSummary struct {
	HostID     string  `json:"host_id"`
	Hostname   string  `json:"hostname"`
	FinalScore float64 `json:"final_score"`
	Acceptable bool    `json:"acceptable"`
	Threshold  float64 `json:"threshold"`
	CheckCount int     `json:"check_count"`
	FailedCount int    `json:"failed_count"`
	SPCScore   float64 `json:"spc_score,omitempty"`
	PrismScore float64 `json:"prism_score,omitempty"`
	PrismSemanticState string `json:"prism_semantic_state,omitempty"`
	PrismInferenceTrend string `json:"prism_inference_trend,omitempty"`
	Timestamp  string  `json:"timestamp"`
}

func (m *Module) handleDashboard(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	resp := dashboardResponse{
		Hosts: make([]hostSummary, 0, len(m.latest)),
	}

	var totalScore float64
	for hostID, ar := range m.latest {
		ts := ar.Timestamp.Format("2006-01-02 15:04:05")
		resp.Hosts = append(resp.Hosts, hostSummary{
			HostID:      hostID,
			Hostname:    ar.Hostname,
			FinalScore:  ar.FinalScore,
			Acceptable:  ar.Acceptable,
			Threshold:   ar.Threshold,
			CheckCount:  len(ar.Checks),
			FailedCount: countFailed(ar.Checks),
			SPCScore:    ar.SPCScore,
			PrismScore:  ar.PrismScore,
			PrismSemanticState: ar.PrismSemanticState,
			PrismInferenceTrend: ar.PrismInferenceTrend,
			Timestamp:   ts,
		})
		totalScore += ar.FinalScore
		if ar.Acceptable {
			resp.Acceptable++
		}
	}

	resp.TotalHosts = len(resp.Hosts)
	resp.Unacceptable = resp.TotalHosts - resp.Acceptable
	if resp.TotalHosts > 0 {
		resp.AvgScore = totalScore / float64(resp.TotalHosts)
	}

	// Sort by score ascending (worst first)
	sort.Slice(resp.Hosts, func(i, j int) bool {
		return resp.Hosts[i].FinalScore < resp.Hosts[j].FinalScore
	})

	writeJSON(w, resp)
}

// ──────────────────────────── API: Hosts ────────────────────────────────

func (m *Module) handleHosts(w http.ResponseWriter, r *http.Request) {
	m.handleDashboard(w, r)
}

// ──────────────────────────── API: Host Detail ──────────────────────────

func (m *Module) handleHostDetail(w http.ResponseWriter, r *http.Request) {
	// Parse /api/hosts/{hostID}[/latest|/report|/history]
	path := strings.TrimPrefix(r.URL.Path, "/api/hosts/")
	parts := strings.SplitN(path, "/", 2)
	hostID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	switch action {
	case "report":
		m.handleReport(w, hostID)
	case "history":
		m.handleHistory(w, hostID)
	case "latest", "":
		m.handleLatest(w, hostID)
	default:
		http.NotFound(w, r)
	}
}

type reportResponse struct {
	HostID     string  `json:"host_id"`
	Hostname   string  `json:"hostname"`
	Timestamp  string  `json:"timestamp"`
	FinalScore float64 `json:"final_score"`
	Acceptable bool    `json:"acceptable"`
	Threshold  float64 `json:"threshold"`

	DomainScores struct {
		AttackSurface      float64 `json:"attack_surface"`
		BusinessContinuity float64 `json:"business_continuity"`
		OperationTrust     float64 `json:"operation_trust"`
		Resilience         float64 `json:"resilience"`
		KernelSecurity     float64 `json:"kernel_security,omitempty"`
	} `json:"domain_scores"`

	EdgeFactors struct {
		TwoFactorFailure  float64 `json:"two_factor_failure"`
		SYNCookieDisabled float64 `json:"syn_cookie_disabled"`
		SELinuxDisabled   float64 `json:"selinux_disabled"`
		AppArmorDisabled  float64 `json:"apparmor_disabled"`
		NoSIEM            float64 `json:"no_siem"`
		NoIDS             float64 `json:"no_ids"`
	} `json:"edge_factors"`

	ThreatCoeff float64 `json:"threat_coefficient"`
	SPCScore    float64 `json:"spc_score,omitempty"`
	PrismScore  float64 `json:"prism_score,omitempty"`
	PrismSemanticState string `json:"prism_semantic_state,omitempty"`
	PrismInferenceTrend string `json:"prism_inference_trend,omitempty"`

	CheckCount  int               `json:"check_count"`
	FailedCount int               `json:"failed_count"`
	Checks      []model.CheckResult `json:"checks"`

	ATTACKCoverage []model.ATTACKCoverageInfo `json:"attck_coverage,omitempty"`
	ATTACKKillChain *model.ATTACKKillChainInfo `json:"attck_kill_chain,omitempty"`
}

func (m *Module) handleReport(w http.ResponseWriter, hostID string) {
	ar, ok := m.latest[hostID]
	if !ok {
		writeJSON(w, map[string]string{"error": "host not found"})
		return
	}

	resp := reportResponse{
		HostID:     ar.HostID,
		Hostname:   ar.Hostname,
		Timestamp:  ar.Timestamp.Format("2006-01-02 15:04:05"),
		FinalScore: ar.FinalScore,
		Acceptable: ar.Acceptable,
		Threshold:  ar.Threshold,
		ThreatCoeff: ar.ThreatCoeff,
		SPCScore:   ar.SPCScore,
		PrismScore: ar.PrismScore,
		PrismSemanticState: ar.PrismSemanticState,
		PrismInferenceTrend: ar.PrismInferenceTrend,
		CheckCount: len(ar.Checks),
		FailedCount: countFailed(ar.Checks),
		Checks:     ar.Checks,
		ATTACKCoverage: ar.ATTACKCoverage,
		ATTACKKillChain: ar.ATTACKKillChain,
	}
	resp.DomainScores.AttackSurface = ar.DomainScores.AttackSurface
	resp.DomainScores.BusinessContinuity = ar.DomainScores.BusinessContinuity
	resp.DomainScores.OperationTrust = ar.DomainScores.OperationTrust
	resp.DomainScores.Resilience = ar.DomainScores.Resilience
	resp.DomainScores.KernelSecurity = ar.DomainScores.KernelSecurity

	resp.EdgeFactors.TwoFactorFailure = ar.EdgeFactors.TwoFactorFailure
	resp.EdgeFactors.SYNCookieDisabled = ar.EdgeFactors.SYNCookieDisabled
	resp.EdgeFactors.SELinuxDisabled = ar.EdgeFactors.SELinuxDisabled
	resp.EdgeFactors.AppArmorDisabled = ar.EdgeFactors.AppArmorDisabled
	resp.EdgeFactors.NoSIEM = ar.EdgeFactors.NoSIEM
	resp.EdgeFactors.NoIDS = ar.EdgeFactors.NoIDS

	writeJSON(w, resp)
}

func (m *Module) handleLatest(w http.ResponseWriter, hostID string) {
	m.handleReport(w, hostID)
}

func (m *Module) handleHistory(w http.ResponseWriter, hostID string) {
	history, ok := m.history[hostID]
	if !ok {
		writeJSON(w, map[string]string{"error": "host not found"})
		return
	}

	type historyPoint struct {
		Timestamp  string  `json:"timestamp"`
		FinalScore float64 `json:"final_score"`
		Acceptable bool    `json:"acceptable"`
		CheckCount int     `json:"check_count"`
		FailedCount int    `json:"failed_count"`
	}

	points := make([]historyPoint, len(history))
	for i, ar := range history {
		points[i] = historyPoint{
			Timestamp:   ar.Timestamp.Format("2006-01-02 15:04:05"),
			FinalScore:  ar.FinalScore,
			Acceptable:  ar.Acceptable,
			CheckCount:  len(ar.Checks),
			FailedCount: countFailed(ar.Checks),
		}
	}

	writeJSON(w, map[string]interface{}{
		"host_id":   hostID,
		"hostname":  m.hostnames[hostID],
		"history":   points,
	})
}

// ──────────────────────────── Helpers ────────────────────────────────────

func countFailed(checks []model.CheckResult) int {
	n := 0
	for _, c := range checks {
		if !c.Passed {
			n++
		}
	}
	return n
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

// ──────────────────────────── Embedded Frontend ──────────────────────────

const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ASSCOR Dashboard</title>
<style>` + cssStyles + `</style>
</head>
<body>
<div id="app">
  <header>
    <h1>ASSCOR <span>Security Dashboard</span></h1>
    <nav>
      <button class="active" data-view="dashboard">概览</button>
      <button data-view="report">报告</button>
      <button data-view="history">历史</button>
    </nav>
    <div id="header-status">就绪</div>
  </header>
  <main id="content"></main>
</div>
<script>` + jsApp + `</script>
</body>
</html>`

const cssStyles = `
:root {
  --bg: #0d1117;        --surface: #161b22;       --border: #30363d;
  --text: #c9d1d9;      --text-dim: #8b949e;      --accent: #58a6ff;
  --green: #3fb950;     --red: #f85149;           --orange: #d29922;
  --yellow: #e3b341;    --purple: #a371f7;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; font-size:14px; line-height:1.5; }
#app { min-height:100vh; display:flex; flex-direction:column; }

/* Header */
header { display:flex; align-items:center; padding:12px 24px; background:var(--surface); border-bottom:1px solid var(--border); gap:24px; }
header h1 { font-size:18px; font-weight:600; }
header h1 span { color:var(--text-dim); font-weight:400; }
nav { display:flex; gap:4px; }
nav button { background:none; border:1px solid transparent; color:var(--text-dim); padding:6px 16px; border-radius:6px; cursor:pointer; font-size:13px; transition:all .15s; }
nav button:hover { color:var(--text); background:rgba(255,255,255,.05); }
nav button.active { color:var(--accent); border-color:var(--accent); background:rgba(88,166,255,.1); }
#header-status { margin-left:auto; font-size:12px; color:var(--text-dim); }

/* Main */
main { flex:1; padding:24px; max-width:1400px; width:100%; margin:0 auto; }

/* Cards */
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:24px; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:16px 20px; }
.card .label { font-size:11px; color:var(--text-dim); text-transform:uppercase; letter-spacing:.5px; margin-bottom:4px; }
.card .value { font-size:28px; font-weight:700; }
.card .value.green { color:var(--green); }
.card .value.red { color:var(--red); }
.card .value.orange { color:var(--orange); }
.card .sub { font-size:12px; color:var(--text-dim); margin-top:2px; }

/* Tables */
.table-wrap { background:var(--surface); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
table { width:100%; border-collapse:collapse; }
th { text-align:left; padding:10px 16px; font-size:11px; color:var(--text-dim); text-transform:uppercase; letter-spacing:.5px; border-bottom:1px solid var(--border); background:rgba(255,255,255,.02); }
td { padding:10px 16px; border-bottom:1px solid var(--border); font-size:13px; }
tr:last-child td { border-bottom:none; }
tr:hover td { background:rgba(255,255,255,.02); }
.host-link { color:var(--accent); cursor:pointer; text-decoration:none; }
.host-link:hover { text-decoration:underline; }

/* Score bar */
.score-bar { display:flex; align-items:center; gap:8px; }
.score-bar .bar-bg { flex:1; height:8px; background:rgba(255,255,255,.08); border-radius:4px; overflow:hidden; }
.score-bar .bar-fill { height:100%; border-radius:4px; transition:width .3s; }
.score-bar .score-text { font-size:13px; font-weight:600; min-width:48px; text-align:right; }
.bg-green { background:var(--green); }
.bg-orange { background:var(--orange); }
.bg-red { background:var(--red); }

/* Badge */
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; }
.badge.pass { background:rgba(63,185,80,.15); color:var(--green); }
.badge.fail { background:rgba(248,81,73,.15); color:var(--red); }

/* Host selector */
.host-select { margin-bottom:20px; }
.host-select select { background:var(--surface); color:var(--text); border:1px solid var(--border); padding:8px 12px; border-radius:6px; font-size:14px; min-width:300px; }

/* Detail sections */
.section { margin-bottom:24px; }
.section h2 { font-size:14px; color:var(--accent); margin-bottom:12px; padding-bottom:8px; border-bottom:1px solid var(--border); text-transform:uppercase; letter-spacing:.5px; }
.domain-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; }
.domain-item { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:12px 16px; }
.domain-item .name { font-size:11px; color:var(--text-dim); margin-bottom:4px; }
.domain-item .score { font-size:22px; font-weight:700; }

.edge-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:8px; margin-bottom:16px; }
.edge-item { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center; }
.edge-item .name { font-size:12px; color:var(--text-dim); }
.edge-item .val { font-size:13px; font-weight:600; }

.check-list { max-height:500px; overflow-y:auto; }
.check-row { display:flex; align-items:center; padding:8px 16px; border-bottom:1px solid var(--border); gap:12px; font-size:13px; }
.check-row:last-child { border-bottom:none; }
.check-row .domain-tag { font-size:10px; padding:2px 6px; border-radius:4px; background:rgba(88,166,255,.15); color:var(--accent); white-space:nowrap; }
.check-row .check-id { color:var(--text-dim); font-family:monospace; font-size:12px; white-space:nowrap; }
.check-row .check-name { flex:1; }
.check-row .check-detail { color:var(--text-dim); font-size:12px; max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.check-row .status { font-weight:600; white-space:nowrap; }

/* History chart */
.history-chart { display:flex; align-items:flex-end; gap:4px; height:200px; padding:0 4px; }
.history-bar { flex:1; border-radius:2px 2px 0 0; min-width:8px; position:relative; cursor:pointer; transition:opacity .15s; }
.history-bar:hover { opacity:.8; }

/* Empty state */
.empty { text-align:center; padding:48px 24px; color:var(--text-dim); }
.empty .icon { font-size:48px; margin-bottom:12px; }
.empty p { font-size:14px; }

/* ATT&CK */
.attck-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:8px; }
.attck-item { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:10px 12px; }
.attck-item .tactic { font-size:11px; color:var(--text-dim); margin-bottom:2px; }
.attck-item .cov { font-size:18px; font-weight:700; }
`

const jsApp = `
// ── State ──
let currentView = 'dashboard';
let dashboardData = null;

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('nav button').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });
  switchView('dashboard');
});

// ── Navigation ──
function switchView(view) {
  currentView = view;
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  const content = document.getElementById('content');
  content.innerHTML = '<div class="empty"><p>加载中...</p></div>';

  switch (view) {
    case 'dashboard': loadDashboard(); break;
    case 'report': loadHostSelector('report'); break;
    case 'history': loadHostSelector('history'); break;
  }
}

// ── Dashboard ──
async function loadDashboard() {
  setStatus('加载中...');
  try {
    const resp = await fetch('/api/dashboard');
    dashboardData = await resp.json();
    renderDashboard(dashboardData);
    setStatus(dashboardData.total_hosts + ' 台主机');
  } catch(e) {
    document.getElementById('content').innerHTML = '<div class="empty"><p>无法连接后端服务</p></div>';
    setStatus('错误');
    console.error(e);
  }
}

function renderDashboard(d) {
  const scoreColor = d.avg_score >= 80 ? 'green' : d.avg_score >= 65 ? 'orange' : 'red';
  const accPct = d.total_hosts > 0 ? Math.round(d.acceptable / d.total_hosts * 100) : 0;

  let hostRows = '';
  d.hosts.forEach(h => {
    const color = h.final_score >= 80 ? 'bg-green' : h.final_score >= 65 ? 'bg-orange' : 'bg-red';
    hostRows += '<tr>' +
      '<td><a class="host-link" onclick="showReport(\'' + h.host_id + '\')">' + esc(h.host_id) + '</a></td>' +
      '<td>' + esc(h.hostname||'-') + '</td>' +
      '<td><div class="score-bar"><div class="bar-bg"><div class="bar-fill ' + color + '" style="width:' + h.final_score + '%"></div></div><span class="score-text">' + h.final_score.toFixed(1) + '</span></div></td>' +
      '<td><span class="badge ' + (h.acceptable ? 'pass' : 'fail') + '">' + (h.acceptable ? '合格' : '不合格') + '</span></td>' +
      '<td>' + h.check_count + '</td>' +
      '<td>' + h.failed_count + '</td>' +
      '<td>' + (h.spc_score ? h.spc_score.toFixed(2) : '-') + '</td>' +
      '<td style="color:var(--text-dim);font-size:12px">' + h.timestamp + '</td>' +
      '</tr>';
  });

  const html = '<div class="cards">' +
    '<div class="card"><div class="label">主机总数</div><div class="value">' + d.total_hosts + '</div></div>' +
    '<div class="card"><div class="label">平均评分</div><div class="value ' + scoreColor + '">' + (d.total_hosts ? d.avg_score.toFixed(1) : '-') + '</div></div>' +
    '<div class="card"><div class="label">合格率</div><div class="value ' + (accPct >= 80 ? 'green' : accPct >= 60 ? 'orange' : 'red') + '">' + accPct + '%</div><div class="sub">' + d.acceptable + ' / ' + d.total_hosts + '</div></div>' +
    '<div class="card"><div class="label">不合格</div><div class="value ' + (d.unacceptable > 0 ? 'red' : 'green') + '">' + d.unacceptable + '</div></div>' +
    '</div>' +
    (d.total_hosts > 0 ? '<div class="table-wrap"><table><thead><tr><th>主机ID</th><th>主机名</th><th>评分</th><th>状态</th><th>检查项</th><th>未通过</th><th>SPC</th><th>时间</th></tr></thead><tbody>' + hostRows + '</tbody></table></div>' : '<div class="empty"><p>暂无评估数据。等待 Agent 上报...</p></div>');

  document.getElementById('content').innerHTML = html;
}

// ── Report ──
async function loadHostSelector(mode) {
  if (!dashboardData) {
    try { const r = await fetch('/api/dashboard'); dashboardData = await r.json(); } catch(e) {}
  }
  const hosts = dashboardData ? dashboardData.hosts : [];
  if (hosts.length === 0) {
    document.getElementById('content').innerHTML = '<div class="empty"><p>暂无主机数据</p></div>';
    return;
  }

  let opts = hosts.map(h => '<option value="' + h.host_id + '">' + esc(h.host_id) + ' — ' + esc(h.hostname||'') + ' (' + h.final_score.toFixed(1) + ')</option>').join('');
  document.getElementById('content').innerHTML =
    '<div class="host-select"><select id="hostSel" onchange="' + (mode === 'report' ? 'showReport' : 'showHistory') + '(this.value)"><option value="">— 选择主机 —</option>' + opts + '</select></div>' +
    '<div id="detailArea"></div>';
}

async function showReport(hostID) {
  if (!hostID) { document.getElementById('detailArea').innerHTML = ''; return; }
  document.getElementById('detailArea').innerHTML = '<div class="empty"><p>加载中...</p></div>';
  try {
    const resp = await fetch('/api/hosts/' + hostID + '/report');
    const r = await resp.json();
    if (r.error) { document.getElementById('detailArea').innerHTML = '<div class="empty"><p>' + r.error + '</p></div>'; return; }
    renderReport(r);
  } catch(e) { console.error(e); }
}

function renderReport(r) {
  const color = r.final_score >= 80 ? 'green' : r.final_score >= 65 ? 'orange' : 'red';

  let checksHtml = '';
  r.checks.forEach(c => {
    checksHtml += '<div class="check-row">' +
      '<span class="domain-tag">' + esc(c.domain) + '</span>' +
      '<span class="check-id">' + esc(c.check_id) + '</span>' +
      '<span class="check-name">' + esc(c.name) + '</span>' +
      '<span class="check-detail">' + esc(c.detail||'') + '</span>' +
      '<span class="status" style="color:' + (c.passed ? 'var(--green)' : 'var(--red)') + '">' + (c.passed ? 'PASS' : 'FAIL') + '</span>' +
      '</div>';
  });

  let edgeHtml = '';
  const edges = r.edge_factors || {};
  const edgeLabels = {two_factor_failure:'双因素认证',syn_cookie_disabled:'SYN Cookie',selinux_disabled:'SELinux',apparmor_disabled:'AppArmor',no_siem:'SIEM集成',no_ids:'IDS/IPS'};
  Object.entries(edgeLabels).forEach(([k,label]) => {
    const v = edges[k] || 1;
    const active = v < 1;
    edgeHtml += '<div class="edge-item"><span class="name">' + label + '</span><span class="val" style="color:' + (active ? 'var(--red)' : 'var(--green)') + '">' + (active ? '✕ ' + v.toFixed(2) : '✓') + '</span></div>';
  });

  let attckHtml = '';
  if (r.attck_coverage && r.attck_coverage.length > 0) {
    attckHtml = '<div class="section"><h2>ATT&amp;CK 覆盖率</h2><div class="attck-grid">';
    r.attck_coverage.forEach(a => {
      attckHtml += '<div class="attck-item"><div class="tactic">' + esc(a.tactic_name) + '</div><div class="cov">' + (a.coverage_detection||0).toFixed(1) + '%</div></div>';
    });
    attckHtml += '</div></div>';
  }

  let killChainHtml = '';
  if (r.attck_kill_chain && r.attck_kill_chain.stages) {
    killChainHtml = '<div class="section"><h2>杀伤链分析</h2><div class="attck-grid">';
    r.attck_kill_chain.stages.forEach(s => {
      killChainHtml += '<div class="attck-item"><div class="tactic">' + esc(s.name) + '</div><div class="cov">' + s.score.toFixed(1) + '</div></div>';
    });
    killChainHtml += '</div></div>';
  }

  const html =
    '<div class="cards">' +
    '<div class="card"><div class="label">综合评分</div><div class="value ' + color + '">' + r.final_score.toFixed(1) + '</div></div>' +
    '<div class="card"><div class="label">阈值</div><div class="value">' + r.threshold.toFixed(0) + '</div></div>' +
    '<div class="card"><div class="label">状态</div><div class="value ' + (r.acceptable ? 'green' : 'red') + '">' + (r.acceptable ? '合格' : '不合格') + '</div></div>' +
    '<div class="card"><div class="label">检查项</div><div class="value">' + r.check_count + '<span class="sub" style="color:var(--red);margin-left:8px;">' + r.failed_count + ' 未通过</span></div></div>' +
    (r.spc_score ? '<div class="card"><div class="label">SPC 修正</div><div class="value">' + r.spc_score.toFixed(2) + '</div></div>' : '') +
    (r.prism_score ? '<div class="card"><div class="label">Prism 风险</div><div class="value">' + r.prism_score.toFixed(2) + '</div></div>' : '') +
    '<div class="card"><div class="label">威胁系数 &mu;</div><div class="value">' + (r.threat_coefficient||1).toFixed(2) + '</div></div>' +
    '</div>' +

    '<div class="section"><h2>四大域评分</h2><div class="domain-grid">' +
    '<div class="domain-item"><div class="name">攻击面 (AS)</div><div class="score">' + (r.domain_scores.attack_surface||0).toFixed(1) + '</div></div>' +
    '<div class="domain-item"><div class="name">业务连续性 (BC)</div><div class="score">' + (r.domain_scores.business_continuity||0).toFixed(1) + '</div></div>' +
    '<div class="domain-item"><div class="name">操作可信度 (OT)</div><div class="score">' + (r.domain_scores.operation_trust||0).toFixed(1) + '</div></div>' +
    '<div class="domain-item"><div class="name">韧性 (RS)</div><div class="score">' + (r.domain_scores.resilience||0).toFixed(1) + '</div></div>' +
    '</div></div>' +

    '<div class="section"><h2>边缘因子</h2><div class="edge-grid">' + edgeHtml + '</div></div>' +

    attckHtml + killChainHtml +

    '<div class="section"><h2>检查项详情 (' + r.check_count + ')</h2><div class="table-wrap check-list">' + checksHtml + '</div></div>';

  document.getElementById('detailArea').innerHTML = html;
}

// ── History ──
async function showHistory(hostID) {
  if (!hostID) { document.getElementById('detailArea').innerHTML = ''; return; }
  document.getElementById('detailArea').innerHTML = '<div class="empty"><p>加载中...</p></div>';
  try {
    const resp = await fetch('/api/hosts/' + hostID + '/history');
    const data = await resp.json();
    if (data.error) { document.getElementById('detailArea').innerHTML = '<div class="empty"><p>' + data.error + '</p></div>'; return; }
    renderHistory(data);
  } catch(e) { console.error(e); }
}

function renderHistory(data) {
  const points = data.history || [];
  if (points.length === 0) {
    document.getElementById('detailArea').innerHTML = '<div class="empty"><p>该主机暂无历史记录</p></div>';
    return;
  }

  const maxScore = 100;
  let bars = '';
  points.forEach(p => {
    const h = Math.max(4, (p.final_score / maxScore) * 190);
    const color = p.final_score >= 80 ? 'var(--green)' : p.final_score >= 65 ? 'var(--orange)' : 'var(--red)';
    const ts = p.timestamp.replace(' ', '<br>');
    bars += '<div class="history-bar" style="height:' + h + 'px; background:' + color + '" title="' + p.timestamp + ' — ' + p.final_score.toFixed(1) + ' | ' + (p.acceptable ? '合格' : '不合格') + ' | ' + p.check_count + '检查/' + p.failed_count + '未通过"></div>';
  });

  let rows = '';
  points.forEach(p => {
    rows += '<tr>' +
      '<td>' + esc(p.timestamp) + '</td>' +
      '<td><span style="color:' + (p.final_score >= 80 ? 'var(--green)' : p.final_score >= 65 ? 'var(--orange)' : 'var(--red)') + ';font-weight:600">' + p.final_score.toFixed(1) + '</span></td>' +
      '<td><span class="badge ' + (p.acceptable ? 'pass' : 'fail') + '">' + (p.acceptable ? '合格' : '不合格') + '</span></td>' +
      '<td>' + p.check_count + '</td>' +
      '<td>' + p.failed_count + '</td>' +
      '</tr>';
  });

  const html =
    '<div class="section"><h2>评分趋势 (' + points.length + ' 次评估)</h2>' +
    '<div class="history-chart" style="margin-bottom:8px;">' + bars + '</div>' +
    '</div>' +
    '<div class="section"><h2>历史记录</h2>' +
    '<div class="table-wrap">' +
    '<table><thead><tr><th>时间</th><th>评分</th><th>状态</th><th>检查项</th><th>未通过</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>' +
    '</div></div>';

  document.getElementById('detailArea').innerHTML = html;
}

// ── Utils ──
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function setStatus(msg) { document.getElementById('header-status').textContent = msg; }
`