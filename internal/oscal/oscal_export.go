package oscal

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/asscor/asscor/internal/kernel"
	"time"

	"github.com/asscor/asscor/internal/model"
)

// OSCALExport generates OSCAL-compliant assessment results from an ASSCOR AssessmentResult.
// Supports both JSON and XML output formats per NIST SP 800-53 OSCAL 1.1.x schema.
//
// OSCAL mapping:
//   SSAM FinalScore (0-100) → OSCAL finding risk-score
//   SSAM DomainScores        → OSCAL control assessments
//   SSAM CheckResults        → OSCAL observations
//   Prism Semantic State     → OSCAL risk characterization
//   Prism Inference Trend    → OSCAL risk trend

// OSCALAssessmentResults is the top-level OSCAL assessment-results document.
type OSCALAssessmentResults struct {
	XMLName  xml.Name      `xml:"http://csrc.nist.gov/ns/oscal/1.0 assessment-results" json:"-"`
	UUID     string        `xml:"uuid"                json:"uuid"`
	Metadata OSCALMetadata `xml:"metadata"       json:"metadata"`
	Results  []OSCALResult `xml:"results>result"  json:"results"`
}

// OSCALMetadata carries document-level metadata.
type OSCALMetadata struct {
	Title        string       `xml:"title"        json:"title"`
	Published    string       `xml:"published"    json:"published"`
	LastModified string       `xml:"last-modified" json:"last-modified"`
	Version      string       `xml:"version"      json:"version"`
	OSCALVersion string       `xml:"oscal-version" json:"oscal-version"`
	Props        []OSCALProp  `xml:"prop"         json:"props,omitempty"`
	Parties      []OSCALParty `xml:"party"        json:"parties,omitempty"`
}

// OSCALProp is a generic key-value property.
type OSCALProp struct {
	XMLName xml.Name `xml:"prop"  json:"-"`
	Name    string   `xml:"name,attr"  json:"name"`
	Value   string   `xml:"value,attr" json:"value"`
	NS      string   `xml:"ns,attr,omitempty" json:"ns,omitempty"`
}

// OSCALParty describes a responsible entity.
type OSCALParty struct {
	UUID string `xml:"uuid,attr" json:"uuid"`
	Type string `xml:"type,attr" json:"type"`
	Name string `xml:"name"      json:"name"`
}

// OSCALResult represents a single assessment result entry.
type OSCALResult struct {
	UUID         string             `xml:"uuid,attr"      json:"uuid"`
	Title        string             `xml:"title"           json:"title"`
	Description  string             `xml:"description"     json:"description"`
	Start        string             `xml:"start"           json:"start"`
	Props        []OSCALProp        `xml:"prop"            json:"props,omitempty"`
	Findings     []OSCALFinding     `xml:"finding"         json:"findings,omitempty"`
	Observations []OSCALObservation `xml:"observation"     json:"observations,omitempty"`
	Risks        []OSCALRisk        `xml:"risk"            json:"risks,omitempty"`
}

// OSCALFinding represents a discrete security finding.
type OSCALFinding struct {
	UUID                string                    `xml:"uuid,attr"     json:"uuid"`
	Title               string                    `xml:"title"          json:"title"`
	Description         string                    `xml:"description"    json:"description"`
	Risk                OSCALRiskStatus           `xml:"risk"         json:"risk"`
	RelatedObservations []OSCALRelatedObservation `xml:"related-observation" json:"related-observations,omitempty"`
	Props               []OSCALProp               `xml:"prop"           json:"props,omitempty"`
}

// OSCALRiskStatus indicates the risk level of a finding.
type OSCALRiskStatus struct {
	XMLName xml.Name `xml:"risk" json:"-"`
	Status  string   `xml:"status,attr" json:"status"`
	Score   float64  `xml:"score,attr" json:"score"`
}

// OSCALRelatedObservation links a finding to its observation.
type OSCALRelatedObservation struct {
	ObservationUUID string `xml:"observation-uuid,attr" json:"observation-uuid"`
}

// OSCALObservation documents a specific evaluation event.
type OSCALObservation struct {
	UUID             string                  `xml:"uuid,attr"    json:"uuid"`
	Title            string                  `xml:"title"         json:"title"`
	Description      string                  `xml:"description"   json:"description"`
	Methods          []string                `xml:"method"        json:"methods"`
	Collected        string                  `xml:"collected"     json:"collected"`
	RelevantEvidence []OSCALRelevantEvidence `xml:"relevant-evidence" json:"relevant-evidence,omitempty"`
	Props            []OSCALProp             `xml:"prop"          json:"props,omitempty"`
}

// OSCALRelevantEvidence references evidence supporting an observation.
type OSCALRelevantEvidence struct {
	Description string `xml:"description" json:"description"`
}

// OSCALRisk represents a characterized risk entry.
type OSCALRisk struct {
	UUID        string      `xml:"uuid,attr"    json:"uuid"`
	Title       string      `xml:"title"         json:"title"`
	Description string      `xml:"description"   json:"description"`
	Statement   string      `xml:"statement"     json:"statement"`
	Status      string      `xml:"status,attr"   json:"status"`
	Source      []string    `xml:"source"        json:"source,omitempty"`
	Props       []OSCALProp `xml:"prop"          json:"props,omitempty"`
}

// --- Export functions ---

// ExportOSCAL generates an OSCAL assessment-results document from an AssessmentResult.
// format: "json" or "xml".
func ExportOSCAL(result *model.AssessmentResult, format string) ([]byte, error) {
	doc := buildOSCAL(result)

	switch format {
	case "xml":
		data, err := xml.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("oscal xml marshal: %w", err)
		}
		return append([]byte(xml.Header), data...), nil
	case "json":
		return json.MarshalIndent(doc, "", "  ")
	default:
		return nil, fmt.Errorf("unknown oscal format: %s (supported: json, xml)", format)
	}
}

// ExportOSCALFromRecord generates an OSCAL document from an kernel.AssessmentRecord.
func ExportOSCALFromRecord(rec *kernel.AssessmentRecord, format string) ([]byte, error) {
	result := &model.AssessmentResult{
		HostID:     rec.HostID,
		Hostname:   rec.Hostname,
		Timestamp:  rec.Timestamp,
		FinalScore: rec.FinalScore,
		Acceptable: rec.Acceptable,
		Threshold:  rec.Threshold,
		DomainScores: model.DomainScores{
			AttackSurface:      rec.AttackSurface,
			BusinessContinuity: rec.BusinessCont,
			OperationTrust:     rec.OperationTrust,
			Resilience:         rec.Resilience,
		},
		ThreatCoeff:                rec.ThreatCoeff,
		SPCScore:                   rec.SPCScore,
		PrismScore:                 rec.PrismScore,
		PrismSemanticState:         rec.PrismSemanticState,
		PrismInferenceTrend:        rec.PrismInferenceTrend,
		PrismInferenceCollapseRisk: rec.PrismInferenceCollapseRisk,
		PrismRiskVelocity:          rec.PrismRiskVelocity,
	}
	return ExportOSCAL(result, format)
}

// buildOSCAL constructs the OSCAL assessment-results structure.
func buildOSCAL(result *model.AssessmentResult) *OSCALAssessmentResults {
	now := time.Now()
	hostUUID := fmt.Sprintf("host-%s", result.HostID)
	assessmentUUID := fmt.Sprintf("assessment-%s-%d", result.HostID, result.Timestamp.Unix())

	doc := &OSCALAssessmentResults{
		UUID: fmt.Sprintf("oscal-%s-%d", result.HostID, result.Timestamp.Unix()),
		Metadata: OSCALMetadata{
			Title:        fmt.Sprintf("ASSCOR Security Assessment for %s", result.Hostname),
			Published:    now.Format(time.RFC3339),
			LastModified: now.Format(time.RFC3339),
			Version:      "1.0",
			OSCALVersion: "1.1.0",
			Props: []OSCALProp{
				{Name: "generator", Value: "ASSCOR"},
				{Name: "assessment-type", Value: "ssam-2.0"},
				{Name: "host-id", Value: result.HostID},
				{Name: "hostname", Value: result.Hostname},
			},
			Parties: []OSCALParty{
				{UUID: "party-asscor", Type: "organization", Name: "ASSCOR Assessment Platform"},
			},
		},
	}

	// Build observations from check results
	observations := make([]OSCALObservation, 0, len(result.Checks))
	for _, c := range result.Checks {
		obsUUID := fmt.Sprintf("obs-%s-%s", result.HostID, c.CheckID)
		methods := []string{"EXAMINE"}
		if c.Domain == model.DomainAttackSurface || c.Domain == model.DomainKernelSecurity {
			methods = append(methods, "TEST")
		}

		status := "pass"
		if !c.Passed {
			status = "fail"
		}

		obs := OSCALObservation{
			UUID:        obsUUID,
			Title:       fmt.Sprintf("Check %s: %s", c.CheckID, c.Name),
			Description: fmt.Sprintf("Domain: %s | Result: %s | Detail: %s", c.Domain, status, c.Detail),
			Methods:     methods,
			Collected:   result.Timestamp.Format(time.RFC3339),
			Props: []OSCALProp{
				{Name: "check-id", Value: c.CheckID},
				{Name: "domain", Value: c.Domain},
				{Name: "passed", Value: fmt.Sprintf("%v", c.Passed)},
				{Name: "delta", Value: fmt.Sprintf("%.2f", c.Delta)},
			},
		}

		if !c.Passed {
			obs.RelevantEvidence = []OSCALRelevantEvidence{
				{Description: fmt.Sprintf("Check %s failed: %s", c.CheckID, c.Detail)},
			}
		}

		observations = append(observations, obs)
	}

	// Build findings
	findings := []OSCALFinding{
		{
			UUID:        fmt.Sprintf("finding-%s-overall", result.HostID),
			Title:       fmt.Sprintf("Overall Security Assessment for %s", result.Hostname),
			Description: fmt.Sprintf("SSAM Final Score: %.2f/100 (Threshold: %.2f, Acceptable: %v)", result.FinalScore, result.Threshold, result.Acceptable),
			Risk:        OSCALRiskStatus{Status: riskStatusFromScore(result.FinalScore), Score: result.FinalScore},
			Props: []OSCALProp{
				{Name: "ssam-score", Value: fmt.Sprintf("%.2f", result.FinalScore)},
				{Name: "threshold", Value: fmt.Sprintf("%.2f", result.Threshold)},
				{Name: "acceptable", Value: fmt.Sprintf("%v", result.Acceptable)},
			},
		},
	}

	// Domain findings
	domains := map[string]struct {
		Name  string
		Score float64
	}{
		model.DomainAttackSurface:      {"Attack Surface Management", result.DomainScores.AttackSurface},
		model.DomainBusinessContinuity: {"Business Continuity", result.DomainScores.BusinessContinuity},
		model.DomainOperationTrust:     {"Operation Trust", result.DomainScores.OperationTrust},
		model.DomainResilience:         {"Resilience", result.DomainScores.Resilience},
	}
	if result.DomainScores.KernelSecurity > 0 {
		domains[model.DomainKernelSecurity] = struct {
			Name  string
			Score float64
		}{"Kernel Security", result.DomainScores.KernelSecurity}
	}

	for domain, info := range domains {
		findings = append(findings, OSCALFinding{
			UUID:        fmt.Sprintf("finding-%s-%s", result.HostID, domain),
			Title:       fmt.Sprintf("%s Domain Assessment", info.Name),
			Description: fmt.Sprintf("Domain score: %.2f/100", info.Score),
			Risk:        OSCALRiskStatus{Status: riskStatusFromScore(info.Score), Score: info.Score},
			Props: []OSCALProp{
				{Name: "domain", Value: domain},
				{Name: "domain-score", Value: fmt.Sprintf("%.2f", info.Score)},
			},
		})
	}

	// Build risks
	risks := []OSCALRisk{
		{
			UUID:        fmt.Sprintf("risk-%s-ssam", result.HostID),
			Title:       "SSAM Security Acceptability Risk",
			Description: fmt.Sprintf("System security acceptability score: %.2f/100", result.FinalScore),
			Statement:   fmt.Sprintf("The assessed system %s has a security acceptability score of %.2f out of 100, which is %s.", result.Hostname, result.FinalScore, acceptableLabel(result.Acceptable)),
			Status:      riskStatusFromScore(result.FinalScore),
			Source:      []string{hostUUID},
			Props: []OSCALProp{
				{Name: "ssam-version", Value: "2.0"},
				{Name: "threat-coefficient", Value: fmt.Sprintf("%.2f", result.ThreatCoeff)},
			},
		},
	}

	// Prism risk entry
	if result.PrismScore > 0 {
		prismRisk := OSCALRisk{
			UUID:        fmt.Sprintf("risk-%s-prism", result.HostID),
			Title:       "Prism Risk Dynamics Assessment",
			Description: fmt.Sprintf("Prism dynamic risk score: %.2f/100", result.PrismScore),
			Statement:   fmt.Sprintf("Prism risk dynamics analysis indicates a dynamic risk score of %.2f. ", result.PrismScore),
			Status:      riskStatusFromScore(result.PrismScore),
			Source:      []string{hostUUID},
			Props: []OSCALProp{
				{Name: "prism-score", Value: fmt.Sprintf("%.2f", result.PrismScore)},
				{Name: "external-risk", Value: fmt.Sprintf("%.4f", result.PrismExternalRisk)},
				{Name: "risk-velocity", Value: fmt.Sprintf("%+.2f", result.PrismRiskVelocity)},
			},
		}

		if result.PrismSemanticState != "" {
			prismRisk.Statement += fmt.Sprintf("Semantic state: %s. ", result.PrismSemanticState)
			prismRisk.Props = append(prismRisk.Props,
				OSCALProp{Name: "semantic-state", Value: result.PrismSemanticState},
				OSCALProp{Name: "stable-membership", Value: fmt.Sprintf("%.2f", result.PrismStableMem)},
				OSCALProp{Name: "degraded-membership", Value: fmt.Sprintf("%.2f", result.PrismDegradedMem)},
				OSCALProp{Name: "untrusted-membership", Value: fmt.Sprintf("%.2f", result.PrismUntrustedMem)},
				OSCALProp{Name: "collapse-membership", Value: fmt.Sprintf("%.2f", result.PrismCollapseMem)},
			)
		}

		if result.PrismInferenceTrend != "" {
			prismRisk.Statement += fmt.Sprintf("Inference trend: %s (confidence: %.2f, collapse risk: %.2f).", result.PrismInferenceTrend, result.PrismInferenceConfidence, result.PrismInferenceCollapseRisk)
			prismRisk.Props = append(prismRisk.Props,
				OSCALProp{Name: "inference-trend", Value: result.PrismInferenceTrend},
				OSCALProp{Name: "inference-confidence", Value: fmt.Sprintf("%.2f", result.PrismInferenceConfidence)},
				OSCALProp{Name: "inference-collapse-risk", Value: fmt.Sprintf("%.2f", result.PrismInferenceCollapseRisk)},
				OSCALProp{Name: "inference-model", Value: result.PrismInferenceModel},
				OSCALProp{Name: "inference-horizon-days", Value: fmt.Sprintf("%d", result.PrismInferenceHorizonDays)},
			)
		}

		risks = append(risks, prismRisk)
	}

	// SPC risk entry
	if result.SPCScore > 0 {
		risks = append(risks, OSCALRisk{
			UUID:        fmt.Sprintf("risk-%s-spc", result.HostID),
			Title:       "SPC Vulnerability Posture",
			Description: fmt.Sprintf("SPC vulnerability posture score: %.2f", result.SPCScore),
			Statement:   fmt.Sprintf("Security posture calculation indicates a vulnerability posture score of %.2f.", result.SPCScore),
			Status:      riskStatusFromScore(result.SPCScore * 100),
			Source:      []string{hostUUID},
			Props: []OSCALProp{
				{Name: "spc-score", Value: fmt.Sprintf("%.2f", result.SPCScore)},
			},
		})
	}

	// Result entry
	doc.Results = []OSCALResult{
		{
			UUID:        assessmentUUID,
			Title:       fmt.Sprintf("Security Assessment for %s", result.Hostname),
			Description: fmt.Sprintf("Automated security assessment performed by ASSCOR on %s", result.Timestamp.Format("2006-01-02 15:04:05")),
			Start:       result.Timestamp.Format(time.RFC3339),
			Props: []OSCALProp{
				{Name: "assessment-tool", Value: "ASSCOR"},
				{Name: "ssam-version", Value: "2.0"},
				{Name: "asscor-version", Value: "v0.2.3"},
			},
			Findings:     findings,
			Observations: observations,
			Risks:        risks,
		},
	}

	return doc
}

// riskStatusFromScore maps a 0-100 score to OSCAL risk status.
func riskStatusFromScore(score float64) string {
	switch {
	case score >= 80:
		return "satisfied"
	case score >= 60:
		return "needs-attention"
	case score >= 40:
		return "significant-deficiencies"
	default:
		return "critical-deficiencies"
	}
}

func acceptableLabel(acceptable bool) string {
	if acceptable {
		return "acceptable"
	}
	return "not acceptable"
}
