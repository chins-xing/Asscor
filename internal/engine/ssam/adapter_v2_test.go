//go:build engine

package ssam

import (
	"testing"

	"github.com/chins-xing/asscor/internal/model"
)

// TestOutputV2ToModelMapsPosteriorStatistics is the red test for audit M-3:
// OutputV2ToModel dropped FinalSigma / Lower95 / Upper95 / EvidenceConfidence,
// so every V2 conversion produced a model result with zero posterior
// statistics. The V1 field names on model.AssessmentResult are
// FinalSigma / ScoreLower95 / ScoreUpper95 / EvidenceConfidence.
func TestOutputV2ToModelMapsPosteriorStatistics(t *testing.T) {
	output := &AssessmentOutputV2{
		HostID:             "v2-posterior-host",
		FinalScore:         FinalScore{Total: 72.5},
		Acceptable:         false,
		Threshold:          80,
		FinalSigma:         4.25,
		Lower95:            64.0,
		Upper95:            81.0,
		EvidenceConfidence: 0.73,
	}

	result := &model.AssessmentResult{}
	OutputV2ToModel(output, result)

	if result.FinalSigma != 4.25 {
		t.Errorf("FinalSigma = %v, want 4.25 (OutputV2ToModel must map output.FinalSigma)", result.FinalSigma)
	}
	if result.ScoreLower95 != 64.0 {
		t.Errorf("ScoreLower95 = %v, want 64.0 (OutputV2ToModel must map output.Lower95)", result.ScoreLower95)
	}
	if result.ScoreUpper95 != 81.0 {
		t.Errorf("ScoreUpper95 = %v, want 81.0 (OutputV2ToModel must map output.Upper95)", result.ScoreUpper95)
	}
	if result.EvidenceConfidence != 0.73 {
		t.Errorf("EvidenceConfidence = %v, want 0.73 (OutputV2ToModel must map output.EvidenceConfidence)",
			result.EvidenceConfidence)
	}
}

// TestOutputV2ToModelPosteriorMatchesV1Fields pins that both converters agree on
// the posterior statistics for the same values, so the V2 path cannot silently
// diverge from the V1 path again.
func TestOutputV2ToModelPosteriorMatchesV1Fields(t *testing.T) {
	v1 := &AssessmentOutput{
		FinalSigma:         1.5,
		Lower95:            70,
		Upper95:            90,
		EvidenceConfidence: 0.6,
	}
	v2 := &AssessmentOutputV2{
		FinalSigma:         1.5,
		Lower95:            70,
		Upper95:            90,
		EvidenceConfidence: 0.6,
	}

	fromV1 := &model.AssessmentResult{}
	fromV2 := &model.AssessmentResult{}
	OutputToModel(v1, fromV1)
	OutputV2ToModel(v2, fromV2)

	if fromV1.FinalSigma != fromV2.FinalSigma ||
		fromV1.ScoreLower95 != fromV2.ScoreLower95 ||
		fromV1.ScoreUpper95 != fromV2.ScoreUpper95 ||
		fromV1.EvidenceConfidence != fromV2.EvidenceConfidence {
		t.Fatalf("V1/V2 posterior mismatch: V1(sigma=%v lo=%v hi=%v ev=%v) V2(sigma=%v lo=%v hi=%v ev=%v)",
			fromV1.FinalSigma, fromV1.ScoreLower95, fromV1.ScoreUpper95, fromV1.EvidenceConfidence,
			fromV2.FinalSigma, fromV2.ScoreLower95, fromV2.ScoreUpper95, fromV2.EvidenceConfidence)
	}
}
