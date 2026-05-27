package ssam

import "strconv"

func ValidateInput(input AssessmentInput) error {
	if input.HostID == "" {
		return &SSAMError{Code: "empty_host_id", Message: "host_id must not be empty"}
	}
	if input.Threshold <= 0 || input.Threshold > 100 {
		return &SSAMError{Code: "invalid_threshold", Message: "threshold must be in range (0, 100]"}
	}
	for i, c := range input.Checks {
		if c.Domain == "" {
			return &SSAMError{Code: "empty_domain", Message: "checks[" + strconv.Itoa(i) + "].domain must not be empty"}
		}
	}
	return nil
}

func ValidateOutput(output AssessmentOutput) error {
	if output.FinalScore < 0 || output.FinalScore > 100 {
		return ErrInvalidScore
	}
	return nil
}
