package ssam

import (
	"errors"
	"strconv"
)

var (
	ErrNilInput        = errors.New("ssam: assessment input must not be nil")
	ErrUnknownFormula  = errors.New("ssam: unknown scoring formula")
	ErrEmptyWeights    = errors.New("ssam: no weights configured")
	ErrInvalidScore    = errors.New("ssam: score out of valid range [0, 100]")
)

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return "ssam validation: " + e.Field + ": " + e.Message
}

func ValidateInput(input *AssessmentInput) error {
	if input == nil {
		return ErrNilInput
	}
	if input.HostID == "" {
		return ValidationError{Field: "host_id", Message: "must not be empty"}
	}
	if input.Threshold <= 0 || input.Threshold > 100 {
		return ValidationError{Field: "threshold", Message: "must be in range (0, 100]"}
	}
	for i, c := range input.Checks {
		if c.Domain == "" {
			return ValidationError{Field: "checks[" + strconv.Itoa(i) + "].domain", Message: "must not be empty"}
		}
	}
	return nil
}

func ValidateOutput(output *AssessmentOutput) error {
	if output == nil {
		return ErrNilInput
	}
	if output.FinalScore < 0 || output.FinalScore > 100 {
		return ErrInvalidScore
	}
	return nil
}
