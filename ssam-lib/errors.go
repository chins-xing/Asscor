package ssam

type SSAMError struct {
	Code    string
	Message string
}

func (e *SSAMError) Error() string {
	return "ssam: " + e.Code + ": " + e.Message
}

var ErrNilInput    = &SSAMError{Code: "nil_input", Message: "assessment input must not be nil"}
var ErrUnknownFormula = &SSAMError{Code: "unknown_formula", Message: "unknown scoring formula"}
var ErrEmptyWeights  = &SSAMError{Code: "empty_weights", Message: "no weights configured"}
var ErrInvalidScore  = &SSAMError{Code: "invalid_score", Message: "score out of valid range [0, 100]"}
