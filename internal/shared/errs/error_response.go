package errs

type ErrorResponse struct {
	Code       string            `json:"code"`
	Message    string            `json:"message"`
	Details    map[string]string `json:"details,omitempty"`
	StatusCode int               `json:"-"`
}