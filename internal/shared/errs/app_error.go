package errs

import "fmt"

type Code string

const (
	CodeValidation   Code = "VALIDATION"
	CodeNotFound     Code = "NOT_FOUND"
	CodeConflict     Code = "CONFLICT"
	CodeUnauthorized Code = "UNAUTHORIZED"
	CodeInternal     Code = "INTERNAL"
)

type AppError struct {
	Code    Code
	Message string
	Details map[string]string
	Err     error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}

	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Err
}
