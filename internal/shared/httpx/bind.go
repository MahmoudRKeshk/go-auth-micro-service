package httpx

import (
	"net/http"
	"log"
	"go-auth-micro-service/internal/shared/errs"
	"encoding/json"
	"errors"
)

// private utils methods

func DecodeJSONBody(r *http.Request, dst interface{}) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	if decoder.More() {
		return errors.New("request body must contain a single JSON object")
	}

	return nil
}

func WriteJSON(rw http.ResponseWriter, status int, payload interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(payload)
}

func WriteError(rw http.ResponseWriter, status int, errResp *errs.ErrorResponse) {
	WriteJSON(rw, status, errResp)
}

func WriteAppError(rw http.ResponseWriter, operation string, appErr *errs.AppError) {
	log.Printf("%s: %v", operation, appErr)
	for field, detail := range appErr.Details {
		log.Printf("%s: %s", field, detail)
	}

	httpErr := toErrorResponse(appErr)
	WriteError(rw, StatusCodeFromAppError(appErr), httpErr)
}

func toErrorResponse(appErr *errs.AppError) *errs.ErrorResponse {
	return &errs.ErrorResponse{
		Code:    string(appErr.Code),
		Message: appErr.Message,
		Details: appErr.Details,
	}
}

func StatusCodeFromAppError(appErr *errs.AppError) int {
	switch appErr.Code {
	case errs.CodeValidation:
		return http.StatusBadRequest
	case errs.CodeNotFound:
		return http.StatusNotFound
	case errs.CodeConflict:
		return http.StatusConflict
	case errs.CodeUnauthorized:
		return http.StatusUnauthorized
	case errs.CodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}