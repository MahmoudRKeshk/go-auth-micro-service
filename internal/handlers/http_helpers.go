package handlers

import (
	"encoding/json"
	"errors"
	"go-auth-micro-service/internal/apperrors"
	"go-auth-micro-service/internal/dtos/common"
	"log"
	"net/http"
)

func decodeJSONBody(r *http.Request, dst interface{}) error {
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

func writeJSON(rw http.ResponseWriter, status int, payload interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(payload)
}

func writeError(rw http.ResponseWriter, status int, errResp *common.ErrorResponse) {
	writeJSON(rw, status, errResp)
}

func writeAppError(rw http.ResponseWriter, operation string, appErr *apperrors.AppError) {
	log.Printf("%s: %v", operation, appErr)
	for field, detail := range appErr.Details {
		log.Printf("%s: %s", field, detail)
	}

	httpErr := toErrorResponse(appErr)
	writeError(rw, statusCodeFromAppError(appErr), httpErr)
}

func toErrorResponse(appErr *apperrors.AppError) *common.ErrorResponse {
	return &common.ErrorResponse{
		Code:    string(appErr.Code),
		Message: appErr.Message,
		Details: appErr.Details,
	}
}

func statusCodeFromAppError(appErr *apperrors.AppError) int {
	switch appErr.Code {
	case apperrors.CodeValidation:
		return http.StatusBadRequest
	case apperrors.CodeNotFound:
		return http.StatusNotFound
	case apperrors.CodeConflict:
		return http.StatusConflict
	case apperrors.CodeUnauthorized:
		return http.StatusUnauthorized
	case apperrors.CodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}
