package handlers

import (
	"encoding/json"
	"errors"
	"go-auth-micro-service/internal/dtos/common"
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

func statusCodeFromError(errResp *common.ErrorResponse) int {
	switch errResp.Code {
	case "VALIDATION_ERROR":
		return http.StatusBadRequest
	case "NOT_FOUND":
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}