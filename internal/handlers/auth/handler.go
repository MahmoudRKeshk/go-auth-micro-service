package auth

import (
	"encoding/json"
	"errors"
	authdto "go-auth-micro-service/internal/dtos/auth"
	"go-auth-micro-service/internal/dtos/common"
	"go-auth-micro-service/internal/services"
	"net/http"
)

type AuthHandler struct {
	srv *services.UserService
}

func NewAuthHandler(srv *services.UserService) *AuthHandler {
	return &AuthHandler{srv: srv}
}

func (h *AuthHandler) Register(rw http.ResponseWriter, r *http.Request) {
	var req authdto.RegisterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(rw, http.StatusBadRequest, &common.ErrorResponse{
			Code:    "INVALID_REQUEST",
			Message: "invalid request body",
			Details: map[string]string{
				"request": err.Error(),
			},
		})
		return
	}

	errResp := h.srv.CreateUser(r.Context(), &req)
	if errResp != nil {
		writeError(rw, statusCodeFromError(errResp), errResp)
		return
	}

	writeJSON(rw, http.StatusCreated, nil)
}

func RegisterRoutes(mux *http.ServeMux, handler *AuthHandler) {
	mux.HandleFunc("POST /auth/register", handler.Register)
}

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
