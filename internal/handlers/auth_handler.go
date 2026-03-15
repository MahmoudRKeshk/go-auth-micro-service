package handlers

import (
	"go-auth-micro-service/internal/dtos"
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
	var req dtos.RegisterRequest
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
