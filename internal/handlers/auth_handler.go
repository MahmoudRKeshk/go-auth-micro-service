package handlers

import (
	"go-auth-micro-service/internal/dtos"
	"go-auth-micro-service/internal/dtos/common"
	"go-auth-micro-service/internal/middlewares"
	"go-auth-micro-service/internal/services"
	"net/http"
)

type AuthHandler struct {
	srv *services.AuthService
	middlewares *middlewares.AuthMiddleware
}

func NewAuthHandler(srv *services.AuthService, middlewares *middlewares.AuthMiddleware) *AuthHandler {
	return &AuthHandler{srv: srv, middlewares: middlewares}
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

func (h *AuthHandler) Login(rw http.ResponseWriter, r *http.Request) {
	var req dtos.LoginRequest
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

	resp, errResp := h.srv.Login(r.Context(), &req)
	if errResp != nil {
		writeError(rw, statusCodeFromError(errResp), errResp)
		return
	}

	writeJSON(rw, http.StatusOK, resp)
}

func (h *AuthHandler) Refresh(rw http.ResponseWriter, r *http.Request) {
	var req dtos.RefreshRequest
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

	resp, errResp := h.srv.Refresh(r.Context(), &req)
	if errResp != nil {
		writeError(rw, statusCodeFromError(errResp), errResp)
		return
	}

	writeJSON(rw, http.StatusOK, resp)
}

func (h *AuthHandler) Logout(rw http.ResponseWriter, r *http.Request) {
	var req dtos.LogoutRequest
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

	errResp := h.srv.Logout(r.Context(), &req)
	if errResp != nil {
		writeError(rw, statusCodeFromError(errResp), errResp)
		return
	}

	writeJSON(rw, http.StatusOK, nil)
}

func (h *AuthHandler) LogoutAll(rw http.ResponseWriter, r *http.Request) {
	var req dtos.LogoutRequest
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

	errResp := h.srv.LogoutAll(r.Context(), &req)
	if errResp != nil {
		writeError(rw, statusCodeFromError(errResp), errResp)
		return
	}

	writeJSON(rw, http.StatusOK, nil)
}

func (h *AuthHandler) AuthMe(rw http.ResponseWriter, r *http.Request) {
	userId, ok := h.middlewares.UserIDFromContext(r.Context())
	if !ok {
		writeError(rw, http.StatusUnauthorized, &common.ErrorResponse{
			Code:    "UNAUTHORIZED",
			Message: "unauthorized",
			Details: nil,
		})
		return
	}
	if userId == "" {
		writeError(rw, http.StatusUnauthorized, &common.ErrorResponse{
			Code:    "UNAUTHORIZED",
			Message: "unauthorized",
			Details: nil,
		})
		return
	}

	resp, errResp := h.srv.GetUserByID(r.Context(), userId)
	if errResp != nil {
		writeError(rw, statusCodeFromError(errResp), errResp)
		return
	}

	writeJSON(rw, http.StatusOK, resp)
}



/*

POST /auth/register -> Implemented
POST /auth/login -> Implemented
POST /auth/refresh -> Implemented
POST /auth/logout -> Implemented
POST /auth/logout-all -> Implemented
GET /auth/me -> Not Implemented
POST /auth/change-password -> Not Implemented
GET /auth/sessions -> Not Implemented
DELETE /auth/sessions/{refreshTokenId} -> Not Implemented

*/
