package handlers

import (
	"go-auth-micro-service/internal/dtos"
	"go-auth-micro-service/internal/dtos/common"
	"go-auth-micro-service/internal/middlewares"
	"go-auth-micro-service/internal/services"
	"net/http"
)

type AuthHandler struct {
	srv         *services.AuthService
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

	appErr := h.srv.CreateUser(r.Context(), services.RegisterInput{
		Email:     req.Email,
		Username:  req.Username,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Password:  req.Password,
	})
	if appErr != nil {
		writeAppError(rw, "failed to create user", appErr)
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

	res, appErr := h.srv.Login(r.Context(), services.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if appErr != nil {
		writeAppError(rw, "failed to login", appErr)
		return
	}

	writeJSON(rw, http.StatusOK, &dtos.LoginResponse{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
	})
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

	res, appErr := h.srv.Refresh(r.Context(), services.RefreshInput{
		RefreshToken: req.RefreshToken,
	})
	if appErr != nil {
		writeAppError(rw, "failed to refresh", appErr)
		return
	}

	writeJSON(rw, http.StatusOK, &dtos.RefreshResponse{
		AccessToken: res.AccessToken,
	})
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

	appErr := h.srv.Logout(r.Context(), services.LogoutInput{
		RefreshToken: req.RefreshToken,
	})
	if appErr != nil {
		writeAppError(rw, "failed to logout", appErr)
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

	appErr := h.srv.LogoutAll(r.Context(), services.LogoutInput{
		RefreshToken: req.RefreshToken,
	})
	if appErr != nil {
		writeAppError(rw, "failed to logout all", appErr)
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

	res, appErr := h.srv.GetUserByID(r.Context(), userId)
	if appErr != nil {
		writeAppError(rw, "failed to get user", appErr)
		return
	}

	writeJSON(rw, http.StatusOK, &dtos.UserResponse{
		ID:        res.ID,
		FirstName: res.FirstName,
		LastName:  res.LastName,
		Email:     res.Email,
		Username:  res.Username,
	})
}
