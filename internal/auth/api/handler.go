package api

import (
	"go-auth-micro-service/internal/auth/service"
	"go-auth-micro-service/internal/platform/middlewares"
	"go-auth-micro-service/internal/shared/errs"
	"go-auth-micro-service/internal/shared/httpx"
	"net/http"
)

type AuthHandler struct {
	srv         *service.AuthService
	middlewares *middlewares.AuthMiddleware
}

func NewAuthHandler(srv *service.AuthService, middlewares *middlewares.AuthMiddleware) *AuthHandler {
	return &AuthHandler{srv: srv, middlewares: middlewares}
}

func (h *AuthHandler) Register(rw http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := httpx.DecodeJSONBody(r, &req); err != nil {
		httpx.WriteError(rw, http.StatusBadRequest, &errs.ErrorResponse{
			Code:    "INVALID_REQUEST",
			Message: "invalid request body",
			Details: map[string]string{
				"request": err.Error(),
			},
		})
		return
	}

	appErr := h.srv.CreateUser(r.Context(), service.RegisterInput{
		Email:     req.Email,
		Username:  req.Username,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Password:  req.Password,
	})
	if appErr != nil {
		httpx.WriteAppError(rw, "failed to create user", appErr)
		return
	}

	httpx.WriteJSON(rw, http.StatusCreated, nil)
}

func (h *AuthHandler) Login(rw http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := httpx.DecodeJSONBody(r, &req); err != nil {
		httpx.WriteError(rw, http.StatusBadRequest, &errs.ErrorResponse{
			Code:    "INVALID_REQUEST",
			Message: "invalid request body",
			Details: map[string]string{
				"request": err.Error(),
			},
		})
		return
	}

	res, appErr := h.srv.Login(r.Context(), service.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if appErr != nil {
		httpx.WriteAppError(rw, "failed to login", appErr)
		return
	}

	httpx.WriteJSON(rw, http.StatusOK, &LoginResponse{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
	})
}

func (h *AuthHandler) Refresh(rw http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := httpx.DecodeJSONBody(r, &req); err != nil {
		httpx.WriteError(rw, http.StatusBadRequest, &errs.ErrorResponse{
			Code:    "INVALID_REQUEST",
			Message: "invalid request body",
			Details: map[string]string{
				"request": err.Error(),
			},
		})
		return
	}

	res, appErr := h.srv.Refresh(r.Context(), service.RefreshInput{
		RefreshToken: req.RefreshToken,
	})
	if appErr != nil {
		httpx.WriteAppError(rw, "failed to refresh", appErr)
		return
	}

	httpx.WriteJSON(rw, http.StatusOK, &RefreshResponse{
		AccessToken: res.AccessToken,
	})
}

func (h *AuthHandler) Logout(rw http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := httpx.DecodeJSONBody(r, &req); err != nil {
		httpx.WriteError(rw, http.StatusBadRequest, &errs.ErrorResponse{
			Code:    "INVALID_REQUEST",
			Message: "invalid request body",
			Details: map[string]string{
				"request": err.Error(),
			},
		})
		return
	}

	appErr := h.srv.Logout(r.Context(), service.LogoutInput{
		RefreshToken: req.RefreshToken,
	})
	if appErr != nil {
		httpx.WriteAppError(rw, "failed to logout", appErr)
		return
	}

	httpx.WriteJSON(rw, http.StatusOK, nil)
}

func (h *AuthHandler) LogoutAll(rw http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := httpx.DecodeJSONBody(r, &req); err != nil {
		httpx.WriteError(rw, http.StatusBadRequest, &errs.ErrorResponse{
			Code:    "INVALID_REQUEST",
			Message: "invalid request body",
			Details: map[string]string{
				"request": err.Error(),
			},
		})
		return
	}

	appErr := h.srv.LogoutAll(r.Context(), service.LogoutInput{
		RefreshToken: req.RefreshToken,
	})
	if appErr != nil {
		httpx.WriteAppError(rw, "failed to logout all", appErr)
		return
	}
	httpx.WriteJSON(rw, http.StatusOK, nil)
}

func (h *AuthHandler) AuthMe(rw http.ResponseWriter, r *http.Request) {
	userId, ok := h.middlewares.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(rw, http.StatusUnauthorized, &errs.ErrorResponse{
			Code:    "UNAUTHORIZED",
			Message: "unauthorized",
			Details: nil,
		})
		return
	}
	if userId == "" {
		httpx.WriteError(rw, http.StatusUnauthorized, &errs.ErrorResponse{
			Code:    "UNAUTHORIZED",
			Message: "unauthorized",
			Details: nil,
		})
		return
	}

	res, appErr := h.srv.GetUserByID(r.Context(), userId)
	if appErr != nil {
		httpx.WriteAppError(rw, "failed to get user", appErr)
		return
	}

	httpx.WriteJSON(rw, http.StatusOK, &UserResponse{
		ID:        res.ID,
		FirstName: res.FirstName,
		LastName:  res.LastName,
		Email:     res.Email,
		Username:  res.Username,
	})
}

func (h *AuthHandler) ChangePassword(rw http.ResponseWriter, r *http.Request) {
	var req ChangePasswordRequest
	if err := httpx.DecodeJSONBody(r, &req); err != nil {
		httpx.WriteError(rw, http.StatusBadRequest, &errs.ErrorResponse{
			Code:    "INVALID_REQUEST",
			Message: "invalid request body",
			Details: map[string]string{
				"request": err.Error(),
			},
		})
		return
	}
	userId, ok := h.middlewares.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(rw, http.StatusUnauthorized, &errs.ErrorResponse{
			Code:    "UNAUTHORIZED",
			Message: "unauthorized",
			Details: nil,
		})
		return
	}
	if userId == "" {
		httpx.WriteError(rw, http.StatusUnauthorized, &errs.ErrorResponse{
			Code:    "UNAUTHORIZED",
			Message: "unauthorized",
			Details: nil,
		})
		return
	}
	appErr := h.srv.ChangePassword(r.Context(), service.ChangePasswordInput{
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}, userId)
	if appErr != nil {
		httpx.WriteAppError(rw, "failed to change password", appErr)
		return
	}
	httpx.WriteJSON(rw, http.StatusOK, nil)
}
