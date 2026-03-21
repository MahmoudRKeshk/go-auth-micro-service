package api

import (
	"go-auth-micro-service/internal/shared/errs"
	"go-auth-micro-service/internal/shared/httpx"
	"go-auth-micro-service/internal/users/service"
	"net/http"
)

type UserHandler struct {
	srv *service.UserService
}

func NewUserHandler(srv *service.UserService) *UserHandler {
	return &UserHandler{srv: srv}
}

func (h *UserHandler) GetUserByID(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	if userID == "" {
		httpx.WriteError(w, http.StatusBadRequest, &errs.ErrorResponse{
			Code:       "VALIDATION_ERROR",
			Message:    "user ID is required",
			Details:    nil,
			StatusCode: http.StatusBadRequest,
		})
		return
	}
	res, appErr := h.srv.GetUserByID(r.Context(), userID)
	if appErr != nil {
		httpx.WriteAppError(w, "failed to get user", appErr)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, &UserResponse{
		ID:        res.ID,
		Username:  res.Username,
		FirstName: res.FirstName,
		LastName:  res.LastName,
		Email:     res.Email,
	})
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	if userID == "" {
		httpx.WriteError(w, http.StatusBadRequest, &errs.ErrorResponse{
			Code:       "VALIDATION_ERROR",
			Message:    "user ID is required",
			Details:    nil,
			StatusCode: http.StatusBadRequest,
		})
		return
	}
	appErr := h.srv.DeleteUser(r.Context(), userID)
	if appErr != nil {
		httpx.WriteAppError(w, "failed to delete user", appErr)
		return
	}
	httpx.WriteJSON(w, http.StatusNoContent, nil)
}
