package api

import (
	"go-auth-micro-service/internal/platform/middlewares"
	"net/http"
)

func RegisterRoutes(mux *http.ServeMux, handler *AuthHandler, authMiddleware *middlewares.AuthMiddleware) {

	protectedAuthMe := authMiddleware.Auth(http.HandlerFunc(handler.AuthMe))
	protectedChancgePassword := authMiddleware.Auth(http.HandlerFunc(handler.ChangePassword))

	mux.HandleFunc("POST /auth/register", handler.Register)
	mux.HandleFunc("POST /auth/login", handler.Login)
	mux.HandleFunc("POST /auth/refresh", handler.Refresh)
	mux.HandleFunc("POST /auth/logout", handler.Logout)
	mux.HandleFunc("POST /auth/logout-all", handler.LogoutAll)
	mux.HandleFunc("GET /auth/me", protectedAuthMe)
	mux.HandleFunc("POST /auth/change-password", protectedChancgePassword)
}
