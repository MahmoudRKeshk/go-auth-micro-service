package api

import (
	"go-auth-micro-service/internal/platform/middlewares"
	"net/http"
)

func RegisterRoutes(mux *http.ServeMux, handler *AuthHandler, middlewares1 *middlewares.AuthMiddleware) {

	mux.HandleFunc("POST /auth/register", handler.Register)
	mux.HandleFunc("POST /auth/login", handler.Login)
	mux.HandleFunc("POST /auth/refresh", handler.Refresh)
	mux.HandleFunc("POST /auth/logout", handler.Logout)
	mux.HandleFunc("POST /auth/logout-all", handler.LogoutAll)
	ProtectedAuthMe := middlewares1.Auth(http.HandlerFunc(handler.AuthMe))
	mux.HandleFunc("GET /auth/me", ProtectedAuthMe)
}
