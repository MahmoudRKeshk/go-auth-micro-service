package routes

import (
	"go-auth-micro-service/internal/handlers"
	"go-auth-micro-service/internal/middlewares"
	"net/http"
)

func RegisterRoutes(mux *http.ServeMux, handler *handlers.AuthHandler, middlewares *middlewares.AuthMiddleware) {

	mux.HandleFunc("POST /auth/register", handler.Register)
	mux.HandleFunc("POST /auth/login", handler.Login)
	mux.HandleFunc("POST /auth/refresh", handler.Refresh)
	mux.HandleFunc("POST /auth/logout", handler.Logout)
	mux.HandleFunc("POST /auth/logout-all", handler.LogoutAll)
	ProtectedAuthMe := middlewares.Auth(http.HandlerFunc(handler.AuthMe)) 
	mux.HandleFunc("GET /auth/me", ProtectedAuthMe)
}
