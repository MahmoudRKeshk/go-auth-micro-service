package routes

import (
	"go-auth-micro-service/internal/handlers"
	"go-auth-micro-service/pkg/security"
	"net/http"
)

func RegisterRoutes(mux *http.ServeMux, handler *handlers.AuthHandler, jwtSrv *security.JwtService) {

	mux.HandleFunc("POST /auth/register", handler.Register)
	mux.HandleFunc("POST /auth/login", handler.Login)
	mux.HandleFunc("POST /auth/refresh", handler.Refresh)
	mux.HandleFunc("POST /auth/logout", handler.Logout)
	mux.HandleFunc("POST /auth/logout-all", handler.LogoutAll)
}
