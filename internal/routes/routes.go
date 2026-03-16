package routes

import (
	"go-auth-micro-service/internal/handlers"
	"go-auth-micro-service/internal/middlewares"
	"go-auth-micro-service/pkg/security"
	"net/http"

)

func RegisterRoutes(mux *http.ServeMux, handler *handlers.AuthHandler, jwtSrv *security.JwtService) {

	mux.HandleFunc("POST /auth/register", handler.Register)
	mux.HandleFunc("POST /auth/login", handler.Login)
	
	// auth handler
	protectedTest := middlewares.AuthMiddleware(jwtSrv, http.HandlerFunc(handler.Test))
	mux.HandleFunc("GET /auth/test", protectedTest)
}
