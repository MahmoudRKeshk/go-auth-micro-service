package handlers

import (
	authhandler "go-auth-micro-service/internal/handlers/auth"
	"net/http"
)

func RegisterRoutes(mux *http.ServeMux, authHandler *authhandler.AuthHandler) {
	authhandler.RegisterRoutes(mux, authHandler)
}
