package routes

import (
	"go-auth-micro-service/internal/handlers"
	"net/http"
)

func RegisterRoutes(mux *http.ServeMux, handler *handlers.AuthHandler) {
	mux.HandleFunc("POST /auth/register", handler.Register)
}
