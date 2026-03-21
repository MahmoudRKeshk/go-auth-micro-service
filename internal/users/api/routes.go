package api

import (
	"net/http"
)

func RegisterRoutes(mux *http.ServeMux, handler *UserHandler) {
	// TODO: protect this route with only moderator users
	mux.HandleFunc("GET /users/{userId}", handler.GetUserByID)
	// TODO: protect this route with only admin users
	mux.HandleFunc("DELETE /users/{userId}", handler.DeleteUser)
}
