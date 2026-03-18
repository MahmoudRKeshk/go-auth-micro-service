package middlewares

import (
	"context"
	"go-auth-micro-service/internal/repositories"
	"go-auth-micro-service/pkg/security"
	"go-auth-micro-service/pkg/utils"
	"net/http"
	"strings"
)

type contextKey string

const userIDContextKey contextKey = "userId"

func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDContextKey).(string)
	return userID, ok
}

func AuthMiddleware(jwtSrv *security.JwtService, tokenRepo repositories.TokenRepository, next http.Handler) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if authorization == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(authorization, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authorization, "Bearer ")
		tokenHash := utils.HashToken(token)

		isRevoked, err := tokenRepo.IsTokenRevoked(r.Context(), tokenHash)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if isRevoked {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		claims, err := jwtSrv.ParseToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userID, ok := claims["userId"].(string)
		if !ok || userID == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userIDContextKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
