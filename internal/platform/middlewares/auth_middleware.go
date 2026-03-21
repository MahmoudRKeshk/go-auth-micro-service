package middlewares

import (
	"context"
	"go-auth-micro-service/internal/auth/repository"
	"go-auth-micro-service/internal/platform/security"
	"go-auth-micro-service/internal/shared/utils"
	"net/http"
	"strings"
)

type contextKey string

type AuthMiddleware struct {
	jwtSrv    *security.JwtService
	tokenRepo repository.TokenRepository
}

func NewAuthMiddlewares(jwtSrv *security.JwtService, tokenRepo repository.TokenRepository) *AuthMiddleware {
	return &AuthMiddleware{jwtSrv: jwtSrv, tokenRepo: tokenRepo}
}

func (m *AuthMiddleware) UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value("userId").(string)
	return userID, ok
}

func (m *AuthMiddleware) Auth(next http.Handler) func(w http.ResponseWriter, r *http.Request) {
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

		isRevoked, err := m.tokenRepo.IsTokenRevoked(r.Context(), tokenHash)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if isRevoked {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		claims, err := m.jwtSrv.ParseToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userID, ok := claims["userId"].(string)
		if !ok || userID == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userId", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
