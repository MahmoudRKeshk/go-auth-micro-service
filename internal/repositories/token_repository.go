package repositories

import (
	"context"
	"go-auth-micro-service/internal/models"
)

type TokenRepository interface {
	InsertToken(ctx context.Context, token *models.Token) error
	RevokeNonExpiredTokens(ctx context.Context, userId string) error
	RevokeToken(ctx context.Context, tokenHash string) error
}
