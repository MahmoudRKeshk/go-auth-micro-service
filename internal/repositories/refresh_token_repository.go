package repositories

import (
	"context"
	"go-auth-micro-service/internal/models"
)

type RefreshTokenRepository interface {
	InsertRefreshToken(ctx context.Context, refreshToken *models.RefreshToken) error
	IsRefreshTokenRevoked(ctx context.Context, refreshTokenHash string) (bool, error)
	RevokeNonExpiredRefreshTokens(ctx context.Context, userId string) error
	RevokeRefreshToken(ctx context.Context, refreshTokenHash string) error
}
