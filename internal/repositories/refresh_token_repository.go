package repositories

import (
	"context"
	"go-auth-micro-service/internal/models"
)

type RefreshTokenRepository interface {
	GetRefreshTokenByTokenHashAndUserID(ctx context.Context, refreshTokenHash string, userID string) (*models.RefreshToken, error)
	InsertRefreshToken(ctx context.Context, refreshToken *models.RefreshToken) (*models.RefreshToken, error)
	IsRefreshTokenRevoked(ctx context.Context, refreshTokenHash string, userID string) (bool, error)
	RevokeNonExpiredRefreshTokens(ctx context.Context, userId string) error
	RevokeRefreshToken(ctx context.Context, refreshTokenHash string, userID string) error
}
