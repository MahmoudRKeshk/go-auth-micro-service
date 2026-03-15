package repositories

import (
	"context"
	"go-auth-micro-service/internal/models"
)

type RefreshTokenRepository interface {
	InsertRefreshToken(ctx context.Context, refreshToken *models.RefreshToken) error
}
